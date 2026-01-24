package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"strings"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
)

// デフォルト値およびマジックナンバーの定数化
const (
	DefaultUserSessionKey     = "user_email"
	DefaultStateCookie        = "oauth_state"
	DefaultRedirectSessionKey = "redirect_after_login"
	googleUserInfoURL         = "https://www.googleapis.com/oauth2/v2/userinfo"
	sessionMaxAgeSec          = 60 * 60 * 24 * 7 // 7日間
	stateCookieMaxAgeSec      = 60 * 10          // 10分間
)

// Config は認証ハンドラーの初期化設定です
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// SessionKey はクッキー署名用の秘密鍵です。
	// 暗号化/署名のため、16, 24, 32バイト(AES) または 64バイト(HMAC) を推奨します。
	SessionKey     string
	SessionName    string // e.g. "my-app-session"
	IsSecureCookie bool
	AllowedEmails  []string
	AllowedDomains []string
	// TaskAudienceURL は Cloud Tasks の OIDC トークン検証に使用する Audience URL です。
	TaskAudienceURL string
}

// googleUserInfo は Google UserInfo エンドポイントのレスポンス形式です
type googleUserInfo struct {
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
}

// Handler は認証ロジックを保持する構造体です
type Handler struct {
	oauthConfig     *oauth2.Config
	store           sessions.Store
	sessionName     string
	taskAudienceURL string
	isSecureCookie  bool
	allowedEmails   map[string]struct{}
	allowedDomains  map[string]struct{}
}

// NewHandler は設定に基づき Handler を生成します
func NewHandler(cfg Config) (*Handler, error) {
	// セッションキーの長さを検証
	keyLen := len(cfg.SessionKey)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 && keyLen != 64 {
		return nil, fmt.Errorf("invalid session key length: %d. Must be 16, 24, 32, or 64 bytes", keyLen)
	}

	// 許可リストが空の場合の警告ログ
	if len(cfg.AllowedEmails) == 0 && len(cfg.AllowedDomains) == 0 {
		slog.Warn("認証許可リスト(AllowedEmails/AllowedDomains)が空です。全てのユーザーが拒否されます。")
	}

	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes: []string{
			"openid", // OIDC 準拠のため追加
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	store := sessions.NewCookieStore([]byte(cfg.SessionKey))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   sessionMaxAgeSec,
		HttpOnly: true,
		Secure:   cfg.IsSecureCookie,
		SameSite: http.SameSiteLaxMode,
	}

	return &Handler{
		oauthConfig:     oauthCfg,
		store:           store,
		sessionName:     cfg.SessionName,
		taskAudienceURL: cfg.TaskAudienceURL,
		isSecureCookie:  cfg.IsSecureCookie,
		allowedEmails:   toMap(cfg.AllowedEmails),
		allowedDomains:  toMap(cfg.AllowedDomains),
	}, nil
}

// Login はGoogleのログイン画面へリダイレクトします
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	state, err := generateState()
	if err != nil {
		slog.Error("State生成失敗", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// セッション取得とリダイレクトURLの保存ロジックの整理
	session, err := h.store.Get(r, h.sessionName)
	if err != nil {
		slog.Warn("セッション取得失敗（ログイン時）。リダイレクト先URLは保存されません。", "error", err)
	} else {
		if redirectTo := r.URL.Query().Get("redirect_to"); redirectTo != "" {
			// オープンリダイレクト対策
			if strings.HasPrefix(redirectTo, "/") && !strings.HasPrefix(redirectTo, "//") {
				session.Values[DefaultRedirectSessionKey] = redirectTo
				if err := session.Save(r, w); err != nil {
					slog.Error("リダイレクトURLの保存失敗", "error", err)
				}
			} else {
				slog.Warn("無効なリダイレクトURL（外部サイトの可能性）を拒否しました", "redirect_to", redirectTo)
			}
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     DefaultStateCookie,
		Value:    state,
		MaxAge:   stateCookieMaxAgeSec,
		HttpOnly: true,
		Secure:   h.isSecureCookie,
		Path:     "/auth/callback",
	})

	url := h.oauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Callback はOAuth2のコールバックを処理しセッションを開始します
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	queryState := r.URL.Query().Get("state")
	cookieState, err := r.Cookie(DefaultStateCookie)
	if err != nil || cookieState.Value != queryState {
		slog.Warn("CSRF攻撃の可能性を検知", "error", err)
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: DefaultStateCookie, Value: "", MaxAge: -1, Path: "/auth/callback",
	})

	code := r.URL.Query().Get("code")
	token, err := h.oauthConfig.Exchange(r.Context(), code)
	if err != nil {
		slog.Error("トークン交換失敗", "error", err)
		http.Error(w, "Auth failed", http.StatusInternalServerError)
		return
	}

	var email string
	if rawIDToken, ok := token.Extra("id_token").(string); ok && rawIDToken != "" {
		payload, err := idtoken.Validate(r.Context(), rawIDToken, h.oauthConfig.ClientID)
		if err == nil {
			if emailClaim, ok := payload.Claims["email"].(string); ok {
				email = emailClaim
			}
		} else {
			slog.Warn("IDトークン検証失敗。UserInfo APIへフォールバックします。", "error", err)
		}
	}

	if email == "" {
		email, err = h.fetchUserEmail(r.Context(), token)
		if err != nil {
			slog.Error("ユーザー情報取得失敗", "error", err)
			http.Error(w, "Failed to get user info", http.StatusInternalServerError)
			return
		}
	}

	if !h.isAuthorized(email) {
		slog.Warn("未許可ユーザー", "email", email)
		http.Error(w, "Unauthorized email", http.StatusForbidden)
		return
	}

	session, err := h.store.Get(r, h.sessionName)
	if err != nil {
		slog.Error("セッション取得失敗", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	targetURL := "/"
	if url, ok := session.Values[DefaultRedirectSessionKey].(string); ok && url != "" {
		targetURL = url
		delete(session.Values, DefaultRedirectSessionKey)
	}

	session.Values[DefaultUserSessionKey] = email
	if err := session.Save(r, w); err != nil {
		slog.Error("セッション保存失敗", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, targetURL, http.StatusSeeOther)
}

// Middleware はユーザー認証を確認し、未認証ならログインへ飛ばします
func (h *Handler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := h.store.Get(r, h.sessionName)
		if err != nil {
			// gorilla/securecookie のエラーメッセージ依存に関する注記:
			// この文字列は将来変更される可能性があるが、現状ではキー不一致を検知する唯一の手段。
			if err != nil && strings.Contains(err.Error(), "securecookie: the value is invalid") {
				slog.Error("セッションキー不一致の可能性。設定を確認してください。", "error", err)
			} else {
				slog.Warn("セッション取得失敗、ログインへリダイレクト", "error", err)
			}
			h.clearSessionCookie(w, r)
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}

		email, ok := session.Values[DefaultUserSessionKey].(string)
		if !ok || email == "" {
			loginURL := "/auth/login"
			if r.URL.Path != "" && r.URL.Path != "/" {
				loginURL = fmt.Sprintf("/auth/login?redirect_to=%s", url.QueryEscape(r.URL.RequestURI()))
			}
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// TaskOIDCVerificationMiddleware はCloud Tasksのトークンを検証します
func (h *Handler) TaskOIDCVerificationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.taskAudienceURL == "" {
			slog.Error("TaskAudienceURLが未設定です")
			http.Error(w, "Configuration error", http.StatusInternalServerError)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized: Bearer token required", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		payload, err := idtoken.Validate(r.Context(), token, h.taskAudienceURL)
		if err != nil {
			slog.Warn("IDトークン検証失敗", "error", err)
			http.Error(w, "Invalid token", http.StatusForbidden)
			return
		}

		slog.Debug("Task認証成功", "sub", payload.Subject)
		next.ServeHTTP(w, r)
	})
}

// fetchUserEmail はGoogle UserInfoエンドポイントからメールアドレスを取得します
func (h *Handler) fetchUserEmail(ctx context.Context, token *oauth2.Token) (string, error) {
	client := h.oauthConfig.Client(ctx, token)
	resp, err := client.Get(googleUserInfoURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var u googleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return "", err
	}

	if !u.VerifiedEmail {
		return "", fmt.Errorf("email '%s' is not verified", u.Email)
	}

	return u.Email, nil
}

// isAuthorized はメールアドレスが許可条件を満たすか判定します
func (h *Handler) isAuthorized(email string) bool {
	if len(h.allowedEmails) == 0 && len(h.allowedDomains) == 0 {
		return false
	}
	if _, ok := h.allowedEmails[email]; ok {
		return true
	}

	// net/mail を使用して厳密にパースし、ドメイン偽装対策を行う
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}

	if i := strings.LastIndex(addr.Address, "@"); i != -1 {
		domain := addr.Address[i+1:]
		if _, ok := h.allowedDomains[domain]; ok {
			return true
		}
	}
	return false
}

// clearSessionCookie は現在のセッションクッキーを確実に無効化します
func (h *Handler) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	session, err := h.store.Get(r, h.sessionName)
	if err != nil {
		slog.Warn("クッキー取得に失敗しましたが、削除を試みます", "error", err)
	}
	session.Options.MaxAge = -1
	if err := session.Save(r, w); err != nil {
		slog.Warn("セッションクッキーのクリアに失敗", "error", err)
	}
}

func toMap(slice []string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, s := range slice {
		if s != "" {
			m[s] = struct{}{}
		}
	}
	return m
}

func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes for state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
