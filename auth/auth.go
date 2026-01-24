package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
)

// デフォルト値の定義
const (
	DefaultUserSessionKey = "user_email"
	DefaultStateCookie    = "oauth_state"
)

// Config は認証ハンドラーの初期化設定です
type Config struct {
	ClientID        string
	ClientSecret    string
	RedirectURL     string
	SessionKey      string // クッキー署名用の秘密鍵
	SessionName     string // e.g. "my-app-session"
	IsSecureCookie  bool
	AllowedEmails   []string
	AllowedDomains  []string
	TaskAudienceURL string // Cloud Tasks検証用
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
func NewHandler(cfg Config) *Handler {
	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	store := sessions.NewCookieStore([]byte(cfg.SessionKey))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
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
	}
}

// Login はGoogleのログイン画面へリダイレクトします
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	state, err := generateState()
	if err != nil {
		slog.Error("State生成失敗", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     DefaultStateCookie,
		Value:    state,
		MaxAge:   600,
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

	// 使い終わったstateクッキーを削除
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

	email, err := h.fetchUserEmail(r.Context(), token)
	if err != nil {
		slog.Error("ユーザー情報取得失敗", "error", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	if !h.isAuthorized(email) {
		slog.Warn("未許可ユーザー", "email", email)
		http.Error(w, "Unauthorized email", http.StatusForbidden)
		return
	}

	session, _ := h.store.Get(r, h.sessionName)
	session.Values[DefaultUserSessionKey] = email
	if err := session.Save(r, w); err != nil {
		slog.Error("セッション保存失敗", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Middleware はユーザー認証を確認し、未認証ならログインへ飛ばします
func (h *Handler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := h.store.Get(r, h.sessionName)
		email, ok := session.Values[DefaultUserSessionKey].(string)
		if !ok || email == "" {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// TaskOIDCVerificationMiddleware はCloud Tasksのトークンを検証します
func (h *Handler) TaskOIDCVerificationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if h.taskAudienceURL == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
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

// fetchUserEmail Google UserInfo エンドポイントを使用して、OAuth2 トークンからユーザーのメールアドレスを取得します。
// // メールアドレスを文字列として返します。プロセスが失敗した場合はエラーを返します
func (h *Handler) fetchUserEmail(ctx context.Context, token *oauth2.Token) (string, error) {
	client := h.oauthConfig.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var u struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return "", err
	}
	return u.Email, nil
}

// isAuthorized ハンドラー構成で許可された電子メールまたはドメインに基づいて、提供された電子メールが承認されているかどうかを確認します。
func (h *Handler) isAuthorized(email string) bool {
	if len(h.allowedEmails) == 0 && len(h.allowedDomains) == 0 {
		return false
	}
	if _, ok := h.allowedEmails[email]; ok {
		return true
	}
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		_, ok := h.allowedDomains[parts[1]]
		return ok
	}
	return false
}

// toMap 文字列のスライスをマップに変換します。マップでは、各文字列がキーとなり、値として空の構造体を持ちます。
func toMap(slice []string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, s := range slice {
		if s != "" {
			m[s] = struct{}{}
		}
	}
	return m
}

// generateState OAuth フローの状態パラメータとして使用されるランダムな base64 エンコード文字列を生成します。
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("state generation failed")
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
