package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/sessions"
	"google.golang.org/api/idtoken"
)

const (
	// CSRFTokenKey はセッション内でトークンを保持するためのキーです。
	CSRFTokenKey = "csrf_token"
	// HeaderXCSRFToken はフロントエンドがトークンを送信する際の標準ヘッダーです。
	HeaderXCSRFToken = "X-CSRF-Token"
)

// Middleware は、セッションベースの認証とCSRF検証を適用します。
func (h *Handler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := h.store.Get(r, h.sessionName)
		if err != nil {
			// セッション解析に失敗した場合（署名キー変更時など）は詳細を記録しクッキーをクリア
			slog.Warn("セッション取得失敗。新規セッションとして扱います", "error", err)
			h.clearSessionCookie(w, r)
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}

		// 1. ログイン認証チェック
		email, ok := session.Values[DefaultUserSessionKey].(string)
		if !ok || email == "" {
			http.Redirect(w, r, buildLoginRedirectURL(r), http.StatusFound)
			return
		}

		// 2. CSRFチェック (副作用のあるメソッドのみ)
		if isStateChangingMethod(r.Method) {
			if !h.validateCSRF(r, session) {
				slog.Warn("CSRF検証失敗", "email", email, "method", r.Method, "path", r.URL.Path)
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// isStateChangingMethod は CSRF 保護が必要な HTTP メソッドを判定します。
func isStateChangingMethod(method string) bool {
	return method == http.MethodPost ||
		method == http.MethodPut ||
		method == http.MethodDelete ||
		method == http.MethodPatch
}

// validateCSRF は、リクエストのトークンを検証します。
func (h *Handler) validateCSRF(r *http.Request, session *sessions.Session) bool {
	expected, ok := session.Values[CSRFTokenKey].(string)
	if !ok || expected == "" {
		return false
	}

	token := r.Header.Get(HeaderXCSRFToken)

	if token == "" {
		contentType := r.Header.Get("Content-Type")
		mediaType, _, _ := mime.ParseMediaType(contentType)
		if mediaType == "application/x-www-form-urlencoded" || mediaType == "multipart/form-data" {
			token = r.PostFormValue(CSRFTokenKey)
		}
	}

	if token == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

// GenerateAndSaveCSRFToken は、URLセーフな新しいトークンを生成して保存します。
func (h *Handler) GenerateAndSaveCSRFToken(w http.ResponseWriter, r *http.Request) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("CSRFトークン生成失敗: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	session, err := h.store.Get(r, h.sessionName)
	if err != nil {
		return "", fmt.Errorf("セッションの取得に失敗しました: %w", err)
	}

	session.Values[CSRFTokenKey] = token
	if err := session.Save(r, w); err != nil {
		return "", fmt.Errorf("CSRFトークン保存失敗: %w", err)
	}

	return token, nil
}

// GetCSRFTokenFromSession は現在のセッションから CSRF トークンを抽出します（表示用）。
func (h *Handler) GetCSRFTokenFromSession(r *http.Request) string {
	session, err := h.store.Get(r, h.sessionName)
	if err != nil {
		return ""
	}
	token, ok := session.Values[CSRFTokenKey].(string)
	if !ok {
		return ""
	}
	return token
}

// buildLoginRedirectURL はオープンリダイレクタ脆弱性を考慮したリダイレクト先URLを構築します。
func buildLoginRedirectURL(r *http.Request) string {
	const loginURL = "/auth/login"

	if r.Method != http.MethodGet || r.URL.Path == "/" {
		return loginURL
	}

	requestedURI := r.URL.RequestURI()
	parsed, err := url.Parse(requestedURI)
	if err != nil {
		return loginURL
	}

	if parsed.Host != "" || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") {
		return loginURL
	}

	return fmt.Sprintf("/auth/login?redirect_to=%s", url.QueryEscape(requestedURI))
}

// TaskOIDCVerificationMiddleware は Google Cloud Tasks からの OIDC トークンを検証します。
func (h *Handler) TaskOIDCVerificationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(h.taskAudienceURL) == "" {
			slog.Error("Task OIDC audience is not configured")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		payload, err := idtoken.Validate(r.Context(), token, h.taskAudienceURL)
		if err != nil {
			slog.Warn("Taskトークン検証失敗", "error", err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		slog.Debug("Task認証成功", "sub", payload.Subject)
		next.ServeHTTP(w, r)
	})
}
