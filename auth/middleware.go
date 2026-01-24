package auth

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"google.golang.org/api/idtoken"
)

// Middleware HTTPハンドラにセッションベースの認証ミドルウェアを適用します。セッションが無効な場合はログインにリダイレクトします。
func (h *Handler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := h.store.Get(r, h.sessionName)
		if err != nil {
			// セッション取得失敗時の詳細ログ
			if session != nil && session.IsNew {
				slog.Error("セッション解析失敗（キー不一致や改竄の可能性）", "error", err)
			} else {
				slog.Warn("セッション取得エラー", "error", err)
			}

			h.clearSessionCookie(w, r)
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}

		email, ok := session.Values[DefaultUserSessionKey].(string)
		if !ok || email == "" {
			loginURL := "/auth/login"

			// GETリクエスト時のみリダイレクト先を付与
			if r.Method == http.MethodGet && r.URL.Path != "/" {
				// [Security] RequestURI をパースして安全性を確認
				requestedURI := r.URL.RequestURI()
				parsed, err := url.Parse(requestedURI)

				// ホストがなく、かつパスが "/" から始まっている場合のみ redirect_to を付与
				if err == nil && parsed.Host == "" && strings.HasPrefix(parsed.Path, "/") {
					loginURL = fmt.Sprintf("/auth/login?redirect_to=%s", url.QueryEscape(requestedURI))
				}
			}

			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// TaskOIDCVerificationMiddleware Authorization ヘッダー内の OIDC トークンを検証するための HTTP ミドルウェアです。
func (h *Handler) TaskOIDCVerificationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
