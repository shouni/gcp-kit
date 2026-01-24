package auth

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"google.golang.org/api/idtoken"
)

func (h *Handler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := h.store.Get(r, h.sessionName)
		if err != nil {
			if session != nil && session.IsNew {
				slog.Error("セッション解析失敗。キー不一致の可能性。")
			}
			h.clearSessionCookie(w, r)
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}

		email, ok := session.Values[DefaultUserSessionKey].(string)
		if !ok || email == "" {
			loginURL := "/auth/login"
			if r.Method == http.MethodGet && r.URL.Path != "/" {
				loginURL = fmt.Sprintf("/auth/login?redirect_to=%s", url.QueryEscape(r.URL.RequestURI()))
			}
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

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
