package auth

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

// Login は、OAuth2 ログイン プロセスを初期化し、状態の生成とセッション管理を処理する
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	state, err := generateState()
	if err != nil {
		slog.Error("State生成失敗", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	session, err := h.store.Get(r, h.sessionName)
	if err == nil {
		if redirectTo := r.URL.Query().Get("redirect_to"); redirectTo != "" {
			// redirectToが'/'で始まり、'//'で始まらないことを確認
			if strings.HasPrefix(redirectTo, "/") && !strings.HasPrefix(redirectTo, "//") {
				session.Values[DefaultRedirectSessionKey] = redirectTo
				if err := session.Save(r, w); err != nil {
					slog.Error("Failed to save session for redirect", "error", err)
					http.Error(w, "Could not save session", http.StatusInternalServerError)
					return
				}
			} else {
				slog.Warn("Invalid redirect_to parameter detected", "redirectTo", redirectTo)
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

	http.Redirect(w, r, h.oauthConfig.AuthCodeURL(state), http.StatusTemporaryRedirect)
}

// Callback OAuth2 コールバックを処理し、CSRF 状態を検証し、認証コードをトークンと交換し、ユーザー セッションを処理します。
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	if !validateCallbackState(r) {
		slog.Warn("CSRF攻撃の可能性を検知")
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	clearStateCookie(w)

	token, err := h.exchangeCode(r)
	if err != nil {
		slog.Error("トークン交換失敗", "error", err)
		http.Error(w, "Auth failed", http.StatusInternalServerError)
		return
	}

	email := h.resolveUserEmail(r, token)

	if email == "" || !h.isAuthorized(email) {
		slog.Warn("未許可ユーザーアクセス", "email", email)
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	h.saveSessionAndRedirect(w, r, email)
}

func validateCallbackState(r *http.Request) bool {
	queryState := r.URL.Query().Get("state")
	cookieState, err := r.Cookie(DefaultStateCookie)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookieState.Value), []byte(queryState)) == 1
}

func clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: DefaultStateCookie, Value: "", MaxAge: -1, Path: "/auth/callback"})
}

func (h *Handler) exchangeCode(r *http.Request) (*oauth2.Token, error) {
	code := r.URL.Query().Get("code")
	return h.oauthConfig.Exchange(r.Context(), code)
}

func (h *Handler) resolveUserEmail(r *http.Request, token *oauth2.Token) string {
	email := extractEmailFromIDToken(r, token, h.oauthConfig.ClientID)
	if email != "" {
		return email
	}

	email, _ = h.fetchUserEmail(r.Context(), token)
	return email
}

func extractEmailFromIDToken(r *http.Request, token *oauth2.Token, clientID string) string {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return ""
	}

	payload, err := idtoken.Validate(r.Context(), rawIDToken, clientID)
	if err != nil {
		return ""
	}

	emailClaim, ok := payload.Claims["email"].(string)
	if !ok {
		return ""
	}
	return emailClaim
}

func (h *Handler) saveSessionAndRedirect(w http.ResponseWriter, r *http.Request, email string) {
	session, err := h.store.Get(r, h.sessionName)
	if err != nil {
		slog.Warn("セッションの取得に失敗したため、新規セッションを作成します", "error", err)
	}

	targetURL := "/"
	if url, ok := session.Values[DefaultRedirectSessionKey].(string); ok && url != "" {
		targetURL = url
		delete(session.Values, DefaultRedirectSessionKey)
	}

	session.Values[DefaultUserSessionKey] = email
	_ = session.Save(r, w)

	http.Redirect(w, r, targetURL, http.StatusSeeOther)
}
