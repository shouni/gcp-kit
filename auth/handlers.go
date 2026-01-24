package auth

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"

	"google.golang.org/api/idtoken"
)

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

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	queryState := r.URL.Query().Get("state")
	cookieState, err := r.Cookie(DefaultStateCookie)

	if err != nil || subtle.ConstantTimeCompare([]byte(cookieState.Value), []byte(queryState)) != 1 {
		slog.Warn("CSRF攻撃の可能性を検知", "error", err)
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &http.Cookie{Name: DefaultStateCookie, Value: "", MaxAge: -1, Path: "/auth/callback"})

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
		}
	}

	if email == "" {
		email, _ = h.fetchUserEmail(r.Context(), token)
	}

	if email == "" || !h.isAuthorized(email) {
		slog.Warn("未許可ユーザーアクセス", "email", email)
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	session, _ := h.store.Get(r, h.sessionName)
	targetURL := "/"
	if url, ok := session.Values[DefaultRedirectSessionKey].(string); ok && url != "" {
		targetURL = url
		delete(session.Values, DefaultRedirectSessionKey)
	}

	session.Values[DefaultUserSessionKey] = email
	_ = session.Save(r, w)

	http.Redirect(w, r, targetURL, http.StatusSeeOther)
}
