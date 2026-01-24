package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/mail"
	"strings"

	"golang.org/x/oauth2"
)

func (h *Handler) fetchUserEmail(ctx context.Context, token *oauth2.Token) (string, error) {
	client := h.oauthConfig.Client(ctx, token)
	resp, err := client.Get(googleUserInfoURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var u googleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil || !u.VerifiedEmail {
		return "", err
	}
	return u.Email, nil
}

func (h *Handler) isAuthorized(email string) bool {
	normalizedEmail := strings.ToLower(email)
	if len(h.allowedEmails) == 0 && len(h.allowedDomains) == 0 {
		return false
	}
	if _, ok := h.allowedEmails[normalizedEmail]; ok {
		return true
	}

	addr, err := mail.ParseAddress(normalizedEmail)
	if err == nil {
		if i := strings.LastIndexByte(addr.Address, '@'); i != -1 {
			domain := addr.Address[i+1:]
			if _, ok := h.allowedDomains[domain]; ok {
				return true
			}
		}
	}
	return false
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	session, _ := h.store.Get(r, h.sessionName)
	session.Options.MaxAge = -1
	_ = session.Save(r, w)
}

func toLowerMap(slice []string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, s := range slice {
		if s != "" {
			m[strings.ToLower(s)] = struct{}{}
		}
	}
	return m
}

func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
