package auth

import (
	"errors"
	"fmt"
)

// VerifiedEmail extracts the verified email address from the claims of a
// Google ID token.
//
// An unverified email address does not prove ownership of it. The check lives
// here, once, so that login (the OAuth callback in auth/session) and
// service-to-service verification (auth/oidc) apply the same standard. If only
// one side loosens, that side can be used to claim someone else's address.
func VerifiedEmail(claims map[string]any) (string, error) {
	email, ok := claims["email"].(string)
	if !ok || email == "" {
		return "", errors.New("auth: token has no email claim")
	}
	if verified, _ := claims["email_verified"].(bool); !verified {
		return "", fmt.Errorf("auth: email %q is not verified", email)
	}
	return email, nil
}
