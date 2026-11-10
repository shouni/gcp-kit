// Package oidc verifies inbound service-to-service calls.
//
// Calls from Cloud Tasks and M2M calls from other services both present a
// Google-signed OIDC ID token in Authorization: Bearer. They differ only in how
// they are composed (reject and stop, or give way to the browser session), so
// there is one verifier, and choosing between the two is left to auth.Require
// and auth.Protected.
//
// This package needs no OAuth2 configuration. A worker without a web UI can
// verify inbound calls without access to a client secret it would never use.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/api/idtoken"

	"github.com/shouni/gcp-kit/auth"
)

// Verifier verifies a Google-signed OIDC ID token against both the audience
// and a service account allowlist.
//
// It satisfies auth.Authenticator, so it can be passed to auth.Require (routes
// only services call) as well as to auth.Protected (routes people and services
// share).
type Verifier struct {
	audience string
	allowed  map[string]struct{}
	validate ValidateFunc
}

// ValidateFunc has the same signature as idtoken.Validate. Swap it in with WithValidator.
type ValidateFunc func(ctx context.Context, token, audience string) (*idtoken.Payload, error)

// Option is an optional setting for New.
type Option func(*Verifier)

// WithValidator replaces the function that verifies the signature and the
// audience. It is for tests only.
//
// Without it, a consuming app's router tests cannot exercise the Bearer path.
// In practice, tests were written that passed an unconfigured Verifier and
// checked only the fallback through the ErrNotConfigured path. That is the
// missing-configuration path, not the path a Bearer takes when it arrives.
//
// There is no reason to pass anything but idtoken.Validate in production. A
// function that does not check signatures lets anyone claim any email. nil is
// ignored and idtoken.Validate stays.
func WithValidator(fn ValidateFunc) Option {
	return func(v *Verifier) {
		if fn != nil {
			v.validate = fn
		}
	}
}

// Kinds of verification failure, kept apart so they map onto the error codes
// and status codes of RFC 6750, Section 3.1. A broken token (401, fixed by
// fetching a new one) and a caller that is not allowed (403, not fixed by
// fetching a new one) call for different next steps from the client.
var (
	errInvalidToken = errors.New("oidc: invalid token")
	errNotAllowed   = errors.New("oidc: caller is not allowed")
)

// New initialises a Verifier.
//
// With an empty allowedServiceAccounts, verification errs on the safe side
// and always fails (fail-closed). Making "empty allowlist = let everyone in"
// would open internal endpoints after forgetting a single setting.
//
// If either is missing, it returns auth.ErrNotConfigured along with what is
// missing. This is to fail at startup: running unconfigured would send every
// call to the session fallback, and the missing setting would surface in a
// confusing form.
//
// On a route where verification is optional (a web face that need not accept
// machine callers, for example), pass a nil *Verifier to auth.Protected rather
// than stopping on this error. A nil method is skipped.
func New(audience string, allowedServiceAccounts []string, opts ...Option) (*Verifier, error) {
	v := &Verifier{
		audience: strings.TrimSpace(audience),
		allowed:  toLowerMap(allowedServiceAccounts),
		validate: idtoken.Validate,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(v)
		}
	}
	switch {
	case v.audience == "" && len(v.allowed) == 0:
		return nil, fmt.Errorf("%w: oidc: audience and allowed service accounts are both empty", auth.ErrNotConfigured)
	case v.audience == "":
		return nil, fmt.Errorf("%w: oidc: audience is empty", auth.ErrNotConfigured)
	case len(v.allowed) == 0:
		return nil, fmt.Errorf("%w: oidc: allowed service accounts are empty", auth.ErrNotConfigured)
	}
	return v, nil
}

// configured reports whether the settings verification needs are present.
// New never returns a Verifier that fails this, but Authenticate checks it
// every time so that one built as a zero value or nil still answers
// fail-closed.
func (v *Verifier) configured() bool {
	return v != nil && v.audience != "" && len(v.allowed) > 0
}

// Authenticate implements auth.Authenticator.
//
// When no Bearer token is presented it returns auth.ErrNotAttempted, so the
// composer tries the next method. When the verifier is not configured it
// returns auth.ErrNotConfigured, so the case is treated as a configuration
// error rather than a fallback.
//
// w is unused. It is taken to match the methods that do need to write to the
// response (updating a session, for example).
func (v *Verifier) Authenticate(_ http.ResponseWriter, r *http.Request) (context.Context, error) {
	if !v.configured() {
		return nil, auth.ErrNotConfigured
	}

	token, ok := extractBearerToken(r)
	if !ok {
		return nil, auth.ErrNotAttempted
	}

	payload, err := v.verifyToken(r.Context(), token)
	if err != nil {
		return nil, err
	}
	return withPayload(r.Context(), payload), nil
}

// verifyToken checks the signature, the audience, the email claim and the allowlist, in that order.
func (v *Verifier) verifyToken(ctx context.Context, token string) (*idtoken.Payload, error) {
	validate := v.validate
	if validate == nil {
		validate = idtoken.Validate
	}

	payload, err := validate(ctx, token, v.audience)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidToken, err)
	}
	if payload == nil {
		return nil, fmt.Errorf("%w: validation returned no payload", errInvalidToken)
	}

	// The audience is just a string anyone can name, so a verified signature
	// does not identify the caller. Always confirm the issuer by its email
	// claim.
	emailClaim, err := auth.VerifiedEmail(payload.Claims)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidToken, err)
	}

	if _, ok := v.allowed[strings.ToLower(emailClaim)]; !ok {
		return nil, fmt.Errorf("%w: service account %q", errNotAllowed, emailClaim)
	}

	return payload, nil
}

// extractBearerToken takes the token from the Authorization header, with the
// "Bearer " prefix (case-insensitive) removed.
func extractBearerToken(r *http.Request) (token string, ok bool) {
	const prefix = "Bearer "
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < len(prefix) || !strings.EqualFold(authHeader[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(authHeader[len(prefix):]), true
}

// toLowerMap normalises the allowlist (trim + lowercase) into a map.
// Whitespace-only entries are dropped so that empty elements from splitting
// an environment variable cannot make a list that is "not empty but allows
// nobody".
func toLowerMap(slice []string) map[string]struct{} {
	m := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			m[strings.ToLower(trimmed)] = struct{}{}
		}
	}
	return m
}

// Challenge implements auth.Challenger and answers per RFC 6750.
//
// RFC 9110, Section 15.5.2 requires a server answering 401 to send
// WWW-Authenticate. Without it the client has no way to learn that the
// resource accepts Bearer. Status codes follow the mapping in RFC 6750,
// Section 3.1.
//
//   - no credentials:       401 Bearer
//   - invalid token:        401 error="invalid_token" (fixed by fetching a new one)
//   - caller not allowed:   403 error="insufficient_scope" (not fixed by fetching a new one)
//   - verifier unconfigured: 500. The fault is on the server, so no challenge is sent
func (v *Verifier) Challenge(w http.ResponseWriter, _ *http.Request, err error) {
	switch {
	case errors.Is(err, auth.ErrNotConfigured):
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	case errors.Is(err, auth.ErrNotAttempted):
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	case errors.Is(err, errNotAllowed):
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	default:
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	}
}
