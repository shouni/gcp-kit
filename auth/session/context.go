package session

import "context"

// contextKey is the context key type private to this package. It is
// unexported so it cannot collide with other packages' keys.
type contextKey int

const (
	emailContextKey contextKey = iota
	csrfTokenContextKey
)

// withEmail stores the authenticated user's email address in the context.
func withEmail(ctx context.Context, email string) context.Context {
	return context.WithValue(ctx, emailContextKey, email)
}

// EmailFromContext returns the authenticated user's email address stored by
// Authenticate. For a request that has not passed authentication, ok is false.
func EmailFromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(emailContextKey).(string)
	return email, ok && email != ""
}

// WithCSRFToken stores a CSRF token in the context for embedding in templates.
//
// Authenticate normally calls it, so callers need not use it directly. It is
// exported so that tests checking only template rendering can attach a token
// without a full authentication round trip (sibling apps' tests do exactly
// that).
func WithCSRFToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, csrfTokenContextKey, token)
}

// CSRFTokenFromContext returns the CSRF token stored by Authenticate. It is
// meant for embedding in a form's hidden field or a meta tag.
//
// Unlike EmailFromContext it returns no ok, because "no token" is not an
// anomaly. An empty string is fine to render as is, and no caller branches on
// whether one exists. The empty value means something different from
// EmailFromContext's, which tells whether the request is authenticated.
func CSRFTokenFromContext(ctx context.Context) string {
	token, _ := ctx.Value(csrfTokenContextKey).(string)
	return token
}
