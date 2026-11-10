package session

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

const (
	// CSRFTokenKey is the key the token is kept under in the session.
	CSRFTokenKey = "csrf_token"
	// HeaderXCSRFToken is the standard header the frontend sends the token in.
	//nolint:gosec // G101: an HTTP header name constant, not a credential
	HeaderXCSRFToken = "X-CSRF-Token"
)

// Reasons authentication did not succeed, used by Challenge to decide the
// response. They are unexported because callers have no need to branch on
// them (what to return is decided by Challenge, inside this package).
var (
	errNoSession   = errors.New("session: no authenticated session")
	errUnauthMail  = errors.New("session: email is not on the allowlist")
	errBadOrigin   = errors.New("session: origin check failed")
	errInvalidCSRF = errors.New("session: CSRF token is invalid")
)

// Authenticate implements auth.Authenticator.
//
// It checks the session, decides authorization, and applies CSRF
// verification to state-changing methods. A request that passes gets a
// context carrying the email address and the CSRF token downstream handlers
// read.
//
// Authorization is evaluated on every request. Checking only at login would
// let an address removed from the allowlist through until its session
// expires (deleting the stored session stops it, but that requires finding
// the person's session).
//
// Even when there is simply no session it returns an error rather than
// auth.ErrNotAttempted, because the browser-facing method sits last in
// auth.Protected and decides the response there.
//
// The store is read once per request, and the loaded session is carried
// through CSRF verification and token minting. With the Firestore store,
// each read is one billed read.
func (h *Handler) Authenticate(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	session, err := h.loadSession(r)
	switch {
	case errors.Is(err, ErrStoreUnavailable):
		// The store is only unreachable, so the cookie is left alone (see ErrStoreUnavailable).
		h.log().ErrorContext(r.Context(), "session store is unreachable", "error", err, "path", r.URL.Path)
		return nil, err
	case err != nil:
		// A broken stored session is deleted so the next login recreates it.
		h.log().WarnContext(r.Context(), "failed to load session, treating it as a new session", "error", err)
		h.clearSessionLogged(w, r, session)
		return nil, fmt.Errorf("%w: %w", errNoSession, err)
	}

	email, ok := session.values[DefaultUserSessionKey]
	if !ok || email == "" {
		return nil, errNoSession
	}

	if !h.isAuthorized(email) {
		h.log().WarnContext(r.Context(), "session email is not on the allowlist", "email", email, "path", r.URL.Path)
		h.clearSessionLogged(w, r, session)
		return nil, fmt.Errorf("%w: %q", errUnauthMail, email)
	}

	if isStateChangingMethod(r.Method) {
		if !validateOrigin(r) {
			h.log().WarnContext(r.Context(), "origin check failed", "email", email, "origin", r.Header.Get("Origin"), "path", r.URL.Path)
			return nil, errBadOrigin
		}
		if !h.validateCSRF(r, session) {
			h.log().WarnContext(r.Context(), "CSRF verification failed", "email", email, "method", r.Method, "path", r.URL.Path)
			return nil, errInvalidCSRF
		}
	}

	// A GET without a token yet gets a new one, saved to the session. Minting
	// is limited to GET because handing a valid token to a state-changing
	// request that arrived without one would make CSRF verification
	// meaningless.
	token := session.values[CSRFTokenKey]
	if token == "" && r.Method == http.MethodGet {
		generated, genErr := h.generateAndSaveCSRFToken(w, r, session)
		if genErr != nil {
			return nil, fmt.Errorf("session: failed to generate CSRF token: %w", genErr)
		}
		token = generated
	}

	ctx := withEmail(r.Context(), email)
	return WithCSRFToken(ctx, token), nil
}

// Challenge implements auth.Challenger.
//
// When authentication is merely missing it sends the caller to the login
// page; when CSRF or Origin verification failed it stops with 403. Redirecting
// the latter would leave neither the user nor the operator able to tell
// whether a request an attacker planted was let through or rejected.
//
// It sends the caller to the login page only when the caller asked for a
// page. A caller asking for JSON gets 401. On a route both people and agents
// use, redirecting unconditionally sends an HTML login page to an agent that
// asked for JSON, which it cannot interpret. Rails, Spring Security,
// ASP.NET Core and the other implementations that handle mixed routes all
// negotiate the same way.
//
// The one 503 is when the session store cannot be reached. That is a failed
// dependency rather than missing authentication, so the login page would not
// fix it.
//
// The 401 carries no WWW-Authenticate because no authentication scheme is
// registered for cookie authentication. The Bearer challenge is sent by
// auth/oidc, the side that accepts it.
func (h *Handler) Challenge(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errBadOrigin):
		http.Error(w, "Invalid origin", http.StatusForbidden)
	case errors.Is(err, errInvalidCSRF):
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
	case errors.Is(err, ErrStoreUnavailable):
		// The login page needs the same store, so sending the caller there would not help.
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
	case errors.Is(err, errNoSession), errors.Is(err, errUnauthMail):
		// wantsJSON also sets Vary: Accept. This response really does vary by
		// Accept, so caches need to be told.
		if wantsJSON(w, r) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, h.buildLoginRedirectURL(r), http.StatusFound)
	default:
		h.log().ErrorContext(r.Context(), "unexpected session authentication failure", "error", err, "path", r.URL.Path)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// wantsJSON reports whether the caller asked for JSON, and sets Vary: Accept
// at the same time.
//
// The check and the declaration are one function so that telling caches the
// response varies by Accept cannot be forgotten. Behind a shared cache or a
// CDN, a missing Vary can serve the login page's HTML to a caller that asked
// for JSON.
//
// It deliberately duplicates go-serve-kit's respond.WantsJSON. Adding a
// dependency between the kits for this one call site was rejected, so the two
// evolve independently.
func wantsJSON(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Add("Vary", "Accept")
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json")
}

// clearSessionLogged tries to clear the session and carries on if that fails.
func (h *Handler) clearSessionLogged(w http.ResponseWriter, r *http.Request, s *session) {
	if err := h.clearSession(w, r, s); err != nil {
		h.log().WarnContext(r.Context(), "failed to clear session", "error", err)
	}
}

// isStateChangingMethod reports whether an HTTP method needs CSRF protection.
func isStateChangingMethod(method string) bool {
	return method == http.MethodPost ||
		method == http.MethodPut ||
		method == http.MethodDelete ||
		method == http.MethodPatch
}

// validateOrigin checks the Origin header as defence in depth on top of token
// verification. Without an Origin (a non-browser client, for example) it
// returns true and leaves the decision to token verification; only when one
// is presented must it match the request's host.
func validateOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

// validateCSRF verifies the request's token.
func (h *Handler) validateCSRF(r *http.Request, session *session) bool {
	if session == nil {
		return false
	}

	expected, ok := session.values[CSRFTokenKey]
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

// generateAndSaveCSRFToken generates a new URL-safe token and saves it to the
// given session. The session is a parameter so that the one the caller
// already loaded is used.
func (h *Handler) generateAndSaveCSRFToken(w http.ResponseWriter, r *http.Request, session *session) (string, error) {
	token, err := randomToken(base64.RawURLEncoding)
	if err != nil {
		return "", fmt.Errorf("generate CSRF token: %w", err)
	}
	if session == nil {
		return "", errors.New("session: no session to store the CSRF token in")
	}

	session.values[CSRFTokenKey] = token
	if err := h.saveSession(w, r, session); err != nil {
		return "", fmt.Errorf("save CSRF token: %w", err)
	}

	return token, nil
}

// buildLoginRedirectURL builds the login redirect URL with open redirects in mind.
func (h *Handler) buildLoginRedirectURL(r *http.Request) string {
	loginURL := h.loginPath()

	if r.Method != http.MethodGet || r.URL.Path == "/" {
		return loginURL
	}

	requestedURI := r.URL.RequestURI()
	if !isSafeRelativePath(requestedURI) {
		return loginURL
	}

	return fmt.Sprintf("%s?redirect_to=%s", loginURL, url.QueryEscape(requestedURI))
}

// isSafeRelativePath reports whether target is a same-origin relative path
// that is safe to redirect to. It rejects anything with a host, anything not
// starting with '/', and anything starting with '//' (a scheme-relative URL).
func isSafeRelativePath(target string) bool {
	if target == "" {
		return false
	}

	// Some browsers normalise a backslash to '/', so input such as
	// "/\evil.com" can be read as a scheme-relative URL. url.Parse treats it
	// as a relative path, so it is rejected first.
	if strings.ContainsRune(target, '\\') {
		return false
	}
	// Control characters (CR/LF and the like) are material for header splitting, so they are rejected.
	if strings.ContainsFunc(target, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return false
	}

	// The check runs on the raw string rather than the parsed result, because
	// some input, such as "//@/", has an empty host to url.Parse but can be
	// read by a browser as a scheme-relative URL.
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		return false
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	return parsed.Scheme == "" && parsed.Host == ""
}
