package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"

	"github.com/shouni/gcp-kit/auth"
)

// userInfoBodyLimit is the most bytes read as a UserInfo response. A normal
// response is a few hundred bytes, so this keeps an abnormal one from eating
// memory.
const userInfoBodyLimit = 64 << 10

// fetchUserEmail calls the Google UserInfo API to get the email address.
func (h *Handler) fetchUserEmail(ctx context.Context, token *oauth2.Token) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleUserInfoURL, nil)
	if err != nil {
		return "", fmt.Errorf("build UserInfo request: %w", err)
	}

	client := h.oauthConfig.Client(ctx, token)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("call google UserInfo API: %w", err)
	}
	defer resp.Body.Close()

	// Check the status first. Decoding an error response as is would yield an
	// "email is not verified" error that misstates what happened.
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("google UserInfo API returned status %d", resp.StatusCode)
	}

	var u googleUserInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, userInfoBodyLimit)).Decode(&u); err != nil {
		return "", fmt.Errorf("decode UserInfo response: %w", err)
	}

	// The judgement itself goes through auth.VerifiedEmail. Calling the same
	// function rather than restating the rule leaves no room for one side to
	// loosen. The UserInfo API's key differs from the ID token's
	// (verified_email vs email_verified), so the translation happens here and
	// the rule stays in one place.
	return auth.VerifiedEmail(map[string]any{
		"email":          u.Email,
		"email_verified": u.VerifiedEmail,
	})
}

// session is the session for one request.
//
// An empty id means a session not yet saved (or one whose stored counterpart
// was not adopted), and saveSession assigns a new ID.
type session struct {
	id     string
	values map[string]string
}

func newSession() *session { return &session{values: map[string]string{}} }

// loadSession reads the session the cookie points at.
//
// The returned *session is never nil. Even on error it carries the ID the
// cookie brought in id, so the caller can pass it straight to clearSession to
// delete the stored session too.
//
// An ID that is not stored is never adopted. The ID arrives in a cookie, so an
// attacker can choose it, and adopting it would let the attacker pick the
// victim's session identifier (session fixation). id is filled only when the
// stored session was read; otherwise it stays empty and saveSession assigns a
// new one.
func (h *Handler) loadSession(r *http.Request) (*session, error) {
	s := newSession()

	cookie, err := r.Cookie(h.sessionName)
	if err != nil || cookie.Value == "" {
		return s, nil
	}
	// An ID not in the shape we mint is dropped before asking the store. There
	// cannot be a stored session for it, and in Firestore the value becomes a
	// document path (see isValidSessionID).
	if !isValidSessionID(cookie.Value) {
		return s, nil
	}

	values, err := h.store.Load(r.Context(), cookie.Value)
	switch {
	case errors.Is(err, ErrNotFound):
		return s, nil
	case err != nil:
		s.id = cookie.Value
		return s, err
	}

	s.id = cookie.Value
	s.values = values
	if s.values == nil {
		s.values = map[string]string{}
	}
	return s, nil
}

// saveSession saves the session and writes the cookie to the response, assigning an id if it is empty.
func (h *Handler) saveSession(w http.ResponseWriter, r *http.Request, s *session) error {
	if s.id == "" {
		id, err := newSessionID()
		if err != nil {
			return err
		}
		s.id = id
	}

	maxAge := h.sessionMaxAge()
	if err := h.store.Save(r.Context(), s.id, s.values, maxAge); err != nil {
		return err
	}
	http.SetCookie(w, h.sessionCookie(s.id, int(maxAge.Seconds())))
	return nil
}

// clearSession deletes the stored session and clears the cookie.
//
// The cookie is cleared even if the stored session could not be deleted.
// Returning early here would leave, from the user's view, a failed logout with
// the cookie still in place. Clearing only the cookie leaves a stolen cookie
// valid, so deleting the stored session is what a real logout consists of.
func (h *Handler) clearSession(w http.ResponseWriter, r *http.Request, s *session) error {
	var err error
	if s != nil && s.id != "" {
		err = h.store.Delete(r.Context(), s.id)
	}
	http.SetCookie(w, h.sessionCookie("", -1))
	return err
}

// sessionCookie builds the cookie carrying the session ID.
//
// Path is "/" (the whole app) and SameSite is Lax. With Strict, the cookie
// would not be sent, because the callback from Google is a cross-site
// top-level navigation. Secure is decided by ServiceURL's scheme (see
// Config.ServiceURL). A negative maxAge makes the browser discard it at once.
func (h *Handler) sessionCookie(value string, maxAge int) *http.Cookie {
	//nolint:gosec // G124: Secure follows whether ServiceURL is https (local development uses http).
	return &http.Cookie{
		Name:     h.sessionName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   h.isSecureCookie,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// IssueSession issues a session for email as an authenticated user. It is the
// same save Callback performs when a login succeeds, except that it writes no
// redirect.
//
// Verifying the identity is the caller's responsibility (it is not checked
// here). The allowlist check, as in Callback, always applies, and a user who
// is not allowed gets an error and no session.
//
// It is exported so that tests checking authenticated screens can create a
// logged-in state without faking the OAuth round trip (the same reason as
// WithCSRFToken).
func (h *Handler) IssueSession(w http.ResponseWriter, r *http.Request, email string) error {
	if !h.isAuthorized(email) {
		return fmt.Errorf("issue session: %q is not authorized", email)
	}
	_, err := h.issueSession(w, r, email)
	return err
}

// issueSession saves an authenticated session and returns where to go after
// login. It is shared so that Callback and IssueSession cannot diverge in how
// they build a session.
func (h *Handler) issueSession(w http.ResponseWriter, r *http.Request, email string) (string, error) {
	s, err := h.loadSession(r)
	if err != nil {
		h.log().WarnContext(r.Context(), "failed to load session, creating a new one", "error", err)
		s = newSession()
	}

	targetURL := redirectTarget(r)

	// Drop the CSRF token tied to the pre-login session so a new one is minted
	// for the authenticated session (a token fixed before login must not be
	// reused).
	delete(s.values, CSRFTokenKey)

	// Drop the ID as well so a new one is assigned (against session fixation).
	// Authenticating under an ID an attacker planted would let the attacker act
	// as the victim with it. saveSession assigns a new ID to an empty one.
	//
	// The old stored session is deleted after the save succeeds. Only
	// authenticated sessions exist in the store (only this and CSRF token
	// issuance reach Save), so leaving it would leave, on every re-login or
	// account switch, a valid session that Logout cannot reach, for its full
	// lifetime. A failed delete is not worth stopping the login over, so it
	// is only a warning.
	oldID := s.id
	s.id = ""

	s.values[DefaultUserSessionKey] = email
	if err := h.saveSession(w, r, s); err != nil {
		return "", fmt.Errorf("save session: %w", err)
	}
	if oldID != "" {
		if err := h.store.Delete(r.Context(), oldID); err != nil {
			h.log().WarnContext(r.Context(), "failed to delete the pre-login session", "error", err)
		}
	}
	return targetURL, nil
}

// redirectTarget decides where to go after login, "/" if nothing is set.
//
// The value rides in the cookie Login issued. It is checked on write too, but
// the other side can rewrite a cookie, so it is always checked on read as
// well.
func redirectTarget(r *http.Request) string {
	cookie, err := r.Cookie(DefaultRedirectCookie)
	if err != nil || cookie.Value == "" {
		return "/"
	}
	decoded, err := url.QueryUnescape(cookie.Value)
	if err != nil || !isSafeRelativePath(decoded) {
		return "/"
	}
	return decoded
}

// isAuthorized reports whether the email address is on the allowlist or in an allowed domain.
func (h *Handler) isAuthorized(email string) bool {
	normalizedEmail := strings.ToLower(email)

	// With empty allowlists, everyone is denied (fail-closed).
	if len(h.allowedEmails) == 0 && len(h.allowedDomains) == 0 {
		return false
	}

	if _, ok := h.allowedEmails[normalizedEmail]; ok {
		return true
	}

	// mail.ParseAddress is not used for the domain check: it also accepts the
	// "Name <a@b.com>" form, which would shift the value compared against the
	// allowlist.
	i := strings.LastIndexByte(normalizedEmail, '@')
	if i <= 0 || i == len(normalizedEmail)-1 {
		return false
	}
	_, ok := h.allowedDomains[normalizedEmail[i+1:]]
	return ok
}

// clearSessionCookie discards the session the cookie points at, stored
// session included. Even when it cannot be read, it still tries to delete the
// stored session under the ID the cookie brought.
func (h *Handler) clearSessionCookie(w http.ResponseWriter, r *http.Request) error {
	s, err := h.loadSession(r)
	if err != nil {
		h.log().WarnContext(r.Context(), "could not read the session to clear, trying to delete it anyway", "error", err)
	}
	if err := h.clearSession(w, r, s); err != nil {
		h.log().ErrorContext(r.Context(), "failed to clear session", "error", err)
		return err
	}
	return nil
}

// randomToken generates 32 cryptographically random bytes and encodes them
// with the given encoding. It is shared by everything that needs an
// unguessable random string, such as the state parameter and CSRF tokens.
func randomToken(encoding *base64.Encoding) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return encoding.EncodeToString(b), nil
}

// generateState generates a random state string against CSRF.
func generateState() (string, error) {
	return randomToken(base64.URLEncoding)
}
