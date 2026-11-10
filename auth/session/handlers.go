package session

import (
	"crypto/subtle"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"

	"github.com/shouni/gcp-kit/auth"
)

// Routes returns an http.Handler serving Login, Callback and Logout at
// loginPath(), callbackPath() and logoutPath() respectively.
//
// Matching runs against the request's full path, so it works the same under
// any prefix (with chi, r.Handle("/auth/*", h.Routes()); with the standard
// mux, mux.Handle("/auth/", h.Routes())). When the three paths were mounted
// one by one, the code building the redirect URL held the same literal, and
// changing only one of them still built.
//
// Login and Callback accept GET only. Logout accepts any method (see Logout).
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+h.loginPath(), h.Login)
	mux.HandleFunc("GET "+h.callbackPath(), h.Callback)
	mux.HandleFunc(h.logoutPath(), h.Logout)
	return mux
}

// Login starts the OAuth2 login. It leaves the state, the PKCE verifier and,
// when redirect_to is given, the return target in short-lived cookies, then
// sends the browser to Google.
//
// It never touches the session store. Anyone can open the login page, so
// creating a stored session here would let unauthenticated callers write as
// much as they like.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	state, err := generateState()
	if err != nil {
		h.log().ErrorContext(r.Context(), "failed to generate state", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// PKCE: the code_verifier is kept on the client side against interception of the authorization code.
	verifier := oauth2.GenerateVerifier()

	if redirectTo := r.URL.Query().Get("redirect_to"); redirectTo != "" {
		// Only a same-origin relative path is kept (against open redirects).
		// It is escaped to survive the round trip as a cookie value; the
		// reading side unescapes it and repeats the same check.
		if isSafeRelativePath(redirectTo) {
			h.setTemporaryCookie(w, DefaultRedirectCookie, url.QueryEscape(redirectTo))
		} else {
			h.log().WarnContext(r.Context(), "Invalid redirect_to parameter detected", "redirectTo", redirectTo)
		}
	}

	h.setTemporaryCookie(w, DefaultStateCookie, state)
	h.setTemporaryCookie(w, DefaultVerifierCookie, verifier)

	// The PKCE challenge is always included. prompt is added only when set, so
	// there is no way for it to overwrite state or code_challenge.
	authOpts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
	if prompt := h.promptParam(); prompt != "" {
		authOpts = append(authOpts, oauth2.SetAuthURLParam("prompt", prompt))
	}

	authURL := h.oauthConfig.AuthCodeURL(state, authOpts...)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// Callback receives the return from Google. It checks the state and the PKCE
// verifier, exchanges the authorization code for a token, and issues a
// session to an allowed user.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	if !validateCallbackState(r) {
		h.log().WarnContext(r.Context(), "OAuth state mismatch, possible CSRF attack")
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	// When the user cancels on the consent screen, or prompt=none needed
	// interaction, Google comes back with error instead of code. Proceeding to
	// the token exchange fails on the empty code, and one user action ends up
	// as an ERROR log line (and a log-based alert).
	if oauthErr := r.URL.Query().Get("error"); oauthErr != "" {
		h.log().WarnContext(r.Context(), "authorization returned an error",
			"error", oauthErr, "description", r.URL.Query().Get("error_description"))
		h.clearTemporaryCookies(w)
		http.Error(w, "Login was not completed: "+oauthErr, http.StatusForbidden)
		return
	}

	verifier, err := r.Cookie(DefaultVerifierCookie)
	if err != nil || verifier.Value == "" {
		// The flow did not go through Login, or the cookie expired. Make the user log in again.
		h.log().WarnContext(r.Context(), "PKCE verifier cookie is missing")
		h.clearTemporaryCookies(w)
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	h.clearTemporaryCookies(w)

	token, err := h.exchangeCode(r, verifier.Value)
	if err != nil {
		h.log().ErrorContext(r.Context(), "token exchange failed", "error", err)
		http.Error(w, "Auth failed", http.StatusInternalServerError)
		return
	}

	email := h.resolveUserEmail(r, token)

	if email == "" || !h.isAuthorized(email) {
		h.log().WarnContext(r.Context(), "access by a user who is not allowed", "email", email)
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	if err := h.saveSessionAndRedirect(w, r, email); err != nil {
		h.log().ErrorContext(r.Context(), "failed to save session", "error", err)
		http.Error(w, "Could not save session", http.StatusInternalServerError)
		return
	}
}

// Logout clears the session and redirects to the login page (or to the
// same-origin path given in redirect_to).
//
// The session lives in the store, so this is server-side revocation. Not only
// the cookie but the stored session goes too, so a stolen cookie is invalid
// from that moment.
//
// Only this app's session goes, though. The Google-side login remains, so on
// reaching the login page approval comes back without asking anything. Making
// "log out" hold on a shared machine needs WithPrompt(PromptSelectAccount).
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.clearSessionCookie(w, r); err != nil {
		h.log().WarnContext(r.Context(), "failed to clear session on logout", "error", err)
	}

	target := h.loginPath()
	if redirectTo := r.URL.Query().Get("redirect_to"); isSafeRelativePath(redirectTo) {
		target = redirectTo
	}
	//nolint:gosec // G710: target is limited to a same-origin relative path by isSafeRelativePath
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func validateCallbackState(r *http.Request) bool {
	queryState := r.URL.Query().Get("state")
	cookieState, err := r.Cookie(DefaultStateCookie)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookieState.Value), []byte(queryState)) == 1
}

// setTemporaryCookie issues a short-lived cookie such as the state or the
// PKCE verifier. SameSite is fixed at Lax: the callback from Google is a
// cross-site top-level GET navigation, so with Strict the cookie would not be
// sent.
func (h *Handler) setTemporaryCookie(w http.ResponseWriter, name, value string) {
	//nolint:gosec // G124: Secure follows the setting to allow local development over http. HttpOnly/SameSite are always set.
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   h.stateCookieMaxAge(),
		Path:     h.callbackPath(),
		HttpOnly: true,
		Secure:   h.isSecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearTemporaryCookies invalidates the state, PKCE verifier and return-target
// cookies. The attributes (Path, SameSite and so on) must match those used
// when they were issued. Only the response side is cleared, so r can still
// read them afterwards (Callback reads the return target later).
func (h *Handler) clearTemporaryCookies(w http.ResponseWriter) {
	for _, name := range []string{DefaultStateCookie, DefaultVerifierCookie, DefaultRedirectCookie} {
		//nolint:gosec // G124: Secure follows the setting to allow local development over http. HttpOnly/SameSite are always set.
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			MaxAge:   -1,
			Path:     h.callbackPath(),
			HttpOnly: true,
			Secure:   h.isSecureCookie,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

func (h *Handler) exchangeCode(r *http.Request, verifier string) (*oauth2.Token, error) {
	code := r.URL.Query().Get("code")
	return h.oauthConfig.Exchange(r.Context(), code, oauth2.VerifierOption(verifier))
}

func (h *Handler) resolveUserEmail(r *http.Request, token *oauth2.Token) string {
	email := h.extractEmailFromIDToken(r, token)
	if email != "" {
		return email
	}

	var err error
	email, err = h.fetchUserEmail(r.Context(), token)
	if err != nil {
		h.log().WarnContext(r.Context(), "failed to fetch the user email address from the API", "error", err)
	}
	return email
}

func (h *Handler) extractEmailFromIDToken(r *http.Request, token *oauth2.Token) string {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return ""
	}

	payload, err := idtoken.Validate(r.Context(), rawIDToken, h.oauthConfig.ClientID)
	if err != nil {
		h.log().DebugContext(r.Context(), "ID token validation failed", "error", err)
		return ""
	}

	// Applies the same standard as the UserInfo API path (fetchUserEmail) and service-to-service verification.
	emailClaim, err := auth.VerifiedEmail(payload.Claims)
	if err != nil {
		h.log().WarnContext(r.Context(), "cannot accept the email address in the ID token", "error", err)
		return ""
	}
	return emailClaim
}

func (h *Handler) saveSessionAndRedirect(w http.ResponseWriter, r *http.Request, email string) error {
	targetURL, err := h.issueSession(w, r, email)
	if err != nil {
		return err
	}

	//nolint:gosec // G710: targetURL is limited to a same-origin relative path by isSafeRelativePath
	http.Redirect(w, r, targetURL, http.StatusSeeOther)
	return nil
}
