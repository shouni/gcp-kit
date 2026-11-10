package session

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// newCallbackTestHandler builds a Handler whose OAuth2 token endpoint and
// Google UserInfo endpoint are both served by a local httptest.Server
// (routed via rewriteTransport, since the UserInfo URL is hardcoded), so the
// full Callback flow can be exercised without touching real Google services.
func newCallbackTestHandler(t *testing.T, tokenHandler, userInfoHandler http.HandlerFunc) (*Handler, context.Context) {
	t.Helper()

	mux := http.NewServeMux()
	if tokenHandler != nil {
		mux.HandleFunc("/token", tokenHandler)
	}
	if userInfoHandler != nil {
		mux.HandleFunc("/oauth2/v2/userinfo", userInfoHandler)
	}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	ctx := newRewriteContext(t, server)

	h := &Handler{
		oauthConfig: &oauth2.Config{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			RedirectURL:  "https://app.example.com/auth/callback",
			Endpoint: oauth2.Endpoint{
				TokenURL: server.URL + "/token",
			},
		},
		store:          newTestStore(),
		sessionName:    "test-session",
		allowedDomains: map[string]struct{}{"example.com": {}},
	}
	return h, ctx
}

func jsonTokenResponse(extra map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		body := map[string]any{"access_token": "test-access-token", "token_type": "Bearer"}
		maps.Copy(body, extra)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
}

func jsonUserInfoResponse(email string, verified bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"email": email, "verified_email": verified})
	}
}

func TestLogin(t *testing.T) {
	t.Parallel()

	newHandler := func(store Store) *Handler {
		if store == nil {
			store = newTestStore()
		}
		return &Handler{
			oauthConfig: &oauth2.Config{
				ClientID: "client-id",
				Endpoint: oauth2.Endpoint{AuthURL: "https://accounts.example.com/o/oauth2/auth"},
			},
			store:       store,
			sessionName: "test-session",
		}
	}

	t.Run("redirects to provider and sets state cookie", func(t *testing.T) {
		t.Parallel()
		h := newHandler(nil)
		req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		rr := httptest.NewRecorder()

		h.Login(rr, req)

		if rr.Code != http.StatusTemporaryRedirect {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusTemporaryRedirect)
		}
		loc := rr.Header().Get("Location")
		if !strings.HasPrefix(loc, "https://accounts.example.com/o/oauth2/auth") {
			t.Fatalf("Location = %q, want AuthCodeURL prefix", loc)
		}

		if !strings.Contains(loc, "code_challenge=") || !strings.Contains(loc, "code_challenge_method=S256") {
			t.Fatalf("Location = %q, want a PKCE S256 challenge", loc)
		}

		got := map[string]string{}
		for _, c := range rr.Result().Cookies() {
			got[c.Name] = c.Value
		}
		for _, name := range []string{DefaultStateCookie, DefaultVerifierCookie} {
			if got[name] == "" {
				t.Fatalf("cookie %q was not set with a value", name)
			}
		}
	})

	t.Run("carries valid redirect_to in a temporary cookie", func(t *testing.T) {
		t.Parallel()
		h := newHandler(nil)
		req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect_to=/private", nil)
		rr := httptest.NewRecorder()

		h.Login(rr, req)

		if rr.Code != http.StatusTemporaryRedirect {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusTemporaryRedirect)
		}

		var redirect *http.Cookie
		for _, c := range rr.Result().Cookies() {
			if c.Name == DefaultRedirectCookie {
				redirect = c
			}
		}
		if redirect == nil {
			t.Fatal("redirect cookie was not set")
		}
		if got, err := url.QueryUnescape(redirect.Value); err != nil || got != "/private" {
			t.Fatalf("redirect cookie = %q (err %v), want %q", redirect.Value, err, "/private")
		}
		// It has to reach the callback, so its attributes match the state and verifier cookies.
		if redirect.Path != DefaultCallbackPath || !redirect.HttpOnly {
			t.Fatalf("redirect cookie Path = %q HttpOnly = %v, want %q and true",
				redirect.Path, redirect.HttpOnly, DefaultCallbackPath)
		}
	})

	t.Run("ignores unsafe redirect_to", func(t *testing.T) {
		t.Parallel()
		h := newHandler(nil)
		req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect_to=//evil.com", nil)
		rr := httptest.NewRecorder()

		h.Login(rr, req)

		if rr.Code != http.StatusTemporaryRedirect {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusTemporaryRedirect)
		}
		for _, c := range rr.Result().Cookies() {
			if c.Name == DefaultRedirectCookie {
				t.Fatalf("redirect cookie was set to %q for an unsafe target", c.Value)
			}
		}
	})

	// Anyone can open the login page. Creating a stored session here would let
	// unauthenticated callers write to the store, so the store is not touched.
	t.Run("does not touch the session store", func(t *testing.T) {
		t.Parallel()
		counting := &countingStore{inner: newTestStore()}
		h := newHandler(counting)
		req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect_to=/private", nil)
		rr := httptest.NewRecorder()

		h.Login(rr, req)

		if rr.Code != http.StatusTemporaryRedirect {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusTemporaryRedirect)
		}
		if counting.gets != 0 || counting.saves != 0 {
			t.Fatalf("store.Get=%d store.Save=%d, want no store access at all",
				counting.gets, counting.saves)
		}
	})
}

func TestValidateCallbackState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		cookie     *http.Cookie
		queryState string
		want       bool
	}{
		{"missing cookie", nil, "abc", false},
		{"mismatched state", &http.Cookie{Name: DefaultStateCookie, Value: "abc"}, "xyz", false},
		{"matching state", &http.Cookie{Name: DefaultStateCookie, Value: "abc"}, "abc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+tt.queryState, nil)
			if tt.cookie != nil {
				req.AddCookie(tt.cookie)
			}
			if got := validateCallbackState(req); got != tt.want {
				t.Fatalf("validateCallbackState() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClearTemporaryCookies(t *testing.T) {
	t.Parallel()

	h := &Handler{isSecureCookie: true}
	rr := httptest.NewRecorder()

	h.clearTemporaryCookies(rr)

	cookies := rr.Result().Cookies()
	if len(cookies) != 3 {
		t.Fatalf("got %d cookies, want 3", len(cookies))
	}
	for _, c := range cookies {
		if c.Name != DefaultStateCookie && c.Name != DefaultVerifierCookie && c.Name != DefaultRedirectCookie {
			t.Fatalf("unexpected cookie %q", c.Name)
		}
		if c.MaxAge != -1 {
			t.Fatalf("%s MaxAge = %d, want -1", c.Name, c.MaxAge)
		}
		// Deletion must use the same attributes as issuance.
		if c.Path != DefaultCallbackPath {
			t.Fatalf("%s Path = %q, want %q", c.Name, c.Path, DefaultCallbackPath)
		}
		if c.SameSite != http.SameSiteLaxMode {
			t.Fatalf("%s SameSite = %v, want Lax", c.Name, c.SameSite)
		}
	}
}

// TestSetTemporaryCookieUsesLaxSameSite guarantees that the state/PKCE cookies
// are Lax. The callback from Google is a cross-site top-level GET navigation,
// so with Strict the cookies are not sent and login always fails.
func TestSetTemporaryCookieUsesLaxSameSite(t *testing.T) {
	t.Parallel()

	h := &Handler{isSecureCookie: true}
	rr := httptest.NewRecorder()

	h.setTemporaryCookie(rr, DefaultStateCookie, "value")

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	if c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite = %v, want Lax", c.SameSite)
	}
	if !c.HttpOnly || !c.Secure {
		t.Fatalf("HttpOnly = %v, Secure = %v, want both true", c.HttpOnly, c.Secure)
	}
	if c.Path != DefaultCallbackPath {
		t.Fatalf("Path = %q, want %q", c.Path, DefaultCallbackPath)
	}
}

func TestExchangeCode(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		h, ctx := newCallbackTestHandler(t, jsonTokenResponse(nil), nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc", nil).WithContext(ctx)
		token, err := h.exchangeCode(req, "test-verifier")
		if err != nil {
			t.Fatalf("exchangeCode() error = %v", err)
		}
		if token.AccessToken != "test-access-token" {
			t.Fatalf("AccessToken = %q, want %q", token.AccessToken, "test-access-token")
		}
	})

	t.Run("failure", func(t *testing.T) {
		t.Parallel()
		h, ctx := newCallbackTestHandler(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		}, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=bad", nil).WithContext(ctx)
		if _, err := h.exchangeCode(req, "test-verifier"); err == nil {
			t.Fatal("exchangeCode() error = nil, want error")
		}
	})
}

func TestExtractEmailFromIDToken(t *testing.T) {
	t.Parallel()

	const clientID = "client-id"

	tests := []struct {
		name  string
		extra map[string]any
	}{
		{
			name:  "no id_token extra",
			extra: nil,
		},
		{
			name:  "malformed id_token",
			extra: map[string]any{"id_token": "not-a-jwt"},
		},
		{
			name: "expired id_token",
			extra: map[string]any{"id_token": makeUnsignedJWT(map[string]any{
				"aud":            clientID,
				"exp":            1,
				"email":          "user@example.com",
				"email_verified": true,
			})},
		},
		{
			name: "audience mismatch",
			extra: map[string]any{"id_token": makeUnsignedJWT(map[string]any{
				"aud": "someone-else",
				"exp": 9999999999,
			})},
		},
	}

	h := &Handler{oauthConfig: &oauth2.Config{ClientID: clientID}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
			token := &oauth2.Token{AccessToken: "tok"}
			if tt.extra != nil {
				token = token.WithExtra(tt.extra)
			}
			if got := h.extractEmailFromIDToken(req, token); got != "" {
				t.Fatalf("extractEmailFromIDToken() = %q, want empty", got)
			}
		})
	}
}

func TestResolveUserEmail(t *testing.T) {
	t.Parallel()

	h, ctx := newCallbackTestHandler(t, nil, jsonUserInfoResponse("user@example.com", true))
	req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil).WithContext(ctx)
	token := &oauth2.Token{AccessToken: "tok"}

	got := h.resolveUserEmail(req, token)
	if got != "user@example.com" {
		t.Fatalf("resolveUserEmail() = %q, want %q", got, "user@example.com")
	}
}

func TestResolveUserEmailFallbackFails(t *testing.T) {
	t.Parallel()

	h, ctx := newCallbackTestHandler(t, nil, jsonUserInfoResponse("user@example.com", false))
	req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil).WithContext(ctx)
	token := &oauth2.Token{AccessToken: "tok"}

	if got := h.resolveUserEmail(req, token); got != "" {
		t.Fatalf("resolveUserEmail() = %q, want empty", got)
	}
}

func TestCallback(t *testing.T) {
	t.Parallel()

	const state = "test-state"

	newRequest := func(ctx context.Context, includeState bool) *http.Request {
		target := "/auth/callback?code=auth-code"
		if includeState {
			target += "&state=" + state
		}
		req := httptest.NewRequest(http.MethodGet, target, nil).WithContext(ctx)
		if includeState {
			req.AddCookie(&http.Cookie{Name: DefaultStateCookie, Value: state})
			req.AddCookie(&http.Cookie{Name: DefaultVerifierCookie, Value: "test-verifier"})
		}
		return req
	}

	t.Run("invalid state returns 400", func(t *testing.T) {
		t.Parallel()
		h, ctx := newCallbackTestHandler(t, nil, nil)
		req := newRequest(ctx, false)
		rr := httptest.NewRecorder()

		h.Callback(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	// A request without the PKCE verifier either skipped Login or has an
	// expired cookie, so it goes back to login instead of the token exchange.
	t.Run("missing PKCE verifier returns 400", func(t *testing.T) {
		t.Parallel()
		h, ctx := newCallbackTestHandler(t, nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=auth-code&state="+state, nil).WithContext(ctx)
		req.AddCookie(&http.Cookie{Name: DefaultStateCookie, Value: state})
		rr := httptest.NewRecorder()

		h.Callback(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	// When the user cancels on the consent screen, Google comes back with error
	// instead of code. Proceeding to the token exchange would be a 500 on the
	// empty code, putting a user action in an ERROR log.
	t.Run("oauth error parameter returns 403 without exchanging", func(t *testing.T) {
		t.Parallel()
		exchanged := false
		h, ctx := newCallbackTestHandler(t, func(http.ResponseWriter, *http.Request) { exchanged = true }, nil)
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied&state="+state, nil).WithContext(ctx)
		req.AddCookie(&http.Cookie{Name: DefaultStateCookie, Value: state})
		req.AddCookie(&http.Cookie{Name: DefaultVerifierCookie, Value: "test-verifier"})
		rr := httptest.NewRecorder()

		h.Callback(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
		}
		if exchanged {
			t.Error("token exchange was attempted with no code")
		}
	})

	t.Run("exchange failure returns 500", func(t *testing.T) {
		t.Parallel()
		h, ctx := newCallbackTestHandler(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}, nil)
		req := newRequest(ctx, true)
		rr := httptest.NewRecorder()

		h.Callback(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
		}
	})

	t.Run("unauthorized email returns 403", func(t *testing.T) {
		t.Parallel()
		h, ctx := newCallbackTestHandler(t, jsonTokenResponse(nil), jsonUserInfoResponse("user@other.com", true))
		req := newRequest(ctx, true)
		rr := httptest.NewRecorder()

		h.Callback(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
		}
	})

	t.Run("authorized email redirects and saves session", func(t *testing.T) {
		t.Parallel()
		h, ctx := newCallbackTestHandler(t, jsonTokenResponse(nil), jsonUserInfoResponse("user@example.com", true))
		req := newRequest(ctx, true)
		rr := httptest.NewRecorder()

		h.Callback(rr, req)

		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusSeeOther)
		}
		if loc := rr.Header().Get("Location"); loc != "/" {
			t.Fatalf("Location = %q, want %q", loc, "/")
		}
	})
}

func TestSaveSessionAndRedirect(t *testing.T) {
	t.Parallel()

	t.Run("defaults to root", func(t *testing.T) {
		t.Parallel()
		store := newTestStore()
		h := &Handler{store: store, sessionName: "test-session"}
		req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
		rr := httptest.NewRecorder()

		if err := h.saveSessionAndRedirect(rr, req, "user@example.com"); err != nil {
			t.Fatalf("saveSessionAndRedirect() error = %v", err)
		}
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusSeeOther)
		}
		if loc := rr.Header().Get("Location"); loc != "/" {
			t.Fatalf("Location = %q, want %q", loc, "/")
		}
	})

	// The cookie Login issued becomes the callback's return target as is.
	t.Run("uses the redirect cookie left by Login", func(t *testing.T) {
		t.Parallel()
		h := &Handler{store: newTestStore(), sessionName: "test-session"}

		loginRR := httptest.NewRecorder()
		loginReq := httptest.NewRequest(http.MethodGet, "/auth/login?redirect_to=/private%3Fpage%3D2", nil)
		h.oauthConfig = &oauth2.Config{ClientID: "client-id"}
		h.Login(loginRR, loginReq)

		req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
		for _, c := range loginRR.Result().Cookies() {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()

		if err := h.saveSessionAndRedirect(rr, req, "user@example.com"); err != nil {
			t.Fatalf("saveSessionAndRedirect() error = %v", err)
		}
		if loc := rr.Header().Get("Location"); loc != "/private?page=2" {
			t.Fatalf("Location = %q, want %q", loc, "/private?page=2")
		}
	})

	t.Run("unreachable store returns error", func(t *testing.T) {
		t.Parallel()
		h := &Handler{store: unavailableStore{}, sessionName: "test-session"}
		req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
		rr := httptest.NewRecorder()

		if err := h.saveSessionAndRedirect(rr, req, "user@example.com"); err == nil {
			t.Fatal("saveSessionAndRedirect() error = nil, want error")
		}
	})
}

func TestSaveSessionAndRedirectReturnsSaveError(t *testing.T) {
	t.Parallel()

	h := &Handler{
		store:       failingStore{},
		sessionName: "test-session",
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	rr := httptest.NewRecorder()

	if err := h.saveSessionAndRedirect(rr, req, "user@example.com"); err == nil {
		t.Fatalf("saveSessionAndRedirect() error = nil, want error")
	}
}

func TestLogout(t *testing.T) {
	t.Parallel()

	newSeededRequest := func(t *testing.T, h *Handler, target string) *http.Request {
		t.Helper()

		seeded := seedSession(t, h.store, h.sessionName, map[string]string{DefaultUserSessionKey: "user@example.com"})

		req := httptest.NewRequest(http.MethodPost, target, nil)
		req.AddCookie(seeded)
		return req
	}

	t.Run("expires the session cookie and redirects to login", func(t *testing.T) {
		t.Parallel()
		h := &Handler{store: newTestStore(), sessionName: "test-session"}
		req := newSeededRequest(t, h, "/auth/logout")
		rr := httptest.NewRecorder()

		h.Logout(rr, req)

		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusSeeOther)
		}
		if loc := rr.Header().Get("Location"); loc != DefaultLoginPath {
			t.Fatalf("Location = %q, want %q", loc, DefaultLoginPath)
		}

		cookies := rr.Result().Cookies()
		if len(cookies) == 0 {
			t.Fatal("expected the session cookie to be cleared")
		}
		if cookies[0].MaxAge != -1 {
			t.Fatalf("MaxAge = %d, want -1", cookies[0].MaxAge)
		}
	})

	t.Run("honours a safe redirect_to", func(t *testing.T) {
		t.Parallel()
		h := &Handler{store: newTestStore(), sessionName: "test-session"}
		req := newSeededRequest(t, h, "/auth/logout?redirect_to=/goodbye")
		rr := httptest.NewRecorder()

		h.Logout(rr, req)

		if loc := rr.Header().Get("Location"); loc != "/goodbye" {
			t.Fatalf("Location = %q, want %q", loc, "/goodbye")
		}
	})

	// External and scheme-relative URLs are ignored, to avoid an open redirect.
	t.Run("ignores unsafe redirect_to", func(t *testing.T) {
		t.Parallel()

		for _, target := range []string{"//evil.com", "https://evil.com/x", "relative"} {
			h := &Handler{store: newTestStore(), sessionName: "test-session"}
			req := httptest.NewRequest(http.MethodGet, "/auth/logout?redirect_to="+target, nil)
			rr := httptest.NewRecorder()

			h.Logout(rr, req)

			if loc := rr.Header().Get("Location"); loc != DefaultLoginPath {
				t.Fatalf("redirect_to=%q gave Location = %q, want %q", target, loc, DefaultLoginPath)
			}
		}
	})

	// Logout still succeeds when the store cannot be reached (the cookie is cleared).
	t.Run("redirects even when the session cannot be cleared", func(t *testing.T) {
		t.Parallel()
		h := &Handler{store: unavailableStore{}, sessionName: "test-session"}
		req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		rr := httptest.NewRecorder()

		h.Logout(rr, req)

		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusSeeOther)
		}
	})
}

// TestLoginPrompt checks that prompt appears on the authorization URL only when
// set, and that adding it loses neither the state nor the PKCE challenge.
//
// prompt decides whether logout appears to work. Without it, Google approves
// without asking anything as soon as the user is sent to the login page right
// after logging out, and the user is back where they were, signed in.
func TestLoginPrompt(t *testing.T) {
	t.Parallel()

	newHandler := func(prompt Prompt) *Handler {
		return &Handler{
			oauthConfig: &oauth2.Config{
				ClientID: "client-id",
				Endpoint: oauth2.Endpoint{AuthURL: "https://accounts.example.com/o/oauth2/auth"},
			},
			store:       newTestStore(),
			sessionName: "test-session",
			prompt:      prompt,
		}
	}

	tests := []struct {
		name   string
		prompt Prompt
		want   string
	}{
		{name: "omitted when unspecified", prompt: "", want: ""},
		{name: "asks to select an account", prompt: PromptSelectAccount, want: "select_account"},
		{name: "requires reauthentication", prompt: PromptLogin, want: "login"},
		{name: "omitted when whitespace only", prompt: "   ", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rr := httptest.NewRecorder()
			newHandler(tt.prompt).Login(rr, httptest.NewRequest(http.MethodGet, "/auth/login", nil))

			loc, err := url.Parse(rr.Header().Get("Location"))
			if err != nil {
				t.Fatalf("Location is not a readable URL: %v", err)
			}
			query := loc.Query()

			if got := query.Get("prompt"); got != tt.want {
				t.Errorf("prompt = %q, want %q", got, tt.want)
			}
			// Even with prompt added, both protections against interception must remain.
			if query.Get("state") == "" {
				t.Error("state is missing from the authorization URL")
			}
			if query.Get("code_challenge") == "" || query.Get("code_challenge_method") != "S256" {
				t.Errorf("the PKCE challenge is missing: challenge=%q method=%q",
					query.Get("code_challenge"), query.Get("code_challenge_method"))
			}
		})
	}
}

// TestWithPromptOption checks that prompt reaches the Handler through New too.
func TestWithPromptOption(t *testing.T) {
	t.Parallel()

	h, err := New(validTestConfig(), WithPrompt(PromptSelectAccount))
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	if got := h.promptParam(); got != "select_account" {
		t.Errorf("promptParam() = %q, want select_account", got)
	}
}

// TestSaveSessionAndRedirectRotatesSessionID checks that login assigns a new
// session ID (against session fixation).
//
// The cookie carries only the ID, so authenticating under an ID an attacker
// planted beforehand would let the attacker act as the victim with it. The
// planted ID has the minted shape: an ID of the wrong shape is dropped before
// the read, which would not test "stored, yet not adopted".
func TestSaveSessionAndRedirectRotatesSessionID(t *testing.T) {
	t.Parallel()

	const email = "user@example.com"
	store := newTestStore()

	// The session the attacker planted is already in the store.
	planted := seedSession(t, store, "test-session", map[string]string{
		CSRFTokenKey: "token-fixed-before-login",
	})
	plantedID := planted.Value

	h := &Handler{store: store, sessionName: "test-session"}
	req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	req.AddCookie(planted)
	// The target noted before login, in the same form as the cookie Login issues.
	req.AddCookie(&http.Cookie{Name: DefaultRedirectCookie, Value: url.QueryEscape("/dashboard")})
	rr := httptest.NewRecorder()

	if err := h.saveSessionAndRedirect(rr, req, email); err != nil {
		t.Fatalf("saveSessionAndRedirect = %v", err)
	}

	// The stored session under the planted ID is gone. Only authenticated
	// sessions are in the store, so leaving it would keep a valid session that
	// Logout cannot reach, for its full lifetime.
	if values, err := store.Load(context.Background(), plantedID); err == nil {
		t.Errorf("the pre-login stored session remains: %v", values)
	}

	// The cookie sent to the browser carries a new ID with an authenticated session under it.
	var cookieValue string
	for _, c := range rr.Result().Cookies() {
		if c.Name == "test-session" {
			cookieValue = c.Value
		}
	}
	if cookieValue == "" || cookieValue == plantedID {
		t.Fatalf("response cookie = %q, still the planted ID or empty", cookieValue)
	}
	values, err := store.Load(context.Background(), cookieValue)
	if err != nil {
		t.Fatalf("cannot read the session under the new ID: %v", err)
	}
	if values[DefaultUserSessionKey] != email {
		t.Errorf("new session email = %q, want %q", values[DefaultUserSessionKey], email)
	}
	// The pre-login CSRF token is not carried over.
	if _, ok := values[CSRFTokenKey]; ok {
		t.Error("the pre-login CSRF token was carried into the new session")
	}

	// Rotating the ID does not lose the target noted before login.
	if got := rr.Header().Get("Location"); got != "/dashboard" {
		t.Errorf("Location = %q, want /dashboard", got)
	}
}
