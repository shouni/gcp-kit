package session

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shouni/gcp-kit/auth"
)

func TestMiddlewareRedirectBehavior(t *testing.T) {
	t.Parallel()

	newHandler := func() *Handler {
		store := newTestStore()
		return &Handler{
			store:       store,
			sessionName: "test-session",
		}
	}

	tests := []struct {
		name            string
		method          string
		target          string
		wantLocation    string
		expectParamPart bool
	}{
		{
			name:            "append redirect_to for normal GET path",
			method:          http.MethodGet,
			target:          "http://example.com/private?x=1",
			wantLocation:    "/auth/login?redirect_to=%2Fprivate%3Fx%3D1",
			expectParamPart: true,
		},
		{
			name:            "do not append redirect_to for root",
			method:          http.MethodGet,
			target:          "http://example.com/",
			wantLocation:    "/auth/login",
			expectParamPart: false,
		},
		{
			name:            "do not append redirect_to for non-GET",
			method:          http.MethodPost,
			target:          "http://example.com/private",
			wantLocation:    "/auth/login",
			expectParamPart: false,
		},
		{
			name:            "do not append redirect_to for schema-relative path",
			method:          http.MethodGet,
			target:          "http://example.com//evil.com",
			wantLocation:    "/auth/login",
			expectParamPart: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHandler()
			nextCalled := false
			next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				nextCalled = true
			})
			handler := auth.Require(h)(next)

			req := httptest.NewRequest(tt.method, tt.target, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if nextCalled {
				t.Fatalf("next handler must not be called when session has no user")
			}
			if rr.Code != http.StatusFound {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusFound)
			}

			location := rr.Header().Get("Location")
			if location != tt.wantLocation {
				t.Fatalf("Location = %q, want %q", location, tt.wantLocation)
			}

			hasParam := strings.Contains(location, "redirect_to=")
			if hasParam != tt.expectParamPart {
				t.Fatalf("Location redirect_to presence = %v, want %v", hasParam, tt.expectParamPart)
			}
		})
	}
}

func TestMiddlewareAllowsAuthenticatedRequest(t *testing.T) {
	t.Parallel()

	store := newTestStore()
	h := &Handler{store: store, sessionName: "test-session", allowedDomains: testAllowedDomains()}

	// Seed a session with a logged-in user and a matching CSRF token.
	seedCookies := []*http.Cookie{seedSession(t, store, h.sessionName, map[string]string{
		DefaultUserSessionKey: "user@example.com",
		CSRFTokenKey:          "csrf-token",
	})}

	t.Run("GET without CSRF token succeeds", func(t *testing.T) {
		t.Parallel()

		nextCalled := false
		next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true })

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, c := range seedCookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		auth.Require(h)(next).ServeHTTP(rr, req)

		if !nextCalled {
			t.Fatal("next handler should be called for an authenticated GET request")
		}
	})

	t.Run("POST without CSRF token is rejected", func(t *testing.T) {
		t.Parallel()

		nextCalled := false
		next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true })

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		for _, c := range seedCookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		auth.Require(h)(next).ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
		}
		if nextCalled {
			t.Fatal("next handler must not be called when CSRF validation fails")
		}
	})

	t.Run("POST with matching CSRF header succeeds", func(t *testing.T) {
		t.Parallel()

		nextCalled := false
		next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true })

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set(HeaderXCSRFToken, "csrf-token")
		for _, c := range seedCookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		auth.Require(h)(next).ServeHTTP(rr, req)

		if !nextCalled {
			t.Fatal("next handler should be called when the CSRF token matches")
		}
	})
}

// TestStoreUnavailableKeepsTheSession checks that the session cookie is not
// cleared when the store is merely unreachable.
//
// Treating a transient outage like a broken session turns a Firestore blip
// into a logout for every user accessing at that moment, and recovery does not
// undo it. The response is 503, not a redirect to the login page (which would
// not help).
func TestStoreUnavailableKeepsTheSession(t *testing.T) {
	t.Parallel()

	h := &Handler{
		store:          unavailableStore{},
		sessionName:    "test-session",
		allowedDomains: testAllowedDomains(),
	}

	// Only a well-formed ID reaches Load; anything else becomes "no session" before hitting the store failure.
	id, err := newSessionID()
	if err != nil {
		t.Fatalf("newSessionID() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(&http.Cookie{Name: "test-session", Value: id})
	rr := httptest.NewRecorder()

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("next handler must not be called while the store is unreachable")
	})
	auth.Require(h)(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
	}
	if got := rr.Result().Cookies(); len(got) != 0 {
		t.Fatalf("response set %d cookies (%v), want none: the session must survive the outage",
			len(got), got)
	}
}

// TestBrokenSessionClearsTheCookie checks that when the store was reached but
// the stored session cannot be decoded, the cookie is cleared, the user is
// sent to the login page, and the broken stored session is deleted. This one
// is fixed by starting over, so clearing it is the right remedy.
func TestBrokenSessionClearsTheCookie(t *testing.T) {
	t.Parallel()

	store := &brokenStore{}
	h := &Handler{
		store:          store,
		sessionName:    "test-session",
		allowedDomains: testAllowedDomains(),
	}

	// An ID of the wrong shape is dropped before Load, so the path reading a
	// broken stored session is entered with an ID of the minted shape.
	id, err := newSessionID()
	if err != nil {
		t.Fatalf("newSessionID() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(&http.Cookie{Name: "test-session", Value: id})
	rr := httptest.NewRecorder()

	auth.Require(h)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d (login redirect)", rr.Code, http.StatusFound)
	}
	var cleared bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == "test-session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("a session that cannot be read must be cleared, so the next login can replace it")
	}
	if len(store.deleted) != 1 || store.deleted[0] != id {
		t.Fatalf("deleted = %v, want the broken entity %q to be removed", store.deleted, id)
	}
}

// TestMiddlewareRejectsRevokedSession checks that a session for an address
// removed from the allowlist does not pass, even before it expires. If
// authorization were evaluated only once at login, a removed address would
// keep passing until the cookie expired.
func TestMiddlewareRejectsRevokedSession(t *testing.T) {
	t.Parallel()

	store := newTestStore()

	// A user who was allowed when the session was created.
	seeded := seedSession(t, store, "test-session", map[string]string{DefaultUserSessionKey: "user@example.com"})

	// The Handler after the user was removed from the allowlist. The session cookie itself is still valid.
	revoked := &Handler{
		store:          store,
		sessionName:    "test-session",
		allowedDomains: map[string]struct{}{"elsewhere.example": {}},
	}

	nextCalled := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true })

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	req.AddCookie(seeded)
	rr := httptest.NewRecorder()
	auth.Require(revoked)(next).ServeHTTP(rr, req)

	if nextCalled {
		t.Fatal("next handler must not be called for an email removed from the allowlist")
	}
	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusFound)
	}

	// Leaving an unusable session would repeat the same warning on every later request.
	var cleared bool
	for _, c := range rr.Result().Cookies() {
		if c.Name == "test-session" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("session cookie should be cleared once the session is no longer authorized")
	}
}

func TestIsStateChangingMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		method string
		want   bool
	}{
		{http.MethodGet, false},
		{http.MethodHead, false},
		{http.MethodOptions, false},
		{http.MethodPost, true},
		{http.MethodPut, true},
		{http.MethodPatch, true},
		{http.MethodDelete, true},
	}

	for _, tt := range tests {
		if got := isStateChangingMethod(tt.method); got != tt.want {
			t.Errorf("isStateChangingMethod(%q) = %v, want %v", tt.method, got, tt.want)
		}
	}
}

func TestValidateCSRF(t *testing.T) {
	t.Parallel()

	newSession := func(token string) *session {
		s := newSession()
		if token != "" {
			s.values[CSRFTokenKey] = token
		}
		return s
	}

	h := &Handler{}

	t.Run("no session token", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		if h.validateCSRF(req, newSession("")) {
			t.Fatal("validateCSRF() = true, want false")
		}
	})

	t.Run("header token matches", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.Header.Set(HeaderXCSRFToken, "tok")
		if !h.validateCSRF(req, newSession("tok")) {
			t.Fatal("validateCSRF() = false, want true")
		}
	})

	t.Run("header token mismatches", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.Header.Set(HeaderXCSRFToken, "wrong")
		if h.validateCSRF(req, newSession("tok")) {
			t.Fatal("validateCSRF() = true, want false")
		}
	})

	t.Run("form-encoded body token matches", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(CSRFTokenKey+"=tok"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if !h.validateCSRF(req, newSession("tok")) {
			t.Fatal("validateCSRF() = false, want true")
		}
	})

	t.Run("no token anywhere", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		if h.validateCSRF(req, newSession("tok")) {
			t.Fatal("validateCSRF() = true, want false")
		}
	})
}

// TestValidateOrigin checks the Origin check as defence in depth on top of
// token verification. A request without an Origin (a non-browser API client,
// for example) passes; only when one is presented must it match.
func TestValidateOrigin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		origin string
		want   bool
	}{
		{name: "no origin header", origin: "", want: true},
		{name: "same origin", origin: "https://app.example.com", want: true},
		{name: "same host different scheme", origin: "http://app.example.com", want: true},
		{name: "cross origin", origin: "https://evil.com", want: false},
		{name: "subdomain is not the same origin", origin: "https://evil.app.example.com", want: false},
		{name: "opaque origin", origin: "null", want: false},
		{name: "malformed origin", origin: "://", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, "https://app.example.com/x", nil)
			req.Host = "app.example.com"
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if got := validateOrigin(req); got != tt.want {
				t.Fatalf("validateOrigin(%q) = %v, want %v", tt.origin, got, tt.want)
			}
		})
	}
}

// TestMiddlewareRejectsCrossOriginPost checks that a request with a mismatched
// Origin is rejected even when it holds a correct CSRF token.
func TestMiddlewareRejectsCrossOriginPost(t *testing.T) {
	t.Parallel()

	store := newTestStore()
	h := &Handler{store: store, sessionName: "test-session", allowedDomains: testAllowedDomains()}

	seeded := seedSession(t, store, h.sessionName, map[string]string{
		DefaultUserSessionKey: "user@example.com",
		CSRFTokenKey:          "tok",
	})

	newReq := func(origin string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "https://app.example.com/private", nil)
		req.Host = "app.example.com"
		req.Header.Set(HeaderXCSRFToken, "tok")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		req.AddCookie(seeded)
		return req
	}

	nextCalled := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true })

	rr := httptest.NewRecorder()
	auth.Require(h)(next).ServeHTTP(rr, newReq("https://evil.com"))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-origin status = %d, want %d", rr.Code, http.StatusForbidden)
	}
	if nextCalled {
		t.Fatal("next handler must not be called for a cross-origin POST")
	}

	rr = httptest.NewRecorder()
	auth.Require(h)(next).ServeHTTP(rr, newReq("https://app.example.com"))
	if !nextCalled {
		t.Fatalf("same-origin POST was rejected with status %d", rr.Code)
	}
}

func TestGenerateAndSaveCSRFToken(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		store := newTestStore()
		h := &Handler{store: store, sessionName: "test-session"}
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		rr := httptest.NewRecorder()
		session := newSession()

		token, err := h.generateAndSaveCSRFToken(rr, req, session)
		if err != nil {
			t.Fatalf("GenerateAndSaveCSRFToken() error = %v", err)
		}
		if token == "" {
			t.Fatal("token is empty")
		}
		if session.values[CSRFTokenKey] != token {
			t.Fatalf("session token = %q, want %q", session.values[CSRFTokenKey], token)
		}
		if len(rr.Result().Cookies()) == 0 {
			t.Fatal("expected session cookie to be set")
		}
	})

	t.Run("nil session", func(t *testing.T) {
		t.Parallel()
		h := &Handler{store: newTestStore(), sessionName: "test-session"}
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		rr := httptest.NewRecorder()

		if _, err := h.generateAndSaveCSRFToken(rr, req, nil); err == nil {
			t.Fatal("GenerateAndSaveCSRFToken() error = nil, want error")
		}
	})

	t.Run("store save error", func(t *testing.T) {
		t.Parallel()
		h := &Handler{store: failingStore{}, sessionName: "test-session"}
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		rr := httptest.NewRecorder()

		if _, err := h.generateAndSaveCSRFToken(rr, req, newSession()); err == nil {
			t.Fatal("GenerateAndSaveCSRFToken() error = nil, want error")
		}
	})
}

// TestAuthenticateIssuesCSRFTokenOnGet checks that an authenticated GET
// without a token mints one and puts it in the context.
//
// If this were empty, templates would render the hidden input empty and every
// POST from that screen would be a 403 (consuming apps get the token from
// here).
func TestAuthenticateIssuesCSRFTokenOnGet(t *testing.T) {
	t.Parallel()

	store := newTestStore()
	h := &Handler{store: store, sessionName: "test-session", allowedDomains: testAllowedDomains()}
	cookies := seedAuthenticatedSession(t, h, "user@example.com")

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()

	ctx, err := h.Authenticate(rr, req)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	token := CSRFTokenFromContext(ctx)
	if token == "" {
		t.Fatal("CSRF token in context is empty")
	}

	// The second GET returns the token already issued.
	req2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	for _, c := range cookies {
		req2.AddCookie(c)
	}
	ctx2, err := h.Authenticate(httptest.NewRecorder(), req2)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if got := CSRFTokenFromContext(ctx2); got != token {
		t.Fatalf("token = %q, want the already issued %q", got, token)
	}
}

// TestAuthenticateReadsStoreOnce pins the store reads per authenticated
// request at one.
//
// With the Firestore store each read is one billed read plus another round
// trip. An implementation that re-reads instead of using the session at hand
// would silently double this number.
func TestAuthenticateReadsStoreOnce(t *testing.T) {
	t.Parallel()

	counting := &countingStore{inner: newTestStore()}
	h := &Handler{store: counting, sessionName: "test-session", allowedDomains: testAllowedDomains()}
	cookies := seedAuthenticatedSession(t, h, "user@example.com")

	// The first GET also mints a CSRF token, so there is exactly one extra save.
	for i, want := range []struct{ gets, saves int }{{1, 1}, {1, 0}} {
		counting.reset()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		if _, err := h.Authenticate(httptest.NewRecorder(), req); err != nil {
			t.Fatalf("GET #%d: Authenticate() error = %v", i+1, err)
		}
		if counting.gets != want.gets || counting.saves != want.saves {
			t.Fatalf("GET #%d: store.Get=%d store.Save=%d, want Get=%d Save=%d",
				i+1, counting.gets, counting.saves, want.gets, want.saves)
		}
	}
}
