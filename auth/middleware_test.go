package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
)

func TestMiddlewareRedirectBehavior(t *testing.T) {
	t.Parallel()

	newHandler := func() *Handler {
		store := newTestCookieStore()
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
			handler := h.Middleware(next)

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

	store := newTestCookieStore()
	h := &Handler{store: store, sessionName: "test-session"}

	// Seed a session with a logged-in user and a matching CSRF token.
	seedReq := httptest.NewRequest(http.MethodGet, "/", nil)
	seedRR := httptest.NewRecorder()
	session, err := h.store.Get(seedReq, h.sessionName)
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	session.Values[DefaultUserSessionKey] = "user@example.com"
	session.Values[CSRFTokenKey] = "csrf-token"
	if err := session.Save(seedReq, seedRR); err != nil {
		t.Fatalf("session.Save() error = %v", err)
	}
	// httptest.ResponseRecorder.Result() is not safe to call concurrently,
	// so extract the cookies once here rather than from inside the parallel
	// subtests below.
	seedCookies := seedRR.Result().Cookies()

	t.Run("GET without CSRF token succeeds", func(t *testing.T) {
		t.Parallel()

		nextCalled := false
		next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true })

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, c := range seedCookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		h.Middleware(next).ServeHTTP(rr, req)

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
		h.Middleware(next).ServeHTTP(rr, req)

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
		h.Middleware(next).ServeHTTP(rr, req)

		if !nextCalled {
			t.Fatal("next handler should be called when the CSRF token matches")
		}
	})
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

	newSession := func(token string) *sessions.Session {
		s := sessions.NewSession(nil, "test")
		s.Values = map[any]any{}
		if token != "" {
			s.Values[CSRFTokenKey] = token
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

func TestGenerateAndSaveCSRFToken(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		store := newTestCookieStore()
		h := &Handler{store: store, sessionName: "test-session"}
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		rr := httptest.NewRecorder()

		token, err := h.GenerateAndSaveCSRFToken(rr, req)
		if err != nil {
			t.Fatalf("GenerateAndSaveCSRFToken() error = %v", err)
		}
		if token == "" {
			t.Fatal("token is empty")
		}
		if len(rr.Result().Cookies()) == 0 {
			t.Fatal("expected session cookie to be set")
		}
	})

	t.Run("store get error", func(t *testing.T) {
		t.Parallel()
		h := &Handler{store: nilSessionStore{}, sessionName: "test-session"}
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		rr := httptest.NewRecorder()

		if _, err := h.GenerateAndSaveCSRFToken(rr, req); err == nil {
			t.Fatal("GenerateAndSaveCSRFToken() error = nil, want error")
		}
	})

	t.Run("store save error", func(t *testing.T) {
		t.Parallel()
		h := &Handler{store: failingStore{}, sessionName: "test-session"}
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		rr := httptest.NewRecorder()

		if _, err := h.GenerateAndSaveCSRFToken(rr, req); err == nil {
			t.Fatal("GenerateAndSaveCSRFToken() error = nil, want error")
		}
	})
}

func TestGetCSRFTokenFromSession(t *testing.T) {
	t.Parallel()

	t.Run("returns saved token", func(t *testing.T) {
		t.Parallel()
		store := newTestCookieStore()
		h := &Handler{store: store, sessionName: "test-session"}

		saveReq := httptest.NewRequest(http.MethodGet, "/x", nil)
		saveRR := httptest.NewRecorder()
		token, err := h.GenerateAndSaveCSRFToken(saveRR, saveReq)
		if err != nil {
			t.Fatalf("GenerateAndSaveCSRFToken() error = %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		for _, c := range saveRR.Result().Cookies() {
			req.AddCookie(c)
		}

		if got := h.GetCSRFTokenFromSession(req); got != token {
			t.Fatalf("GetCSRFTokenFromSession() = %q, want %q", got, token)
		}
	})

	t.Run("store get error returns empty", func(t *testing.T) {
		t.Parallel()
		h := &Handler{store: nilSessionStore{}, sessionName: "test-session"}
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		if got := h.GetCSRFTokenFromSession(req); got != "" {
			t.Fatalf("GetCSRFTokenFromSession() = %q, want empty", got)
		}
	})

	t.Run("no token in session returns empty", func(t *testing.T) {
		t.Parallel()
		store := newTestCookieStore()
		h := &Handler{store: store, sessionName: "test-session"}
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		if got := h.GetCSRFTokenFromSession(req); got != "" {
			t.Fatalf("GetCSRFTokenFromSession() = %q, want empty", got)
		}
	})
}

func TestTaskOIDCVerificationMiddlewareMissingAudience(t *testing.T) {
	t.Parallel()

	h := &Handler{}
	nextCalled := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	})

	req := httptest.NewRequest(http.MethodPost, "/tasks", nil)
	req.Header.Set("Authorization", "Bearer token")
	rr := httptest.NewRecorder()

	h.TaskOIDCVerificationMiddleware(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
	if nextCalled {
		t.Fatalf("next handler must not be called")
	}
}

func TestTaskOIDCVerificationMiddleware(t *testing.T) {
	t.Parallel()

	newHandler := func() *Handler {
		return &Handler{taskAudienceURL: "https://worker.example.com/tasks"}
	}

	t.Run("missing bearer token returns 401", func(t *testing.T) {
		t.Parallel()
		h := newHandler()
		nextCalled := false
		next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true })

		req := httptest.NewRequest(http.MethodPost, "/tasks", nil)
		rr := httptest.NewRecorder()
		h.TaskOIDCVerificationMiddleware(next).ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
		}
		if nextCalled {
			t.Fatal("next handler must not be called")
		}
	})

	t.Run("invalid token returns 403", func(t *testing.T) {
		t.Parallel()
		h := newHandler()
		nextCalled := false
		next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true })

		// A well-formed but expired JWT fails idtoken's expiry check before
		// any network call is made to fetch Google's signing keys.
		jwt := makeUnsignedJWT(map[string]any{
			"aud": h.taskAudienceURL,
			"exp": 1,
		})
		req := httptest.NewRequest(http.MethodPost, "/tasks", nil)
		req.Header.Set("Authorization", "Bearer "+jwt)
		rr := httptest.NewRecorder()
		h.TaskOIDCVerificationMiddleware(next).ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
		}
		if nextCalled {
			t.Fatal("next handler must not be called")
		}
	})
}
