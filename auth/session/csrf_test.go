package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shouni/gcp-kit/auth"
)

// newCSRFTestHandler returns a Handler with only a session store. OAuth
// settings play no part in the CSRF path, so none are set.
func newCSRFTestHandler() *Handler {
	return &Handler{store: newTestStore(), sessionName: "test-session", allowedDomains: testAllowedDomains()}
}

func TestAuthenticatePutsCSRFTokenOnContext(t *testing.T) {
	t.Parallel()

	t.Run("GET generates a token into the context and session", func(t *testing.T) {
		t.Parallel()

		h := newCSRFTestHandler()
		var token string
		next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			token = CSRFTokenFromContext(r.Context())
		})

		req := httptest.NewRequest(http.MethodGet, "/web/compose", nil)
		req.AddCookie(loginSessionCookie(t, h, "user@example.com"))
		rec := httptest.NewRecorder()
		auth.Require(h)(next).ServeHTTP(rec, req)

		if token == "" {
			t.Fatal("GET did not generate a CSRF token")
		}
		if len(rec.Result().Cookies()) == 0 {
			t.Fatal("no session cookie was set to store the generated token")
		}
	})

	// Minting on POST would hand a valid token to a request that arrived
	// without one, making CSRF verification meaningless.
	t.Run("POST does not generate a token", func(t *testing.T) {
		t.Parallel()

		h := newCSRFTestHandler()
		var token string
		next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			token = CSRFTokenFromContext(r.Context())
		})

		// It fails CSRF verification, but what matters here is that nothing is minted.
		req := httptest.NewRequest(http.MethodPost, "/web/compose", nil)
		req.AddCookie(loginSessionCookie(t, h, "user@example.com"))
		auth.Require(h)(next).ServeHTTP(httptest.NewRecorder(), req)

		if token != "" {
			t.Fatalf("POST generated a CSRF token: %q", token)
		}
	})

	t.Run("keeps an existing token", func(t *testing.T) {
		t.Parallel()

		h := newCSRFTestHandler()
		var got string
		next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got = CSRFTokenFromContext(r.Context())
		})

		// Mint a token on the first request and carry its cookie to the second.
		firstReq := httptest.NewRequest(http.MethodGet, "/web/compose", nil)
		firstReq.AddCookie(loginSessionCookie(t, h, "user@example.com"))
		first := httptest.NewRecorder()
		auth.Require(h)(next).ServeHTTP(first, firstReq)
		firstToken := got

		req := httptest.NewRequest(http.MethodGet, "/web/compose", nil)
		for _, c := range first.Result().Cookies() {
			req.AddCookie(c)
		}
		auth.Require(h)(next).ServeHTTP(httptest.NewRecorder(), req)

		if got != firstToken {
			t.Fatalf("the existing token was regenerated: %q → %q", firstToken, got)
		}
	})
}

// loginSessionCookie returns a cookie for a logged-in session.
func loginSessionCookie(t *testing.T, h *Handler, email string) *http.Cookie {
	t.Helper()

	return seedSession(t, h.store, h.sessionName, map[string]string{DefaultUserSessionKey: email})
}

// CSRFTokenFromContext returns an empty string for a context without the value.
func TestCSRFTokenFromContextWithoutValue(t *testing.T) {
	t.Parallel()

	if got := CSRFTokenFromContext(context.Background()); got != "" {
		t.Fatalf("CSRFTokenFromContext() = %q, want empty", got)
	}
}
