package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
)

func TestToLowerMap(t *testing.T) {
	t.Parallel()

	got := toLowerMap([]string{"User@Example.COM", "", "ADMIN@example.com", "user@example.com"})

	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if _, ok := got["user@example.com"]; !ok {
		t.Fatalf("expected normalized user email to exist")
	}
	if _, ok := got["admin@example.com"]; !ok {
		t.Fatalf("expected normalized admin email to exist")
	}
}

func TestIsAuthorized(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler Handler
		email   string
		want    bool
	}{
		{
			name:    "deny when allow lists are empty",
			handler: Handler{},
			email:   "user@example.com",
			want:    false,
		},
		{
			name: "allow exact email with case-insensitive match",
			handler: Handler{
				allowedEmails: map[string]struct{}{"user@example.com": {}},
			},
			email: "User@Example.com",
			want:  true,
		},
		{
			name: "allow by domain",
			handler: Handler{
				allowedDomains: map[string]struct{}{"example.com": {}},
			},
			email: "member@example.com",
			want:  true,
		},
		{
			name: "deny invalid email format",
			handler: Handler{
				allowedDomains: map[string]struct{}{"example.com": {}},
			},
			email: "invalid-address",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.handler.isAuthorized(tt.email); got != tt.want {
				t.Fatalf("isAuthorized(%q) = %v, want %v", tt.email, got, tt.want)
			}
		})
	}
}

// newFetchUserEmailHandler builds a Handler and a context whose HTTP client
// transparently redirects requests to the hardcoded Google UserInfo URL to a
// local httptest.Server, so fetchUserEmail's JSON-handling logic can be
// exercised without a real network call.
func newFetchUserEmailHandler(t *testing.T, userInfoHandler http.HandlerFunc) (*Handler, context.Context) {
	t.Helper()

	server := httptest.NewServer(userInfoHandler)
	t.Cleanup(server.Close)

	return &Handler{oauthConfig: &oauth2.Config{}}, newRewriteContext(t, server)
}

func TestFetchUserEmail(t *testing.T) {
	t.Parallel()

	t.Run("verified email succeeds", func(t *testing.T) {
		t.Parallel()
		h, ctx := newFetchUserEmailHandler(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"email": "user@example.com", "verified_email": true})
		})

		got, err := h.fetchUserEmail(ctx, &oauth2.Token{AccessToken: "tok"})
		if err != nil {
			t.Fatalf("fetchUserEmail() error = %v", err)
		}
		if got != "user@example.com" {
			t.Fatalf("fetchUserEmail() = %q, want %q", got, "user@example.com")
		}
	})

	t.Run("unverified email fails", func(t *testing.T) {
		t.Parallel()
		h, ctx := newFetchUserEmailHandler(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"email": "user@example.com", "verified_email": false})
		})

		if _, err := h.fetchUserEmail(ctx, &oauth2.Token{AccessToken: "tok"}); err == nil {
			t.Fatal("fetchUserEmail() error = nil, want error")
		}
	})

	t.Run("malformed response fails", func(t *testing.T) {
		t.Parallel()
		h, ctx := newFetchUserEmailHandler(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json"))
		})

		if _, err := h.fetchUserEmail(ctx, &oauth2.Token{AccessToken: "tok"}); err == nil {
			t.Fatal("fetchUserEmail() error = nil, want error")
		}
	})
}

func TestClearSessionCookie(t *testing.T) {
	t.Parallel()

	store := newTestCookieStore()
	h := &Handler{store: store, sessionName: "test-session"}
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()

	if err := h.clearSessionCookie(rr, req); err != nil {
		t.Fatalf("clearSessionCookie() error = %v", err)
	}

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected a cookie to be set")
	}
	if cookies[0].MaxAge != -1 {
		t.Fatalf("MaxAge = %d, want -1", cookies[0].MaxAge)
	}
}

func TestClearSessionCookieSaveError(t *testing.T) {
	t.Parallel()

	h := &Handler{store: failingStore{}, sessionName: "test-session"}
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()

	if err := h.clearSessionCookie(rr, req); err == nil {
		t.Fatal("clearSessionCookie() error = nil, want error")
	}
}

func TestRandomTokenAndGenerateState(t *testing.T) {
	t.Parallel()

	token, err := randomToken(base64.RawURLEncoding)
	if err != nil {
		t.Fatalf("randomToken() error = %v", err)
	}
	if token == "" {
		t.Fatal("randomToken() returned empty string")
	}

	state, err := generateState()
	if err != nil {
		t.Fatalf("generateState() error = %v", err)
	}
	if state == "" {
		t.Fatal("generateState() returned empty string")
	}
}
