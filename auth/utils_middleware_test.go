package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.handler.isAuthorized(tt.email); got != tt.want {
				t.Fatalf("isAuthorized(%q) = %v, want %v", tt.email, got, tt.want)
			}
		})
	}
}

func TestMiddlewareRedirectBehavior(t *testing.T) {
	t.Parallel()

	newHandler := func() *Handler {
		store := sessions.NewCookieStore([]byte("1234567890123456"), []byte("1234567890123456"))
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
		tt := tt
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
