package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/idtoken"
)

func stubM2MValidate(email string, err error) func(context.Context, string, string) (*idtoken.Payload, error) {
	return func(context.Context, string, string) (*idtoken.Payload, error) {
		if err != nil {
			return nil, err
		}
		return &idtoken.Payload{
			Subject: "sub",
			Claims:  map[string]interface{}{"email": email, "email_verified": true},
		}, nil
	}
}

func TestM2MVerifierAuthorized(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		allowed   []string
		authz     string
		validate  func(context.Context, string, string) (*idtoken.Payload, error)
		wantAuthz bool
	}{
		{
			name:      "empty allowlist always fails",
			allowed:   nil,
			authz:     "Bearer valid-token",
			validate:  stubM2MValidate("mcp@project.iam.gserviceaccount.com", nil),
			wantAuthz: false,
		},
		{
			name:      "valid token from allowed service account succeeds",
			allowed:   []string{"mcp@project.iam.gserviceaccount.com"},
			authz:     "Bearer valid-token",
			validate:  stubM2MValidate("mcp@project.iam.gserviceaccount.com", nil),
			wantAuthz: true,
		},
		{
			name:      "valid token from non-allowed service account fails",
			allowed:   []string{"mcp@project.iam.gserviceaccount.com"},
			authz:     "Bearer valid-token",
			validate:  stubM2MValidate("someone-else@project.iam.gserviceaccount.com", nil),
			wantAuthz: false,
		},
		{
			name:      "missing authorization header fails",
			allowed:   []string{"mcp@project.iam.gserviceaccount.com"},
			authz:     "",
			validate:  stubM2MValidate("mcp@project.iam.gserviceaccount.com", nil),
			wantAuthz: false,
		},
		{
			name:      "token validation error fails",
			allowed:   []string{"mcp@project.iam.gserviceaccount.com"},
			authz:     "Bearer invalid-token",
			validate:  stubM2MValidate("", errors.New("invalid token")),
			wantAuthz: false,
		},
		{
			name:      "lowercase bearer scheme still succeeds",
			allowed:   []string{"mcp@project.iam.gserviceaccount.com"},
			authz:     "bearer valid-token",
			validate:  stubM2MValidate("mcp@project.iam.gserviceaccount.com", nil),
			wantAuthz: true,
		},
		{
			name:    "missing email claim fails",
			allowed: []string{"mcp@project.iam.gserviceaccount.com"},
			authz:   "Bearer valid-token-no-email",
			validate: func(context.Context, string, string) (*idtoken.Payload, error) {
				return &idtoken.Payload{
					Subject: "sub",
					Claims:  map[string]interface{}{},
				}, nil
			},
			wantAuthz: false,
		},
		{
			name:    "unverified email claim fails",
			allowed: []string{"mcp@project.iam.gserviceaccount.com"},
			authz:   "Bearer valid-token-unverified-email",
			validate: func(context.Context, string, string) (*idtoken.Payload, error) {
				return &idtoken.Payload{
					Subject: "sub",
					Claims:  map[string]interface{}{"email": "mcp@project.iam.gserviceaccount.com", "email_verified": false},
				}, nil
			},
			wantAuthz: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := NewM2MVerifier("https://service.example.com", tt.allowed)
			v.validate = tt.validate

			req := httptest.NewRequest(http.MethodGet, "/web/history", nil)
			if tt.authz != "" {
				req.Header.Set("Authorization", tt.authz)
			}

			if got := v.Authorized(req); got != tt.wantAuthz {
				t.Errorf("Authorized() = %v, want %v", got, tt.wantAuthz)
			}
		})
	}
}

func TestM2MVerifierAuthorizedNilReceiver(t *testing.T) {
	t.Parallel()

	var v *M2MVerifier
	req := httptest.NewRequest(http.MethodGet, "/web/history", nil)
	req.Header.Set("Authorization", "Bearer whatever")

	if v.Authorized(req) {
		t.Fatal("nil verifier should never authorize")
	}
}
