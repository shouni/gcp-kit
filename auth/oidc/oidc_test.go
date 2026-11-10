package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/idtoken"

	"github.com/shouni/gcp-kit/auth"
)

const (
	testAudience = "https://worker.example.com"
	testAccount  = "tasks@project.iam.gserviceaccount.com"
)

// stubValidate stands in for idtoken.Validate and returns a verified payload
// with the given email, or err if it is non-nil.
func stubValidate(email string, err error) ValidateFunc {
	return func(context.Context, string, string) (*idtoken.Payload, error) {
		if err != nil {
			return nil, err
		}
		return &idtoken.Payload{
			Subject: "sub",
			Claims:  map[string]any{"email": email, "email_verified": true},
		}, nil
	}
}

// newTestVerifier builds a Verifier without New's checks, to exercise
// Authenticate and Challenge on an unconfigured Verifier.
func newTestVerifier(allowed []string, validate ValidateFunc) *Verifier {
	return &Verifier{audience: testAudience, allowed: toLowerMap(allowed), validate: validate}
}

// TestWithValidatorDrivesAuthenticate checks that a validation function
// swapped in with WithValidator takes effect on Authenticate's Bearer path as
// is. The point is that callers can exercise the Bearer path end to end with
// it.
func TestWithValidatorDrivesAuthenticate(t *testing.T) {
	t.Parallel()

	v, err := New(testAudience, []string{testAccount}, WithValidator(stubValidate(testAccount, nil)))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer any-token")
	ctx, err := v.Authenticate(httptest.NewRecorder(), req)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	payload, ok := PayloadFromContext(ctx)
	if !ok || payload.Claims["email"] != testAccount {
		t.Fatalf("payload in context = %+v, ok = %v", payload, ok)
	}

	// nil is ignored and the default (idtoken.Validate) stays.
	v, err = New(testAudience, []string{testAccount}, WithValidator(nil), nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if v.validate == nil {
		t.Fatal("WithValidator(nil) removed the default validator")
	}
}

// TestNewRequiresAudienceAndAllowlist checks that New never returns a Verifier
// with missing settings. It is the entry point that keeps "empty allowlist =
// let everyone in" from happening.
func TestNewRequiresAudienceAndAllowlist(t *testing.T) {
	t.Parallel()

	if _, err := New(testAudience, []string{testAccount}); err != nil {
		t.Fatalf("New() error = %v, want nil", err)
	}

	tests := []struct {
		name     string
		audience string
		allowed  []string
	}{
		{name: "empty allowlist", audience: testAudience, allowed: nil},
		{name: "blank entries only", audience: testAudience, allowed: []string{"", "  "}},
		{name: "missing audience", audience: "  ", allowed: []string{testAccount}},
		{name: "both missing", audience: "", allowed: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			v, err := New(tt.audience, tt.allowed)
			if !errors.Is(err, auth.ErrNotConfigured) {
				t.Fatalf("New() error = %v, want auth.ErrNotConfigured", err)
			}
			if v != nil {
				t.Fatal("New() returned a Verifier alongside the error")
			}
		})
	}
}

func TestVerifierAuthenticate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		allowed  []string
		authz    string
		validate ValidateFunc
		wantErr  error // compared with errors.Is; nil expects success
	}{
		{
			name:     "allowed service account passes",
			allowed:  []string{testAccount},
			authz:    "Bearer valid-token",
			validate: stubValidate(testAccount, nil),
		},
		{
			name:     "matches the allowlist case-insensitively",
			allowed:  []string{testAccount},
			authz:    "Bearer valid-token",
			validate: stubValidate("Tasks@Project.IAM.gserviceaccount.com", nil),
		},
		{
			name:     "passes with a lowercase bearer scheme",
			allowed:  []string{testAccount},
			authz:    "bearer valid-token",
			validate: stubValidate(testAccount, nil),
		},
		{
			name:     "rejects a service account not on the allowlist",
			allowed:  []string{testAccount},
			authz:    "Bearer valid-token",
			validate: stubValidate("attacker@evil.iam.gserviceaccount.com", nil),
			wantErr:  errSentinel,
		},
		{
			name:     "rejects on signature verification failure",
			allowed:  []string{testAccount},
			authz:    "Bearer invalid-token",
			validate: stubValidate("", errors.New("bad signature")),
			wantErr:  errSentinel,
		},
		{
			// An unverified email address does not prove ownership.
			name:    "rejects an unverified email",
			allowed: []string{testAccount},
			authz:   "Bearer valid-token",
			validate: func(context.Context, string, string) (*idtoken.Payload, error) {
				return &idtoken.Payload{Claims: map[string]any{"email": testAccount, "email_verified": false}}, nil
			},
			wantErr: errSentinel,
		},
		{
			name:    "rejects a missing email claim",
			allowed: []string{testAccount},
			authz:   "Bearer valid-token",
			validate: func(context.Context, string, string) (*idtoken.Payload, error) {
				return &idtoken.Payload{Subject: "sub", Claims: map[string]any{}}, nil
			},
			wantErr: errSentinel,
		},
		{
			name:    "rejects a nil payload",
			allowed: []string{testAccount},
			authz:   "Bearer valid-token",
			validate: func(context.Context, string, string) (*idtoken.Payload, error) {
				return nil, nil
			},
			wantErr: errSentinel,
		},
		{
			// Calls from browsers land here. The composer moves on to the next method.
			name:     "not attempted without an Authorization header",
			allowed:  []string{testAccount},
			authz:    "",
			validate: stubValidate(testAccount, nil),
			wantErr:  auth.ErrNotAttempted,
		},
		{
			// An empty allowlist is a missing setting. Mixed with not-attempted, it would hide behind the fallback.
			name:     "unconfigured with an empty allowlist",
			allowed:  nil,
			authz:    "Bearer valid-token",
			validate: stubValidate(testAccount, nil),
			wantErr:  auth.ErrNotConfigured,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := newTestVerifier(tt.allowed, tt.validate)

			req := httptest.NewRequest(http.MethodPost, "/tasks", nil)
			if tt.authz != "" {
				req.Header.Set("Authorization", tt.authz)
			}

			ctx, err := v.Authenticate(httptest.NewRecorder(), req)

			switch {
			case tt.wantErr == nil:
				if err != nil {
					t.Fatalf("Authenticate() error = %v, want nil", err)
				}
				payload, ok := PayloadFromContext(ctx)
				if !ok || payload.Subject == "" {
					t.Fatal("verified payload is not in the context")
				}
			case errors.Is(tt.wantErr, errSentinel):
				// A general verification failure without a sentinel.
				if err == nil {
					t.Fatal("Authenticate() error = nil, want a verification failure")
				}
				if errors.Is(err, auth.ErrNotAttempted) || errors.Is(err, auth.ErrNotConfigured) {
					t.Fatalf("Authenticate() error = %v, want a plain verification failure", err)
				}
			default:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Authenticate() error = %v, want %v", err, tt.wantErr)
				}
			}

			if tt.wantErr != nil && ctx != nil {
				t.Fatalf("Authenticate() ctx = %v, want nil on failure", ctx)
			}
		})
	}
}

// errSentinel is the test's marker for "a verification failure without a sentinel".
var errSentinel = errors.New("verification failure")

// TestVerifierNilReceiver checks that an unbuilt Verifier does not panic.
func TestVerifierNilReceiver(t *testing.T) {
	t.Parallel()

	var v *Verifier

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := v.Authenticate(httptest.NewRecorder(), req); !errors.Is(err, auth.ErrNotConfigured) {
		t.Fatalf("Authenticate() error = %v, want auth.ErrNotConfigured", err)
	}
}

// Challenge, per RFC 6750, Section 3.1, answers an invalid token (fixed by
// fetching a new one) and a caller that is not allowed (not fixed by fetching
// a new one) differently. Checked by passing real Authenticate failures as is.
func TestVerifierChallenge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		allowed    []string
		authz      string
		validate   ValidateFunc
		wantStatus int
		wantWWW    string
	}{
		{
			name: "no credentials", allowed: []string{testAccount}, authz: "",
			validate:   stubValidate(testAccount, nil),
			wantStatus: http.StatusUnauthorized, wantWWW: "Bearer",
		},
		{
			name: "invalid token", allowed: []string{testAccount}, authz: "Bearer bogus",
			validate:   stubValidate("", errors.New("bad signature")),
			wantStatus: http.StatusUnauthorized, wantWWW: `Bearer error="invalid_token"`,
		},
		{
			name: "caller not on the allowlist", allowed: []string{testAccount}, authz: "Bearer valid",
			validate:   stubValidate("stranger@evil.iam.gserviceaccount.com", nil),
			wantStatus: http.StatusForbidden, wantWWW: `Bearer error="insufficient_scope"`,
		},
		{
			// A missing setting is the server's fault, so no challenge is sent.
			name: "verifier not configured", allowed: nil, authz: "Bearer valid",
			validate:   stubValidate(testAccount, nil),
			wantStatus: http.StatusInternalServerError, wantWWW: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := newTestVerifier(tt.allowed, tt.validate)

			req := httptest.NewRequest(http.MethodGet, "/tasks", nil)
			if tt.authz != "" {
				req.Header.Set("Authorization", tt.authz)
			}
			rec := httptest.NewRecorder()

			_, err := v.Authenticate(rec, req)
			if err == nil {
				t.Fatal("Authenticate() error = nil, want a failure")
			}
			v.Challenge(rec, req, err)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != tt.wantWWW {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tt.wantWWW)
			}
		})
	}
}
