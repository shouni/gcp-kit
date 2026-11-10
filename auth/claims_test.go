package auth_test

import (
	"strings"
	"testing"

	"github.com/shouni/gcp-kit/auth"
)

// VerifiedEmail is the single check shared by three paths: ID token login, the
// UserInfo API and service-to-service verification. If it loosens, the
// loosened path can be used to claim someone else's address. Claims are JSON
// supplied from outside, with no guarantee of the expected types, so anything
// unexpected must fall on the rejecting side.
func TestVerifiedEmail(t *testing.T) {
	t.Parallel()

	const addr = "user@example.com"

	tests := []struct {
		name    string
		claims  map[string]any
		want    string
		wantErr string // a word the error must contain
	}{
		{
			name:   "passes when verified",
			claims: map[string]any{"email": addr, "email_verified": true},
			want:   addr,
		},
		{
			name:    "rejects unverified",
			claims:  map[string]any{"email": addr, "email_verified": false},
			wantErr: "not verified",
		},
		{
			// A missing claim is not "verified".
			name:    "rejects missing email_verified",
			claims:  map[string]any{"email": addr},
			wantErr: "not verified",
		},
		{
			// A JSON value can arrive as a string rather than a bool. Trying to
			// interpret it as a boolean could make even "false" true, so a wrong
			// type is rejected.
			name:    "rejects string email_verified",
			claims:  map[string]any{"email": addr, "email_verified": "true"},
			wantErr: "not verified",
		},
		{
			name:    "rejects numeric email_verified",
			claims:  map[string]any{"email": addr, "email_verified": 1},
			wantErr: "not verified",
		},
		{
			name:    "rejects missing email",
			claims:  map[string]any{"email_verified": true},
			wantErr: "no email claim",
		},
		{
			// Letting an empty string through would hand an empty address to the allowlist check.
			name:    "rejects empty email",
			claims:  map[string]any{"email": "", "email_verified": true},
			wantErr: "no email claim",
		},
		{
			name:    "rejects non-string email",
			claims:  map[string]any{"email": 12345, "email_verified": true},
			wantErr: "no email claim",
		},
		{
			name:    "rejects nil claims",
			claims:  nil,
			wantErr: "no email claim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := auth.VerifiedEmail(tt.claims)

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("VerifiedEmail() error = %v, want nil", err)
				}
				if got != tt.want {
					t.Errorf("VerifiedEmail() = %q, want %q", got, tt.want)
				}
				return
			}

			if err == nil {
				t.Fatalf("VerifiedEmail() = %q, error = nil, want error", got)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("VerifiedEmail() error = %v, want it to mention %q", err, tt.wantErr)
			}
			if got != "" {
				t.Errorf("VerifiedEmail() = %q, want \"\" on failure", got)
			}
		})
	}
}
