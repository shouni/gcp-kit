package auth

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/api/idtoken"
)

func TestOIDCVerifierConfigured(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		verifier *oidcVerifier
		want     bool
	}{
		{name: "nil verifier", verifier: nil, want: false},
		{name: "audience and allowlist", verifier: newOIDCVerifier("https://a.example.com", []string{"sa@p.iam.gserviceaccount.com"}), want: true},
		// 許可リストが空の場合は fail-closed のため未設定として扱います。
		{name: "empty allowlist", verifier: newOIDCVerifier("https://a.example.com", nil), want: false},
		{name: "blank entries only", verifier: newOIDCVerifier("https://a.example.com", []string{"", "  "}), want: false},
		{name: "missing audience", verifier: newOIDCVerifier("  ", []string{"sa@p.iam.gserviceaccount.com"}), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.verifier.configured(); got != tt.want {
				t.Fatalf("configured() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOIDCVerifierVerifyToken(t *testing.T) {
	t.Parallel()

	const allowedSA = "tasks@project.iam.gserviceaccount.com"

	tests := []struct {
		name     string
		validate validateFunc
		wantErr  bool
	}{
		{
			name:     "allowed service account",
			validate: stubM2MValidate(allowedSA, nil),
			wantErr:  false,
		},
		{
			name:     "case-insensitive service account match",
			validate: stubM2MValidate("Tasks@Project.IAM.gserviceaccount.com", nil),
			wantErr:  false,
		},
		{
			name:     "other service account is rejected",
			validate: stubM2MValidate("attacker@evil.iam.gserviceaccount.com", nil),
			wantErr:  true,
		},
		{
			name:     "validation failure",
			validate: stubM2MValidate("", errors.New("bad signature")),
			wantErr:  true,
		},
		{
			name: "unverified email is rejected",
			validate: func(context.Context, string, string) (*idtoken.Payload, error) {
				return &idtoken.Payload{Claims: map[string]any{"email": allowedSA, "email_verified": false}}, nil
			},
			wantErr: true,
		},
		{
			name: "nil payload is rejected",
			validate: func(context.Context, string, string) (*idtoken.Payload, error) {
				return nil, nil
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := newOIDCVerifier("https://worker.example.com", []string{allowedSA})
			v.validate = tt.validate

			payload, err := v.verifyToken(context.Background(), "token")
			if (err != nil) != tt.wantErr {
				t.Fatalf("verifyToken() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && payload != nil {
				t.Fatalf("verifyToken() payload = %+v, want nil on failure", payload)
			}
		})
	}
}

// TestVerifiedEmailFromClaims は、IDトークン経由のログインと M2M/Cloud Tasks 検証が
// 共有する「未検証メールアドレスは採用しない」基準を直接検証します。
func TestVerifiedEmailFromClaims(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		claims  map[string]any
		want    string
		wantErr bool
	}{
		{
			name:   "verified email",
			claims: map[string]any{"email": "user@example.com", "email_verified": true},
			want:   "user@example.com",
		},
		{
			name:    "unverified email is rejected",
			claims:  map[string]any{"email": "user@example.com", "email_verified": false},
			wantErr: true,
		},
		{
			name:    "missing email_verified claim is rejected",
			claims:  map[string]any{"email": "user@example.com"},
			wantErr: true,
		},
		{
			// 一部のプロバイダは文字列 "true" を返しますが、bool でなければ信用しません。
			name:    "non-boolean email_verified is rejected",
			claims:  map[string]any{"email": "user@example.com", "email_verified": "true"},
			wantErr: true,
		},
		{
			name:    "missing email claim",
			claims:  map[string]any{"email_verified": true},
			wantErr: true,
		},
		{
			name:    "empty email claim",
			claims:  map[string]any{"email": "", "email_verified": true},
			wantErr: true,
		},
		{
			name:    "nil claims",
			claims:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := verifiedEmailFromClaims(tt.claims)
			if (err != nil) != tt.wantErr {
				t.Fatalf("verifiedEmailFromClaims() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("verifiedEmailFromClaims() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOIDCVerifierVerifyTokenNotConfigured(t *testing.T) {
	t.Parallel()

	v := newOIDCVerifier("https://worker.example.com", nil)
	if _, err := v.verifyToken(context.Background(), "token"); !errors.Is(err, ErrOIDCNotAttempted) {
		t.Fatalf("verifyToken() error = %v, want ErrOIDCNotAttempted", err)
	}
}
