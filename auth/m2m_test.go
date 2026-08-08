package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/idtoken"
)

// TestNewM2MVerifierConfigured は、M2MVerifier が audience と許可リストの両方が
// 揃ったときだけ有効になることを確認します。TaskVerifier と違い M2M の設定漏れは
// 401 ではなくセッション認証へのフォールバックとして現れ、気付きにくいため、
// 起動時に検出できることが要件です。
func TestNewM2MVerifierConfigured(t *testing.T) {
	t.Parallel()

	const (
		audience = "https://service.example.com"
		account  = "caller@example.iam.gserviceaccount.com"
	)

	tests := []struct {
		name     string
		audience string
		allowed  []string
		want     bool
	}{
		{"audience と許可リストが揃えば有効", audience, []string{account}, true},
		{"許可リストが空なら無効", audience, nil, false},
		{"audience が空なら無効", "", []string{account}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := NewM2MVerifier(tt.audience, tt.allowed).Configured(); got != tt.want {
				t.Fatalf("Configured() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("nil レシーバーは未設定として扱う", func(t *testing.T) {
		t.Parallel()
		var v *M2MVerifier
		if v.Configured() {
			t.Fatal("nil M2MVerifier must not be configured")
		}
	})
}

func stubM2MValidate(email string, err error) func(context.Context, string, string) (*idtoken.Payload, error) {
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

func TestM2MVerifierVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		allowed          []string
		authz            string
		validate         func(context.Context, string, string) (*idtoken.Payload, error)
		wantOK           bool
		wantNotAttempted bool
	}{
		{
			name:             "empty allowlist is treated as not attempted",
			allowed:          nil,
			authz:            "Bearer valid-token",
			validate:         stubM2MValidate("mcp@project.iam.gserviceaccount.com", nil),
			wantOK:           false,
			wantNotAttempted: true,
		},
		{
			name:     "valid token from allowed service account succeeds",
			allowed:  []string{"mcp@project.iam.gserviceaccount.com"},
			authz:    "Bearer valid-token",
			validate: stubM2MValidate("mcp@project.iam.gserviceaccount.com", nil),
			wantOK:   true,
		},
		{
			name:     "valid token from non-allowed service account fails",
			allowed:  []string{"mcp@project.iam.gserviceaccount.com"},
			authz:    "Bearer valid-token",
			validate: stubM2MValidate("someone-else@project.iam.gserviceaccount.com", nil),
			wantOK:   false,
		},
		{
			name:             "missing authorization header is treated as not attempted",
			allowed:          []string{"mcp@project.iam.gserviceaccount.com"},
			authz:            "",
			validate:         stubM2MValidate("mcp@project.iam.gserviceaccount.com", nil),
			wantOK:           false,
			wantNotAttempted: true,
		},
		{
			name:     "token validation error fails",
			allowed:  []string{"mcp@project.iam.gserviceaccount.com"},
			authz:    "Bearer invalid-token",
			validate: stubM2MValidate("", errors.New("invalid token")),
			wantOK:   false,
		},
		{
			name:     "lowercase bearer scheme still succeeds",
			allowed:  []string{"mcp@project.iam.gserviceaccount.com"},
			authz:    "bearer valid-token",
			validate: stubM2MValidate("mcp@project.iam.gserviceaccount.com", nil),
			wantOK:   true,
		},
		{
			name:    "missing email claim fails",
			allowed: []string{"mcp@project.iam.gserviceaccount.com"},
			authz:   "Bearer valid-token-no-email",
			validate: func(context.Context, string, string) (*idtoken.Payload, error) {
				return &idtoken.Payload{
					Subject: "sub",
					Claims:  map[string]any{},
				}, nil
			},
			wantOK: false,
		},
		{
			name:    "unverified email claim fails",
			allowed: []string{"mcp@project.iam.gserviceaccount.com"},
			authz:   "Bearer valid-token-unverified-email",
			validate: func(context.Context, string, string) (*idtoken.Payload, error) {
				return &idtoken.Payload{
					Subject: "sub",
					Claims:  map[string]any{"email": "mcp@project.iam.gserviceaccount.com", "email_verified": false},
				}, nil
			},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := NewM2MVerifier("https://service.example.com", tt.allowed)
			v.verifier.validate = tt.validate

			req := httptest.NewRequest(http.MethodGet, "/web/history", nil)
			if tt.authz != "" {
				req.Header.Set("Authorization", tt.authz)
			}

			payload, err := v.Verify(req)

			if tt.wantOK {
				if err != nil {
					t.Fatalf("Verify() error = %v, want nil", err)
				}
				if payload == nil {
					t.Fatal("Verify() payload = nil, want non-nil on success")
				}
				return
			}

			if err == nil {
				t.Fatal("Verify() error = nil, want non-nil")
			}
			if payload != nil {
				t.Fatalf("Verify() payload = %+v, want nil on failure", payload)
			}
			if got := errors.Is(err, ErrM2MNotAttempted); got != tt.wantNotAttempted {
				t.Errorf("errors.Is(err, ErrM2MNotAttempted) = %v, want %v (err=%v)", got, tt.wantNotAttempted, err)
			}
		})
	}
}

func TestM2MVerifierVerifyNilReceiver(t *testing.T) {
	t.Parallel()

	var v *M2MVerifier
	req := httptest.NewRequest(http.MethodGet, "/web/history", nil)
	req.Header.Set("Authorization", "Bearer whatever")

	payload, err := v.Verify(req)
	if err == nil || payload != nil {
		t.Fatalf("Verify() = (%v, %v), want (nil, non-nil error)", payload, err)
	}
	if !errors.Is(err, ErrM2MNotAttempted) {
		t.Errorf("expected ErrM2MNotAttempted, got %v", err)
	}
}
