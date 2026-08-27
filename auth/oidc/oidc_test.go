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

// stubValidate は idtoken.Validate を差し替え、指定した email を持つ
// 検証済みペイロードを返します。err が非 nil ならそれを返します。
func stubValidate(email string, err error) validateFunc {
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

func TestVerifierConfigured(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		verifier *Verifier
		want     bool
	}{
		{name: "nil verifier", verifier: nil, want: false},
		{name: "audience and allowlist", verifier: New(testAudience, []string{testAccount}), want: true},
		// 許可リストが空の場合は fail-closed のため未設定として扱います。
		{name: "empty allowlist", verifier: New(testAudience, nil), want: false},
		{name: "blank entries only", verifier: New(testAudience, []string{"", "  "}), want: false},
		{name: "missing audience", verifier: New("  ", []string{testAccount}), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.verifier.Configured(); got != tt.want {
				t.Fatalf("Configured() = %v, want %v", got, tt.want)
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
		validate validateFunc
		wantErr  error // errors.Is で比較。nil なら成功を期待する
	}{
		{
			name:     "許可済みサービスアカウントは通過する",
			allowed:  []string{testAccount},
			authz:    "Bearer valid-token",
			validate: stubValidate(testAccount, nil),
		},
		{
			name:     "大文字小文字が違っても許可リストに一致する",
			allowed:  []string{testAccount},
			authz:    "Bearer valid-token",
			validate: stubValidate("Tasks@Project.IAM.gserviceaccount.com", nil),
		},
		{
			name:     "小文字の bearer スキームでも通過する",
			allowed:  []string{testAccount},
			authz:    "bearer valid-token",
			validate: stubValidate(testAccount, nil),
		},
		{
			name:     "許可リストに無いサービスアカウントは拒否する",
			allowed:  []string{testAccount},
			authz:    "Bearer valid-token",
			validate: stubValidate("attacker@evil.iam.gserviceaccount.com", nil),
			wantErr:  errSentinel,
		},
		{
			name:     "署名検証に失敗したら拒否する",
			allowed:  []string{testAccount},
			authz:    "Bearer invalid-token",
			validate: stubValidate("", errors.New("bad signature")),
			wantErr:  errSentinel,
		},
		{
			// 未検証のメールアドレスは所有者であることを保証しません。
			name:    "未検証のメールアドレスは拒否する",
			allowed: []string{testAccount},
			authz:   "Bearer valid-token",
			validate: func(context.Context, string, string) (*idtoken.Payload, error) {
				return &idtoken.Payload{Claims: map[string]any{"email": testAccount, "email_verified": false}}, nil
			},
			wantErr: errSentinel,
		},
		{
			name:    "email クレームが無ければ拒否する",
			allowed: []string{testAccount},
			authz:   "Bearer valid-token",
			validate: func(context.Context, string, string) (*idtoken.Payload, error) {
				return &idtoken.Payload{Subject: "sub", Claims: map[string]any{}}, nil
			},
			wantErr: errSentinel,
		},
		{
			name:    "ペイロードが nil なら拒否する",
			allowed: []string{testAccount},
			authz:   "Bearer valid-token",
			validate: func(context.Context, string, string) (*idtoken.Payload, error) {
				return nil, nil
			},
			wantErr: errSentinel,
		},
		{
			// ブラウザからの呼び出しはここに落ちる。合成側は次の方式へ進む。
			name:     "Authorization ヘッダーが無ければ未着手",
			allowed:  []string{testAccount},
			authz:    "",
			validate: stubValidate(testAccount, nil),
			wantErr:  auth.ErrNotAttempted,
		},
		{
			// 許可リストが空＝設定漏れ。未着手と混ぜるとフォールバックに隠れる。
			name:     "許可リストが空なら未設定",
			allowed:  nil,
			authz:    "Bearer valid-token",
			validate: stubValidate(testAccount, nil),
			wantErr:  auth.ErrNotConfigured,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := New(testAudience, tt.allowed)
			v.validate = tt.validate

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
					t.Fatal("検証済みペイロードがコンテキストに載っていません")
				}
			case errors.Is(tt.wantErr, errSentinel):
				// センチネルを持たない一般の検証失敗。
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

// errSentinel は「センチネルを持たない検証失敗」を表すテスト内の目印です。
var errSentinel = errors.New("verification failure")

// TestVerifierNilReceiver は、未構築の Verifier でも panic しないことを確認します。
func TestVerifierNilReceiver(t *testing.T) {
	t.Parallel()

	var v *Verifier
	if v.Configured() {
		t.Fatal("Configured() = true, want false for a nil verifier")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := v.Authenticate(httptest.NewRecorder(), req); !errors.Is(err, auth.ErrNotConfigured) {
		t.Fatalf("Authenticate() error = %v, want auth.ErrNotConfigured", err)
	}
}

// Challenge は RFC 6750 §3.1 に沿って、トークンの不正（取り直せば直る）と
// 呼び出し元の不許可（取り直しても直らない）を別の応答で伝えます。
// 実際の Authenticate の失敗をそのまま渡して確認します。
func TestVerifierChallenge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		allowed    []string
		authz      string
		validate   validateFunc
		wantStatus int
		wantWWW    string
	}{
		{
			name: "資格情報なし", allowed: []string{testAccount}, authz: "",
			validate:   stubValidate(testAccount, nil),
			wantStatus: http.StatusUnauthorized, wantWWW: "Bearer",
		},
		{
			name: "トークンが不正", allowed: []string{testAccount}, authz: "Bearer bogus",
			validate:   stubValidate("", errors.New("bad signature")),
			wantStatus: http.StatusUnauthorized, wantWWW: `Bearer error="invalid_token"`,
		},
		{
			name: "許可リストに無い呼び出し元", allowed: []string{testAccount}, authz: "Bearer valid",
			validate:   stubValidate("stranger@evil.iam.gserviceaccount.com", nil),
			wantStatus: http.StatusForbidden, wantWWW: `Bearer error="insufficient_scope"`,
		},
		{
			// 設定漏れはサーバー側の落ち度なので、チャレンジは返しません。
			name: "検証器が未設定", allowed: nil, authz: "Bearer valid",
			validate:   stubValidate(testAccount, nil),
			wantStatus: http.StatusInternalServerError, wantWWW: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := New(testAudience, tt.allowed)
			v.validate = tt.validate

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
