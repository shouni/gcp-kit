package auth_test

import (
	"strings"
	"testing"

	"github.com/shouni/gcp-kit/auth"
)

// VerifiedEmail は、ID トークンによるログイン・UserInfo API・サービス間検証の
// 3 経路が共有する唯一の判定です。ここが緩むと、緩んだ経路から他人のアドレスを
// 名乗れます。クレームは外から与えられた JSON なので、型が想定どおりである保証は
// 無く、想定外はすべて拒否側へ倒れる必要があります。
func TestVerifiedEmail(t *testing.T) {
	t.Parallel()

	const addr = "user@example.com"

	tests := []struct {
		name    string
		claims  map[string]any
		want    string
		wantErr string // エラーに含まれるべき語
	}{
		{
			name:   "検証済みなら通す",
			claims: map[string]any{"email": addr, "email_verified": true},
			want:   addr,
		},
		{
			name:    "未検証は拒否",
			claims:  map[string]any{"email": addr, "email_verified": false},
			wantErr: "not verified",
		},
		{
			// クレームが欠けているのは「検証済み」ではありません。
			name:    "email_verified が無い場合は拒否",
			claims:  map[string]any{"email": addr},
			wantErr: "not verified",
		},
		{
			// JSON の値が bool でなく文字列で来ることがあります。真偽値として
			// 解釈しにいくと "false" まで真になりうるため、型が違えば拒否します。
			name:    "email_verified が文字列なら拒否",
			claims:  map[string]any{"email": addr, "email_verified": "true"},
			wantErr: "not verified",
		},
		{
			name:    "email_verified が数値なら拒否",
			claims:  map[string]any{"email": addr, "email_verified": 1},
			wantErr: "not verified",
		},
		{
			name:    "email が無い場合は拒否",
			claims:  map[string]any{"email_verified": true},
			wantErr: "no email claim",
		},
		{
			// 空文字を通すと、許可リストの照合に空のアドレスが渡ります。
			name:    "email が空文字なら拒否",
			claims:  map[string]any{"email": "", "email_verified": true},
			wantErr: "no email claim",
		},
		{
			name:    "email が文字列でないなら拒否",
			claims:  map[string]any{"email": 12345, "email_verified": true},
			wantErr: "no email claim",
		},
		{
			name:    "クレームが nil なら拒否",
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
