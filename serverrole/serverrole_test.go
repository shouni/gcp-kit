package serverrole

import (
	"encoding"
	"encoding/json"
	"strings"
	"testing"
)

// 空文字と未知の値を拒否することが、このパッケージの存在意義です。
// 未設定を Both に落とすと、公開している Web 面に Worker のルートが復活します。
func TestParse(t *testing.T) {
	t.Parallel()

	t.Run("有効な値", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			raw  string
			want Role
		}{
			{"both", Both},
			{"web", Web},
			{"worker", Worker},
			// 大文字小文字と前後の空白は正規化する。
			{" WEB ", Web},
			{"Worker", Worker},
		}
		for _, tt := range tests {
			raw, want := tt.raw, tt.want
			got, err := Parse(raw)
			if err != nil {
				t.Errorf("Parse(%q) error = %v", raw, err)
				continue
			}
			if got != want {
				t.Errorf("Parse(%q) = %q, want %q", raw, got, want)
			}
		}
	})

	t.Run("空文字と未知の値はエラー", func(t *testing.T) {
		t.Parallel()
		for _, raw := range []string{"", "   ", "wrker", "all", "true", "batch"} {
			got, err := Parse(raw)
			if err == nil {
				t.Errorf("Parse(%q) = %q, want error", raw, got)
			}
		}
	})

	// 設定した値がエラーメッセージに出ないと、打ち間違いの発見に時間がかかります。
	t.Run("エラーに入力値と候補が出る", func(t *testing.T) {
		t.Parallel()
		_, err := Parse("wrker")
		if err == nil {
			t.Fatal("Parse(\"wrker\") = nil error, want error")
		}
		for _, want := range []string{`"wrker"`, string(Web), string(Worker), string(Both)} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), want)
			}
		}
	})
}

func TestRoleServes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		role       Role
		servesWeb  bool
		servesWork bool
	}{
		{Both, true, true},
		{Web, true, false},
		{Worker, false, true},
		// 利用側が足した独自の役割は、キットが知る2面のどちらも提供しません。
		{Role("batch"), false, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			t.Parallel()
			if got := tt.role.ServesWeb(); got != tt.servesWeb {
				t.Errorf("ServesWeb() = %v, want %v", got, tt.servesWeb)
			}
			if got := tt.role.ServesWorker(); got != tt.servesWork {
				t.Errorf("ServesWorker() = %v, want %v", got, tt.servesWork)
			}
		})
	}
}

// TestRoleUnmarshalText は、デコードの時点で Parse の厳しさが効くことを検証します。
//
// 各アプリは env タグで Role を直接受けているため、ここで弾けないと
// 未知の値がそのまま Role に入り、起動はするがどのルートも提供しない
// サービスができあがります。
func TestRoleUnmarshalText(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		want    Role
		wantErr bool
	}{
		{name: "既知の値", text: "worker", want: Worker},
		{name: "大文字と空白は正規化する", text: "  Web  ", want: Web},
		{name: "空はエラー", text: "", wantErr: true},
		{name: "未知の値はエラー", text: "api", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var role Role
			err := role.UnmarshalText([]byte(tt.text))

			if tt.wantErr {
				if err == nil {
					t.Fatalf("UnmarshalText(%q) = nil, want エラー", tt.text)
				}
				// 失敗しても値を書き換えない（呼び出し側がゼロ値のまま扱える）。
				if role != "" {
					t.Errorf("エラー時に role = %q が入っています", role)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalText(%q) = %v", tt.text, err)
			}
			if role != tt.want {
				t.Errorf("role = %q, want %q", role, tt.want)
			}
		})
	}
}

// TestRoleImplementsTextUnmarshaler は、デコーダが実際にこの経路を通ることを固定します。
// encoding/json は encoding.TextUnmarshaler を見て呼び分けるため、
// caarlos0/env（各アプリが使っている）も同じ判定で通ります。
func TestRoleImplementsTextUnmarshaler(t *testing.T) {
	var _ encoding.TextUnmarshaler = (*Role)(nil)

	var cfg struct {
		Role Role `json:"role"`
	}
	if err := json.Unmarshal([]byte(`{"role":"WORKER"}`), &cfg); err != nil {
		t.Fatalf("Unmarshal = %v", err)
	}
	if cfg.Role != Worker {
		t.Errorf("role = %q, want %q", cfg.Role, Worker)
	}

	if err := json.Unmarshal([]byte(`{"role":"api"}`), &cfg); err == nil {
		t.Error("未知の値がデコードで通ってしまいました")
	}
}
