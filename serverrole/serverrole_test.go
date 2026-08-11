package serverrole

import (
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
