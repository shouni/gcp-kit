package negotiate_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shouni/gcp-kit/negotiate"
)

func TestWantsJSON(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		want   bool
	}{
		{"JSON を明示していれば true", "application/json", true},
		{"charset 付きでも true", "application/json; charset=utf-8", true},
		{"大文字でも true", "Application/JSON", true},
		{"ブラウザの Accept は false", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", false},
		{"curl の既定 */* は false", "*/*", false},
		{"Accept なしは false", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			rec := httptest.NewRecorder()

			if got := negotiate.WantsJSON(rec, req); got != tt.want {
				t.Errorf("WantsJSON() = %v, want %v", got, tt.want)
			}
			// 判定の結果によらず Vary は必ず立つ。
			if got := rec.Header().Get("Vary"); got != "Accept" {
				t.Errorf("Vary = %q, want %q", got, "Accept")
			}
		})
	}
}

// 判定と Vary を 1 つの関数にまとめている意図の確認。
// w を渡さずに判定だけを行う経路でも panic しないこと。
func TestWantsJSON_NilArgs(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "application/json")

	if got := negotiate.WantsJSON(nil, req); !got {
		t.Error("WantsJSON(nil, req) = false, want true")
	}
	if got := negotiate.WantsJSON(httptest.NewRecorder(), nil); got {
		t.Error("WantsJSON(w, nil) = true, want false")
	}
}

func TestAddVaryAccept(t *testing.T) {
	t.Run("重複して追加しないこと", func(t *testing.T) {
		h := http.Header{}
		negotiate.AddVaryAccept(h)
		negotiate.AddVaryAccept(h)

		if got := h.Values("Vary"); len(got) != 1 || got[0] != "Accept" {
			t.Errorf("Vary = %v, want [Accept]", got)
		}
	})

	// 他のヘッダーで既に Vary が立っている場合は、Accept を足す。
	t.Run("既存の Vary を壊さないこと", func(t *testing.T) {
		h := http.Header{}
		h.Add("Vary", "Origin")
		negotiate.AddVaryAccept(h)

		got := h.Values("Vary")
		if len(got) != 2 || got[0] != "Origin" || got[1] != "Accept" {
			t.Errorf("Vary = %v, want [Origin Accept]", got)
		}
	})

	// カンマ区切りで既に含まれている場合は追加しない。
	t.Run("カンマ区切りの既存値も検出すること", func(t *testing.T) {
		h := http.Header{}
		h.Add("Vary", "Origin, accept")
		negotiate.AddVaryAccept(h)

		if got := h.Values("Vary"); len(got) != 1 {
			t.Errorf("Vary = %v, want 追加されないこと", got)
		}
	})

	t.Run("nil でも panic しないこと", func(_ *testing.T) {
		negotiate.AddVaryAccept(nil)
	})
}
