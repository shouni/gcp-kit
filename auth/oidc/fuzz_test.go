package oidc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzExtractBearerToken は、Authorization ヘッダーの解析がパニックせず、
// 受理したトークンに "Bearer " プレフィックスや前後の空白が残らないことを検証します。
func FuzzExtractBearerToken(f *testing.F) {
	for _, seed := range []string{"Bearer abc", "bearer abc", "BEARER  abc  ", "Basic abc", "Bearer", "", "Bearer\tabc"} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, header string) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", header)

		token, ok := extractBearerToken(req)

		// Set したヘッダーは正規化され得るため、実際に届く値を基準に判定します。
		const prefix = "Bearer "
		received := req.Header.Get("Authorization")
		wantOK := len(received) >= len(prefix) && strings.EqualFold(received[:len(prefix)], prefix)

		if ok != wantOK {
			t.Fatalf("extractBearerToken(%q) ok = %v, want %v", received, ok, wantOK)
		}
		if !ok {
			if token != "" {
				t.Fatalf("extractBearerToken(%q) = (%q, false), want an empty token when not ok", received, token)
			}
			return
		}

		// トークン本体は任意の文字列であり得ますが、スキーム部分は必ず取り除かれ、
		// 前後の空白も残りません。
		if want := strings.TrimSpace(received[len(prefix):]); token != want {
			t.Fatalf("extractBearerToken(%q) = %q, want %q", received, token, want)
		}
		if token != strings.TrimSpace(token) {
			t.Fatalf("extractBearerToken(%q) = %q, which is not trimmed", received, token)
		}
	})
}
