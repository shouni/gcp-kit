package oidc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzExtractBearerToken checks that parsing the Authorization header never
// panics, and that an accepted token keeps no "Bearer " prefix or surrounding
// whitespace.
func FuzzExtractBearerToken(f *testing.F) {
	for _, seed := range []string{"Bearer abc", "bearer abc", "BEARER  abc  ", "Basic abc", "Bearer", "", "Bearer\tabc"} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, header string) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", header)

		token, ok := extractBearerToken(req)

		// A header that was Set may be normalised, so judge by the value that actually arrives.
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

		// The token itself can be any string, but the scheme is always removed
		// and no surrounding whitespace remains.
		if want := strings.TrimSpace(received[len(prefix):]); token != want {
			t.Fatalf("extractBearerToken(%q) = %q, want %q", received, token, want)
		}
		if token != strings.TrimSpace(token) {
			t.Fatalf("extractBearerToken(%q) = %q, which is not trimmed", received, token)
		}
	})
}
