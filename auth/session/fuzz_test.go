package session

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// FuzzBuildLoginRedirectURL checks the open-redirect invariant. For any input,
// the generated redirect must be a relative URL starting with the login path
// and must never lead to an external host.
func FuzzBuildLoginRedirectURL(f *testing.F) {
	seeds := []string{
		"/private?x=1",
		"/",
		"//evil.com",
		"///evil.com",
		"/\\evil.com",
		"https://evil.com/x",
		"/private#fragment",
		"/private?redirect_to=//evil.com",
		"/%2f%2fevil.com",
		"/private?x=%00",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	h := &Handler{}

	f.Fuzz(func(t *testing.T, target string) {
		// httptest.NewRequest panics on an invalid target, so only inputs
		// that form a valid request are used.
		req, err := http.NewRequest(http.MethodGet, "http://example.com"+target, nil)
		if err != nil {
			t.Skip()
		}

		got := h.buildLoginRedirectURL(req)

		if !strings.HasPrefix(got, DefaultLoginPath) {
			t.Fatalf("buildLoginRedirectURL(%q) = %q, want a %q prefix", target, got, DefaultLoginPath)
		}

		parsed, err := url.Parse(got)
		if err != nil {
			t.Fatalf("buildLoginRedirectURL(%q) = %q, which does not parse: %v", target, got, err)
		}
		if parsed.Scheme != "" || parsed.Host != "" {
			t.Fatalf("buildLoginRedirectURL(%q) = %q, which points off-origin", target, got)
		}
		// Browsers read the "//host" form as a scheme-relative URL.
		if strings.HasPrefix(got, "//") {
			t.Fatalf("buildLoginRedirectURL(%q) = %q, which is protocol-relative", target, got)
		}
	})
}

// FuzzIsSafeRelativePath checks that a string accepted as a redirect target is
// always a same-origin relative path.
func FuzzIsSafeRelativePath(f *testing.F) {
	for _, seed := range []string{"/ok", "//evil.com", "https://evil.com", "", "/", "\\/evil.com", "/\\evil.com", "/a\r\nSet-Cookie: x=1"} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, target string) {
		if !isSafeRelativePath(target) {
			return
		}

		parsed, err := url.Parse(target)
		if err != nil {
			t.Fatalf("isSafeRelativePath(%q) = true, but it does not parse: %v", target, err)
		}
		if parsed.Scheme != "" || parsed.Host != "" {
			t.Fatalf("isSafeRelativePath(%q) = true, but it points off-origin", target)
		}
		if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
			t.Fatalf("isSafeRelativePath(%q) = true, but it is not a plain absolute path", target)
		}
		// Browsers that normalise a backslash to '/' read "/\host" as a
		// scheme-relative URL.
		if strings.ContainsRune(target, '\\') {
			t.Fatalf("isSafeRelativePath(%q) = true, but it contains a backslash", target)
		}
	})
}

// TestIsSafeRelativePath pins the redirect-target check on representative inputs.
func TestIsSafeRelativePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		target string
		want   bool
	}{
		{target: "/private", want: true},
		{target: "/private?x=1&y=2", want: true},
		{target: "/private#frag", want: true},
		{target: "/", want: true},
		{target: "", want: false},
		{target: "private", want: false},
		{target: "//evil.com", want: false},
		{target: "///evil.com", want: false},
		{target: "https://evil.com/x", want: false},
		// Defence against browsers that normalise a backslash to '/'.
		{target: `/\evil.com`, want: false},
		{target: `\\evil.com`, want: false},
		// Control characters can be material for header splitting.
		{target: "/a\r\nSet-Cookie: x=1", want: false},
		{target: "/a\nb", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			t.Parallel()
			if got := isSafeRelativePath(tt.target); got != tt.want {
				t.Fatalf("isSafeRelativePath(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

// TestLoginRejectsBackslashRedirect checks that Login never puts a redirect
// target like "/\evil.com" into the return-target cookie.
func TestLoginRejectsBackslashRedirect(t *testing.T) {
	t.Parallel()

	h := &Handler{
		oauthConfig: &oauth2.Config{ClientID: "client-id"},
		store:       newTestStore(),
		sessionName: "test-session",
	}

	req := httptest.NewRequest(http.MethodGet, `/auth/login?redirect_to=/\evil.com`, nil)
	rr := httptest.NewRecorder()

	h.Login(rr, req)

	for _, c := range rr.Result().Cookies() {
		if c.Name == DefaultRedirectCookie {
			t.Fatalf("redirect target %q was carried, want none", c.Value)
		}
	}
}

// TestRedirectTargetRejectsTamperedCookie checks that a tampered return-target
// cookie still never sends the user to an external site. The other side can
// replace the cookie, so checking on write alone is not enough.
func TestRedirectTargetRejectsTamperedCookie(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		url.QueryEscape("//evil.com"),
		url.QueryEscape(`/\evil.com`),
		url.QueryEscape("https://evil.com/"),
		"%zz",        // a value QueryUnescape fails on
		"//evil.com", // a value not even escaped
	} {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
		req.AddCookie(&http.Cookie{Name: DefaultRedirectCookie, Value: value})

		if got := redirectTarget(req); got != "/" {
			t.Fatalf("redirectTarget(%q) = %q, want \"/\"", value, got)
		}
	}
}
