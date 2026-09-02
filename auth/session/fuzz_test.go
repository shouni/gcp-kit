package session

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// FuzzBuildLoginRedirectURL は、オープンリダイレクタ脆弱性の不変条件を検証します。
// どんな入力に対しても、生成されるリダイレクト先はログインパスで始まる相対URLであり、
// 外部ホストへ遷移させてはいけません。
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
		// httptest.NewRequest は不正なターゲットでパニックするため、
		// リクエストとして成立するものだけを対象にします。
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
		// "//host" 形式はブラウザにスキーマ相対URLとして解釈されます。
		if strings.HasPrefix(got, "//") {
			t.Fatalf("buildLoginRedirectURL(%q) = %q, which is protocol-relative", target, got)
		}
	})
}

// FuzzIsSafeRelativePath は、リダイレクト先として受理した文字列が
// 常に同一オリジンの相対パスであることを検証します。
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
		// バックスラッシュを '/' と正規化するブラウザでは "/\host" が
		// スキーマ相対 URL として解釈されます。
		if strings.ContainsRune(target, '\\') {
			t.Fatalf("isSafeRelativePath(%q) = true, but it contains a backslash", target)
		}
	})
}

// TestIsSafeRelativePath は、リダイレクト先の判定を代表的な入力で固定します。
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
		// バックスラッシュを '/' に正規化するブラウザ向けの防御。
		{target: `/\evil.com`, want: false},
		{target: `\\evil.com`, want: false},
		// 制御文字はヘッダー分割の材料になり得ます。
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

// TestLoginRejectsBackslashRedirect は、Login が "/\evil.com" のような
// リダイレクト先をセッションに保存しないことを確認します。
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

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rr.Result().Cookies() {
		req2.AddCookie(c)
	}
	session, err := h.store.Get(req2, h.sessionName)
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if got, ok := session.Values[DefaultRedirectSessionKey]; ok {
		t.Fatalf("redirect target %v was saved, want none", got)
	}
}
