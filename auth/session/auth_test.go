package session

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// validTestConfig は、必須項目だけを埋めた最小の有効な Config を返します。
func validTestConfig() Config {
	return Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://example.com/auth/callback",
		SessionName:  "session",
		Store:        newTestStore(),
	}
}

func TestNewHandlerValidatesConfig(t *testing.T) {
	t.Parallel()

	// 必須項目を1つだけ欠いた Config を作ります。
	without := func(invalidate func(*Config)) Config {
		cfg := validTestConfig()
		invalidate(&cfg)
		return cfg
	}

	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "missing client id",
			cfg:  without(func(c *Config) { c.ClientID = "" }),
		},
		{
			name: "missing client secret",
			cfg:  without(func(c *Config) { c.ClientSecret = "" }),
		},
		{
			name: "relative redirect url",
			cfg:  without(func(c *Config) { c.RedirectURL = "/auth/callback" }),
		},
		{
			name: "missing session name",
			cfg:  without(func(c *Config) { c.SessionName = "" }),
		},
		{
			// 保存先に既定は置きません。通すと、プロセス内に持つ実装へ黙って倒れ、
			// インスタンスが替わるたびに利用者がログアウトされます。
			name: "missing store",
			cfg:  without(func(c *Config) { c.Store = nil }),
		},
	}

	if _, err := New(validTestConfig()); err != nil {
		t.Fatalf("New(valid) returned error: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(tt.cfg); err == nil {
				t.Fatalf("New() error = nil, want error")
			}
		})
	}
}

// TestValidateConfigErrorIsDeterministic は、複数フィールドが空のときのエラーが
// 実行ごとに変わらないこと（map 反復順に依存しないこと）を確認します。
func TestValidateConfigErrorIsDeterministic(t *testing.T) {
	t.Parallel()

	cfg := Config{}
	first := validateConfig(cfg).Error()
	for range 50 {
		if got := validateConfig(cfg).Error(); got != first {
			t.Fatalf("validateConfig() error = %q, want the stable %q", got, first)
		}
	}
	if !strings.Contains(first, "ClientID") {
		t.Fatalf("error = %q, want the first declared field (ClientID)", first)
	}
}

func TestConfigDefaults(t *testing.T) {
	t.Parallel()

	h, err := New(validTestConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if h.loginPath() != DefaultLoginPath {
		t.Fatalf("LoginPath() = %q, want %q", h.loginPath(), DefaultLoginPath)
	}
	if h.callbackPath() != DefaultCallbackPath {
		t.Fatalf("CallbackPath() = %q, want %q", h.callbackPath(), DefaultCallbackPath)
	}
	if h.logoutPath() != DefaultLogoutPath {
		t.Fatalf("LogoutPath() = %q, want %q", h.logoutPath(), DefaultLogoutPath)
	}
	if h.stateCookieMaxAge() != int(defaultStateMaxAge.Seconds()) {
		t.Fatalf("stateCookieMaxAge() = %d, want %d", h.stateCookieMaxAge(), int(defaultStateMaxAge.Seconds()))
	}

	if len(h.oauthConfig.Scopes) != len(defaultScopes) {
		t.Fatalf("Scopes = %v, want %v", h.oauthConfig.Scopes, defaultScopes)
	}
}

func TestOptionOverrides(t *testing.T) {
	t.Parallel()

	h, err := New(validTestConfig(),
		WithPaths("/signin", "/signin/callback", "/signout"),
		WithStateMaxAge(5*time.Minute),
		WithScopes("openid"),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if h.loginPath() != "/signin" || h.callbackPath() != "/signin/callback" || h.logoutPath() != "/signout" {
		t.Fatalf("paths = %q/%q/%q", h.loginPath(), h.callbackPath(), h.logoutPath())
	}
	if h.stateCookieMaxAge() != 300 {
		t.Fatalf("stateCookieMaxAge() = %d, want 300", h.stateCookieMaxAge())
	}
	if len(h.oauthConfig.Scopes) != 1 {
		t.Fatalf("Scopes = %v, want [openid]", h.oauthConfig.Scopes)
	}
}

// TestCallbackPathDrivesStateCookiePath は、CallbackPath を変えると state/PKCE
// クッキーの Path も追随することを確認します（一致していないとコールバック時に
// クッキーが送信されず、ログインが必ず失敗します）。
func TestCallbackPathDrivesStateCookiePath(t *testing.T) {
	t.Parallel()

	h, err := New(validTestConfig(), WithPaths("", "/signin/callback", ""))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	rr := newRecorderForCookies()
	h.setTemporaryCookie(rr, DefaultStateCookie, "value")

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Path != "/signin/callback" {
		t.Fatalf("state cookie path = %+v, want /signin/callback", cookies)
	}
}

func TestStoreInjection(t *testing.T) {
	t.Parallel()

	injected := newTestStore()
	cfg := validTestConfig()
	cfg.Store = injected

	h, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if h.store != injected {
		t.Fatal("New() did not use the configured store")
	}
}

// ログアウトはセッションを破棄してログインページへ 303 を返します。
// Routes() は廃止したため、利用側と同じくハンドラーを直接叩いて確認します。
func TestLogoutRedirectsToLogin(t *testing.T) {
	t.Parallel()

	h, err := New(validTestConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := newRequestForRoutes(http.MethodGet, DefaultLogoutPath)
	rr := newRecorderForCookies()
	h.Logout(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusSeeOther)
	}
	if loc := rr.Header().Get("Location"); loc != DefaultLoginPath {
		t.Fatalf("Location = %q, want %q", loc, DefaultLoginPath)
	}
}
