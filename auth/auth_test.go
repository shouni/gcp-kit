package auth

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

// validTestConfig は、必須項目だけを埋めた最小の有効な Config を返します。
func validTestConfig() Config {
	return Config{
		ClientID:          "client-id",
		ClientSecret:      "client-secret",
		RedirectURL:       "https://example.com/auth/callback",
		SessionAuthKey:    "1234567890123456",
		SessionEncryptKey: "1234567890123456",
		SessionName:       "session",
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
			// 署名キーは16バイト以上が必要です。
			name: "short auth key",
			cfg:  without(func(c *Config) { c.SessionAuthKey = "too-short" }),
		},
		{
			// 暗号化キーは 16/24/32 バイトのいずれかである必要があります。
			name: "invalid encrypt key length",
			cfg:  without(func(c *Config) { c.SessionEncryptKey = "12345678901234567" }),
		},
	}

	if _, err := NewHandler(validTestConfig()); err != nil {
		t.Fatalf("NewHandler(valid) returned error: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewHandler(tt.cfg); err == nil {
				t.Fatalf("NewHandler() error = nil, want error")
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

	h, err := NewHandler(validTestConfig())
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	if h.LoginPath() != DefaultLoginPath {
		t.Fatalf("LoginPath() = %q, want %q", h.LoginPath(), DefaultLoginPath)
	}
	if h.CallbackPath() != DefaultCallbackPath {
		t.Fatalf("CallbackPath() = %q, want %q", h.CallbackPath(), DefaultCallbackPath)
	}
	if h.LogoutPath() != DefaultLogoutPath {
		t.Fatalf("LogoutPath() = %q, want %q", h.LogoutPath(), DefaultLogoutPath)
	}
	if h.stateCookieMaxAge() != int(defaultStateMaxAge.Seconds()) {
		t.Fatalf("stateCookieMaxAge() = %d, want %d", h.stateCookieMaxAge(), int(defaultStateMaxAge.Seconds()))
	}

	store, ok := h.store.(*sessions.CookieStore)
	if !ok {
		t.Fatalf("store type = %T, want *sessions.CookieStore", h.store)
	}
	if store.Options.MaxAge != int(defaultSessionMaxAge.Seconds()) {
		t.Fatalf("session MaxAge = %d, want %d", store.Options.MaxAge, int(defaultSessionMaxAge.Seconds()))
	}
	if len(h.oauthConfig.Scopes) != len(defaultScopes) {
		t.Fatalf("Scopes = %v, want %v", h.oauthConfig.Scopes, defaultScopes)
	}
}

func TestConfigOverrides(t *testing.T) {
	t.Parallel()

	cfg := validTestConfig()
	cfg.LoginPath = "/signin"
	cfg.CallbackPath = "/signin/callback"
	cfg.LogoutPath = "/signout"
	cfg.SessionMaxAge = time.Hour
	cfg.StateMaxAge = 5 * time.Minute
	cfg.Scopes = []string{"openid"}

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	if h.LoginPath() != "/signin" || h.CallbackPath() != "/signin/callback" || h.LogoutPath() != "/signout" {
		t.Fatalf("paths = %q/%q/%q", h.LoginPath(), h.CallbackPath(), h.LogoutPath())
	}
	if h.stateCookieMaxAge() != 300 {
		t.Fatalf("stateCookieMaxAge() = %d, want 300", h.stateCookieMaxAge())
	}
	store := h.store.(*sessions.CookieStore)
	if store.Options.MaxAge != 3600 {
		t.Fatalf("session MaxAge = %d, want 3600", store.Options.MaxAge)
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

	cfg := validTestConfig()
	cfg.CallbackPath = "/signin/callback"

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	rr := newRecorderForCookies()
	h.setTemporaryCookie(rr, DefaultStateCookie, "value")

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Path != "/signin/callback" {
		t.Fatalf("state cookie path = %+v, want /signin/callback", cookies)
	}
}

func TestConfigStoreInjection(t *testing.T) {
	t.Parallel()

	cfg := validTestConfig()
	injected := newTestCookieStore()
	cfg.Store = injected

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	if h.store != sessions.Store(injected) {
		t.Fatal("NewHandler() did not use the injected store")
	}
}

func TestRoutes(t *testing.T) {
	t.Parallel()

	h, err := NewHandler(validTestConfig())
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	routes := h.Routes()

	// ログアウトはセッションを破棄してログインページへ 303 を返します。
	req := newRequestForRoutes(http.MethodGet, DefaultLogoutPath)
	rr := newRecorderForCookies()
	routes.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusSeeOther)
	}
	if loc := rr.Header().Get("Location"); loc != DefaultLoginPath {
		t.Fatalf("Location = %q, want %q", loc, DefaultLoginPath)
	}
}
