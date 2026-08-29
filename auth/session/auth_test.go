package session

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

// validTestConfig は、必須項目だけを埋めた最小の有効な Config を返します。
func validTestConfig() Config {
	return Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://example.com/auth/callback",
		SessionKeys: []SessionKey{{
			Auth:    []byte("1234567890123456"),
			Encrypt: []byte("1234567890123456"),
		}},
		SessionName: "session",
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
			// 鍵が 1 組も無いと、鍵の無い CookieStore が出来上がります。
			name: "no session keys",
			cfg:  without(func(c *Config) { c.SessionKeys = nil }),
		},
		{
			// 署名キーは16バイト以上が必要です。
			name: "short auth key",
			cfg:  without(func(c *Config) { c.SessionKeys[0].Auth = []byte("too-short") }),
		},
		{
			// 暗号化キーは 16/24/32 バイトのいずれかである必要があります。
			name: "invalid encrypt key length",
			cfg:  without(func(c *Config) { c.SessionKeys[0].Encrypt = []byte("12345678901234567") }),
		},
		{
			// 検証は先頭だけでなく全ての組に掛かります。旧鍵が壊れていると、
			// 鍵の入れ替え中にだけ復号が失敗する、という形で現れます。
			name: "invalid rotated key",
			cfg: without(func(c *Config) {
				c.SessionKeys = append(c.SessionKeys, SessionKey{Auth: []byte("short"), Encrypt: []byte("1234567890123456")})
			}),
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

func TestOptionOverrides(t *testing.T) {
	t.Parallel()

	h, err := New(validTestConfig(),
		WithPaths("/signin", "/signin/callback", "/signout"),
		WithSessionMaxAge(time.Hour),
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

	injected := newTestCookieStore()

	h, err := New(validTestConfig(), WithStore(injected))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if h.store != sessions.Store(injected) {
		t.Fatal("New() did not use the injected store")
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

// 鍵のローテーション。組を 1 つしか渡せないと、鍵を変えた瞬間に全利用者が
// 強制ログアウトになります。旧鍵を残せる形になっていることを押さえます。
func TestSessionKeyRotation(t *testing.T) {
	t.Parallel()

	oldKey := SessionKey{Auth: []byte("old-auth-key-01234567890"), Encrypt: []byte("old-encrypt-key-")}
	newKey := SessionKey{Auth: []byte("new-auth-key-01234567890"), Encrypt: []byte("new-encrypt-key-")}

	handlerWith := func(t *testing.T, keys ...SessionKey) *Handler {
		t.Helper()
		cfg := validTestConfig()
		cfg.SessionKeys = keys
		cfg.AllowedDomains = []string{"example.com"}
		h, err := New(cfg)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		return h
	}

	// issue は、その鍵構成で発行されたセッションクッキーを返します。
	issue := func(t *testing.T, h *Handler) *http.Cookie {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		sess, err := h.store.Get(req, h.sessionName)
		if err != nil {
			t.Fatalf("store.Get() error = %v", err)
		}
		sess.Values[DefaultUserSessionKey] = "user@example.com"
		if err := sess.Save(req, rec); err != nil {
			t.Fatalf("session.Save() error = %v", err)
		}
		cookies := rec.Result().Cookies()
		if len(cookies) == 0 {
			t.Fatal("セッションクッキーが発行されていません")
		}
		return cookies[0]
	}

	// reads は、その鍵構成でクッキーを認証済みとして読めるかを返します。
	reads := func(t *testing.T, h *Handler, cookie *http.Cookie) bool {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(cookie)
		_, err := h.Authenticate(httptest.NewRecorder(), req)
		return err == nil
	}

	issued := issue(t, handlerWith(t, oldKey))

	// 新鍵を先頭に、旧鍵を残した構成。配布済みのクッキーはまだ読めます。
	if !reads(t, handlerWith(t, newKey, oldKey), issued) {
		t.Error("旧鍵を残しているのに、発行済みのクッキーが読めません")
	}

	// 旧鍵を外した構成では読めません（それが外すという操作の意味です）。
	if reads(t, handlerWith(t, newKey), issued) {
		t.Error("外したはずの旧鍵でクッキーが読めています")
	}

	// 発行に使われるのは先頭の組だけです。これが成り立たないと、旧鍵は
	// いつまでも外せません。
	rotated := issue(t, handlerWith(t, newKey, oldKey))
	if !reads(t, handlerWith(t, newKey), rotated) {
		t.Error("ローテーション後に発行したクッキーが、新鍵だけでは読めません")
	}
}
