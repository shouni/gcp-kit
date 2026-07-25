package auth

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

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

// TestValidateConfigTaskAudienceRequiresAllowlist は、Cloud Tasks 検証の設定漏れを
// 起動時に落とすことを保証します。リクエスト時に 403 を返すと、Cloud Tasks が
// リトライを重ねた末にタスクを破棄してしまうためです。
func TestValidateConfigTaskAudienceRequiresAllowlist(t *testing.T) {
	t.Parallel()

	t.Run("audience without allowlist is rejected", func(t *testing.T) {
		t.Parallel()
		cfg := validTestConfig()
		cfg.TaskAudienceURL = "https://worker.example.com"

		_, err := NewHandler(cfg)
		if err == nil {
			t.Fatal("NewHandler() error = nil, want error")
		}
		if !strings.Contains(err.Error(), "AllowedTaskServiceAccounts") {
			t.Fatalf("error = %v, want it to mention AllowedTaskServiceAccounts", err)
		}
	})

	t.Run("blank allowlist entries are rejected", func(t *testing.T) {
		t.Parallel()
		cfg := validTestConfig()
		cfg.TaskAudienceURL = "https://worker.example.com"
		cfg.AllowedTaskServiceAccounts = []string{"", "   "}

		if _, err := NewHandler(cfg); err == nil {
			t.Fatal("NewHandler() error = nil, want error")
		}
	})

	t.Run("audience with allowlist is accepted", func(t *testing.T) {
		t.Parallel()
		cfg := validTestConfig()
		cfg.TaskAudienceURL = "https://worker.example.com"
		cfg.AllowedTaskServiceAccounts = []string{"tasks@project.iam.gserviceaccount.com"}

		h, err := NewHandler(cfg)
		if err != nil {
			t.Fatalf("NewHandler() error = %v", err)
		}
		if !h.taskVerifier.configured() {
			t.Fatal("task verifier is not configured")
		}
	})

	t.Run("no audience means task verification is unused", func(t *testing.T) {
		t.Parallel()
		h, err := NewHandler(validTestConfig())
		if err != nil {
			t.Fatalf("NewHandler() error = %v", err)
		}
		if h.taskVerifier != nil {
			t.Fatal("task verifier should be nil when TaskAudienceURL is unset")
		}
	})
}

func TestValidateConfigRejectsShortAuthKey(t *testing.T) {
	t.Parallel()

	cfg := validTestConfig()
	cfg.SessionAuthKey = "too-short"

	if _, err := NewHandler(cfg); err == nil {
		t.Fatal("NewHandler() error = nil, want error for a short SessionAuthKey")
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

	cfg := validTestConfig()
	h, err := NewHandler(cfg)
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
