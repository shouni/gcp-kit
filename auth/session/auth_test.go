package session

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// validTestConfig returns the smallest valid Config, with only the required fields filled.
func validTestConfig() Config {
	return Config{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		ServiceURL:   "https://example.com",
		SessionName:  "session",
		Store:        newTestStore(),
	}
}

func TestNewHandlerValidatesConfig(t *testing.T) {
	t.Parallel()

	// Builds a Config missing exactly one required field.
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
			name: "relative service url",
			cfg:  without(func(c *Config) { c.ServiceURL = "/app" }),
		},
		{
			// Allowing a path would let it reach the redirect URL but not the route matching in Routes.
			name: "service url with a path",
			cfg:  without(func(c *Config) { c.ServiceURL = "https://example.com/app" }),
		},
		{
			name: "missing session name",
			cfg:  without(func(c *Config) { c.SessionName = "" }),
		},
		{
			// The store has no default. Letting this through would silently fall
			// back to an in-process implementation, logging users out every time
			// the instance changes.
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

// TestValidateConfigErrorIsDeterministic checks that the error for several
// empty fields does not change between runs (does not depend on map iteration
// order).
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

// TestRedirectURLFollowsCallbackPath checks that the OAuth redirect URL is
// built from ServiceURL and callbackPath(). When callers built it, changing
// WithPaths could leave the redirect URL alone on the old value.
func TestRedirectURLFollowsCallbackPath(t *testing.T) {
	t.Parallel()

	h, err := New(validTestConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := h.oauthConfig.RedirectURL; got != "https://example.com"+DefaultCallbackPath {
		t.Fatalf("RedirectURL = %q, want ServiceURL + DefaultCallbackPath", got)
	}

	h, err = New(validTestConfig(), WithPaths("", "/signin/callback", ""))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := h.oauthConfig.RedirectURL; got != "https://example.com/signin/callback" {
		t.Fatalf("RedirectURL = %q, want the WithPaths callback", got)
	}
}

// TestSecureCookieFollowsScheme checks that the Secure attribute is decided by
// ServiceURL's scheme alone. Setting Secure on non-TLS traffic protects
// nothing, and over http on a development machine some browsers discard the
// cookie.
func TestSecureCookieFollowsScheme(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		serviceURL string
		want       bool
	}{
		{"https://example.com", true},
		{"HTTPS://example.com", true},
		{"http://localhost:8080", false},
		{"http://example.com", false},
	} {
		cfg := validTestConfig()
		cfg.ServiceURL = tt.serviceURL
		h, err := New(cfg)
		if err != nil {
			t.Fatalf("New(%q) error = %v", tt.serviceURL, err)
		}
		if h.isSecureCookie != tt.want {
			t.Errorf("ServiceURL %q: secure = %v, want %v", tt.serviceURL, h.isSecureCookie, tt.want)
		}
	}
}

// TestNewRejectsCollidingPaths checks that New stops a configuration giving
// the same path two roles. Getting as far as Routes would make http.ServeMux
// panic.
func TestNewRejectsCollidingPaths(t *testing.T) {
	t.Parallel()

	if _, err := New(validTestConfig(), WithPaths("/auth", "/auth", "")); err == nil {
		t.Fatal("New() error = nil, want an error for login and callback sharing a path")
	}
	if _, err := New(validTestConfig(), WithPaths("auth/login", "", "")); err == nil {
		t.Fatal("New() error = nil, want an error for a path without a leading slash")
	}
}

// TestRoutes checks that Routes serves the three handlers on the configured
// paths and methods. Mounted under a prefix, it still matches on the full
// path.
func TestRoutes(t *testing.T) {
	t.Parallel()

	h, err := New(validTestConfig(), WithPaths("/signin", "/signin/callback", "/signout"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	routes := h.Routes()

	for _, tt := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/signin", http.StatusTemporaryRedirect},   // to Google
		{http.MethodPost, "/signin", http.StatusMethodNotAllowed},   // GET only
		{http.MethodGet, "/signin/callback", http.StatusBadRequest}, // no state
		{http.MethodGet, "/signout", http.StatusSeeOther},           // to login
		{http.MethodPost, "/signout", http.StatusSeeOther},          // any method
		{http.MethodGet, DefaultLoginPath, http.StatusNotFound},     // the default path is not registered
	} {
		rr := newRecorderForCookies()
		routes.ServeHTTP(rr, newRequestForRoutes(tt.method, tt.path))
		if rr.Code != tt.want {
			t.Errorf("%s %s = %d, want %d", tt.method, tt.path, rr.Code, tt.want)
		}
	}
}

// TestCallbackPathDrivesStateCookiePath checks that changing CallbackPath
// moves the Path of the state/PKCE cookies too (if they do not match, the
// cookies are not sent on the callback and login always fails).
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

// Logout clears the session and answers 303 to the login page.
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
