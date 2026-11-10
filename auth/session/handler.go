// Package session authenticates people (browsers).
//
// It logs in with Google OAuth2 + PKCE, keeps the login in a server-side
// session, and applies CSRF verification to state-changing requests. Handler
// satisfies auth.Authenticator and auth.Challenger, so it can be passed to
// auth.Protected alongside service-to-service verification (auth/oidc).
//
// The session lives in a Store, and the cookie carries only an opaque ID. So
// there are no session keys to distribute, and logout and revocation actually
// take effect.
//
//	store, err := session.NewFirestoreStore(session.FirestoreConfig{
//		Client: fsClient, Collection: "sessions",
//		StoreConfig: session.StoreConfig{Secure: true},
//	})
//	handler, err := session.New(session.Config{Store: store, ...})
//	r.Use(auth.Protected(verifier, handler))
package session

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	// DefaultUserSessionKey is the session key holding the authenticated user's email address.
	DefaultUserSessionKey = "user_email"
	// DefaultStateCookie is the name of the cookie that temporarily holds the OAuth2 state parameter.
	DefaultStateCookie = "oauth_state"
	// DefaultVerifierCookie is the name of the cookie that temporarily holds the PKCE code_verifier.
	DefaultVerifierCookie = "oauth_verifier"
	// DefaultRedirectCookie is the name of the cookie that temporarily holds
	// where to return after login. It has the same lifetime and Path as the
	// state and verifier cookies and is consumed by the callback.
	DefaultRedirectCookie = "oauth_redirect"

	// DefaultLoginPath is the default path the Login handler is mounted on.
	DefaultLoginPath = "/auth/login"
	// DefaultCallbackPath is the default path the Callback handler is mounted
	// on. It is also the Path attribute of the state and PKCE cookies, so if
	// it does not match the actual mount point, the cookies are not sent on
	// the callback and authentication fails.
	DefaultCallbackPath = "/auth/callback"
	// DefaultLogoutPath is the default path the Logout handler is mounted on.
	DefaultLogoutPath = "/auth/logout"

	googleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"

	defaultSessionMaxAge = 7 * 24 * time.Hour
	defaultStateMaxAge   = 10 * time.Minute
)

// defaultScopes is the minimal set of scopes needed to authorize by email address.
var defaultScopes = []string{
	"openid",
	"https://www.googleapis.com/auth/userinfo.email",
}

// Config holds the required settings of a Handler.
// Optional settings are given as Options (the functions starting with With).
type Config struct {
	ClientID     string
	ClientSecret string

	// ServiceURL is the origin at which browsers see this app (for example
	// https://app.example.com). It cannot carry a path.
	//
	// Two things are derived from it: the OAuth redirect URL
	// (ServiceURL + callbackPath()) and the cookie's Secure attribute (whether
	// the scheme is https). When callers assembled the redirect themselves, the
	// "/auth/callback" literal existed a second time apart from the route
	// registration, and changing WithPaths moved only one of them while the
	// build still passed.
	//
	// Secure is decided by the scheme alone because that is exactly the
	// cookie's question (is it TLS?). "Is http acceptable on a development
	// machine?" is a question about whether a setting is valid, and is decided
	// elsewhere.
	ServiceURL string

	SessionName string

	// Store is where sessions are kept (required).
	//
	// It has no default because there is no default that would work. Kept in
	// the process, users would be logged out every time the Cloud Run instance
	// changed, and during development there is one instance, so nobody would
	// notice. Pass NewFirestoreStore (NewMemoryStore exists for tests and local
	// development).
	Store Store

	AllowedEmails  []string
	AllowedDomains []string
}

type googleUserInfo struct {
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
}

// Handler holds the authentication logic.
type Handler struct {
	oauthConfig    *oauth2.Config
	store          Store
	sessionName    string
	isSecureCookie bool
	allowedEmails  map[string]struct{}
	allowedDomains map[string]struct{}

	cfgLoginPath     string
	cfgCallbackPath  string
	cfgLogoutPath    string
	cfgStateMaxAge   time.Duration
	cfgSessionMaxAge time.Duration
	prompt           Prompt
	logger           *slog.Logger
}

// New builds a Handler from the configuration.
func New(cfg Config, opts ...Option) (*Handler, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	o := newOptions(opts)
	if err := validatePaths(o.loginPath, o.callbackPath, o.logoutPath); err != nil {
		return nil, err
	}

	serviceURL, _ := url.Parse(cfg.ServiceURL) // validateConfig has checked its shape
	redirectURL, err := url.JoinPath(cfg.ServiceURL, o.callbackPath)
	if err != nil {
		return nil, fmt.Errorf("auth config: cannot build the redirect URL: %w", err)
	}

	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       o.scopes,
		Endpoint:     google.Endpoint,
	}
	if len(oauthCfg.Scopes) == 0 {
		oauthCfg.Scopes = defaultScopes
	}

	return &Handler{
		oauthConfig:      oauthCfg,
		store:            cfg.Store,
		sessionName:      cfg.SessionName,
		isSecureCookie:   strings.EqualFold(serviceURL.Scheme, "https"),
		allowedEmails:    toLowerMap(cfg.AllowedEmails),
		allowedDomains:   toLowerMap(cfg.AllowedDomains),
		cfgLoginPath:     o.loginPath,
		cfgCallbackPath:  o.callbackPath,
		cfgLogoutPath:    o.logoutPath,
		cfgStateMaxAge:   o.stateMaxAge,
		cfgSessionMaxAge: o.sessionMaxAge,
		prompt:           o.prompt,
		logger:           o.logger,
	}, nil
}

func validateConfig(cfg Config) error {
	// Checked over an ordered slice rather than a map so the error message is reproducible.
	required := []struct {
		name  string
		value string
	}{
		{"ClientID", cfg.ClientID},
		{"ClientSecret", cfg.ClientSecret},
		{"ServiceURL", cfg.ServiceURL},
		{"SessionName", cfg.SessionName},
	}

	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("auth config %s must not be empty", field.name)
		}
	}

	// The store has no default (see Config.Store).
	if cfg.Store == nil {
		return errors.New("auth config Store must not be nil")
	}

	serviceURL, err := url.Parse(cfg.ServiceURL)
	if err != nil || serviceURL.Scheme == "" || serviceURL.Host == "" {
		return errors.New("auth config ServiceURL must be an absolute URL")
	}
	// Allowing a path would let it reach the redirect URL but not the route
	// matching in Routes. Only an origin is accepted; paths go through
	// WithPaths alone.
	if (serviceURL.Path != "" && serviceURL.Path != "/") || serviceURL.RawQuery != "" || serviceURL.Fragment != "" {
		return errors.New("auth config ServiceURL must be an origin without path, query or fragment")
	}

	return nil
}

// validatePaths checks that the three mount points do not collide in Routes.
// http.ServeMux panics when the same path is registered twice, so this stops
// earlier with a readable error.
func validatePaths(loginPath, callbackPath, logoutPath string) error {
	// Walked as an ordered slice so the error text is reproducible.
	named := []struct{ name, path string }{
		{"login", loginPath}, {"callback", callbackPath}, {"logout", logoutPath},
	}
	seen := map[string]string{}
	for _, n := range named {
		if !strings.HasPrefix(n.path, "/") {
			return fmt.Errorf("auth config: %s path %q must start with /", n.name, n.path)
		}
		if other, dup := seen[n.path]; dup {
			return fmt.Errorf("auth config: %s and %s share the path %q", other, n.name, n.path)
		}
		seen[n.path] = n.name
	}
	return nil
}

// log returns the configured logger, or slog.Default() if none is set.
func (h *Handler) log() *slog.Logger {
	if h != nil && h.logger != nil {
		return h.logger
	}
	return slog.Default()
}

// The accessors below turn zero values into defaults, so a Handler built
// without New (in tests, for example) still works with the defaults. This is
// the same policy as the other types in this repository.

func (h *Handler) loginPath() string    { return pathOrDefault(h.cfgLoginPath, DefaultLoginPath) }
func (h *Handler) callbackPath() string { return pathOrDefault(h.cfgCallbackPath, DefaultCallbackPath) }
func (h *Handler) logoutPath() string   { return pathOrDefault(h.cfgLogoutPath, DefaultLogoutPath) }

func pathOrDefault(path, fallback string) string {
	if strings.TrimSpace(path) == "" {
		return fallback
	}
	return path
}

// promptParam returns the prompt value to put on the authorization URL, or empty if unset.
func (h *Handler) promptParam() string {
	return strings.TrimSpace(string(h.prompt))
}

func (h *Handler) stateCookieMaxAge() int {
	if h.cfgStateMaxAge > 0 {
		return int(h.cfgStateMaxAge.Seconds())
	}
	return int(defaultStateMaxAge.Seconds())
}

// sessionMaxAge is the session's lifetime. The same value is used for both the cookie and the stored session.
func (h *Handler) sessionMaxAge() time.Duration {
	if h.cfgSessionMaxAge > 0 {
		return h.cfgSessionMaxAge
	}
	return defaultSessionMaxAge
}

// toLowerMap normalises the allowlist (trim + lowercase) into a map.
// Whitespace-only entries are dropped so that empty elements from splitting
// an environment variable cannot make a list that is "not empty but allows
// nobody".
func toLowerMap(slice []string) map[string]struct{} {
	m := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			m[strings.ToLower(trimmed)] = struct{}{}
		}
	}
	return m
}
