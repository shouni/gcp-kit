package session

import (
	"log/slog"
	"strings"
	"time"
)

// Option is an optional setting of a Handler.
// Required settings live in Config.
type Option func(*options)

type options struct {
	scopes        []string
	loginPath     string
	callbackPath  string
	logoutPath    string
	stateMaxAge   time.Duration
	sessionMaxAge time.Duration
	logger        *slog.Logger
	prompt        Prompt
}

func newOptions(opts []Option) *options {
	o := &options{
		loginPath:     DefaultLoginPath,
		callbackPath:  DefaultCallbackPath,
		logoutPath:    DefaultLogoutPath,
		stateMaxAge:   defaultStateMaxAge,
		sessionMaxAge: defaultSessionMaxAge,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(o)
		}
	}
	return o
}

// WithScopes replaces the requested OAuth2 scopes.
// They default to openid + userinfo.email.
func WithScopes(scopes ...string) Option {
	return func(o *options) {
		if len(scopes) > 0 {
			o.scopes = scopes
		}
	}
}

// WithPaths sets where the Login, Callback and Logout handlers are mounted.
// Empty values keep their defaults.
//
// callbackPath is also used as the Path attribute of the state and PKCE
// cookies. If it does not match the actual routing, the cookies are not sent
// on the callback and authentication always fails.
func WithPaths(loginPath, callbackPath, logoutPath string) Option {
	return func(o *options) {
		if p := strings.TrimSpace(loginPath); p != "" {
			o.loginPath = p
		}
		if p := strings.TrimSpace(callbackPath); p != "" {
			o.callbackPath = p
		}
		if p := strings.TrimSpace(logoutPath); p != "" {
			o.logoutPath = p
		}
	}
}

// WithSessionMaxAge sets how long a session lasts (default: 7 days). It is
// both the cookie's lifetime and the stored session's expiry. Values of 0 or
// less are ignored.
//
// This used to be a Store setting. Now that the Handler owns the cookie
// outright, the lifetime is decided here too.
func WithSessionMaxAge(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.sessionMaxAge = d
		}
	}
}

// WithStateMaxAge sets how long the state and PKCE cookies last (default: 10
// minutes). Values of 0 or less are ignored.
func WithStateMaxAge(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.stateMaxAge = d
		}
	}
}

// WithLogger sets the logger this package uses.
// It defaults to slog.Default().
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) { o.logger = logger }
}

// Prompt says what Google should ask on the authorization screen
// (the OpenID Connect prompt parameter).
type Prompt string

const (
	// PromptSelectAccount always shows the account chooser.
	//
	// Its main use is making logout effective. Logout can only clear this
	// app's cookie; the Google-side session remains. Without a prompt, Google
	// approves without asking anything as soon as the user is sent to the
	// login page after logging out, so to the user the screen flickers and
	// they are back where they were, still signed in. "Log out" does not hold
	// on a shared machine.
	PromptSelectAccount Prompt = "select_account"

	// PromptLogin goes as far as requiring re-authentication with Google (entering the password, for example).
	PromptLogin Prompt = "login"

	// PromptConsent shows the consent screen every time.
	PromptConsent Prompt = "consent"

	// PromptNone shows no screen at all and returns an error when interaction
	// would be needed. It is for re-fetching without user action. It cannot be
	// combined with other values.
	PromptNone Prompt = "none"
)

// WithPrompt sets the prompt parameter of the authorization URL.
//
// Unset, none is sent (Google's default is "do not ask if it can be avoided").
// To make users always choose an account after logging out, pass
// PromptSelectAccount.
func WithPrompt(prompt Prompt) Option {
	return func(o *options) { o.prompt = prompt }
}
