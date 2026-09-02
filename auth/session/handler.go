// Package session は、人（ブラウザ）の認証を提供します。
//
// Google OAuth2 + PKCE でログインし、Cookie セッションで維持し、状態を変える
// リクエストには CSRF 検証を掛けます。Handler は auth.Authenticator と
// auth.Challenger を満たすため、サービス間検証（auth/oidc）と並べて
// auth.Protected に渡せます。
//
//	handler, err := session.New(session.Config{...})
//	r.Use(auth.Protected(verifier, handler))
package session

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	// DefaultUserSessionKey は、認証済みユーザーのメールアドレスを保持するセッションキーです。
	DefaultUserSessionKey = "user_email"
	// DefaultStateCookie は、OAuth2の state パラメータを一時保持するクッキー名です。
	DefaultStateCookie = "oauth_state"
	// DefaultVerifierCookie は、PKCE の code_verifier を一時保持するクッキー名です。
	DefaultVerifierCookie = "oauth_verifier"
	// DefaultRedirectSessionKey は、ログイン後のリダイレクト先を保持するセッションキーです。
	DefaultRedirectSessionKey = "redirect_after_login"

	// DefaultLoginPath は Login ハンドラーを配置する既定パスです。
	DefaultLoginPath = "/auth/login"
	// DefaultCallbackPath は Callback ハンドラーを配置する既定パスです。
	// state / PKCE クッキーの Path 属性にも使われるため、実際のマウント先と
	// 一致していない場合、コールバック時にクッキーが送信されず認証に失敗します。
	DefaultCallbackPath = "/auth/callback"
	// DefaultLogoutPath は Logout ハンドラーを配置する既定パスです。
	DefaultLogoutPath = "/auth/logout"

	googleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"

	defaultSessionMaxAge = 7 * 24 * time.Hour
	defaultStateMaxAge   = 10 * time.Minute
)

// defaultScopes は、メールアドレスによる認可判定に必要な最小のスコープ集合です。
var defaultScopes = []string{
	"openid",
	"https://www.googleapis.com/auth/userinfo.email",
}

// Config は Handler の必須設定です。
// 任意の項目は Option（With で始まる関数）で指定します。
type Config struct {
	ClientID          string
	ClientSecret      string
	RedirectURL       string
	SessionAuthKey    string // 署名用 (HMAC)
	SessionEncryptKey string // 暗号化用 (AES)
	SessionName       string
	IsSecureCookie    bool
	AllowedEmails     []string
	AllowedDomains    []string
}

type googleUserInfo struct {
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
}

// Handler は認証ロジックを保持する構造体です
type Handler struct {
	oauthConfig    *oauth2.Config
	store          Store
	sessionName    string
	isSecureCookie bool
	allowedEmails  map[string]struct{}
	allowedDomains map[string]struct{}

	cfgLoginPath    string
	cfgCallbackPath string
	cfgLogoutPath   string
	cfgStateMaxAge  time.Duration
	prompt          Prompt
	logger          *slog.Logger
}

// New は設定に基づき Handler を生成します。
func New(cfg Config, opts ...Option) (*Handler, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	o := newOptions(opts)

	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       o.scopes,
		Endpoint:     google.Endpoint,
	}
	if len(oauthCfg.Scopes) == 0 {
		oauthCfg.Scopes = defaultScopes
	}

	store := o.store
	if store == nil {
		// 認証キーと暗号化キーを個別に渡す
		store = NewCookieStore(Options{
			Path:     "/",
			MaxAge:   int(o.sessionMaxAge.Seconds()),
			HTTPOnly: true,
			Secure:   cfg.IsSecureCookie,
			SameSite: http.SameSiteLaxMode,
		}, []byte(cfg.SessionAuthKey), []byte(cfg.SessionEncryptKey))
	}

	return &Handler{
		oauthConfig:     oauthCfg,
		store:           store,
		sessionName:     cfg.SessionName,
		isSecureCookie:  cfg.IsSecureCookie,
		allowedEmails:   toLowerMap(cfg.AllowedEmails),
		allowedDomains:  toLowerMap(cfg.AllowedDomains),
		cfgLoginPath:    o.loginPath,
		cfgCallbackPath: o.callbackPath,
		cfgLogoutPath:   o.logoutPath,
		cfgStateMaxAge:  o.stateMaxAge,
		prompt:          o.prompt,
		logger:          o.logger,
	}, nil
}

func validateConfig(cfg Config) error {
	// エラーメッセージを再現可能にするため、map ではなく順序の定まったスライスで検証します。
	required := []struct {
		name  string
		value string
	}{
		{"ClientID", cfg.ClientID},
		{"ClientSecret", cfg.ClientSecret},
		{"RedirectURL", cfg.RedirectURL},
		{"SessionAuthKey", cfg.SessionAuthKey},
		{"SessionEncryptKey", cfg.SessionEncryptKey},
		{"SessionName", cfg.SessionName},
	}

	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("auth config %s must not be empty", field.name)
		}
	}

	// 署名キー (HMAC) は十分な長さがあれば良いため、16バイト以上であることを確認します。
	if authLen := len(cfg.SessionAuthKey); authLen < 16 {
		return fmt.Errorf("auth config SessionAuthKey length is %d: must be at least 16 bytes for security", authLen)
	}

	// 暗号化キー (AES) は 16/24/32 バイトのいずれかである必要があります。
	keyLen := len(cfg.SessionEncryptKey)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return errors.New("auth config SessionEncryptKey must be 16, 24, or 32 bytes long")
	}

	redirectURL, err := url.Parse(cfg.RedirectURL)
	if err != nil || redirectURL.Scheme == "" || redirectURL.Host == "" {
		return errors.New("auth config RedirectURL must be an absolute URL")
	}

	return nil
}

// log は設定されたロガー、未設定なら slog.Default() を返します。
func (h *Handler) log() *slog.Logger {
	if h != nil && h.logger != nil {
		return h.logger
	}
	return slog.Default()
}

// 以下のアクセサは、New を通さず組み立てた Handler（テストなど）でも
// 既定値で動くよう、ゼロ値を既定へ倒します。このリポジトリの他の型と同じ方針です。

func (h *Handler) loginPath() string    { return pathOrDefault(h.cfgLoginPath, DefaultLoginPath) }
func (h *Handler) callbackPath() string { return pathOrDefault(h.cfgCallbackPath, DefaultCallbackPath) }
func (h *Handler) logoutPath() string   { return pathOrDefault(h.cfgLogoutPath, DefaultLogoutPath) }

func pathOrDefault(path, fallback string) string {
	if strings.TrimSpace(path) == "" {
		return fallback
	}
	return path
}

// promptParam は認可 URL へ載せる prompt の値を返します。未指定なら空です。
func (h *Handler) promptParam() string {
	return strings.TrimSpace(string(h.prompt))
}

func (h *Handler) stateCookieMaxAge() int {
	if h.cfgStateMaxAge > 0 {
		return int(h.cfgStateMaxAge.Seconds())
	}
	return int(defaultStateMaxAge.Seconds())
}

// toLowerMap は許可リストを正規化（トリム + 小文字化）して map にします。
// 空白のみの要素を捨てるのは、環境変数を分割した値に空要素が混ざっても、
// 「空ではないが誰も許可しない」リストにならないようにするためです。
func toLowerMap(slice []string) map[string]struct{} {
	m := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			m[strings.ToLower(trimmed)] = struct{}{}
		}
	}
	return m
}
