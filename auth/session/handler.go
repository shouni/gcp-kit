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

	"github.com/gorilla/sessions"
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
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// SessionKeys は、セッションクッキーの署名鍵と暗号化鍵の組です。
	//
	// 先頭の組が現行の鍵で、新しいセッションはこれで発行されます。2 つ目以降は
	// 読み出しにだけ使われる旧鍵です。鍵を差し替えるときに旧鍵を残しておけば、
	// 既に配ったクッキーを失効させずに入れ替えられます（ローテーション）。
	// 組を 1 つしか渡せないと、鍵を変えた瞬間に全利用者が強制ログアウトになります。
	//
	// 入れ替えが行き渡った後（クッキーの有効期間、既定 7 日）に旧鍵を外します。
	// WithStore で外部ストアを渡す場合、この鍵は使われません。
	SessionKeys    []SessionKey
	SessionName    string
	IsSecureCookie bool
	AllowedEmails  []string
	AllowedDomains []string
}

// SessionKey は、セッションクッキーに使う鍵の組です。
type SessionKey struct {
	// Auth は署名 (HMAC) 用の鍵です。16 バイト以上が要ります。
	Auth []byte
	// Encrypt は暗号化 (AES) 用の鍵です。16 / 24 / 32 バイトのいずれかです。
	Encrypt []byte
}

// keyPairs は、gorilla の NewCookieStore が期待する並び（署名鍵と暗号化鍵の交互）へ
// 展開します。先頭の組が発行に、全ての組が読み出しに使われます。
func (c Config) keyPairs() [][]byte {
	pairs := make([][]byte, 0, len(c.SessionKeys)*2)
	for _, key := range c.SessionKeys {
		pairs = append(pairs, key.Auth, key.Encrypt)
	}
	return pairs
}

type googleUserInfo struct {
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
}

// Handler は認証ロジックを保持する構造体です
type Handler struct {
	oauthConfig    *oauth2.Config
	store          sessions.Store
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
		// 先頭が現行の鍵、以降は読み出し専用の旧鍵として渡ります。
		cookieStore := sessions.NewCookieStore(cfg.keyPairs()...)
		cookieStore.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   int(o.sessionMaxAge.Seconds()),
			HttpOnly: true,
			Secure:   cfg.IsSecureCookie,
			SameSite: http.SameSiteLaxMode,
		}
		store = cookieStore
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
		{"SessionName", cfg.SessionName},
	}

	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("auth config %s must not be empty", field.name)
		}
	}

	// 空のリストを許すと、鍵の無い CookieStore が出来上がります。
	if len(cfg.SessionKeys) == 0 {
		return errors.New("auth config SessionKeys must not be empty")
	}
	for i, key := range cfg.SessionKeys {
		// 署名キー (HMAC) は十分な長さがあれば良いため、16バイト以上であることを確認します。
		if authLen := len(key.Auth); authLen < 16 {
			return fmt.Errorf("auth config SessionKeys[%d].Auth length is %d: must be at least 16 bytes for security", i, authLen)
		}
		// 暗号化キー (AES) は 16/24/32 バイトのいずれかである必要があります。
		switch len(key.Encrypt) {
		case 16, 24, 32:
		default:
			return fmt.Errorf("auth config SessionKeys[%d].Encrypt is %d bytes: must be 16, 24, or 32", i, len(key.Encrypt))
		}
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
