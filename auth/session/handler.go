// Package session は、人（ブラウザ）の認証を提供します。
//
// Google OAuth2 + PKCE でログインし、サーバー側のセッションで維持し、状態を変える
// リクエストには CSRF 検証を掛けます。Handler は auth.Authenticator と
// auth.Challenger を満たすため、サービス間検証（auth/oidc）と並べて
// auth.Protected に渡せます。
//
// セッションの実体は Store にあり、クッキーが運ぶのは不透明な ID だけです。
// だからセッション鍵を配る必要がなく、ログアウトと失効が実際に効きます。
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
	// DefaultUserSessionKey は、認証済みユーザーのメールアドレスを保持するセッションキーです。
	DefaultUserSessionKey = "user_email"
	// DefaultStateCookie は、OAuth2の state パラメータを一時保持するクッキー名です。
	DefaultStateCookie = "oauth_state"
	// DefaultVerifierCookie は、PKCE の code_verifier を一時保持するクッキー名です。
	DefaultVerifierCookie = "oauth_verifier"
	// DefaultRedirectCookie は、ログイン後の戻り先を一時保持するクッキー名です。
	// state / verifier と同じ寿命・同じ Path で、コールバックで消費されます。
	DefaultRedirectCookie = "oauth_redirect"

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

	// ServiceURL は、このアプリがブラウザから見えるオリジンです（例: https://app.example.com）。
	// パスは持てません。
	//
	// ここから 2 つを導出します。OAuth のリダイレクト先（ServiceURL + callbackPath()）と、
	// クッキーの Secure 属性（スキームが https かどうか）です。呼び出し側に組み立てさせて
	// いた頃は、"/auth/callback" というリテラルがルート登録と別の場所にもう 1 つあり、
	// WithPaths を変えても片方だけが動いてビルドは通りました。
	//
	// Secure をスキームだけで決めるのは、それがクッキーの問い（TLS か）そのものだから
	// です。「開発機なら http でもよいか」は設定値の妥当性の問いで、別の場所の判断です。
	ServiceURL string

	SessionName string

	// Store はセッションの保存先です（必須）。
	//
	// 既定を持たないのは、置ける既定が無いからです。プロセス内に持つと Cloud Run の
	// インスタンスが替わるたびに利用者がログアウトされ、しかも開発中は 1 インスタンス
	// なので気付けません。NewFirestoreStore を渡してください（テストとローカル開発には
	// NewMemoryStore があります）。
	Store Store

	AllowedEmails  []string
	AllowedDomains []string
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

	cfgLoginPath     string
	cfgCallbackPath  string
	cfgLogoutPath    string
	cfgStateMaxAge   time.Duration
	cfgSessionMaxAge time.Duration
	prompt           Prompt
	logger           *slog.Logger
}

// New は設定に基づき Handler を生成します。
func New(cfg Config, opts ...Option) (*Handler, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	o := newOptions(opts)
	if err := validatePaths(o.loginPath, o.callbackPath, o.logoutPath); err != nil {
		return nil, err
	}

	serviceURL, _ := url.Parse(cfg.ServiceURL) // validateConfig が形を確かめています
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
	// エラーメッセージを再現可能にするため、map ではなく順序の定まったスライスで検証します。
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

	// 保存先に既定は置きません（Config.Store を参照）。
	if cfg.Store == nil {
		return errors.New("auth config Store must not be nil")
	}

	serviceURL, err := url.Parse(cfg.ServiceURL)
	if err != nil || serviceURL.Scheme == "" || serviceURL.Host == "" {
		return errors.New("auth config ServiceURL must be an absolute URL")
	}
	// パスを許すと、リダイレクト先には付くのに Routes の照合には付かない、という
	// ずれが生まれます。オリジンだけを受け、パスは WithPaths に一本化します。
	if (serviceURL.Path != "" && serviceURL.Path != "/") || serviceURL.RawQuery != "" || serviceURL.Fragment != "" {
		return errors.New("auth config ServiceURL must be an origin without path, query or fragment")
	}

	return nil
}

// validatePaths は、3 つのマウント先が Routes で衝突しないことを確かめます。
// 同じパスを 2 つ登録すると http.ServeMux は panic するので、先に読める形で止めます。
func validatePaths(loginPath, callbackPath, logoutPath string) error {
	// エラー文を再現可能にするため、順序の定まったスライスで見ます。
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

// sessionMaxAge はセッションの寿命です。クッキーと保存した実体の両方に同じ値を使います。
func (h *Handler) sessionMaxAge() time.Duration {
	if h.cfgSessionMaxAge > 0 {
		return h.cfgSessionMaxAge
	}
	return defaultSessionMaxAge
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
