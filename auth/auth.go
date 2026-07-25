// Package auth は、Google OAuth2 によるセッションベース認証、CSRF検証、
// サーバー間通信向けの OIDC トークン検証 (M2M) を提供します。
package auth

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

// Config は認証ハンドラーの初期化設定です
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

	// TaskAudienceURL は、Cloud Tasks が発行する OIDC トークンの audience です。
	// 設定した場合は AllowedTaskServiceAccounts も必須になります。
	TaskAudienceURL string
	// AllowedTaskServiceAccounts は、Cloud Tasks からの呼び出しを許可する
	// サービスアカウントのメールアドレス（= tasks.Config.ServiceAccountEmail）です。
	//
	// audience は署名対象に含まれるだけの単なる文字列であり、任意の GCP プロジェクトの
	// 任意のサービスアカウントが同じ audience を持つ OIDC トークンを発行できます。
	// そのため audience の検証だけでは呼び出し元を認証したことになりません。
	// TaskOIDCVerificationMiddleware はこのリストと email クレームを突き合わせます。
	AllowedTaskServiceAccounts []string

	// --- 以下は任意。ゼロ値の場合は既定値が使われます。 ---

	// Scopes は OAuth2 の要求スコープです。未指定の場合は openid + userinfo.email です。
	Scopes []string
	// LoginPath / CallbackPath / LogoutPath は各ハンドラーのマウント先パスです。
	// CallbackPath は state / PKCE クッキーの Path 属性としても使われるため、
	// 実際のルーティングと一致させてください。
	LoginPath    string
	CallbackPath string
	LogoutPath   string
	// SessionMaxAge はセッションクッキーの有効期間です（既定: 7日）。
	SessionMaxAge time.Duration
	// StateMaxAge は state / PKCE クッキーの有効期間です（既定: 10分）。
	StateMaxAge time.Duration
	// Store はセッションストアです。未指定の場合は SessionAuthKey / SessionEncryptKey を
	// 用いた sessions.CookieStore が生成されます。サーバー側でセッションを失効させたい
	// 場合（ログアウトを確実に反映したい場合など）は Redis 等のストアを注入してください。
	Store sessions.Store
	// Logger は本パッケージが使うロガーです。未指定の場合は slog.Default() です。
	Logger *slog.Logger
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

	taskVerifier *oidcVerifier

	loginPath    string
	callbackPath string
	logoutPath   string
	stateMaxAge  time.Duration
	logger       *slog.Logger
}

// NewHandler は設定に基づき Handler を生成します
func NewHandler(cfg Config) (*Handler, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       cfg.Scopes,
		Endpoint:     google.Endpoint,
	}
	if len(oauthCfg.Scopes) == 0 {
		oauthCfg.Scopes = defaultScopes
	}

	store := cfg.Store
	if store == nil {
		// 認証キーと暗号化キーを個別に渡す
		cookieStore := sessions.NewCookieStore([]byte(cfg.SessionAuthKey), []byte(cfg.SessionEncryptKey))
		cookieStore.Options = &sessions.Options{
			Path:     "/",
			MaxAge:   int(sessionMaxAge(cfg).Seconds()),
			HttpOnly: true,
			Secure:   cfg.IsSecureCookie,
			SameSite: http.SameSiteLaxMode,
		}
		store = cookieStore
	}

	var taskVerifier *oidcVerifier
	if strings.TrimSpace(cfg.TaskAudienceURL) != "" {
		taskVerifier = newOIDCVerifier(cfg.TaskAudienceURL, cfg.AllowedTaskServiceAccounts)
	}

	return &Handler{
		oauthConfig:    oauthCfg,
		store:          store,
		sessionName:    cfg.SessionName,
		isSecureCookie: cfg.IsSecureCookie,
		allowedEmails:  toLowerMap(cfg.AllowedEmails),
		allowedDomains: toLowerMap(cfg.AllowedDomains),
		taskVerifier:   taskVerifier,
		loginPath:      cfg.LoginPath,
		callbackPath:   cfg.CallbackPath,
		logoutPath:     cfg.LogoutPath,
		stateMaxAge:    cfg.StateMaxAge,
		logger:         cfg.Logger,
	}, nil
}

func sessionMaxAge(cfg Config) time.Duration {
	if cfg.SessionMaxAge > 0 {
		return cfg.SessionMaxAge
	}
	return defaultSessionMaxAge
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

	// Cloud Tasks 検証を有効にする場合、許可サービスアカウントの指定は必須です。
	// audience だけでは呼び出し元を認証できないため fail-closed に倒しますが、
	// リクエスト時に 403 を返すと Cloud Tasks がリトライを重ねた末にタスクを
	// 破棄してしまうため、設定漏れは起動時に失敗させます。
	if strings.TrimSpace(cfg.TaskAudienceURL) != "" && len(toLowerMap(cfg.AllowedTaskServiceAccounts)) == 0 {
		return errors.New("auth config AllowedTaskServiceAccounts must not be empty when TaskAudienceURL is set: " +
			"verifying the audience alone does not authenticate the caller")
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

// LoginPath は Login ハンドラーのマウント先パスを返します。
func (h *Handler) LoginPath() string {
	return pathOrDefault(h.loginPath, DefaultLoginPath)
}

// CallbackPath は Callback ハンドラーのマウント先パスを返します。
func (h *Handler) CallbackPath() string {
	return pathOrDefault(h.callbackPath, DefaultCallbackPath)
}

// LogoutPath は Logout ハンドラーのマウント先パスを返します。
func (h *Handler) LogoutPath() string {
	return pathOrDefault(h.logoutPath, DefaultLogoutPath)
}

func pathOrDefault(path, fallback string) string {
	if strings.TrimSpace(path) == "" {
		return fallback
	}
	return path
}

func (h *Handler) stateCookieMaxAge() int {
	if h.stateMaxAge > 0 {
		return int(h.stateMaxAge.Seconds())
	}
	return int(defaultStateMaxAge.Seconds())
}

// Routes は Login / Callback / Logout を設定済みパスに登録した http.Handler を返します。
// 既存のルーターに各ハンドラーを個別登録している場合は使う必要はありません。
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+h.LoginPath(), h.Login)
	mux.HandleFunc("GET "+h.CallbackPath(), h.Callback)
	mux.HandleFunc("GET "+h.LogoutPath(), h.Logout)
	mux.HandleFunc("POST "+h.LogoutPath(), h.Logout)
	return mux
}
