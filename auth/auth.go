// Package auth は、Google OAuth2 によるセッションベース認証、CSRF検証、
// サーバー間通信向けの OIDC トークン検証 (M2M) を提供します。
package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	// DefaultUserSessionKey は、認証済みユーザーのメールアドレスを保持するセッションキーです。
	DefaultUserSessionKey = "user_email"
	// DefaultStateCookie は、OAuth2の state パラメータを一時保持するクッキー名です。
	DefaultStateCookie = "oauth_state"
	// DefaultRedirectSessionKey は、ログイン後のリダイレクト先を保持するセッションキーです。
	DefaultRedirectSessionKey = "redirect_after_login"
	googleUserInfoURL         = "https://www.googleapis.com/oauth2/v2/userinfo"
	sessionMaxAgeSec          = 60 * 60 * 24 * 7
	stateCookieMaxAgeSec      = 60 * 10
)

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
	TaskAudienceURL   string
}

type googleUserInfo struct {
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
}

// Handler は認証ロジックを保持する構造体です
type Handler struct {
	oauthConfig     *oauth2.Config
	store           sessions.Store
	sessionName     string
	taskAudienceURL string
	isSecureCookie  bool
	allowedEmails   map[string]struct{}
	allowedDomains  map[string]struct{}
}

// NewHandler は設定に基づき Handler を生成します
func NewHandler(cfg Config) (*Handler, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	authKey := []byte(cfg.SessionAuthKey)
	encKey := []byte(cfg.SessionEncryptKey)

	// 署名キー (HMAC) のバリデーション。
	// 署名用キーは十分な長さがあれば良いため、16バイト以上であることを確認します。
	// 暗号化キー (AES) の長さ (16/24/32バイト) は validateConfig で検証済みです。
	authLen := len(authKey)
	if authLen < 16 {
		return nil, fmt.Errorf("invalid AuthKey length: %d. Must be at least 16 bytes for security", authLen)
	}

	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes: []string{
			"openid",
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	// 認証キーと暗号化キーを個別に渡す
	store := sessions.NewCookieStore(authKey, encKey)
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   sessionMaxAgeSec,
		HttpOnly: true,
		Secure:   cfg.IsSecureCookie,
		SameSite: http.SameSiteLaxMode,
	}

	return &Handler{
		oauthConfig:     oauthCfg,
		store:           store,
		sessionName:     cfg.SessionName,
		taskAudienceURL: cfg.TaskAudienceURL,
		isSecureCookie:  cfg.IsSecureCookie,
		allowedEmails:   toLowerMap(cfg.AllowedEmails),
		allowedDomains:  toLowerMap(cfg.AllowedDomains),
	}, nil
}

func validateConfig(cfg Config) error {
	required := map[string]string{
		"ClientID":          cfg.ClientID,
		"ClientSecret":      cfg.ClientSecret,
		"RedirectURL":       cfg.RedirectURL,
		"SessionAuthKey":    cfg.SessionAuthKey,
		"SessionEncryptKey": cfg.SessionEncryptKey,
		"SessionName":       cfg.SessionName,
	}

	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("auth config %s must not be empty", name)
		}
	}

	keyLen := len(cfg.SessionEncryptKey)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return fmt.Errorf("auth config SessionEncryptKey must be 16, 24, or 32 bytes long")
	}

	redirectURL, err := url.Parse(cfg.RedirectURL)
	if err != nil || redirectURL.Scheme == "" || redirectURL.Host == "" {
		return fmt.Errorf("auth config RedirectURL must be an absolute URL")
	}

	return nil
}
