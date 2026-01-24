package auth

import (
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	DefaultUserSessionKey     = "user_email"
	DefaultStateCookie        = "oauth_state"
	DefaultRedirectSessionKey = "redirect_after_login"
	googleUserInfoURL         = "https://www.googleapis.com/oauth2/v2/userinfo"
	sessionMaxAgeSec          = 60 * 60 * 24 * 7
	stateCookieMaxAgeSec      = 60 * 10
)

type Config struct {
	ClientID        string
	ClientSecret    string
	RedirectURL     string
	SessionKey      string
	SessionName     string
	IsSecureCookie  bool
	AllowedEmails   []string
	AllowedDomains  []string
	TaskAudienceURL string
}

type googleUserInfo struct {
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
}

type Handler struct {
	oauthConfig     *oauth2.Config
	store           sessions.Store
	sessionName     string
	taskAudienceURL string
	isSecureCookie  bool
	allowedEmails   map[string]struct{}
	allowedDomains  map[string]struct{}
}

func NewHandler(cfg Config) (*Handler, error) {
	keyBytes := []byte(cfg.SessionKey)
	keyLen := len(keyBytes)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return nil, fmt.Errorf("invalid session key length: %d. Must be 16, 24, or 32 bytes", keyLen)
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

	store := sessions.NewCookieStore(keyBytes, keyBytes)
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
