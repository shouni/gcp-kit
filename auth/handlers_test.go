package auth

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

// newCallbackTestHandler builds a Handler whose OAuth2 token endpoint and
// Google UserInfo endpoint are both served by a local httptest.Server
// (routed via rewriteTransport, since the UserInfo URL is hardcoded), so the
// full Callback flow can be exercised without touching real Google services.
func newCallbackTestHandler(t *testing.T, tokenHandler, userInfoHandler http.HandlerFunc) (*Handler, context.Context) {
	t.Helper()

	mux := http.NewServeMux()
	if tokenHandler != nil {
		mux.HandleFunc("/token", tokenHandler)
	}
	if userInfoHandler != nil {
		mux.HandleFunc("/oauth2/v2/userinfo", userInfoHandler)
	}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	ctx := newRewriteContext(t, server)

	h := &Handler{
		oauthConfig: &oauth2.Config{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			RedirectURL:  "https://app.example.com/auth/callback",
			Endpoint: oauth2.Endpoint{
				TokenURL: server.URL + "/token",
			},
		},
		store:          newTestCookieStore(),
		sessionName:    "test-session",
		allowedDomains: map[string]struct{}{"example.com": {}},
	}
	return h, ctx
}

func jsonTokenResponse(extra map[string]any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		body := map[string]any{"access_token": "test-access-token", "token_type": "Bearer"}
		maps.Copy(body, extra)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
}

func jsonUserInfoResponse(email string, verified bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"email": email, "verified_email": verified})
	}
}

func TestLogin(t *testing.T) {
	t.Parallel()

	newHandler := func(store sessions.Store) *Handler {
		if store == nil {
			store = newTestCookieStore()
		}
		return &Handler{
			oauthConfig: &oauth2.Config{
				ClientID: "client-id",
				Endpoint: oauth2.Endpoint{AuthURL: "https://accounts.example.com/o/oauth2/auth"},
			},
			store:       store,
			sessionName: "test-session",
		}
	}

	t.Run("redirects to provider and sets state cookie", func(t *testing.T) {
		t.Parallel()
		h := newHandler(nil)
		req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		rr := httptest.NewRecorder()

		h.Login(rr, req)

		if rr.Code != http.StatusTemporaryRedirect {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusTemporaryRedirect)
		}
		loc := rr.Header().Get("Location")
		if !strings.HasPrefix(loc, "https://accounts.example.com/o/oauth2/auth") {
			t.Fatalf("Location = %q, want AuthCodeURL prefix", loc)
		}

		found := false
		for _, c := range rr.Result().Cookies() {
			if c.Name == DefaultStateCookie {
				found = true
				if c.Value == "" {
					t.Fatal("state cookie value is empty")
				}
			}
		}
		if !found {
			t.Fatal("state cookie not set")
		}
	})

	t.Run("saves valid redirect_to in session", func(t *testing.T) {
		t.Parallel()
		h := newHandler(nil)
		req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect_to=/private", nil)
		rr := httptest.NewRecorder()

		h.Login(rr, req)

		if rr.Code != http.StatusTemporaryRedirect {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusTemporaryRedirect)
		}

		req2 := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, c := range rr.Result().Cookies() {
			req2.AddCookie(c)
		}
		session, err := h.store.Get(req2, h.sessionName)
		if err != nil {
			t.Fatalf("store.Get() error = %v", err)
		}
		if got, _ := session.Values[DefaultRedirectSessionKey].(string); got != "/private" {
			t.Fatalf("redirect session value = %q, want %q", got, "/private")
		}
	})

	t.Run("ignores unsafe redirect_to", func(t *testing.T) {
		t.Parallel()
		h := newHandler(nil)
		req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect_to=//evil.com", nil)
		rr := httptest.NewRecorder()

		h.Login(rr, req)

		if rr.Code != http.StatusTemporaryRedirect {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusTemporaryRedirect)
		}
		for _, c := range rr.Result().Cookies() {
			if c.Name == h.sessionName {
				t.Fatal("session cookie should not be set when redirect_to is unsafe")
			}
		}
	})

	t.Run("proceeds when session store Get fails", func(t *testing.T) {
		t.Parallel()
		h := newHandler(nilSessionStore{})
		req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect_to=/private", nil)
		rr := httptest.NewRecorder()

		h.Login(rr, req)

		if rr.Code != http.StatusTemporaryRedirect {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusTemporaryRedirect)
		}
	})

	t.Run("500 when session save fails", func(t *testing.T) {
		t.Parallel()
		h := newHandler(failingStore{})
		req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect_to=/private", nil)
		rr := httptest.NewRecorder()

		h.Login(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
		}
	})
}

func TestValidateCallbackState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		cookie     *http.Cookie
		queryState string
		want       bool
	}{
		{"missing cookie", nil, "abc", false},
		{"mismatched state", &http.Cookie{Name: DefaultStateCookie, Value: "abc"}, "xyz", false},
		{"matching state", &http.Cookie{Name: DefaultStateCookie, Value: "abc"}, "abc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/auth/callback?state="+tt.queryState, nil)
			if tt.cookie != nil {
				req.AddCookie(tt.cookie)
			}
			if got := validateCallbackState(req); got != tt.want {
				t.Fatalf("validateCallbackState() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClearStateCookie(t *testing.T) {
	t.Parallel()

	h := &Handler{isSecureCookie: true}
	rr := httptest.NewRecorder()

	h.clearStateCookie(rr)

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != DefaultStateCookie {
		t.Fatalf("cookie name = %q, want %q", c.Name, DefaultStateCookie)
	}
	if c.MaxAge != -1 {
		t.Fatalf("MaxAge = %d, want -1", c.MaxAge)
	}
}

func TestExchangeCode(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()
		h, ctx := newCallbackTestHandler(t, jsonTokenResponse(nil), nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc", nil).WithContext(ctx)
		token, err := h.exchangeCode(req)
		if err != nil {
			t.Fatalf("exchangeCode() error = %v", err)
		}
		if token.AccessToken != "test-access-token" {
			t.Fatalf("AccessToken = %q, want %q", token.AccessToken, "test-access-token")
		}
	})

	t.Run("failure", func(t *testing.T) {
		t.Parallel()
		h, ctx := newCallbackTestHandler(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		}, nil)

		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=bad", nil).WithContext(ctx)
		if _, err := h.exchangeCode(req); err == nil {
			t.Fatal("exchangeCode() error = nil, want error")
		}
	})
}

func TestExtractEmailFromIDToken(t *testing.T) {
	t.Parallel()

	const clientID = "client-id"

	tests := []struct {
		name  string
		extra map[string]any
	}{
		{
			name:  "no id_token extra",
			extra: nil,
		},
		{
			name:  "malformed id_token",
			extra: map[string]any{"id_token": "not-a-jwt"},
		},
		{
			name: "expired id_token",
			extra: map[string]any{"id_token": makeUnsignedJWT(map[string]any{
				"aud":            clientID,
				"exp":            1,
				"email":          "user@example.com",
				"email_verified": true,
			})},
		},
		{
			name: "audience mismatch",
			extra: map[string]any{"id_token": makeUnsignedJWT(map[string]any{
				"aud": "someone-else",
				"exp": 9999999999,
			})},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
			token := &oauth2.Token{AccessToken: "tok"}
			if tt.extra != nil {
				token = token.WithExtra(tt.extra)
			}
			if got := extractEmailFromIDToken(req, token, clientID); got != "" {
				t.Fatalf("extractEmailFromIDToken() = %q, want empty", got)
			}
		})
	}
}

func TestResolveUserEmail(t *testing.T) {
	t.Parallel()

	h, ctx := newCallbackTestHandler(t, nil, jsonUserInfoResponse("user@example.com", true))
	req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil).WithContext(ctx)
	token := &oauth2.Token{AccessToken: "tok"}

	got := h.resolveUserEmail(req, token)
	if got != "user@example.com" {
		t.Fatalf("resolveUserEmail() = %q, want %q", got, "user@example.com")
	}
}

func TestResolveUserEmailFallbackFails(t *testing.T) {
	t.Parallel()

	h, ctx := newCallbackTestHandler(t, nil, jsonUserInfoResponse("user@example.com", false))
	req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil).WithContext(ctx)
	token := &oauth2.Token{AccessToken: "tok"}

	if got := h.resolveUserEmail(req, token); got != "" {
		t.Fatalf("resolveUserEmail() = %q, want empty", got)
	}
}

func TestCallback(t *testing.T) {
	t.Parallel()

	const state = "test-state"

	newRequest := func(ctx context.Context, includeState bool) *http.Request {
		target := "/auth/callback?code=auth-code"
		if includeState {
			target += "&state=" + state
		}
		req := httptest.NewRequest(http.MethodGet, target, nil).WithContext(ctx)
		if includeState {
			req.AddCookie(&http.Cookie{Name: DefaultStateCookie, Value: state})
		}
		return req
	}

	t.Run("invalid state returns 400", func(t *testing.T) {
		t.Parallel()
		h, ctx := newCallbackTestHandler(t, nil, nil)
		req := newRequest(ctx, false)
		rr := httptest.NewRecorder()

		h.Callback(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})

	t.Run("exchange failure returns 500", func(t *testing.T) {
		t.Parallel()
		h, ctx := newCallbackTestHandler(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}, nil)
		req := newRequest(ctx, true)
		rr := httptest.NewRecorder()

		h.Callback(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
		}
	})

	t.Run("unauthorized email returns 403", func(t *testing.T) {
		t.Parallel()
		h, ctx := newCallbackTestHandler(t, jsonTokenResponse(nil), jsonUserInfoResponse("user@other.com", true))
		req := newRequest(ctx, true)
		rr := httptest.NewRecorder()

		h.Callback(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
		}
	})

	t.Run("authorized email redirects and saves session", func(t *testing.T) {
		t.Parallel()
		h, ctx := newCallbackTestHandler(t, jsonTokenResponse(nil), jsonUserInfoResponse("user@example.com", true))
		req := newRequest(ctx, true)
		rr := httptest.NewRecorder()

		h.Callback(rr, req)

		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusSeeOther)
		}
		if loc := rr.Header().Get("Location"); loc != "/" {
			t.Fatalf("Location = %q, want %q", loc, "/")
		}
	})
}

func TestSaveSessionAndRedirect(t *testing.T) {
	t.Parallel()

	t.Run("defaults to root", func(t *testing.T) {
		t.Parallel()
		store := newTestCookieStore()
		h := &Handler{store: store, sessionName: "test-session"}
		req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
		rr := httptest.NewRecorder()

		if err := h.saveSessionAndRedirect(rr, req, "user@example.com"); err != nil {
			t.Fatalf("saveSessionAndRedirect() error = %v", err)
		}
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusSeeOther)
		}
		if loc := rr.Header().Get("Location"); loc != "/" {
			t.Fatalf("Location = %q, want %q", loc, "/")
		}
	})

	t.Run("uses and clears saved redirect target", func(t *testing.T) {
		t.Parallel()
		store := newTestCookieStore()
		h := &Handler{store: store, sessionName: "test-session"}

		seedReq := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		seedRR := httptest.NewRecorder()
		session, err := h.store.Get(seedReq, h.sessionName)
		if err != nil {
			t.Fatalf("store.Get() error = %v", err)
		}
		session.Values[DefaultRedirectSessionKey] = "/private"
		if err := session.Save(seedReq, seedRR); err != nil {
			t.Fatalf("session.Save() error = %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
		for _, c := range seedRR.Result().Cookies() {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()

		if err := h.saveSessionAndRedirect(rr, req, "user@example.com"); err != nil {
			t.Fatalf("saveSessionAndRedirect() error = %v", err)
		}
		if loc := rr.Header().Get("Location"); loc != "/private" {
			t.Fatalf("Location = %q, want %q", loc, "/private")
		}
	})

	t.Run("nil session returns error", func(t *testing.T) {
		t.Parallel()
		h := &Handler{store: nilSessionStore{}, sessionName: "test-session"}
		req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
		rr := httptest.NewRecorder()

		if err := h.saveSessionAndRedirect(rr, req, "user@example.com"); err == nil {
			t.Fatal("saveSessionAndRedirect() error = nil, want error")
		}
	})
}

func TestSaveSessionAndRedirectReturnsSaveError(t *testing.T) {
	t.Parallel()

	h := &Handler{
		store:       failingStore{},
		sessionName: "test-session",
	}

	req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	rr := httptest.NewRecorder()

	if err := h.saveSessionAndRedirect(rr, req, "user@example.com"); err == nil {
		t.Fatalf("saveSessionAndRedirect() error = nil, want error")
	}
}
