package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shouni/gcp-kit/auth"
	"github.com/shouni/gcp-kit/auth/oidc"
	"github.com/shouni/gcp-kit/auth/session"
)

const browserAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

func newTestSession(t *testing.T) *session.Handler {
	t.Helper()

	h, err := session.New(session.Config{
		ClientID:       "id",
		ClientSecret:   "secret",
		ServiceURL:     "https://app.example.com",
		SessionName:    "s",
		Store:          session.NewMemoryStore(),
		AllowedDomains: []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("session.New() error = %v", err)
	}
	return h
}

// When people and agents share a route, each gets a response it can interpret.
//
// RFC 9110, Section 15.5.2 requires WWW-Authenticate on a 401, and RFC 6750,
// Section 3.1 makes an invalid token 401 and a caller that is not allowed 403.
func TestChallengeMatrix(t *testing.T) {
	t.Parallel()

	verifier, err := oidc.New("https://app.example.com", []string{"sa@p.iam.gserviceaccount.com"})
	if err != nil {
		t.Fatalf("oidc.New() error = %v", err)
	}
	// New never returns an unconfigured Verifier, so the zero value reproduces a missing setting.
	unconfigured := &oidc.Verifier{}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	tests := []struct {
		name       string
		accept     string
		authz      string
		protected  bool // false means Require (a service-only route)
		badConfig  bool
		wantStatus int
		wantWWW    string
		wantRedir  bool
		wantVary   bool // session's response varies by Accept, so it needs Vary
	}{
		{
			// A redirect would hand the agent an HTML login page.
			name: "Protected: エージェントが Bearer を忘れた", accept: "application/json",
			protected: true, wantStatus: http.StatusUnauthorized, wantVary: true,
		},
		{
			name: "Protected: エージェントの Bearer が不正", accept: "application/json", authz: "Bearer bogus",
			protected: true, wantStatus: http.StatusUnauthorized, wantWWW: `Bearer error="invalid_token"`,
		},
		{
			// Browser behaviour is unchanged.
			name: "Protected: 未ログインのブラウザ", accept: browserAccept,
			protected: true, wantStatus: http.StatusFound, wantRedir: true, wantVary: true,
		},
		{
			name: "Require: 資格情報なし", accept: "application/json",
			wantStatus: http.StatusUnauthorized, wantWWW: "Bearer",
		},
		{
			name: "Require: トークンが不正", accept: "application/json", authz: "Bearer bogus",
			wantStatus: http.StatusUnauthorized, wantWWW: `Bearer error="invalid_token"`,
		},
		{
			// A missing setting is the server's fault, so no challenge is sent.
			name: "Require: 検証器が未設定", accept: "application/json", authz: "Bearer x",
			badConfig: true, wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := verifier
			if tt.badConfig {
				v = unconfigured
			}
			mw := auth.Require(v)
			if tt.protected {
				mw = auth.Protected(v, newTestSession(t))
			}

			req := httptest.NewRequest(http.MethodGet, "https://app.example.com/api/x", nil)
			req.Header.Set("Accept", tt.accept)
			if tt.authz != "" {
				req.Header.Set("Authorization", tt.authz)
			}
			rec := httptest.NewRecorder()
			mw(next).ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != tt.wantWWW {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tt.wantWWW)
			}
			if gotRedir := rec.Header().Get("Location") != ""; gotRedir != tt.wantRedir {
				t.Errorf("redirect = %v, want %v (Location=%q)", gotRedir, tt.wantRedir, rec.Header().Get("Location"))
			}
			// On a path whose response varies by Accept, failing to tell caches
			// can serve the login page's HTML to a caller that asked for JSON.
			if gotVary := rec.Header().Get("Vary") == "Accept"; gotVary != tt.wantVary {
				t.Errorf("Vary: Accept = %v, want %v", gotVary, tt.wantVary)
			}
		})
	}
}
