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
		ClientID:          "id",
		ClientSecret:      "secret",
		RedirectURL:       "https://app.example.com/auth/callback",
		SessionAuthKey:    "0123456789abcdef0123456789abcdef",
		SessionEncryptKey: "0123456789abcdef",
		SessionName:       "s",
		AllowedDomains:    []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("session.New() error = %v", err)
	}
	return h
}

// 人とエージェントが同じルートに来たとき、それぞれが解釈できる応答を受け取ること。
//
// RFC 9110 §15.5.2 は 401 に WWW-Authenticate を要求し、RFC 6750 §3.1 は
// トークン不正を 401、許可されない呼び出し元を 403 と定めています。
func TestChallengeMatrix(t *testing.T) {
	t.Parallel()

	verifier := oidc.New("https://app.example.com", []string{"sa@p.iam.gserviceaccount.com"})
	unconfigured := oidc.New("https://app.example.com", nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	tests := []struct {
		name       string
		accept     string
		authz      string
		protected  bool // false なら Require（サービス専用ルート）
		badConfig  bool
		wantStatus int
		wantWWW    string
		wantRedir  bool
	}{
		{
			// リダイレクトを返すと、エージェントは HTML のログイン画面を受け取ります。
			name: "Protected: エージェントが Bearer を忘れた", accept: "application/json",
			protected: true, wantStatus: http.StatusUnauthorized,
		},
		{
			name: "Protected: エージェントの Bearer が不正", accept: "application/json", authz: "Bearer bogus",
			protected: true, wantStatus: http.StatusUnauthorized, wantWWW: `Bearer error="invalid_token"`,
		},
		{
			// ブラウザの挙動は変わりません。
			name: "Protected: 未ログインのブラウザ", accept: browserAccept,
			protected: true, wantStatus: http.StatusFound, wantRedir: true,
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
			// 設定漏れはサーバー側の落ち度なので、チャレンジは返しません。
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
				t.Errorf("リダイレクト = %v, want %v (Location=%q)", gotRedir, tt.wantRedir, rec.Header().Get("Location"))
			}
		})
	}
}
