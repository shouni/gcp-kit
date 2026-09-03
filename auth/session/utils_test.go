package session

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestToLowerMap(t *testing.T) {
	t.Parallel()

	got := toLowerMap([]string{"User@Example.COM", "", "ADMIN@example.com", "user@example.com"})

	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if _, ok := got["user@example.com"]; !ok {
		t.Fatalf("expected normalized user email to exist")
	}
	if _, ok := got["admin@example.com"]; !ok {
		t.Fatalf("expected normalized admin email to exist")
	}
}

func TestIsAuthorized(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler Handler
		email   string
		want    bool
	}{
		{
			name:    "deny when allow lists are empty",
			handler: Handler{},
			email:   "user@example.com",
			want:    false,
		},
		{
			name: "allow exact email with case-insensitive match",
			handler: Handler{
				allowedEmails: map[string]struct{}{"user@example.com": {}},
			},
			email: "User@Example.com",
			want:  true,
		},
		{
			name: "allow by domain",
			handler: Handler{
				allowedDomains: map[string]struct{}{"example.com": {}},
			},
			email: "member@example.com",
			want:  true,
		},
		{
			name: "deny invalid email format",
			handler: Handler{
				allowedDomains: map[string]struct{}{"example.com": {}},
			},
			email: "invalid-address",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.handler.isAuthorized(tt.email); got != tt.want {
				t.Fatalf("isAuthorized(%q) = %v, want %v", tt.email, got, tt.want)
			}
		})
	}
}

// newFetchUserEmailHandler builds a Handler and a context whose HTTP client
// transparently redirects requests to the hardcoded Google UserInfo URL to a
// local httptest.Server, so fetchUserEmail's JSON-handling logic can be
// exercised without a real network call.
func newFetchUserEmailHandler(t *testing.T, userInfoHandler http.HandlerFunc) (*Handler, context.Context) {
	t.Helper()

	server := httptest.NewServer(userInfoHandler)
	t.Cleanup(server.Close)

	return &Handler{oauthConfig: &oauth2.Config{}}, newRewriteContext(t, server)
}

func TestFetchUserEmail(t *testing.T) {
	t.Parallel()

	t.Run("verified email succeeds", func(t *testing.T) {
		t.Parallel()
		h, ctx := newFetchUserEmailHandler(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"email": "user@example.com", "verified_email": true})
		})

		got, err := h.fetchUserEmail(ctx, &oauth2.Token{AccessToken: "tok"})
		if err != nil {
			t.Fatalf("fetchUserEmail() error = %v", err)
		}
		if got != "user@example.com" {
			t.Fatalf("fetchUserEmail() = %q, want %q", got, "user@example.com")
		}
	})

	t.Run("unverified email fails", func(t *testing.T) {
		t.Parallel()
		h, ctx := newFetchUserEmailHandler(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"email": "user@example.com", "verified_email": false})
		})

		if _, err := h.fetchUserEmail(ctx, &oauth2.Token{AccessToken: "tok"}); err == nil {
			t.Fatal("fetchUserEmail() error = nil, want error")
		}
	})

	// 判定を auth.VerifiedEmail に委ねる前は、この経路だけ空アドレスを素通しして
	// いました（ID トークン経路は弾いていました）。基準を書き写すのではなく同じ
	// 関数を呼ぶようにした理由がこれで、片側だけが緩んだ状態が実際に起きていました。
	t.Run("verified but empty email fails", func(t *testing.T) {
		t.Parallel()
		h, ctx := newFetchUserEmailHandler(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"email": "", "verified_email": true})
		})

		got, err := h.fetchUserEmail(ctx, &oauth2.Token{AccessToken: "tok"})
		if err == nil {
			t.Fatalf("fetchUserEmail() = %q, error = nil, want error", got)
		}
	})

	// エラー応答をそのままデコードすると「未検証」という実態と異なるエラーに
	// なってしまうため、ステータスコードを先に確認します。
	t.Run("non-200 response reports the status", func(t *testing.T) {
		t.Parallel()
		h, ctx := newFetchUserEmailHandler(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
		})

		_, err := h.fetchUserEmail(ctx, &oauth2.Token{AccessToken: "tok"})
		if err == nil {
			t.Fatal("fetchUserEmail() error = nil, want error")
		}
		if !strings.Contains(err.Error(), "401") {
			t.Fatalf("error = %v, want it to mention the 401 status", err)
		}
	})

	t.Run("malformed response fails", func(t *testing.T) {
		t.Parallel()
		h, ctx := newFetchUserEmailHandler(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json"))
		})

		if _, err := h.fetchUserEmail(ctx, &oauth2.Token{AccessToken: "tok"}); err == nil {
			t.Fatal("fetchUserEmail() error = nil, want error")
		}
	})
}

func TestClearSessionCookie(t *testing.T) {
	t.Parallel()

	store := newTestStore()
	h := &Handler{store: store, sessionName: "test-session"}
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()

	if err := h.clearSessionCookie(rr, req); err != nil {
		t.Fatalf("clearSessionCookie() error = %v", err)
	}

	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected a cookie to be set")
	}
	if cookies[0].MaxAge != -1 {
		t.Fatalf("MaxAge = %d, want -1", cookies[0].MaxAge)
	}
}

// TestClearSessionCookieDeletesTheEntity は、クッキーを落とすだけでなく保存された実体も
// 消すことを確認します。盗まれたクッキーが有効なままなら、ログアウトになりません。
func TestClearSessionCookieDeletesTheEntity(t *testing.T) {
	t.Parallel()

	store := newTestStore()
	h := &Handler{store: store, sessionName: "test-session"}
	seeded := seedSession(t, store, h.sessionName, map[string]string{DefaultUserSessionKey: "user@example.com"})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.AddCookie(seeded)
	rr := httptest.NewRecorder()

	if err := h.clearSessionCookie(rr, req); err != nil {
		t.Fatalf("clearSessionCookie() error = %v", err)
	}
	if _, err := store.Load(context.Background(), seeded.Value); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load() after clear = %v, want ErrNotFound: the stored session must be gone", err)
	}
}

// TestClearSessionCookieUnreachableStore は、実体を消せなくてもクッキーは落とし、
// エラーは呼び出し元へ返すことを確認します。
func TestClearSessionCookieUnreachableStore(t *testing.T) {
	t.Parallel()

	h := &Handler{store: unavailableStore{}, sessionName: "test-session"}
	id, err := newSessionID()
	if err != nil {
		t.Fatalf("newSessionID() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.AddCookie(&http.Cookie{Name: "test-session", Value: id})
	rr := httptest.NewRecorder()

	if err := h.clearSessionCookie(rr, req); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("clearSessionCookie() error = %v, want ErrStoreUnavailable", err)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != -1 {
		t.Fatalf("cookies = %+v, want one expiring session cookie", cookies)
	}
}

func TestRandomTokenAndGenerateState(t *testing.T) {
	t.Parallel()

	token, err := randomToken(base64.RawURLEncoding)
	if err != nil {
		t.Fatalf("randomToken() error = %v", err)
	}
	if token == "" {
		t.Fatal("randomToken() returned empty string")
	}

	state, err := generateState()
	if err != nil {
		t.Fatalf("generateState() error = %v", err)
	}
	if state == "" {
		t.Fatal("generateState() returned empty string")
	}
}

// TestIssueSessionProducesAcceptedCookie は、IssueSession が出したクッキーを
// Authenticate がそのまま受け付けることを確認します。この往復が IssueSession の
// 存在理由なので、クッキーの作り方を変えたらここが壊れます。
func TestIssueSessionProducesAcceptedCookie(t *testing.T) {
	t.Parallel()

	h := &Handler{store: newTestStore(), sessionName: "test-session", allowedDomains: testAllowedDomains()}

	rr := httptest.NewRecorder()
	if err := h.IssueSession(rr, httptest.NewRequest(http.MethodGet, "/", nil), "user@example.com"); err != nil {
		t.Fatalf("IssueSession() error = %v", err)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("IssueSession() がセッションクッキーを出していません")
	}
	// リダイレクトを書くと、ハンドラーの前でログイン状態を作る用途に使えません。
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	ctx, err := h.Authenticate(httptest.NewRecorder(), req)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if email, ok := EmailFromContext(ctx); !ok || email != "user@example.com" {
		t.Errorf("EmailFromContext() = %q, %v; want %q, true", email, ok, "user@example.com")
	}
}

// TestIssueSessionFailsClosed は、許可リストに無いアドレスと許可リストが空の
// Handler の両方で、セッションを発行しないことを確認します。
func TestIssueSessionFailsClosed(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		handler *Handler
		email   string
	}{
		"許可リストに無いアドレス": {
			handler: &Handler{store: newTestStore(), sessionName: "test-session", allowedDomains: testAllowedDomains()},
			email:   "intruder@evil.example",
		},
		"許可リストが空": {
			handler: &Handler{store: newTestStore(), sessionName: "test-session"},
			email:   "user@example.com",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rr := httptest.NewRecorder()
			if err := tt.handler.IssueSession(rr, httptest.NewRequest(http.MethodGet, "/", nil), tt.email); err == nil {
				t.Fatal("セッションが発行されました")
			}
			if got := rr.Result().Cookies(); len(got) != 0 {
				t.Errorf("エラーを返しつつクッキーを出しています: %v", got)
			}
		})
	}
}

// TestIssueSessionRotatesSessionID は、IssueSession でも ID が振り直されることを確認し、
// 2 つの入口が同じ issueSession を通ることを振る舞いで固定します。
func TestIssueSessionRotatesSessionID(t *testing.T) {
	t.Parallel()

	const email = "user@example.com"
	store := newTestStore()
	planted := seedSession(t, store, "test-session", map[string]string{CSRFTokenKey: "token-fixed-before-login"})

	h := &Handler{store: store, sessionName: "test-session", allowedDomains: testAllowedDomains()}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(planted)
	rr := httptest.NewRecorder()

	if err := h.IssueSession(rr, req, email); err != nil {
		t.Fatalf("IssueSession() error = %v", err)
	}

	if values, err := store.Load(context.Background(), planted.Value); err == nil {
		if _, authenticated := values[DefaultUserSessionKey]; authenticated {
			t.Error("攻撃者が知っている ID がそのまま認証済みになりました（セッション固定）")
		}
	}

	var issued string
	for _, c := range rr.Result().Cookies() {
		if c.Name == "test-session" {
			issued = c.Value
		}
	}
	if issued == "" || issued == planted.Value {
		t.Fatalf("発行されたクッキー = %q、仕込まれた ID のままか空です", issued)
	}
	values, err := store.Load(context.Background(), issued)
	if err != nil || values[DefaultUserSessionKey] != email {
		t.Fatalf("新しい ID の実体 = %v (err %v), want email %q", values, err, email)
	}
	if _, ok := values[CSRFTokenKey]; ok {
		t.Error("ログイン前の CSRF トークンが新しいセッションへ持ち越されています")
	}
}
