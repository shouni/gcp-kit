package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shouni/gcp-kit/auth"
)

// newCSRFTestHandler は、セッションストアだけを備えた Handler を返します。
// OAuth 設定は CSRF の経路に関係しないため設定しません。
func newCSRFTestHandler() *Handler {
	return &Handler{store: newTestStore(), sessionName: "test-session", allowedDomains: testAllowedDomains()}
}

func TestAuthenticatePutsCSRFTokenOnContext(t *testing.T) {
	t.Parallel()

	t.Run("GET ではトークンを自動生成してコンテキストとセッションへ入れる", func(t *testing.T) {
		t.Parallel()

		h := newCSRFTestHandler()
		var token string
		next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			token = CSRFTokenFromContext(r.Context())
		})

		req := httptest.NewRequest(http.MethodGet, "/web/compose", nil)
		req.AddCookie(loginSessionCookie(t, h, "user@example.com"))
		rec := httptest.NewRecorder()
		auth.Require(h)(next).ServeHTTP(rec, req)

		if token == "" {
			t.Fatal("GET で CSRF トークンが自動生成されていない")
		}
		if len(rec.Result().Cookies()) == 0 {
			t.Fatal("生成したトークンを保存するセッションクッキーが設定されていない")
		}
	})

	// POST で生成してしまうと、トークンを持たないリクエストに正当なトークンを
	// 与えることになり、CSRF 検証が意味をなさなくなります。
	t.Run("POST ではトークンを生成しない", func(t *testing.T) {
		t.Parallel()

		h := newCSRFTestHandler()
		var token string
		next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			token = CSRFTokenFromContext(r.Context())
		})

		// CSRF 検証には引っかかりますが、ここで見たいのは「発行しないこと」です。
		req := httptest.NewRequest(http.MethodPost, "/web/compose", nil)
		req.AddCookie(loginSessionCookie(t, h, "user@example.com"))
		auth.Require(h)(next).ServeHTTP(httptest.NewRecorder(), req)

		if token != "" {
			t.Fatalf("POST で CSRF トークンが生成されている: %q", token)
		}
	})

	t.Run("既存トークンがあれば作り直さない", func(t *testing.T) {
		t.Parallel()

		h := newCSRFTestHandler()
		var got string
		next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got = CSRFTokenFromContext(r.Context())
		})

		// 1 回目でトークンを作り、そのクッキーを 2 回目のリクエストへ引き継ぐ。
		firstReq := httptest.NewRequest(http.MethodGet, "/web/compose", nil)
		firstReq.AddCookie(loginSessionCookie(t, h, "user@example.com"))
		first := httptest.NewRecorder()
		auth.Require(h)(next).ServeHTTP(first, firstReq)
		firstToken := got

		req := httptest.NewRequest(http.MethodGet, "/web/compose", nil)
		for _, c := range first.Result().Cookies() {
			req.AddCookie(c)
		}
		auth.Require(h)(next).ServeHTTP(httptest.NewRecorder(), req)

		if got != firstToken {
			t.Fatalf("既存トークンが作り直されている: %q → %q", firstToken, got)
		}
	})
}

// loginSessionCookie は、ログイン済みセッションを表すクッキーを返します。
func loginSessionCookie(t *testing.T, h *Handler, email string) *http.Cookie {
	t.Helper()

	return seedSession(t, h.store, h.sessionName, map[string]string{DefaultUserSessionKey: email})
}

// CSRFTokenFromContext は、値が無いコンテキストでも空文字を返すこと。
func TestCSRFTokenFromContextWithoutValue(t *testing.T) {
	t.Parallel()

	if got := CSRFTokenFromContext(context.Background()); got != "" {
		t.Fatalf("CSRFTokenFromContext() = %q, want empty", got)
	}
}
