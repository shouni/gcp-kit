package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEmailFromContext(t *testing.T) {
	t.Parallel()

	t.Run("absent", func(t *testing.T) {
		t.Parallel()
		if _, ok := EmailFromContext(context.Background()); ok {
			t.Fatal("EmailFromContext() ok = true, want false")
		}
	})

	t.Run("present", func(t *testing.T) {
		t.Parallel()
		ctx := WithEmail(context.Background(), "user@example.com")
		email, ok := EmailFromContext(ctx)
		if !ok || email != "user@example.com" {
			t.Fatalf("EmailFromContext() = (%q, %v)", email, ok)
		}
	})

	t.Run("empty string is not reported as present", func(t *testing.T) {
		t.Parallel()
		ctx := WithEmail(context.Background(), "")
		if _, ok := EmailFromContext(ctx); ok {
			t.Fatal("EmailFromContext() ok = true, want false")
		}
	})
}

func TestOIDCPayloadFromContextAbsent(t *testing.T) {
	t.Parallel()

	if _, ok := OIDCPayloadFromContext(context.Background()); ok {
		t.Fatal("OIDCPayloadFromContext() ok = true, want false")
	}
}

// TestMiddlewareInjectsEmail は、下流のハンドラーがセッションを再度開かずに
// 認証済みユーザーを参照できることを確認します。
func TestMiddlewareInjectsEmail(t *testing.T) {
	t.Parallel()

	store := newTestCookieStore()
	h := &Handler{store: store, sessionName: "test-session"}

	seedReq := httptest.NewRequest(http.MethodGet, "/", nil)
	seedRR := httptest.NewRecorder()
	session, err := store.Get(seedReq, h.sessionName)
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	session.Values[DefaultUserSessionKey] = "user@example.com"
	if err := session.Save(seedReq, seedRR); err != nil {
		t.Fatalf("session.Save() error = %v", err)
	}

	var gotEmail string
	var gotOK bool
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotEmail, gotOK = EmailFromContext(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/private", nil)
	for _, c := range seedRR.Result().Cookies() {
		req.AddCookie(c)
	}
	h.Middleware(next).ServeHTTP(httptest.NewRecorder(), req)

	if !gotOK || gotEmail != "user@example.com" {
		t.Fatalf("EmailFromContext() = (%q, %v), want (user@example.com, true)", gotEmail, gotOK)
	}
}
