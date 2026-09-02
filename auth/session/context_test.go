package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shouni/gcp-kit/auth"
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
		ctx := withEmail(context.Background(), "user@example.com")
		email, ok := EmailFromContext(ctx)
		if !ok || email != "user@example.com" {
			t.Fatalf("EmailFromContext() = (%q, %v)", email, ok)
		}
	})

	t.Run("empty string is not reported as present", func(t *testing.T) {
		t.Parallel()
		ctx := withEmail(context.Background(), "")
		if _, ok := EmailFromContext(ctx); ok {
			t.Fatal("EmailFromContext() ok = true, want false")
		}
	})
}

// TestAuthenticateInjectsEmail は、下流のハンドラーがセッションを再度開かずに
// 認証済みユーザーを参照できることを確認します。
func TestAuthenticateInjectsEmail(t *testing.T) {
	t.Parallel()

	store := newTestCookieStore()
	h := &Handler{store: store, sessionName: "test-session", allowedDomains: testAllowedDomains()}

	seedReq := httptest.NewRequest(http.MethodGet, "/", nil)
	seedRR := httptest.NewRecorder()
	session, err := store.Get(seedReq, h.sessionName)
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	session.Values[DefaultUserSessionKey] = "user@example.com"
	if err := h.store.Save(seedReq, seedRR, session); err != nil {
		t.Fatalf("store.Save() error = %v", err)
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
	auth.Require(h)(next).ServeHTTP(httptest.NewRecorder(), req)

	if !gotOK || gotEmail != "user@example.com" {
		t.Fatalf("EmailFromContext() = (%q, %v), want (user@example.com, true)", gotEmail, gotOK)
	}
}
