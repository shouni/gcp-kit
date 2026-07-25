package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLogout(t *testing.T) {
	t.Parallel()

	newSeededRequest := func(t *testing.T, h *Handler, target string) *http.Request {
		t.Helper()

		seedReq := httptest.NewRequest(http.MethodGet, "/", nil)
		seedRR := httptest.NewRecorder()
		session, err := h.store.Get(seedReq, h.sessionName)
		if err != nil {
			t.Fatalf("store.Get() error = %v", err)
		}
		session.Values[DefaultUserSessionKey] = "user@example.com"
		if err := session.Save(seedReq, seedRR); err != nil {
			t.Fatalf("session.Save() error = %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, target, nil)
		for _, c := range seedRR.Result().Cookies() {
			req.AddCookie(c)
		}
		return req
	}

	t.Run("expires the session cookie and redirects to login", func(t *testing.T) {
		t.Parallel()
		h := &Handler{store: newTestCookieStore(), sessionName: "test-session"}
		req := newSeededRequest(t, h, "/auth/logout")
		rr := httptest.NewRecorder()

		h.Logout(rr, req)

		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusSeeOther)
		}
		if loc := rr.Header().Get("Location"); loc != DefaultLoginPath {
			t.Fatalf("Location = %q, want %q", loc, DefaultLoginPath)
		}

		cookies := rr.Result().Cookies()
		if len(cookies) == 0 {
			t.Fatal("expected the session cookie to be cleared")
		}
		if cookies[0].MaxAge != -1 {
			t.Fatalf("MaxAge = %d, want -1", cookies[0].MaxAge)
		}
	})

	t.Run("honours a safe redirect_to", func(t *testing.T) {
		t.Parallel()
		h := &Handler{store: newTestCookieStore(), sessionName: "test-session"}
		req := newSeededRequest(t, h, "/auth/logout?redirect_to=/goodbye")
		rr := httptest.NewRecorder()

		h.Logout(rr, req)

		if loc := rr.Header().Get("Location"); loc != "/goodbye" {
			t.Fatalf("Location = %q, want %q", loc, "/goodbye")
		}
	})

	// オープンリダイレクタを避けるため、外部URLやスキーマ相対URLは無視します。
	t.Run("ignores unsafe redirect_to", func(t *testing.T) {
		t.Parallel()

		for _, target := range []string{"//evil.com", "https://evil.com/x", "relative"} {
			h := &Handler{store: newTestCookieStore(), sessionName: "test-session"}
			req := httptest.NewRequest(http.MethodGet, "/auth/logout?redirect_to="+target, nil)
			rr := httptest.NewRecorder()

			h.Logout(rr, req)

			if loc := rr.Header().Get("Location"); loc != DefaultLoginPath {
				t.Fatalf("redirect_to=%q gave Location = %q, want %q", target, loc, DefaultLoginPath)
			}
		}
	})

	// セッションが壊れていてもログアウト自体は成立させます。
	t.Run("redirects even when the session cannot be cleared", func(t *testing.T) {
		t.Parallel()
		h := &Handler{store: nilSessionStore{}, sessionName: "test-session"}
		req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		rr := httptest.NewRecorder()

		h.Logout(rr, req)

		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusSeeOther)
		}
	})
}
