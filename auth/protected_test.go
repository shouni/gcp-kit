package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/api/idtoken"
)

// newProtectedTestHandler は、セッションストアだけを備えた Handler を返します。
// OAuth 設定は経路の分岐に関係しないため設定しません。
func newProtectedTestHandler() *Handler {
	return &Handler{store: newTestCookieStore(), sessionName: "test-session"}
}

// newTestM2M は、検証結果を固定した M2MVerifier を返します。
func newTestM2M(email string, err error) *M2MVerifier {
	v := NewM2MVerifier("https://service.example.com", []string{"caller@project.iam.gserviceaccount.com"})
	v.verifier.validate = stubM2MValidate(email, err)
	return v
}

// 有効な M2M トークンはセッション認証と CSRF 検証をバイパスし、
// 検証済みペイロードをコンテキストへ載せて次のハンドラーへ進むこと。
func TestProtectedMiddlewareBypassesSessionForValidM2M(t *testing.T) {
	t.Parallel()

	h := newProtectedTestHandler()
	var gotPayload *idtoken.Payload
	reached := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		reached = true
		gotPayload, _ = OIDCPayloadFromContext(r.Context())
	})

	// セッションを持たない POST。セッション認証へ落ちればリダイレクトされる。
	req := httptest.NewRequest(http.MethodPost, "https://service.example.com/web/compose", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	h.ProtectedMiddleware(newTestM2M("caller@project.iam.gserviceaccount.com", nil))(next).ServeHTTP(rec, req)

	if !reached {
		t.Fatal("有効な M2M トークンで保護ルートに到達していない")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if gotPayload == nil {
		t.Fatal("検証済みペイロードがコンテキストに載っていない")
	}
	if got := gotPayload.Claims["email"]; got != "caller@project.iam.gserviceaccount.com" {
		t.Fatalf("payload email = %v", got)
	}
}

// M2M を試みていないリクエスト（Bearer なし）はセッション認証へフォールバックすること。
func TestProtectedMiddlewareFallsBackWithoutBearer(t *testing.T) {
	t.Parallel()

	h := newProtectedTestHandler()
	reached := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })

	req := httptest.NewRequest(http.MethodGet, "https://service.example.com/web/history", nil)
	rec := httptest.NewRecorder()

	h.ProtectedMiddleware(newTestM2M("caller@project.iam.gserviceaccount.com", nil))(next).ServeHTTP(rec, req)

	if reached {
		t.Fatal("未認証リクエストが保護ルートに到達している")
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d (ログインへのリダイレクト)", rec.Code, http.StatusFound)
	}
}

// 不正な Bearer トークンで M2M 経路をすり抜けられないこと。
//
// M2M 経路はセッション認証と CSRF 検証の両方をバイパスするため、ここが破れると
// 認証なしで状態変更エンドポイントを叩けてしまいます。
func TestProtectedMiddlewareRejectsInvalidBearer(t *testing.T) {
	t.Parallel()

	h := newProtectedTestHandler()
	reached := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })

	req := httptest.NewRequest(http.MethodPost, "https://service.example.com/web/compose", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rec := httptest.NewRecorder()

	m2m := newTestM2M("", errors.New("signature mismatch"))
	h.ProtectedMiddleware(m2m)(next).ServeHTTP(rec, req)

	if reached {
		t.Fatal("不正な Bearer トークンで保護ルートに到達している")
	}
	if rec.Code == http.StatusOK {
		t.Fatalf("status = %d, want リクエストが拒否されること", rec.Code)
	}
}

// 許可リストに無いサービスアカウントは、署名が正しくても通らないこと。
// 署名検証だけでは呼び出し元を認証できない、という不変条件をこの経路でも守ります。
func TestProtectedMiddlewareRejectsDisallowedServiceAccount(t *testing.T) {
	t.Parallel()

	h := newProtectedTestHandler()
	reached := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })

	req := httptest.NewRequest(http.MethodPost, "https://service.example.com/web/compose", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	m2m := newTestM2M("stranger@evil.iam.gserviceaccount.com", nil)
	h.ProtectedMiddleware(m2m)(next).ServeHTTP(rec, req)

	if reached {
		t.Fatal("許可リスト外のサービスアカウントが保護ルートに到達している")
	}
}

// m2m が nil でもパニックせず、セッション認証だけになること。
func TestProtectedMiddlewareToleratesNilVerifier(t *testing.T) {
	t.Parallel()

	h := newProtectedTestHandler()
	reached := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })

	req := httptest.NewRequest(http.MethodGet, "https://service.example.com/web/history", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	h.ProtectedMiddleware(nil)(next).ServeHTTP(rec, req)

	if reached {
		t.Fatal("検証器が無いのに保護ルートへ到達している")
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
}

// セッション認証を通ったリクエストでは、CSRF トークンがコンテキストへ載ること。
func TestProtectedMiddlewarePutsCSRFTokenOnSessionPath(t *testing.T) {
	t.Parallel()

	h := newProtectedTestHandler()
	var token string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		token = CSRFTokenFromContext(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "https://service.example.com/web/history", nil)
	req.AddCookie(loginSessionCookie(t, h, "user@example.com"))
	rec := httptest.NewRecorder()

	h.ProtectedMiddleware(nil)(next).ServeHTTP(rec, req)

	if token == "" {
		t.Fatal("セッション経路で CSRF トークンがコンテキストに載っていない")
	}
}

func TestCSRFContextMiddleware(t *testing.T) {
	t.Parallel()

	t.Run("GET ではトークンを自動生成してコンテキストとセッションへ入れる", func(t *testing.T) {
		t.Parallel()

		h := newProtectedTestHandler()
		var token string
		next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			token = CSRFTokenFromContext(r.Context())
		})

		rec := httptest.NewRecorder()
		h.CSRFContextMiddleware(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/web/compose", nil))

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

		h := newProtectedTestHandler()
		var token string
		next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			token = CSRFTokenFromContext(r.Context())
		})

		rec := httptest.NewRecorder()
		h.CSRFContextMiddleware(next).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/web/compose", nil))

		if token != "" {
			t.Fatalf("POST で CSRF トークンが生成されている: %q", token)
		}
	})

	t.Run("既存トークンがあれば作り直さない", func(t *testing.T) {
		t.Parallel()

		h := newProtectedTestHandler()
		var got string
		next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got = CSRFTokenFromContext(r.Context())
		})

		// 1 回目でトークンを作り、そのクッキーを 2 回目のリクエストへ引き継ぐ。
		first := httptest.NewRecorder()
		h.CSRFContextMiddleware(next).ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/web/compose", nil))
		firstToken := got

		req := httptest.NewRequest(http.MethodGet, "/web/compose", nil)
		for _, c := range first.Result().Cookies() {
			req.AddCookie(c)
		}
		h.CSRFContextMiddleware(next).ServeHTTP(httptest.NewRecorder(), req)

		if got != firstToken {
			t.Fatalf("既存トークンが作り直されている: %q → %q", firstToken, got)
		}
	})
}

// loginSessionCookie は、ログイン済みセッションを表すクッキーを返します。
func loginSessionCookie(t *testing.T, h *Handler, email string) *http.Cookie {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	session, err := h.store.Get(req, h.sessionName)
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	session.Values[DefaultUserSessionKey] = email
	if err := session.Save(req, rec); err != nil {
		t.Fatalf("session.Save() error = %v", err)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("セッションクッキーが生成されていない")
	}
	return cookies[0]
}

// CSRFTokenFromContext は、値が無いコンテキストでも空文字を返すこと。
func TestCSRFTokenFromContextWithoutValue(t *testing.T) {
	t.Parallel()

	if got := CSRFTokenFromContext(context.Background()); got != "" {
		t.Fatalf("CSRFTokenFromContext() = %q, want empty", got)
	}
}
