package auth_test

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/shouni/gcp-kit/auth"
)

// Handler をブラウザ向けのログイン・セッション認証に使う最小構成です。
func ExampleNewHandler() {
	h, err := auth.NewHandler(auth.Config{
		ClientID:          "xxxxx.apps.googleusercontent.com",
		ClientSecret:      "secret",
		RedirectURL:       "https://app.example.com/auth/callback",
		SessionAuthKey:    "0123456789abcdef0123456789abcdef", // 16バイト以上
		SessionEncryptKey: "0123456789abcdef",                 // 16/24/32バイト
		SessionName:       "app-session",
		IsSecureCookie:    true,
		AllowedDomains:    []string{"example.com"},
	})
	if err != nil {
		slog.Error("failed to build auth handler", "error", err)
		return
	}

	mux := http.NewServeMux()
	// Login / Callback / Logout をまとめて登録します。
	mux.Handle("/auth/", h.Routes())

	// 保護したいハンドラーを Middleware で包みます。
	mux.Handle("/private", h.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email, _ := auth.EmailFromContext(r.Context())
		_, _ = fmt.Fprintf(w, "hello %s", email)
	})))
}

// Cloud Tasks からの呼び出しを受けるワーカーエンドポイントの保護方法です。
//
// 許可サービスアカウントには tasks.Config.ServiceAccountEmail と同じものを指定します。
// audience は誰でも指定できる文字列に過ぎず、それだけでは呼び出し元を認証したことに
// ならないため、この指定は必須です（空なら常に検証失敗＝ fail-closed）。
//
// TaskVerifier は OAuth 設定を要求しないため、Web UI を持たない Worker プロセスでも
// 使えます。使いもしない OAuth シークレットへのアクセス権を配らずに済みます。
func ExampleTaskVerifier_Middleware() {
	verifier := auth.NewTaskVerifier(
		"https://worker.example.com",
		[]string{"tasks@my-project.iam.gserviceaccount.com"},
	)
	if !verifier.Configured() {
		slog.Error("task verification is not configured")
		return
	}

	worker := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if payload, ok := auth.OIDCPayloadFromContext(r.Context()); ok {
			slog.Info("task accepted", "caller", payload.Claims["email"])
		}
		w.WriteHeader(http.StatusOK)
	})

	mux := http.NewServeMux()
	mux.Handle("POST /tasks/run", verifier.Middleware(worker))
}

// M2M(サーバー間通信)を許可しつつ、ブラウザからのアクセスはセッション認証へ
// フォールバックさせる例です。
//
// 有効な OIDC Bearer トークンを提示した呼び出しはセッション認証と CSRF 検証を
// バイパスし、それ以外はブラウザのログインへ回ります。CSRF トークンは
// コンテキストへ載るので、テンプレートからは CSRFTokenFromContext で取り出せます。
func ExampleHandler_ProtectedMiddleware() {
	h, err := auth.NewHandler(auth.Config{
		ClientID:          "xxxxx.apps.googleusercontent.com",
		ClientSecret:      "secret",
		RedirectURL:       "https://app.example.com/auth/callback",
		SessionAuthKey:    "0123456789abcdef0123456789abcdef",
		SessionEncryptKey: "0123456789abcdef",
		SessionName:       "app-session",
		AllowedDomains:    []string{"example.com"},
	})
	if err != nil {
		slog.Error("failed to build auth handler", "error", err)
		return
	}

	m2m := auth.NewM2MVerifier(
		"https://app.example.com",
		[]string{"caller@other-project.iam.gserviceaccount.com"},
	)

	page := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "<input name=%q value=%q>", "csrf_token", auth.CSRFTokenFromContext(r.Context()))
	})

	mux := http.NewServeMux()
	mux.Handle("/private", h.ProtectedMiddleware(m2m)(page))
}
