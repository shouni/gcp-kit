package auth_test

import (
	"errors"
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
// AllowedTaskServiceAccounts には、tasks.Config.ServiceAccountEmail と同じ
// サービスアカウントを指定します。audience の検証だけでは呼び出し元を
// 認証したことにならないため、この指定は必須です。
func ExampleHandler_TaskOIDCVerificationMiddleware() {
	h, err := auth.NewHandler(auth.Config{
		ClientID:                   "xxxxx.apps.googleusercontent.com",
		ClientSecret:               "secret",
		RedirectURL:                "https://app.example.com/auth/callback",
		SessionAuthKey:             "0123456789abcdef0123456789abcdef",
		SessionEncryptKey:          "0123456789abcdef",
		SessionName:                "app-session",
		TaskAudienceURL:            "https://app.example.com",
		AllowedTaskServiceAccounts: []string{"tasks@my-project.iam.gserviceaccount.com"},
	})
	if err != nil {
		slog.Error("failed to build auth handler", "error", err)
		return
	}

	worker := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if payload, ok := auth.OIDCPayloadFromContext(r.Context()); ok {
			slog.Info("task accepted", "caller", payload.Claims["email"])
		}
		w.WriteHeader(http.StatusOK)
	})

	mux := http.NewServeMux()
	mux.Handle("POST /tasks/run", h.TaskOIDCVerificationMiddleware(worker))
}

// M2M(サーバー間通信)を許可しつつ、ブラウザからのアクセスはセッション認証に
// フォールバックさせるミドルウェアの例です。
func ExampleM2MVerifier_Verify() {
	verifier := auth.NewM2MVerifier(
		"https://app.example.com",
		[]string{"caller@other-project.iam.gserviceaccount.com"},
	)

	protect := func(sessionChain, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			payload, err := verifier.Verify(r)
			if err == nil {
				slog.Debug("m2m accepted", "caller", payload.Claims["email"])
				next.ServeHTTP(w, r)
				return
			}
			// Bearer トークンを提示していないリクエストは通常のブラウザアクセスなので、
			// 失敗としてログに出さずセッション認証へ回します。
			if !errors.Is(err, auth.ErrM2MNotAttempted) {
				slog.Info("m2m verification failed", "error", err)
			}
			sessionChain.ServeHTTP(w, r)
		})
	}
	_ = protect
}
