package auth_test

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/shouni/gcp-kit/auth"
	"github.com/shouni/gcp-kit/auth/oidc"
	"github.com/shouni/gcp-kit/auth/session"
)

// Cloud Tasks からの呼び出しだけを受けるワーカーエンドポイントの保護です。
//
// 許可サービスアカウントには tasks.Config.ServiceAccountEmail と同じものを指定します。
// 空にすると常に検証失敗になります（理由は oidc.New を参照）。
//
// oidc は OAuth 設定を要求しないため、Web UI を持たない Worker プロセスでも使えます。
// 使いもしない OAuth シークレットへのアクセス権を配らずに済みます。
func ExampleRequire() {
	// 設定漏れはリクエスト時ではなく起動時に落とします。
	verifier, err := oidc.New(
		"https://worker.example.com",
		[]string{"tasks@my-project.iam.gserviceaccount.com"},
	)
	if err != nil {
		slog.Error("task verification is not configured", "error", err)
		return
	}

	worker := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if payload, ok := oidc.PayloadFromContext(r.Context()); ok {
			slog.Info("task accepted", "caller", payload.Claims["email"])
		}
		w.WriteHeader(http.StatusOK)
	})

	mux := http.NewServeMux()
	mux.Handle("POST /tasks/run", auth.Require(verifier)(worker))
}

// 人（ブラウザ）とサービス（エージェント）が同じルートを使う場合の構成です。
//
// 有効な OIDC Bearer トークンを提示した呼び出しはセッション認証と CSRF 検証を
// バイパスし、それ以外はブラウザのログインへ回ります。人向けの方式を最後に
// 置くと、どれも成立しなかったときログイン画面へ送られます。
func ExampleProtected() {
	handler, err := session.New(session.Config{
		ClientID:       "xxxxx.apps.googleusercontent.com",
		ClientSecret:   "secret",
		RedirectURL:    "https://app.example.com/auth/callback",
		SessionName:    "app-session",
		Store:          session.NewMemoryStore(session.StoreConfig{Secure: true}),
		IsSecureCookie: true,
		AllowedDomains: []string{"example.com"},
	})
	if err != nil {
		slog.Error("failed to build session handler", "error", err)
		return
	}

	verifier, err := oidc.New(
		"https://app.example.com",
		[]string{"caller@other-project.iam.gserviceaccount.com"},
	)
	if err != nil {
		slog.Error("failed to build verifier", "error", err)
		return
	}

	page := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CSRF トークンはセッション経路でのみコンテキストに載ります。
		_, _ = fmt.Fprintf(w, "<input name=%q value=%q>", "csrf_token", session.CSRFTokenFromContext(r.Context()))
	})

	mux := http.NewServeMux()
	mux.Handle("GET /auth/login", http.HandlerFunc(handler.Login))
	mux.Handle("GET /auth/callback", http.HandlerFunc(handler.Callback))
	mux.Handle("/private", auth.Protected(verifier, handler)(page))
}
