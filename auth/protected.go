package auth

import (
	"errors"
	"net/http"
)

// ProtectedMiddleware は、M2M（OIDC Bearer）とブラウザセッションの二経路で
// 保護されたルートを守るミドルウェアを返します。
//
// 有効な M2M トークンを提示したリクエストはセッション認証と CSRF 検証をバイパスし、
// 検証済みペイロードをコンテキストへ載せて次へ進みます（OIDCPayloadFromContext で参照可能）。
// トークンを提示していない、または検証に失敗したリクエストは Middleware
// （セッション認証 + CSRF 検証 + CSRFContextMiddleware）へフォールバックします。
//
// この合成をライブラリ側に置いているのは、同じ組み立てを各サービスが書くと
// 認証経路が散らばり、片方だけ強化されてドリフトするためです。ErrM2MNotAttempted は
// まさにこのフォールバックを書けるようにするために存在します。
//
// m2m が nil の場合は常にセッション認証になります（M2MVerifier.Verify が
// nil レシーバーを ErrM2MNotAttempted として扱うため）。
//
// M2M 経路が CSRF 検証を通らないのは、CSRF がブラウザのクッキー自動送出を悪用する
// 攻撃への対策であり、Bearer トークンを明示的に付けるサーバー間呼び出しには
// 当てはまらないためです。代わりに呼び出し元はサービスアカウント許可リストで絞られます。
func (h *Handler) ProtectedMiddleware(m2m *M2MVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		sessionChain := h.Middleware(h.CSRFContextMiddleware(next))

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			payload, err := m2m.Verify(r)
			if err == nil {
				h.log().DebugContext(r.Context(), "M2M認証成功",
					"email", payload.Claims["email"], "path", r.URL.Path)
				next.ServeHTTP(w, r.WithContext(WithOIDCPayload(r.Context(), payload)))
				return
			}

			// ブラウザなど、そもそも M2M を試みていないリクエストはノイズになるためログしない。
			if !errors.Is(err, ErrM2MNotAttempted) {
				h.log().InfoContext(r.Context(), "M2M認証失敗、セッション認証にフォールバック",
					"error", err, "path", r.URL.Path)
			}
			sessionChain.ServeHTTP(w, r)
		})
	}
}

// CSRFContextMiddleware は、セッションが保持する CSRF トークンをコンテキストへ載せます。
// トークンがまだ無い GET リクエストでは新規に生成してセッションへ保存します。
//
// 生成を GET に限るのは、トークンを持たない状態変更リクエストに正当なトークンを
// 与えてしまうと、CSRF 検証そのものが意味をなさなくなるためです。検証は
// Middleware が行うため、このミドルウェアは検証を行いません。
func (h *Handler) CSRFContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := h.GetCSRFTokenFromSession(r)
		if token == "" && r.Method == http.MethodGet {
			generated, err := h.GenerateAndSaveCSRFToken(w, r)
			if err != nil {
				h.log().ErrorContext(r.Context(), "CSRFトークンの自動生成に失敗", "error", err, "path", r.URL.Path)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			token = generated
		}

		next.ServeHTTP(w, r.WithContext(WithCSRFToken(r.Context(), token)))
	})
}
