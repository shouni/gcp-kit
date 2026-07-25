package auth

import (
	"context"

	"google.golang.org/api/idtoken"
)

// contextKey は本パッケージ専用のコンテキストキー型です。
// 他パッケージのキーと衝突しないよう、非公開型を使います。
type contextKey int

const (
	emailContextKey contextKey = iota
	oidcPayloadContextKey
)

// WithEmail は認証済みユーザーのメールアドレスをコンテキストに格納します。
// Middleware が自動的に呼び出すため、通常は利用側が直接呼ぶ必要はありません。
func WithEmail(ctx context.Context, email string) context.Context {
	return context.WithValue(ctx, emailContextKey, email)
}

// EmailFromContext は Middleware が格納した認証済みユーザーのメールアドレスを返します。
// 認証を通過していないリクエストでは ok=false になります。
func EmailFromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(emailContextKey).(string)
	return email, ok && email != ""
}

// WithOIDCPayload は検証済み OIDC トークンのペイロードをコンテキストに格納します。
func WithOIDCPayload(ctx context.Context, payload *idtoken.Payload) context.Context {
	return context.WithValue(ctx, oidcPayloadContextKey, payload)
}

// OIDCPayloadFromContext は TaskOIDCVerificationMiddleware が格納した検証済み
// OIDC ペイロードを返します。呼び出し元サービスアカウントの特定などに使えます。
func OIDCPayloadFromContext(ctx context.Context) (*idtoken.Payload, bool) {
	payload, ok := ctx.Value(oidcPayloadContextKey).(*idtoken.Payload)
	return payload, ok && payload != nil
}
