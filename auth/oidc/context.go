package oidc

import (
	"context"

	"google.golang.org/api/idtoken"
)

// contextKey は本パッケージ専用のコンテキストキー型です。
// 他パッケージのキーと衝突しないよう、非公開型を使います。
type contextKey int

const payloadContextKey contextKey = iota

// withPayload は検証済み OIDC トークンのペイロードをコンテキストに格納します。
func withPayload(ctx context.Context, payload *idtoken.Payload) context.Context {
	return context.WithValue(ctx, payloadContextKey, payload)
}

// PayloadFromContext は、Verifier が格納した検証済みペイロードを返します。
// 呼び出し元サービスアカウントの特定などに使えます。
func PayloadFromContext(ctx context.Context) (*idtoken.Payload, bool) {
	payload, ok := ctx.Value(payloadContextKey).(*idtoken.Payload)
	return payload, ok && payload != nil
}
