package session

import "context"

// contextKey は本パッケージ専用のコンテキストキー型です。
// 他パッケージのキーと衝突しないよう、非公開型を使います。
type contextKey int

const (
	emailContextKey contextKey = iota
	csrfTokenContextKey
)

// withEmail は認証済みユーザーのメールアドレスをコンテキストに格納します。
func withEmail(ctx context.Context, email string) context.Context {
	return context.WithValue(ctx, emailContextKey, email)
}

// EmailFromContext は Authenticate が格納した認証済みユーザーのメールアドレスを返します。
// 認証を通過していないリクエストでは ok=false になります。
func EmailFromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(emailContextKey).(string)
	return email, ok && email != ""
}

// WithCSRFToken は、テンプレートへ埋め込むための CSRF トークンをコンテキストに格納します。
//
// 通常は Authenticate が呼ぶため、利用側が直接使う必要はありません。公開しているのは、
// テンプレートの描画だけを確かめるテストが、認証を一往復させずにトークンを載せられる
// ようにするためです（実際に姉妹アプリのテストがそう使っています）。
func WithCSRFToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, csrfTokenContextKey, token)
}

// CSRFTokenFromContext は Authenticate が格納した CSRF トークンを返します。
// フォームの hidden フィールドやメタタグへ埋め込む用途を想定しています。
//
// EmailFromContext と違い ok を返さないのは、「トークンが無い」が異常ではないためです。
// 空文字はそのまま描画して差し支えなく、有無で分岐する呼び出し側もありません。
// 認証の有無を表す EmailFromContext とは、空値の意味が違います。
func CSRFTokenFromContext(ctx context.Context) string {
	token, _ := ctx.Value(csrfTokenContextKey).(string)
	return token
}
