// Package oidc は、サービス間呼び出しの受信検証を提供します。
//
// Cloud Tasks からの呼び出しも、他サービスからの M2M 呼び出しも、Google 署名付きの
// OIDC ID トークンを Authorization: Bearer で提示する点は同じです。違うのは
// **合成のされ方**（拒否して止めるか、ブラウザセッションへ譲るか）だけなので、
// 検証器は 1 つにまとめ、その使い分けは auth.Require / auth.Protected が持ちます。
//
// このパッケージは OAuth2 の設定を要求しません。Web UI を持たない Worker が、
// 使いもしないクライアントシークレットへのアクセス権を持たずに受信検証できます。
package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/api/idtoken"

	"github.com/shouni/gcp-kit/auth"
)

// Verifier は、Google 署名の OIDC ID トークンを audience と
// サービスアカウント許可リストの両方に対して検証します。
//
// auth.Authenticator を満たすため、auth.Require（サービス専用のルート）にも
// auth.Protected（人とサービスが同じルートを使う場合）にも渡せます。
type Verifier struct {
	audience string
	allowed  map[string]struct{}
	validate validateFunc
}

// validateFunc は idtoken.Validate と同じシグネチャです。
// テストで差し替えるために関数フィールドとして保持します。
type validateFunc func(ctx context.Context, token, audience string) (*idtoken.Payload, error)

// New は Verifier を初期化します。
//
// allowedServiceAccounts が空の場合、検証は安全側に倒して常に失敗します（fail-closed）。
// 「許可リストが空 = 誰でも通す」にすると、設定を1つ書き忘れただけで
// 内部エンドポイントが開くためです。
func New(audience string, allowedServiceAccounts []string) *Verifier {
	return &Verifier{
		audience: audience,
		allowed:  toLowerMap(allowedServiceAccounts),
		validate: idtoken.Validate,
	}
}

// Configured は、検証に必要な設定（audience と許可リスト）が揃っているかを返します。
//
// 未設定の Verifier は常に検証失敗となり、auth.Protected では全ての呼び出しが
// セッション認証へフォールバックします。設定漏れが「なぜかエージェントだけ
// ログイン画面に飛ばされる」という分かりにくい形で現れるため、
// 起動時に落とせるよう公開しています。
func (v *Verifier) Configured() bool {
	return v != nil && strings.TrimSpace(v.audience) != "" && len(v.allowed) > 0
}

// Authenticate は auth.Authenticator を実装します。
//
// Bearer トークンが提示されていなければ auth.ErrNotAttempted を返し、
// 合成側に次の方式を試させます。検証器が未設定の場合は auth.ErrNotConfigured を
// 返すため、フォールバックではなく設定ミスとして扱われます。
//
// w は使いません。応答へ書き込む必要がある方式（セッションの更新など）と
// 口を揃えるために受け取っています。
func (v *Verifier) Authenticate(_ http.ResponseWriter, r *http.Request) (context.Context, error) {
	if !v.Configured() {
		return nil, auth.ErrNotConfigured
	}

	token, ok := extractBearerToken(r)
	if !ok {
		return nil, auth.ErrNotAttempted
	}

	payload, err := v.verifyToken(r.Context(), token)
	if err != nil {
		return nil, err
	}
	return withPayload(r.Context(), payload), nil
}

// verifyToken は署名・audience・email クレーム・許可リストの順に検証します。
func (v *Verifier) verifyToken(ctx context.Context, token string) (*idtoken.Payload, error) {
	validate := v.validate
	if validate == nil {
		validate = idtoken.Validate
	}

	payload, err := validate(ctx, token, v.audience)
	if err != nil {
		return nil, fmt.Errorf("oidc: token validation failed: %w", err)
	}
	if payload == nil {
		return nil, errors.New("oidc: token validation returned no payload")
	}

	// audience は誰でも指定できる文字列に過ぎないため、署名検証だけでは
	// 呼び出し元を特定できません。必ず email クレームで発行者を確認します。
	emailClaim, err := auth.VerifiedEmail(payload.Claims)
	if err != nil {
		return nil, err
	}

	if _, ok := v.allowed[strings.ToLower(emailClaim)]; !ok {
		return nil, fmt.Errorf("oidc: service account %q is not in the allowlist", emailClaim)
	}

	return payload, nil
}

// extractBearerToken は Authorization ヘッダーから "Bearer " プレフィックス
// （大文字小文字を区別しない）を除いたトークン本体を取り出します。
func extractBearerToken(r *http.Request) (token string, ok bool) {
	const prefix = "Bearer "
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < len(prefix) || !strings.EqualFold(authHeader[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(authHeader[len(prefix):]), true
}

// toLowerMap はスライス内の文字列を正規化（トリム + 小文字化）して map に格納します。
// 空白のみの要素は破棄します。環境変数から分割したリストに空要素が混ざっても、
// 許可リストが「空ではないが誰も許可しない」状態にならないようにするためです。
func toLowerMap(slice []string) map[string]struct{} {
	m := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			m[strings.ToLower(trimmed)] = struct{}{}
		}
	}
	return m
}
