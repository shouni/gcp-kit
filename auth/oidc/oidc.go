// Package oidc は、サービス間呼び出しの受信検証を提供します。
//
// Cloud Tasks からの呼び出しも、他サービスからの M2M 呼び出しも、Google 署名付きの
// OIDC ID トークンを Authorization: Bearer で提示する点は同じです。違うのは
// 合成のされ方（拒否して止めるか、ブラウザセッションへ譲るか）だけなので、
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

// 検証失敗の種類。RFC 6750, Section 3.1 の error コードと状態コードに対応させるために分けています。
// トークンが壊れている（401・取り直せば直る）のと、呼び出し元が許可されていない
// （403・取り直しても直らない）のとでは、クライアントが次に取るべき行動が違います。
var (
	errInvalidToken = errors.New("oidc: invalid token")
	errNotAllowed   = errors.New("oidc: caller is not allowed")
)

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
// 起動時に落とせるよう公開しています。未設定のまま動かすと全ての呼び出しが
// セッション認証へフォールバックし、設定漏れが分かりにくい形で現れます。
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
		return nil, fmt.Errorf("%w: %w", errInvalidToken, err)
	}
	if payload == nil {
		return nil, fmt.Errorf("%w: validation returned no payload", errInvalidToken)
	}

	// audience は誰でも指定できる文字列に過ぎないため、署名検証だけでは
	// 呼び出し元を特定できません。必ず email クレームで発行者を確認します。
	emailClaim, err := auth.VerifiedEmail(payload.Claims)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidToken, err)
	}

	if _, ok := v.allowed[strings.ToLower(emailClaim)]; !ok {
		return nil, fmt.Errorf("%w: service account %q", errNotAllowed, emailClaim)
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

// toLowerMap は許可リストを正規化（トリム + 小文字化）して map にします。
// 空白のみの要素を捨てるのは、環境変数を分割した値に空要素が混ざっても、
// 「空ではないが誰も許可しない」リストにならないようにするためです。
func toLowerMap(slice []string) map[string]struct{} {
	m := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			m[strings.ToLower(trimmed)] = struct{}{}
		}
	}
	return m
}

// Challenge は auth.Challenger を実装し、RFC 6750 に沿った応答を返します。
//
// RFC 9110, Section 15.5.2 は、401 を返すサーバーが WWW-Authenticate を送ることを要求します。
// これが無いと、クライアントは「このリソースが Bearer を受け付ける」ことを知る手段が
// ありません。状態コードは RFC 6750, Section 3.1 の対応に従います。
//
//   - 資格情報なし:       401 Bearer
//   - トークンが不正:     401 error="invalid_token"（取り直せば直る）
//   - 呼び出し元が不許可: 403 error="insufficient_scope"（取り直しても直らない）
//   - 検証器が未設定:     500。サーバー側の落ち度なのでチャレンジは返しません
func (v *Verifier) Challenge(w http.ResponseWriter, _ *http.Request, err error) {
	switch {
	case errors.Is(err, auth.ErrNotConfigured):
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	case errors.Is(err, auth.ErrNotAttempted):
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	case errors.Is(err, errNotAllowed):
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	default:
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	}
}
