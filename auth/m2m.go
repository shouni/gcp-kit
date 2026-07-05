package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/api/idtoken"
)

// ErrM2MNotAttempted は、M2M検証器が未設定、またはリクエストがそもそも
// M2M(OIDC Bearer)呼び出しを試みていない（Authorizationヘッダーが無い等）ことを示します。
// 呼び出し側はこのエラーを通常のフォールバック経路（例: ブラウザセッション認証）として扱い、
// 失敗ログを出す必要はありません。
var ErrM2MNotAttempted = errors.New("m2m: no bearer token presented")

// M2MVerifier は、サーバー間通信（他サービスからの呼び出し）を
// GCP署名付きIDトークン（OIDC Bearer）で検証します。
// ブラウザセッションを前提とする Handler とは独立して利用できます。
type M2MVerifier struct {
	audience string
	allowed  map[string]struct{}
	validate func(ctx context.Context, token, audience string) (*idtoken.Payload, error)
}

// NewM2MVerifier は M2MVerifier を初期化します。allowedServiceAccounts が空の場合、
// M2M認証は安全側に倒して常に失敗します（fail-closed）。
func NewM2MVerifier(audience string, allowedServiceAccounts []string) *M2MVerifier {
	return &M2MVerifier{
		audience: audience,
		allowed:  toLowerMap(allowedServiceAccounts),
		validate: idtoken.Validate,
	}
}

// Verify は、リクエストが保持するOIDC Bearerトークンを検証し、許可済みサービスアカウントからの
// 呼び出しであればそのペイロードを返します。失敗時は理由を示すエラーを返すのみで、ロギングは
// 呼び出し側に委ねます（トークン欠損などM2Mを試みていない呼び出しは ErrM2MNotAttempted を返すため、
// 呼び出し側は errors.Is で本当に失敗したM2M呼び出しとを区別してログできます）。
func (v *M2MVerifier) Verify(r *http.Request) (*idtoken.Payload, error) {
	if v == nil || len(v.allowed) == 0 {
		return nil, ErrM2MNotAttempted
	}

	token, ok := extractBearerToken(r)
	if !ok {
		return nil, ErrM2MNotAttempted
	}

	payload, err := v.validate(r.Context(), token, v.audience)
	if err != nil {
		return nil, fmt.Errorf("m2m: token validation failed: %w", err)
	}

	emailClaim, ok := payload.Claims["email"].(string)
	emailVerified, _ := payload.Claims["email_verified"].(bool)
	if !ok || emailClaim == "" || !emailVerified {
		return nil, fmt.Errorf("m2m: token has no verified email claim (verified=%t)", emailVerified)
	}

	if _, ok := v.allowed[strings.ToLower(emailClaim)]; !ok {
		return nil, fmt.Errorf("m2m: service account %q is not in the allowlist", emailClaim)
	}

	return payload, nil
}
