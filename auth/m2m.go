package auth

import (
	"errors"
	"fmt"
	"net/http"

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
	verifier *oidcVerifier
}

// NewM2MVerifier は M2MVerifier を初期化します。allowedServiceAccounts が空の場合、
// M2M認証は安全側に倒して常に失敗します（fail-closed）。
func NewM2MVerifier(audience string, allowedServiceAccounts []string) *M2MVerifier {
	return &M2MVerifier{verifier: newOIDCVerifier(audience, allowedServiceAccounts)}
}

// Verify は、リクエストが保持するOIDC Bearerトークンを検証し、許可済みサービスアカウントからの
// 呼び出しであればそのペイロードを返します。失敗時は理由を示すエラーを返すのみで、ロギングは
// 呼び出し側に委ねます（トークン欠損などM2Mを試みていない呼び出しは ErrM2MNotAttempted を返すため、
// 呼び出し側は errors.Is で本当に失敗したM2M呼び出しとを区別してログできます）。
func (v *M2MVerifier) Verify(r *http.Request) (*idtoken.Payload, error) {
	if v == nil {
		return nil, ErrM2MNotAttempted
	}

	payload, err := v.verifier.verifyRequest(r)
	if err != nil {
		if errors.Is(err, ErrOIDCNotAttempted) {
			return nil, ErrM2MNotAttempted
		}
		return nil, fmt.Errorf("m2m: %w", err)
	}
	return payload, nil
}
