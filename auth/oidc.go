package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/api/idtoken"
)

// ErrOIDCNotAttempted は、検証器が未設定、またはリクエストがそもそも OIDC Bearer 認証を
// 試みていない（Authorization ヘッダーが無い等）ことを示します。
var ErrOIDCNotAttempted = errors.New("oidc: no bearer token presented")

// validateFunc は idtoken.Validate と同じシグネチャです。テストで差し替えるために
// 関数フィールドとして保持します（CLAUDE.md の「interface/func-field seam」方針）。
type validateFunc func(ctx context.Context, token, audience string) (*idtoken.Payload, error)

// oidcVerifier は Google 署名の OIDC ID トークンを、audience と
// サービスアカウント許可リストの両方に対して検証します。
//
// M2MVerifier（他サービスからの呼び出し）と TaskVerifier（Cloud Tasks からの
// 呼び出し）は、どちらもこの型を通して検証を行います。
// 片方だけが強化される事故を避けるため、検証ロジックは意図的に一本化しています。
type oidcVerifier struct {
	audience string
	allowed  map[string]struct{}
	validate validateFunc
}

func newOIDCVerifier(audience string, allowedServiceAccounts []string) *oidcVerifier {
	return &oidcVerifier{
		audience: audience,
		allowed:  toLowerMap(allowedServiceAccounts),
		validate: idtoken.Validate,
	}
}

// configured は、検証に必要な設定（audience と許可リスト）が揃っているかを返します。
// 許可リストが空の場合は fail-closed のため未設定として扱います。
func (v *oidcVerifier) configured() bool {
	return v != nil && strings.TrimSpace(v.audience) != "" && len(v.allowed) > 0
}

// verifyRequest は Authorization ヘッダーの Bearer トークンを検証します。
// トークンが提示されていない場合は ErrOIDCNotAttempted を返します。
func (v *oidcVerifier) verifyRequest(r *http.Request) (*idtoken.Payload, error) {
	if !v.configured() {
		return nil, ErrOIDCNotAttempted
	}

	token, ok := extractBearerToken(r)
	if !ok {
		return nil, ErrOIDCNotAttempted
	}

	return v.verifyToken(r.Context(), token)
}

// verifyToken は署名・audience・email クレーム・許可リストの順に検証します。
func (v *oidcVerifier) verifyToken(ctx context.Context, token string) (*idtoken.Payload, error) {
	if !v.configured() {
		return nil, ErrOIDCNotAttempted
	}

	validate := v.validate
	if validate == nil {
		validate = idtoken.Validate
	}

	payload, err := validate(ctx, token, v.audience)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}
	if payload == nil {
		return nil, errors.New("token validation returned no payload")
	}

	// audience は誰でも指定できる文字列に過ぎないため、署名検証だけでは
	// 呼び出し元を特定できません。必ず email クレームで発行者を確認します。
	emailClaim, err := verifiedEmailFromClaims(payload.Claims)
	if err != nil {
		return nil, err
	}

	if _, ok := v.allowed[strings.ToLower(emailClaim)]; !ok {
		return nil, fmt.Errorf("service account %q is not in the allowlist", emailClaim)
	}

	return payload, nil
}

// verifiedEmailFromClaims は、検証済みの email クレームを取り出します。
// 未検証のメールアドレスはそのアドレスの所有者であることを保証しないため、
// ID トークン経由のログイン・M2M 検証・Cloud Tasks 検証のすべてで同じ基準を適用します。
func verifiedEmailFromClaims(claims map[string]any) (string, error) {
	emailClaim, ok := claims["email"].(string)
	if !ok || emailClaim == "" {
		return "", errors.New("token has no email claim")
	}
	if verified, _ := claims["email_verified"].(bool); !verified {
		return "", fmt.Errorf("email %q is not verified", emailClaim)
	}
	return emailClaim, nil
}

// extractBearerToken は Authorization ヘッダーから "Bearer " プレフィックス（大文字小文字を
// 区別しない）を除いたトークン本体を取り出します。プレフィックスが無い場合は ok=false を返します。
func extractBearerToken(r *http.Request) (token string, ok bool) {
	const prefix = "Bearer "
	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < len(prefix) || !strings.EqualFold(authHeader[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(authHeader[len(prefix):]), true
}
