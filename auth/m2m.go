package auth

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"google.golang.org/api/idtoken"
)

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

// Authorized は、リクエストが許可済みサービスアカウントの有効なOIDCトークンを
// 保持しているかを検証します。
func (v *M2MVerifier) Authorized(r *http.Request) bool {
	if v == nil || len(v.allowed) == 0 {
		return false
	}

	authHeader := r.Header.Get("Authorization")
	if len(authHeader) < 7 || !strings.EqualFold(authHeader[:7], "Bearer ") {
		return false
	}
	token := authHeader[7:]

	payload, err := v.validate(r.Context(), token, v.audience)
	if err != nil {
		// クライアント起因（未認証スキャン等）で日常的に発生しうるため Warn ではなく Info に留める。
		slog.Info("M2Mトークン検証失敗", "error", err)
		return false
	}

	emailClaim, ok := payload.Claims["email"].(string)
	emailVerified, _ := payload.Claims["email_verified"].(bool)
	if !ok || emailClaim == "" || !emailVerified {
		slog.Info("M2Mトークンに有効なemailクレームがありません", "sub", payload.Subject)
		return false
	}

	if _, ok := v.allowed[strings.ToLower(emailClaim)]; !ok {
		slog.Info("M2M呼び出し元が許可リストに存在しません", "email", emailClaim)
		return false
	}

	slog.Debug("M2M認証成功", "email", emailClaim)
	return true
}
