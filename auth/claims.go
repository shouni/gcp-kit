package auth

import (
	"errors"
	"fmt"
)

// VerifiedEmail は、Google の ID トークンのクレームから検証済みメールアドレスを取り出します。
//
// 未検証のメールアドレスは、その所有者であることを保証しません。ログイン
// （auth/session の OAuth コールバック）と、サービス間検証（auth/oidc）で
// 同じ基準を適用するために、判定はここに 1 つだけ置いています。片方だけが
// 緩むと、緩んだ側から他人のアドレスを名乗れます。
func VerifiedEmail(claims map[string]any) (string, error) {
	email, ok := claims["email"].(string)
	if !ok || email == "" {
		return "", errors.New("auth: token has no email claim")
	}
	if verified, _ := claims["email_verified"].(bool); !verified {
		return "", fmt.Errorf("auth: email %q is not verified", email)
	}
	return email, nil
}
