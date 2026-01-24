package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"

	"golang.org/x/oauth2"
)

// fetchUserEmail は Google UserInfo API を呼び出してメールアドレスを取得します。
func (h *Handler) fetchUserEmail(ctx context.Context, token *oauth2.Token) (string, error) {
	client := h.oauthConfig.Client(ctx, token)
	resp, err := client.Get(googleUserInfoURL)
	if err != nil {
		return "", fmt.Errorf("Google UserInfo API へのアクセスに失敗: %w", err)
	}
	defer resp.Body.Close()

	var u googleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return "", fmt.Errorf("UserInfo レスポンスの解析に失敗: %w", err)
	}

	// [Minor] 修正: 検証済みでない場合は明示的なエラーを返す
	if !u.VerifiedEmail {
		return "", fmt.Errorf("email %q is not verified", u.Email)
	}
	return u.Email, nil
}

// isAuthorized はメールアドレスが許可リストまたは許可ドメインに含まれるか判定します。
func (h *Handler) isAuthorized(email string) bool {
	// 比較のために小文字に正規化
	normalizedEmail := strings.ToLower(email)

	// 許可リストが空の場合は、安全のために全員拒否する (fail-closed)
	if len(h.allowedEmails) == 0 && len(h.allowedDomains) == 0 {
		return false
	}

	// メールアドレスそのものが許可されているか
	if _, ok := h.allowedEmails[normalizedEmail]; ok {
		return true
	}

	// ドメイン単位での許可判定
	addr, err := mail.ParseAddress(normalizedEmail)
	if err == nil {
		// strings.LastIndexByte を使用して効率的にドメインを抽出
		if i := strings.LastIndexByte(addr.Address, '@'); i != -1 {
			domain := addr.Address[i+1:]
			if _, ok := h.allowedDomains[domain]; ok {
				return true
			}
		}
	}
	return false
}

// clearSessionCookie はセッションクッキーを無効化（削除）します。
func (h *Handler) clearSessionCookie(w http.ResponseWriter, r *http.Request) error {
	session, err := h.store.Get(r, h.sessionName)
	if err != nil {
		slog.Warn("Failed to get session on clear, proceeding with new session", "error", err)
	}

	session.Options.MaxAge = -1 // クッキーを即時期限切れにする
	if err := session.Save(r, w); err != nil {
		slog.Error("Failed to save session for clearing cookie", "error", err)
		return err // エラーを呼び出し元に返す
	}
	return nil
}

// toLowerMap はスライス内の文字列を小文字に変換して map に格納します。
func toLowerMap(slice []string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, s := range slice {
		if s != "" {
			m[strings.ToLower(s)] = struct{}{}
		}
	}
	return m
}

// generateState は CSRF 対策のためのランダムな state 文字列を生成します。
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
