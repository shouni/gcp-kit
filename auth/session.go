package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

// userInfoBodyLimit は UserInfo レスポンスとして読み込む最大バイト数です。
// 想定される応答は数百バイトのため、異常な応答でメモリを消費しないよう制限します。
const userInfoBodyLimit = 64 << 10

// fetchUserEmail は Google UserInfo API を呼び出してメールアドレスを取得します。
func (h *Handler) fetchUserEmail(ctx context.Context, token *oauth2.Token) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleUserInfoURL, nil)
	if err != nil {
		return "", fmt.Errorf("UserInfo リクエストの生成に失敗: %w", err)
	}

	client := h.oauthConfig.Client(ctx, token)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("google UserInfo API へのアクセスに失敗: %w", err)
	}
	defer resp.Body.Close()

	// ステータスを先に確認します。エラー応答をそのままデコードすると
	// 「メールアドレスが未検証」という実態と異なるエラーになってしまいます。
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("google UserInfo API returned status %d", resp.StatusCode)
	}

	var u googleUserInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, userInfoBodyLimit)).Decode(&u); err != nil {
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

	// ドメイン単位での許可判定。
	// mail.ParseAddress は "Name <a@b.com>" 形式も受け付けてしまうため、
	// 許可リスト照合に使う値と一致させる目的でここでは使いません。
	i := strings.LastIndexByte(normalizedEmail, '@')
	if i <= 0 || i == len(normalizedEmail)-1 {
		return false
	}
	_, ok := h.allowedDomains[normalizedEmail[i+1:]]
	return ok
}

// clearSessionCookie はセッションクッキーを無効化（削除）します。
func (h *Handler) clearSessionCookie(w http.ResponseWriter, r *http.Request) error {
	session, err := h.store.Get(r, h.sessionName)
	if err != nil {
		h.log().WarnContext(r.Context(), "Failed to get session on clear, proceeding with new session", "error", err)
	}
	if session == nil {
		return errors.New("session store returned nil session")
	}
	if session.Options == nil {
		session.Options = &sessions.Options{Path: "/"}
	}

	session.Options.MaxAge = -1 // クッキーを即時期限切れにする
	if err := session.Save(r, w); err != nil {
		h.log().ErrorContext(r.Context(), "Failed to save session for clearing cookie", "error", err)
		return err // エラーを呼び出し元に返す
	}
	return nil
}

// randomToken は 32 バイトの暗号論的乱数を生成し、指定エンコーディングで文字列化します。
// state パラメータや CSRF トークンなど、推測不可能なランダム文字列が必要な箇所で共通利用します。
func randomToken(encoding *base64.Encoding) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return encoding.EncodeToString(b), nil
}

// generateState は CSRF 対策のためのランダムな state 文字列を生成します。
func generateState() (string, error) {
	return randomToken(base64.URLEncoding)
}
