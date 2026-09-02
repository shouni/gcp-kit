package session

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

	"golang.org/x/oauth2"

	"github.com/shouni/gcp-kit/auth"
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

	// 判定そのものを auth.VerifiedEmail に通します。同じ基準を書き写すのではなく
	// 同じ関数を呼ぶのは、片方だけが緩む余地を残さないためです。UserInfo API の
	// キーは ID トークンと違う（verified_email / email_verified）ので、詰め替えは
	// ここで行い、基準の判断は 1 か所に置きます。
	return auth.VerifiedEmail(map[string]any{
		"email":          u.Email,
		"email_verified": u.VerifiedEmail,
	})
}

// IssueSession は、email を認証済みの本人としてセッションを発行します。
// Callback がログイン成立時に行う保存と同じで、リダイレクトを書かない点だけが違います。
//
// 本人性は呼び出し元の責任です（ここでは検証しません）。許可リストの判定だけは
// Callback と同じく必ず通り、許可されない相手には発行せずエラーを返します。
//
// 公開しているのは、認証済みの画面を確かめるテストが OAuth の往復を偽装せずに
// ログイン状態を作れるようにするためです（WithCSRFToken と同じ理由）。
func (h *Handler) IssueSession(w http.ResponseWriter, r *http.Request, email string) error {
	if !h.isAuthorized(email) {
		return fmt.Errorf("issue session: %q is not authorized", email)
	}
	_, err := h.issueSession(w, r, email)
	return err
}

// issueSession は認証済みのセッションを保存し、ログイン後に戻る先を返します。
// Callback と IssueSession でセッションの作り方が枝分かれしないよう、ここに集めます。
func (h *Handler) issueSession(w http.ResponseWriter, r *http.Request, email string) (string, error) {
	session, err := h.store.Get(r, h.sessionName)
	if err != nil {
		h.log().WarnContext(r.Context(), "セッションの取得に失敗したため、新規セッションを作成します", "error", err)
	}
	if session == nil {
		return "", errors.New("session store returned nil session")
	}

	targetURL := "/"
	if url, ok := session.Values[DefaultRedirectSessionKey]; ok {
		delete(session.Values, DefaultRedirectSessionKey)
		// 保存時にも検証済みですが、セッションの中身を信用せず読み出し時にも確認します。
		if isSafeRelativePath(url) {
			targetURL = url
		}
	}

	// ログイン前のセッションに紐づく CSRF トークンは破棄し、認証済みセッション用に
	// 再生成させます（ログイン前に固定されたトークンを使い回させないため）。
	delete(session.Values, CSRFTokenKey)

	// ID も捨てて振り直させます（セッション固定攻撃対策）。攻撃者が仕込んだ ID の
	// まま認証済みにすると、その ID で被害者として振る舞えます。空の ID には Save が
	// 新しい ID を振ります（Store を参照）。
	//
	// 古い実体は消しません。認証前の値しか持たず、認証済みになることもないので、
	// TTL に任せます。
	session.ID = ""

	session.Values[DefaultUserSessionKey] = email
	if err := h.store.Save(r, w, session); err != nil {
		return "", fmt.Errorf("save session: %w", err)
	}
	return targetURL, nil
}

// isAuthorized はメールアドレスが許可リストまたは許可ドメインに含まれるか判定します。
func (h *Handler) isAuthorized(email string) bool {
	normalizedEmail := strings.ToLower(email)

	// 許可リストが空なら全員拒否します (fail-closed)。
	if len(h.allowedEmails) == 0 && len(h.allowedDomains) == 0 {
		return false
	}

	if _, ok := h.allowedEmails[normalizedEmail]; ok {
		return true
	}

	// ドメイン単位の判定に mail.ParseAddress を使いません。"Name <a@b.com>" 形式まで
	// 受け付けてしまい、許可リストと照合する値がずれるためです。
	i := strings.LastIndexByte(normalizedEmail, '@')
	if i <= 0 || i == len(normalizedEmail)-1 {
		return false
	}
	_, ok := h.allowedDomains[normalizedEmail[i+1:]]
	return ok
}

// clearSessionCookie はセッションを破棄します。MaxAge を負にして Save へ渡すので、
// クッキーの無効化と保存された実体の削除が同時に起きます。
func (h *Handler) clearSessionCookie(w http.ResponseWriter, r *http.Request) error {
	session, err := h.store.Get(r, h.sessionName)
	if err != nil {
		h.log().WarnContext(r.Context(), "Failed to get session on clear, proceeding with new session", "error", err)
	}
	if session == nil {
		return errors.New("session store returned nil session")
	}
	if session.Options == nil {
		session.Options = &Options{Path: "/"}
	}

	session.Options.MaxAge = -1 // クッキーを即時期限切れにする
	if err := h.store.Save(r, w, session); err != nil {
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
