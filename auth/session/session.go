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
	"net/url"
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

// session は、1 リクエスト分のセッションです。
//
// id が空なら、まだ保存されていない（または保存されている実体を採用しなかった）
// セッションで、saveSession が新しい ID を振ります。
type session struct {
	id     string
	values map[string]string
}

func newSession() *session { return &session{values: map[string]string{}} }

// loadSession は、クッキーが指すセッションを読み出します。
//
// 返す *session は常に非 nil です。エラーのときも、クッキーが運んできた ID を id に
// 持たせて返すので、呼び出し側はそのまま clearSession に渡して実体ごと消せます。
//
// ★ 保存されていない ID は採用しません。ID はクッキー経由で攻撃者が指定できるので、
// 採用すると攻撃者が被害者のセッション識別子を選べます（セッション固定）。実体が
// 読めたときだけ id を埋め、それ以外は空のまま saveSession に振り直させます。
func (h *Handler) loadSession(r *http.Request) (*session, error) {
	s := newSession()

	cookie, err := r.Cookie(h.sessionName)
	if err != nil || cookie.Value == "" {
		return s, nil
	}
	// 発行した形でない ID は、保存先に問い合わせる前に捨てます。実体があるはずも
	// なく、Firestore ではドキュメントのパスになる値です（isValidSessionID を参照）。
	if !isValidSessionID(cookie.Value) {
		return s, nil
	}

	values, err := h.store.Load(r.Context(), cookie.Value)
	switch {
	case errors.Is(err, ErrNotFound):
		return s, nil
	case err != nil:
		s.id = cookie.Value
		return s, err
	}

	s.id = cookie.Value
	s.values = values
	if s.values == nil {
		s.values = map[string]string{}
	}
	return s, nil
}

// saveSession は、セッションを保存してクッキーを応答へ書きます。id が空なら振ります。
func (h *Handler) saveSession(w http.ResponseWriter, r *http.Request, s *session) error {
	if s.id == "" {
		id, err := newSessionID()
		if err != nil {
			return err
		}
		s.id = id
	}

	maxAge := h.sessionMaxAge()
	if err := h.store.Save(r.Context(), s.id, s.values, maxAge); err != nil {
		return err
	}
	http.SetCookie(w, h.sessionCookie(s.id, int(maxAge.Seconds())))
	return nil
}

// clearSession は、セッションの実体を消してクッキーを破棄します。
//
// 実体を消せなくてもクッキーは落とします。ここで戻ると、利用者から見てログアウトが
// 失敗したのにクッキーだけ残る形になります。クッキーを落とすだけでは盗まれた
// クッキーは有効なままなので、実体を消すことが「本当のログアウト」の中身です。
func (h *Handler) clearSession(w http.ResponseWriter, r *http.Request, s *session) error {
	var err error
	if s != nil && s.id != "" {
		err = h.store.Delete(r.Context(), s.id)
	}
	http.SetCookie(w, h.sessionCookie("", -1))
	return err
}

// sessionCookie は、セッション ID を運ぶクッキーを組み立てます。
//
// Path は "/"（アプリ全体）、SameSite は Lax です。Strict にすると、Google からの
// コールバックがクロスサイトのトップレベル遷移なのでクッキーが送られません。
// Secure は ServiceURL のスキームから決まります（Config.ServiceURL を参照）。
// maxAge が負なら、ブラウザはその場で破棄します。
func (h *Handler) sessionCookie(value string, maxAge int) *http.Cookie {
	//nolint:gosec // G124: Secure は ServiceURL が https かどうかに従う（ローカル開発は http）。
	return &http.Cookie{
		Name:     h.sessionName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   h.isSecureCookie,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
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
	s, err := h.loadSession(r)
	if err != nil {
		h.log().WarnContext(r.Context(), "セッションの取得に失敗したため、新規セッションを作成します", "error", err)
		s = newSession()
	}

	targetURL := redirectTarget(r)

	// ログイン前のセッションに紐づく CSRF トークンは破棄し、認証済みセッション用に
	// 再生成させます（ログイン前に固定されたトークンを使い回させないため）。
	delete(s.values, CSRFTokenKey)

	// ID も捨てて振り直させます（セッション固定攻撃対策）。攻撃者が仕込んだ ID の
	// まま認証済みにすると、その ID で被害者として振る舞えます。空の ID には
	// saveSession が新しい ID を振ります。
	//
	// 古い実体は消しません。認証前の値しか持たず、認証済みになることもないので、
	// TTL に任せます。
	s.id = ""

	s.values[DefaultUserSessionKey] = email
	if err := h.saveSession(w, r, s); err != nil {
		return "", fmt.Errorf("save session: %w", err)
	}
	return targetURL, nil
}

// redirectTarget は、ログイン後に戻る先を決めます。無ければ "/" です。
//
// 値は Login が発行したクッキーが運びます。書き込み時にも検証していますが、
// クッキーは相手が書き換えられるので、読み出し時にも必ず確認します。
func redirectTarget(r *http.Request) string {
	cookie, err := r.Cookie(DefaultRedirectCookie)
	if err != nil || cookie.Value == "" {
		return "/"
	}
	decoded, err := url.QueryUnescape(cookie.Value)
	if err != nil || !isSafeRelativePath(decoded) {
		return "/"
	}
	return decoded
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

// clearSessionCookie は、クッキーが指すセッションを実体ごと破棄します。
// 読めなかった場合も、クッキーが運んできた ID の実体は消しに行きます。
func (h *Handler) clearSessionCookie(w http.ResponseWriter, r *http.Request) error {
	s, err := h.loadSession(r)
	if err != nil {
		h.log().WarnContext(r.Context(), "破棄するセッションを読めませんでした。実体の削除は試みます", "error", err)
	}
	if err := h.clearSession(w, r, s); err != nil {
		h.log().ErrorContext(r.Context(), "セッションの破棄に失敗", "error", err)
		return err
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
