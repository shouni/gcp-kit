package session

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

const (
	// CSRFTokenKey はセッション内でトークンを保持するためのキーです。
	CSRFTokenKey = "csrf_token"
	// HeaderXCSRFToken はフロントエンドがトークンを送信する際の標準ヘッダーです。
	//nolint:gosec // G101: 認証情報ではなく HTTP ヘッダー名の定数
	HeaderXCSRFToken = "X-CSRF-Token"
)

// 認証が成立しなかった理由。Challenge が応答を決めるために使います。
// 公開していないのは、呼び出し側が分岐する必要が無いためです
// （何を返すかは Challenge がこのパッケージの中で決めます）。
var (
	errNoSession   = errors.New("session: no authenticated session")
	errUnauthMail  = errors.New("session: email is not on the allowlist")
	errBadOrigin   = errors.New("session: origin check failed")
	errInvalidCSRF = errors.New("session: CSRF token is invalid")
)

// Authenticate は auth.Authenticator を実装します。
//
// セッションを確認し、認可を判定し、状態を変えるメソッドには CSRF 検証を掛けます。
// 通過したリクエストには、下流が参照するメールアドレスと CSRF トークンを載せた
// コンテキストを返します。
//
// 認可は毎リクエスト評価します。ログイン時だけ見ると、許可リストから外した
// アドレスがセッションの有効期限まで通り続けます（実体を消せば止まりますが、
// それには当人のセッションを特定する必要があります）。
//
// セッションが無いだけの場合も auth.ErrNotAttempted ではなくエラーを返します。
// ブラウザ向けの方式は auth.Protected の最後に置かれ、そこで応答を決めるためです。
//
// ストアを読むのは 1 リクエストにつき 1 回だけです。取得したセッションは CSRF の
// 検証と発行まで持ち回します。Firestore ストアでは 1 回が 1 件の課金対象の読み取りで、
// 同じ実体を読み直すぶんだけ往復と請求が増えます。
func (h *Handler) Authenticate(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	session, err := h.store.Get(r, h.sessionName)
	switch {
	case errors.Is(err, ErrStoreUnavailable):
		// 保存先へ到達できないだけなので、クッキーには触れません。ここで消すと
		// バックエンドの瞬断が、その瞬間の利用者全員のログアウトになります。
		h.log().ErrorContext(r.Context(), "セッションストアへ到達できません", "error", err, "path", r.URL.Path)
		return nil, err
	case err != nil:
		// 実体が壊れている場合は、クッキーを消して次のログインで作り直させます。
		h.log().WarnContext(r.Context(), "セッション取得失敗。新規セッションとして扱います", "error", err)
		h.clearSessionCookieLogged(w, r)
		return nil, fmt.Errorf("%w: %w", errNoSession, err)
	}
	if session == nil {
		// Store の約束では nil を返しませんが、外部実装を差せる以上は確かめます。
		return nil, fmt.Errorf("%w: store returned nil session", errNoSession)
	}

	email, ok := session.Values[DefaultUserSessionKey]
	if !ok || email == "" {
		return nil, errNoSession
	}

	if !h.isAuthorized(email) {
		h.log().WarnContext(r.Context(), "許可リストにないセッション", "email", email, "path", r.URL.Path)
		h.clearSessionCookieLogged(w, r)
		return nil, fmt.Errorf("%w: %q", errUnauthMail, email)
	}

	if isStateChangingMethod(r.Method) {
		if !validateOrigin(r) {
			h.log().WarnContext(r.Context(), "Origin検証失敗", "email", email, "origin", r.Header.Get("Origin"), "path", r.URL.Path)
			return nil, errBadOrigin
		}
		if !h.validateCSRF(r, session) {
			h.log().WarnContext(r.Context(), "CSRF検証失敗", "email", email, "method", r.Method, "path", r.URL.Path)
			return nil, errInvalidCSRF
		}
	}

	// トークンがまだ無い GET では新規に生成してセッションへ保存します。
	// 生成を GET に限るのは、トークンを持たない状態変更リクエストに正当なトークンを
	// 与えてしまうと、CSRF 検証そのものが意味をなさなくなるためです。
	//
	// トークンは手元のセッションから読みます。ここで読み直すと、認証済みの
	// リクエストごとにストアを 2 回叩くことになります。
	token := session.Values[CSRFTokenKey]
	if token == "" && r.Method == http.MethodGet {
		generated, genErr := h.generateAndSaveCSRFToken(w, r, session)
		if genErr != nil {
			return nil, fmt.Errorf("session: CSRFトークンの自動生成に失敗しました: %w", genErr)
		}
		token = generated
	}

	ctx := withEmail(r.Context(), email)
	return WithCSRFToken(ctx, token), nil
}

// Challenge は auth.Challenger を実装します。
//
// 認証が足りないだけならログイン画面へ送り、CSRF や Origin の検証に落ちた場合は
// 403 で止めます。後者をリダイレクトにすると、攻撃者の仕掛けたリクエストが
// 素通りしたのか拒否されたのかを利用者も運用も区別できません。
//
// ログイン画面へ送るのは、相手がページを求めている場合だけです。JSON を求めて
// いる相手には 401 を返します。同じルートに人とエージェントが来る構成で
// リダイレクト一択にすると、JSON を求めたエージェントに HTML のログイン画面が
// 返り、相手はそれを解釈できません。Rails・Spring Security・ASP.NET Core など、
// 混在ルートを扱う実装はいずれも同じ出し分けをしています。
//
// セッションの保存先へ到達できなかった場合だけは 503 です。認証が足りないのでは
// なく依存が落ちているので、ログイン画面へ送っても直りません。
//
// なお 401 に WWW-Authenticate を添えないのは、クッキーによる認証に対応する
// 認証スキームが登録されていないためです。Bearer のチャレンジは、それを
// 受け付ける auth/oidc の側が返します。
func (h *Handler) Challenge(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errBadOrigin):
		http.Error(w, "Invalid origin", http.StatusForbidden)
	case errors.Is(err, errInvalidCSRF):
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
	case errors.Is(err, ErrStoreUnavailable):
		// ログイン画面へ送ってはいけません。認証は失われておらず、送った先の
		// ログインもストアを要求するので、利用者は往復して同じ場所に戻るだけです。
		// 503 なら、監視にも「認証が壊れた」ではなく「依存が落ちた」として出ます。
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
	case errors.Is(err, errNoSession), errors.Is(err, errUnauthMail):
		// wantsJSON は Vary: Accept も立てます。この応答は実際に Accept で
		// 変わるため、キャッシュへ伝える必要があります。
		if wantsJSON(w, r) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, h.buildLoginRedirectURL(r), http.StatusFound)
	default:
		h.log().ErrorContext(r.Context(), "セッション認証で予期しない失敗", "error", err, "path", r.URL.Path)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// wantsJSON は、呼び出し元が JSON を求めているかを返し、同時に Vary: Accept を立てます。
//
// 判定と宣言を 1 つにまとめてあるのは、Accept で応答が変わることをキャッシュへ伝え
// 忘れる取りこぼしを塞ぐためです。共有キャッシュや CDN を前に置いたとき、Vary が
// 無いと、JSON を求めた呼び出し元へログイン画面の HTML が返りえます。
//
// go-serve-kit の respond.WantsJSON と意図的に重複させています。この 1 か所のために
// キット間の依存を増やさない判断で、両者は独立に動きます。
func wantsJSON(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Add("Vary", "Accept")
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json")
}

// clearSessionCookieLogged はクッキーの破棄を試み、失敗しても処理を止めません。
func (h *Handler) clearSessionCookieLogged(w http.ResponseWriter, r *http.Request) {
	if err := h.clearSessionCookie(w, r); err != nil {
		h.log().WarnContext(r.Context(), "セッションクッキーのクリアに失敗", "error", err)
	}
}

// isStateChangingMethod は CSRF 保護が必要な HTTP メソッドを判定します。
func isStateChangingMethod(method string) bool {
	return method == http.MethodPost ||
		method == http.MethodPut ||
		method == http.MethodDelete ||
		method == http.MethodPatch
}

// validateOrigin は、トークン検証に加えた多層防御として Origin ヘッダーを検証します。
// Origin が無い場合（ブラウザ以外のクライアントなど）はトークン検証に委ねるため true を返し、
// 提示されている場合のみリクエスト先ホストとの一致を要求します。
func validateOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

// validateCSRF は、リクエストのトークンを検証します。
func (h *Handler) validateCSRF(r *http.Request, session *Session) bool {
	if session == nil {
		return false
	}

	expected, ok := session.Values[CSRFTokenKey]
	if !ok || expected == "" {
		return false
	}

	token := r.Header.Get(HeaderXCSRFToken)

	if token == "" {
		contentType := r.Header.Get("Content-Type")
		mediaType, _, _ := mime.ParseMediaType(contentType)
		if mediaType == "application/x-www-form-urlencoded" || mediaType == "multipart/form-data" {
			token = r.PostFormValue(CSRFTokenKey)
		}
	}

	if token == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

// generateAndSaveCSRFToken は、URLセーフな新しいトークンを生成し、渡された
// セッションへ保存します。
//
// セッションを引数で受け取るのは、呼び出し元が既に読み込んだものを使うためです。
// ここで読み直すと、トークンを持たない最初の GET だけストアへの往復が 1 つ増えます。
func (h *Handler) generateAndSaveCSRFToken(w http.ResponseWriter, r *http.Request, session *Session) (string, error) {
	token, err := randomToken(base64.RawURLEncoding)
	if err != nil {
		return "", fmt.Errorf("CSRFトークン生成失敗: %w", err)
	}
	if session == nil {
		return "", errors.New("session store returned nil session")
	}

	session.Values[CSRFTokenKey] = token
	if err := h.store.Save(r, w, session); err != nil {
		return "", fmt.Errorf("CSRFトークン保存失敗: %w", err)
	}

	return token, nil
}

// buildLoginRedirectURL はオープンリダイレクタ脆弱性を考慮したリダイレクト先URLを構築します。
func (h *Handler) buildLoginRedirectURL(r *http.Request) string {
	loginURL := h.loginPath()

	if r.Method != http.MethodGet || r.URL.Path == "/" {
		return loginURL
	}

	requestedURI := r.URL.RequestURI()
	if !isSafeRelativePath(requestedURI) {
		return loginURL
	}

	return fmt.Sprintf("%s?redirect_to=%s", loginURL, url.QueryEscape(requestedURI))
}

// isSafeRelativePath は、リダイレクト先として安全な同一オリジンの相対パスかを判定します。
// ホストを含むもの、'/' で始まらないもの、'//'（スキーマ相対 URL）で始まるものを拒否します。
func isSafeRelativePath(target string) bool {
	if target == "" {
		return false
	}

	// バックスラッシュを '/' と同一視して正規化するブラウザがあるため、
	// "/\evil.com" のような入力がスキーマ相対 URL として解釈され得ます。
	// url.Parse はこれを相対パスとして扱ってしまうので、先に弾きます。
	if strings.ContainsRune(target, '\\') {
		return false
	}
	// 制御文字（CR/LF 等）を含むものはヘッダー分割の材料になるため拒否します。
	if strings.ContainsFunc(target, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return false
	}

	// 判定は解析結果ではなく生の文字列で行います。"//@/" のように、
	// url.Parse ではホストが空になるのにブラウザにはスキーマ相対 URL として
	// 解釈され得る入力があるためです。
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		return false
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	return parsed.Scheme == "" && parsed.Host == ""
}
