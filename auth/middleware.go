package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/sessions"
)

const (
	// CSRFTokenKey はセッション内でトークンを保持するためのキーです。
	CSRFTokenKey = "csrf_token"
	// HeaderXCSRFToken はフロントエンドがトークンを送信する際の標準ヘッダーです。
	//nolint:gosec // G101: 認証情報ではなく HTTP ヘッダー名の定数
	HeaderXCSRFToken = "X-CSRF-Token"
)

// Middleware は、セッションベースの認証とCSRF検証を適用します。
// 認証を通過したリクエストには、下流のハンドラーが EmailFromContext で参照できるよう
// ユーザーのメールアドレスがコンテキストに格納されます。
func (h *Handler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := h.store.Get(r, h.sessionName)
		if err != nil {
			// セッション解析に失敗した場合（署名キー変更時など）は詳細を記録しクッキーをクリア
			h.log().WarnContext(r.Context(), "セッション取得失敗。新規セッションとして扱います", "error", err)
			if clearErr := h.clearSessionCookie(w, r); clearErr != nil {
				h.log().WarnContext(r.Context(), "セッションクッキーのクリアに失敗", "error", clearErr)
			}
			http.Redirect(w, r, h.buildLoginRedirectURL(r), http.StatusFound)
			return
		}

		// 1. ログイン認証チェック
		email, ok := session.Values[DefaultUserSessionKey].(string)
		if !ok || email == "" {
			http.Redirect(w, r, h.buildLoginRedirectURL(r), http.StatusFound)
			return
		}

		// 2. CSRFチェック (副作用のあるメソッドのみ)
		if isStateChangingMethod(r.Method) {
			if !validateOrigin(r) {
				h.log().WarnContext(r.Context(), "Origin検証失敗", "email", email, "origin", r.Header.Get("Origin"), "path", r.URL.Path)
				http.Error(w, "Invalid origin", http.StatusForbidden)
				return
			}
			if !h.validateCSRF(r, session) {
				h.log().WarnContext(r.Context(), "CSRF検証失敗", "email", email, "method", r.Method, "path", r.URL.Path)
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r.WithContext(WithEmail(r.Context(), email)))
	})
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
func (h *Handler) validateCSRF(r *http.Request, session *sessions.Session) bool {
	if session == nil {
		return false
	}

	expected, ok := session.Values[CSRFTokenKey].(string)
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

// GenerateAndSaveCSRFToken は、URLセーフな新しいトークンを生成して保存します。
func (h *Handler) GenerateAndSaveCSRFToken(w http.ResponseWriter, r *http.Request) (string, error) {
	token, err := randomToken(base64.RawURLEncoding)
	if err != nil {
		return "", fmt.Errorf("CSRFトークン生成失敗: %w", err)
	}
	session, err := h.store.Get(r, h.sessionName)
	if err != nil {
		return "", fmt.Errorf("セッションの取得に失敗しました: %w", err)
	}
	if session == nil {
		return "", errors.New("session store returned nil session")
	}

	session.Values[CSRFTokenKey] = token
	if err := session.Save(r, w); err != nil {
		return "", fmt.Errorf("CSRFトークン保存失敗: %w", err)
	}

	return token, nil
}

// GetCSRFTokenFromSession は現在のセッションから CSRF トークンを抽出します（表示用）。
func (h *Handler) GetCSRFTokenFromSession(r *http.Request) string {
	session, err := h.store.Get(r, h.sessionName)
	if err != nil || session == nil {
		return ""
	}
	token, ok := session.Values[CSRFTokenKey].(string)
	if !ok {
		return ""
	}
	return token
}

// buildLoginRedirectURL はオープンリダイレクタ脆弱性を考慮したリダイレクト先URLを構築します。
func (h *Handler) buildLoginRedirectURL(r *http.Request) string {
	loginURL := h.LoginPath()

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

// TaskOIDCVerificationMiddleware は Google Cloud Tasks からの OIDC トークンを検証します。
//
// 検証は audience だけでなく Config.AllowedTaskServiceAccounts との照合まで行います。
// audience は誰でも指定できる文字列に過ぎず、それだけでは呼び出し元を認証できないためです。
// 検証済みペイロードは OIDCPayloadFromContext で下流のハンドラーから参照できます。
// Web UI を持たないサービスは、OAuth 設定なしで同じ検証を行える TaskVerifier を使えます。
func (h *Handler) TaskOIDCVerificationMiddleware(next http.Handler) http.Handler {
	return taskOIDCMiddleware(h.taskVerifier, h.log(), next)
}
