package session

import (
	"crypto/subtle"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"

	"github.com/shouni/gcp-kit/auth"
)

// Login は OAuth2 のログインを開始します。state と PKCE の verifier、
// および redirect_to があれば戻り先を短命クッキーに残し、Google へ送ります。
//
// セッションの保存先には触れません。ログイン画面は誰でも開けるので、ここで実体を
// 作ると未認証の相手がいくらでも書き込めることになります。
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	state, err := generateState()
	if err != nil {
		h.log().ErrorContext(r.Context(), "State生成失敗", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// PKCE: 認可コードの横取りに備え、code_verifier をクライアント側に保持します。
	verifier := oauth2.GenerateVerifier()

	if redirectTo := r.URL.Query().Get("redirect_to"); redirectTo != "" {
		// 同一オリジンの相対パスのみを載せます（オープンリダイレクタ対策）。
		// エスケープするのはクッキー値として往復させるためで、読み出し側は
		// 復元したうえで同じ判定をやり直します。
		if isSafeRelativePath(redirectTo) {
			h.setTemporaryCookie(w, DefaultRedirectCookie, url.QueryEscape(redirectTo))
		} else {
			h.log().WarnContext(r.Context(), "Invalid redirect_to parameter detected", "redirectTo", redirectTo)
		}
	}

	h.setTemporaryCookie(w, DefaultStateCookie, state)
	h.setTemporaryCookie(w, DefaultVerifierCookie, verifier)

	// PKCE のチャレンジは必ず載せます。prompt は指定があるときだけ足すので、
	// state と code_challenge を上書きする余地はありません。
	authOpts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
	if prompt := h.promptParam(); prompt != "" {
		authOpts = append(authOpts, oauth2.SetAuthURLParam("prompt", prompt))
	}

	authURL := h.oauthConfig.AuthCodeURL(state, authOpts...)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// Callback は Google からの戻りを受けます。state と PKCE verifier を確認し、
// 認可コードをトークンへ交換し、許可された相手にセッションを発行します。
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	if !validateCallbackState(r) {
		h.log().WarnContext(r.Context(), "CSRF攻撃の可能性を検知")
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	verifier, err := r.Cookie(DefaultVerifierCookie)
	if err != nil || verifier.Value == "" {
		// Login を経由していない、あるいはクッキーが期限切れ。再ログインさせます。
		h.log().WarnContext(r.Context(), "PKCE verifier クッキーがありません")
		h.clearTemporaryCookies(w)
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	h.clearTemporaryCookies(w)

	token, err := h.exchangeCode(r, verifier.Value)
	if err != nil {
		h.log().ErrorContext(r.Context(), "トークン交換失敗", "error", err)
		http.Error(w, "Auth failed", http.StatusInternalServerError)
		return
	}

	email := h.resolveUserEmail(r, token)

	if email == "" || !h.isAuthorized(email) {
		h.log().WarnContext(r.Context(), "未許可ユーザーアクセス", "email", email)
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	if err := h.saveSessionAndRedirect(w, r, email); err != nil {
		h.log().ErrorContext(r.Context(), "セッション保存失敗", "error", err)
		http.Error(w, "Could not save session", http.StatusInternalServerError)
		return
	}
}

// Logout はセッションを破棄し、ログインページ（または redirect_to で指定された同一オリジンの
// パス）へリダイレクトします。
//
// セッションの実体はストア側にあるので、これはサーバー側の失効です。クッキーを
// 落とすだけでなく保存された実体も消えるため、盗まれたクッキーもその時点で無効です。
//
// ただし消えるのはこのアプリのセッションだけです。Google 側のログインは残るので、
// ログイン画面へ送られた時点で何も聞かれずに承認が返ります。共用端末で「ログアウト」を
// 成立させるには WithPrompt(PromptSelectAccount) が要ります。
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.clearSessionCookie(w, r); err != nil {
		h.log().WarnContext(r.Context(), "ログアウト時のセッション破棄に失敗", "error", err)
	}

	target := h.loginPath()
	if redirectTo := r.URL.Query().Get("redirect_to"); isSafeRelativePath(redirectTo) {
		target = redirectTo
	}
	//nolint:gosec // G710: target は isSafeRelativePath で同一オリジンの相対パスに限定済み
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func validateCallbackState(r *http.Request) bool {
	queryState := r.URL.Query().Get("state")
	cookieState, err := r.Cookie(DefaultStateCookie)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookieState.Value), []byte(queryState)) == 1
}

// setTemporaryCookie は state / PKCE verifier のような短命のクッキーを発行します。
// SameSite は Lax 固定です。Google からのコールバックはクロスサイトのトップレベル
// GET ナビゲーションであるため、Strict にするとクッキーが送信されません。
func (h *Handler) setTemporaryCookie(w http.ResponseWriter, name, value string) {
	//nolint:gosec // G124: Secure はローカル開発(http)を許容するため設定値に従う。HttpOnly/SameSite は常に設定済み。
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   h.stateCookieMaxAge(),
		Path:     h.callbackPath(),
		HttpOnly: true,
		Secure:   h.isSecureCookie,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearTemporaryCookies は state / PKCE verifier / 戻り先クッキーを無効化します。
// 属性（Path/SameSite など）は発行時と一致させる必要があります。破棄するのは応答側
// だけなので、この後でも r からは読めます（Callback は戻り先を後で読みます）。
func (h *Handler) clearTemporaryCookies(w http.ResponseWriter) {
	for _, name := range []string{DefaultStateCookie, DefaultVerifierCookie, DefaultRedirectCookie} {
		//nolint:gosec // G124: Secure はローカル開発(http)を許容するため設定値に従う。HttpOnly/SameSite は常に設定済み。
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			MaxAge:   -1,
			Path:     h.callbackPath(),
			HttpOnly: true,
			Secure:   h.isSecureCookie,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

func (h *Handler) exchangeCode(r *http.Request, verifier string) (*oauth2.Token, error) {
	code := r.URL.Query().Get("code")
	return h.oauthConfig.Exchange(r.Context(), code, oauth2.VerifierOption(verifier))
}

func (h *Handler) resolveUserEmail(r *http.Request, token *oauth2.Token) string {
	email := h.extractEmailFromIDToken(r, token)
	if email != "" {
		return email
	}

	var err error
	email, err = h.fetchUserEmail(r.Context(), token)
	if err != nil {
		h.log().WarnContext(r.Context(), "API経由でのユーザーメールアドレス取得に失敗しました", "error", err)
	}
	return email
}

func (h *Handler) extractEmailFromIDToken(r *http.Request, token *oauth2.Token) string {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return ""
	}

	payload, err := idtoken.Validate(r.Context(), rawIDToken, h.oauthConfig.ClientID)
	if err != nil {
		h.log().DebugContext(r.Context(), "IDトークンの検証に失敗しました", "error", err)
		return ""
	}

	// UserInfo API 経由 (fetchUserEmail) やサービス間検証と同じ基準を適用します。
	emailClaim, err := auth.VerifiedEmail(payload.Claims)
	if err != nil {
		h.log().WarnContext(r.Context(), "IDトークンのメールアドレスを採用できません", "error", err)
		return ""
	}
	return emailClaim
}

func (h *Handler) saveSessionAndRedirect(w http.ResponseWriter, r *http.Request, email string) error {
	targetURL, err := h.issueSession(w, r, email)
	if err != nil {
		return err
	}

	//nolint:gosec // G710: targetURL は isSafeRelativePath で同一オリジンの相対パスに限定済み
	http.Redirect(w, r, targetURL, http.StatusSeeOther)
	return nil
}
