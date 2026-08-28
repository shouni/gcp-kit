package session

import (
	"log/slog"
	"strings"
	"time"

	"github.com/gorilla/sessions"
)

// Option は Handler の任意設定です。
// 必須の設定は Config が持ちます。
type Option func(*options)

type options struct {
	scopes        []string
	loginPath     string
	callbackPath  string
	logoutPath    string
	sessionMaxAge time.Duration
	stateMaxAge   time.Duration
	store         sessions.Store
	logger        *slog.Logger
	prompt        Prompt
}

func newOptions(opts []Option) *options {
	o := &options{
		loginPath:     DefaultLoginPath,
		callbackPath:  DefaultCallbackPath,
		logoutPath:    DefaultLogoutPath,
		sessionMaxAge: defaultSessionMaxAge,
		stateMaxAge:   defaultStateMaxAge,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(o)
		}
	}
	return o
}

// WithScopes は OAuth2 の要求スコープを差し替えます。
// 未指定の場合は openid + userinfo.email です。
func WithScopes(scopes ...string) Option {
	return func(o *options) {
		if len(scopes) > 0 {
			o.scopes = scopes
		}
	}
}

// WithPaths は Login / Callback / Logout ハンドラーのマウント先を指定します。
// 空文字の項目は既定値のままです。
//
// callbackPath は state / PKCE クッキーの Path 属性としても使われます。
// 実際のルーティングと一致していないと、コールバック時にクッキーが送信されず
// 認証が必ず失敗します。
func WithPaths(loginPath, callbackPath, logoutPath string) Option {
	return func(o *options) {
		if p := strings.TrimSpace(loginPath); p != "" {
			o.loginPath = p
		}
		if p := strings.TrimSpace(callbackPath); p != "" {
			o.callbackPath = p
		}
		if p := strings.TrimSpace(logoutPath); p != "" {
			o.logoutPath = p
		}
	}
}

// WithSessionMaxAge はセッションクッキーの有効期間を指定します（既定: 7日）。
// 負値以下は無視されます。
func WithSessionMaxAge(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.sessionMaxAge = d
		}
	}
}

// WithStateMaxAge は state / PKCE クッキーの有効期間を指定します（既定: 10分）。
// 負値以下は無視されます。
func WithStateMaxAge(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.stateMaxAge = d
		}
	}
}

// WithStore はセッションストアを注入します。
//
// 未指定の場合は Config のキーから sessions.CookieStore が生成されます。
// クッキー自体がセッションの実体になるため、サーバー側から失効させられません。
// ログアウトを確実に反映したい場合は Redis 等のストアを渡してください。
func WithStore(store sessions.Store) Option {
	return func(o *options) {
		if store != nil {
			o.store = store
		}
	}
}

// WithLogger はこのパッケージが使うロガーを指定します。
// 未指定の場合は slog.Default() です。
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) { o.logger = logger }
}

// Prompt は、認可画面で Google に何を尋ねさせるかの指定です
// （OpenID Connect の prompt パラメータ）。
type Prompt string

const (
	// PromptSelectAccount はアカウント選択画面を必ず挟みます。
	//
	// ログアウトを実効あるものにするのが主な用途です。Logout が消せるのは
	// このアプリのクッキーだけで、Google 側のセッションは残ります。prompt を
	// 付けないと、ログアウト後にログイン画面へ送られた時点で Google が何も
	// 聞かずに承認を返すため、利用者から見ると一瞬ちらついて元のログイン状態に
	// 戻るだけになります。共用端末で「ログアウト」が効きません。
	PromptSelectAccount Prompt = "select_account"

	// PromptLogin は Google での再認証（パスワード入力など）まで要求します。
	PromptLogin Prompt = "login"

	// PromptConsent は同意画面を毎回表示させます。
	PromptConsent Prompt = "consent"

	// PromptNone は画面を一切出させず、対話が必要な場合はエラーを返させます。
	// 利用者の操作を伴わない再取得に使います。他の値と併用はできません。
	PromptNone Prompt = "none"
)

// WithPrompt は認可 URL の prompt パラメータを指定します。
//
// 未指定なら付けません（Google の既定は「聞かずに済むなら聞かない」です）。
// ログアウト後に必ずアカウントを選ばせたい場合は PromptSelectAccount を渡します。
func WithPrompt(prompt Prompt) Option {
	return func(o *options) { o.prompt = prompt }
}
