// Package auth は、「誰として通すか」の契約と、その合成だけを持ちます。
//
// 実装は 2 つの子パッケージにあります。人（ブラウザ）は auth/session、
// サービス間呼び出しは auth/oidc です。どちらも Authenticator を満たすため、
// 合成はこのパッケージの Require / Protected が引き受けます。
//
//	// Worker 用: サービスしか来ないルート
//	r.Use(auth.Require(verifier))
//
//	// Web 用: 人もエージェントも来るルート
//	r.Use(auth.Protected(verifier, handler))
//
// 依存の向きは session → auth ← oidc の一方向で、このパッケージ自身は
// 標準ライブラリしか使いません。合成の判断を 1 か所に集めるためであって、
// 各アプリが同じ組み立てを手で書くと、認証経路が散らばって片方だけが
// 強化される事故が起きます。
package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
)

// Authenticator は、リクエストの主体を 1 つの方式で確認します。
//
// 自分宛ての資格情報が無い場合は ErrNotAttempted を返し、合成側に次の方式を
// 試させます。確認できた場合は、下流が参照する値を載せたコンテキストを返します。
//
// w を受け取るのは、確認の過程で応答へ書き込む必要がある方式があるためです
// （壊れたセッションクッキーの破棄など）。ただし応答本体
// （リダイレクトや 401）は書きません。それは Challenge の仕事です。
//
// ここで書いたヘッダーは、確認に失敗しても応答に残ります。Protected は失敗した
// 方式で走査を止めないため、後の方式が成立して 200 を返しても取り消されません。
// 書き込みは、そうなっても差し支えないものに限ってください。
type Authenticator interface {
	Authenticate(w http.ResponseWriter, r *http.Request) (context.Context, error)
}

// Challenger は、認証が成立しなかったときの応答を自分で決められる Authenticator です。
//
// セッション方式がログイン画面へリダイレクトするように、失敗時に何を返すかは
// 方式ごとに違います。実装しない場合、Require / Protected が既定の応答を返します。
type Challenger interface {
	Challenge(w http.ResponseWriter, r *http.Request, err error)
}

var (
	// ErrNotAttempted は、リクエストがその方式を試してすらいないことを示します
	// （Bearer トークンが無い、セッションクッキーが無い、など）。
	//
	// 失敗ではなく「自分の担当ではない」の意味なので、Protected は次の方式へ進み、
	// 呼び出し側もログを出す必要はありません。
	ErrNotAttempted = errors.New("auth: no credentials for this method")

	// ErrNotConfigured は、方式そのものが設定されていないことを示します。
	//
	// ErrNotAttempted と区別するのは、設定漏れをフォールバックで隠さないためです。
	// 混ぜると「なぜかエージェントだけログイン画面に飛ばされる」という分かりにくい
	// 形で現れます。
	ErrNotConfigured = errors.New("auth: authenticator is not configured")
)

// Require は、a で確認できなければ止めるミドルウェアを返します。
// サービスしか来ないルート（Cloud Tasks の Worker など）に使います。
//
// a が Challenger なら失敗時の応答を委ね、そうでなければ次を返します。
//
//   - ErrNotConfigured: 500。設定漏れは呼び出し元の落ち度ではありません
//   - ErrNotAttempted:  401。資格情報が無い
//   - それ以外:          403。提示されたが通らなかった
func Require(a Authenticator, opts ...Option) func(http.Handler) http.Handler {
	o := newOptions(opts)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, err := a.Authenticate(w, r)
			if err == nil {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			if errors.Is(err, ErrNotConfigured) {
				o.logger().ErrorContext(r.Context(), "認証方式が未設定です", "error", err, "path", r.URL.Path)
			} else if !errors.Is(err, ErrNotAttempted) {
				o.logger().WarnContext(r.Context(), "認証失敗", "error", err, "path", r.URL.Path)
			}

			challenge(w, r, a, err)
		})
	}
}

// Protected は、方式を順に試して最初に成立したもので通すミドルウェアを返します。
// 人もサービスも来るルートに使います。
//
// どれも成立しなかった場合、応答を決めるのは資格情報を提示したうえで落ちた方式です。
// 「Bearer を出したが通らなかった」は確定的な失敗で、次の方式に望みはありません。
// 最後の方式に答えさせると、JSON を求めたエージェントに HTML のログイン画面が返ります。
// 提示すらしていない方式しか無ければ、最後の方式が答えます。
//
// ErrNotConfigured だけは確定的な失敗に数えません。設定漏れでフォールバックを止めると、
// サービス側の設定を直すまで人までログインできなくなります。
//
// 方式の順序は、どれも成立しなかった場合だけでなく、成立した場合の応答にも効きます。
// Authenticate が応答へ書いたヘッダーは、その方式が落ちても残るためです（走査を
// 続ける以上、巻き戻す先がありません）。人向けの方式は最後に置いてください。
// auth/session を先に置くと、壊れたクッキーを持ったまま Bearer で通った呼び出しの
// 200 応答に、セッションを破棄する Set-Cookie が紛れ込みます。
func Protected(first Authenticator, rest ...Authenticator) func(http.Handler) http.Handler {
	return ProtectedWith(nil, append([]Authenticator{first}, rest...)...)
}

// ProtectedWith は、オプションを指定できる Protected です。
func ProtectedWith(opts []Option, authenticators ...Authenticator) func(http.Handler) http.Handler {
	o := newOptions(opts)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// decisive は「資格情報を提示したうえで落ちた」最初の方式です。
			// last は、どの方式も提示されなかった場合の応答役です。
			var decisiveAuth, lastAuth Authenticator
			var decisiveErr, lastErr error

			for _, a := range authenticators {
				if a == nil {
					continue
				}
				ctx, err := a.Authenticate(w, r)
				if err == nil {
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}

				// そもそも試していない呼び出しはノイズになるためログしない。
				if !errors.Is(err, ErrNotAttempted) {
					o.logger().InfoContext(r.Context(), "認証方式が成立せず、次の方式へフォールバック",
						"error", err, "path", r.URL.Path)
				}
				// 提示して落ちた方式を覚えつつ、走査は続けます。不正な Bearer と
				// 有効なセッションを同時に持つ呼び出しを、締め出さないためです。
				if decisiveAuth == nil && !errors.Is(err, ErrNotAttempted) && !errors.Is(err, ErrNotConfigured) {
					decisiveAuth, decisiveErr = a, err
				}
				lastAuth, lastErr = a, err
			}

			switch {
			case decisiveAuth != nil:
				challenge(w, r, decisiveAuth, decisiveErr)
			case lastAuth != nil:
				challenge(w, r, lastAuth, lastErr)
			default:
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			}
		})
	}
}

// challenge は、方式が応答を決められるならそれに委ね、そうでなければ既定を返します。
func challenge(w http.ResponseWriter, r *http.Request, a Authenticator, err error) {
	if c, ok := a.(Challenger); ok {
		c.Challenge(w, r, err)
		return
	}

	switch {
	case errors.Is(err, ErrNotConfigured):
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	case errors.Is(err, ErrNotAttempted):
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	default:
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	}
}

// Option は Require / ProtectedWith の挙動を調整します。
type Option func(*options)

type options struct {
	log *slog.Logger
}

func newOptions(opts []Option) *options {
	o := &options{}
	for _, opt := range opts {
		if opt != nil {
			opt(o)
		}
	}
	return o
}

func (o *options) logger() *slog.Logger {
	if o != nil && o.log != nil {
		return o.log
	}
	return slog.Default()
}

// WithLogger は合成の判断を記録するロガーを指定します。
// 未指定の場合は slog.Default() です。
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) { o.log = logger }
}
