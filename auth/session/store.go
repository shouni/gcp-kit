package session

import (
	"net/http"

	"github.com/gorilla/securecookie"
)

// Store は、セッションの保存先です。
//
// 既定はクッキー自身（NewCookieStore）です。WithStore でサーバーサイドの実装へ
// 差し替えると、Logout が本当の失効になり、issueSession の ID 振り直しが
// セッション固定攻撃対策として実際に効き始めます。
type Store interface {
	// Get は、リクエストのクッキーからセッションを読み出します。
	// クッキーが無い・読めない場合も空のセッションを返し、nil は返しません。
	Get(r *http.Request, name string) (*Session, error)

	// Save は、セッションを保存してクッキーを応答へ書きます。
	//
	// s.ID が空なら、新しい ID を振ってから保存します。ログインはここで ID を
	// 空にして振り直させるので、これが無いとセッション固定攻撃が通ります。
	// s.Options.MaxAge が負なら、保存ではなくクッキーの破棄を指示します。
	Save(r *http.Request, w http.ResponseWriter, s *Session) error
}

// Session は、1 リクエスト分のセッションです。
type Session struct {
	// ID は、サーバーサイドのストアがセッションを識別する値です。
	// クッキー自体がセッションである既定のストアでは使いません。
	ID string

	// Values は、セッションが持つ値です。
	//
	// 文字列に限っているのは、この kit が保存するのがメールアドレス・CSRF トークン・
	// ログイン後の戻り先の 3 つだけだからです。任意の型を許すと gob への型登録が要り、
	// 読み出しは毎回型アサーションになります。
	Values map[string]string

	// Options は、発行するクッキーの属性です。
	Options *Options

	// IsNew は、既存のクッキーから読めなかったことを表します。
	IsNew bool

	name string
}

// Name はセッション名（クッキー名）を返します。
func (s *Session) Name() string { return s.name }

// NewSession は空のセッションを返します。Store の実装が使います。
func NewSession(name string) *Session {
	return &Session{
		Values:  map[string]string{},
		Options: &Options{},
		IsNew:   true,
		name:    name,
	}
}

// Options は、セッションクッキーの属性です。
type Options struct {
	Path     string
	Domain   string
	MaxAge   int
	Secure   bool
	HTTPOnly bool
	SameSite http.SameSite
}

// cookieStore は、クッキー自身をセッションの実体とする Store です。
type cookieStore struct {
	codecs  []securecookie.Codec
	options Options
}

// NewCookieStore は、クッキー自身をセッションの実体とする Store を返します。
//
// keyPairs は署名キーと暗号化キーの組です（securecookie.CodecsFromPairs と同じ並び）。
// サーバー側に何も持たないので失効はできません。詳細は Logout を参照してください。
func NewCookieStore(opts Options, keyPairs ...[]byte) Store {
	codecs := securecookie.CodecsFromPairs(keyPairs...)
	// MaxAge はコーデックにも渡します。クッキー属性だけに設定すると、有効期限は
	// ブラウザの自己申告になり、期限切れのクッキーを送り返されても受理してしまいます
	// （securecookie は MAC に載せたタイムスタンプで検証します）。
	for _, c := range codecs {
		if sc, ok := c.(*securecookie.SecureCookie); ok {
			sc.MaxAge(opts.MaxAge)
		}
	}
	return &cookieStore{codecs: codecs, options: opts}
}

func (s *cookieStore) Get(r *http.Request, name string) (*Session, error) {
	session := NewSession(name)
	opts := s.options
	session.Options = &opts

	c, err := r.Cookie(name)
	if err != nil || c.Value == "" {
		return session, nil
	}
	if err := securecookie.DecodeMulti(name, c.Value, &session.Values, s.codecs...); err != nil {
		// 復号に失敗した場合も呼び出し元が触れる形で返します（鍵の入れ替え直後など）。
		// 途中まで書き込まれている可能性があるので、値は捨て直します。
		session.Values = map[string]string{}
		return session, err
	}
	session.IsNew = false
	return session, nil
}

func (s *cookieStore) Save(_ *http.Request, w http.ResponseWriter, session *Session) error {
	opts := session.Options
	if opts == nil {
		o := s.options
		opts = &o
	}

	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, s.codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, newCookie(session.Name(), encoded, opts))
	return nil
}

// newCookie は Options からクッキーを組み立てます。
// MaxAge が負なら、ブラウザはその場で破棄します（Logout / clearSessionCookie）。
func newCookie(name, value string, o *Options) *http.Cookie {
	//nolint:gosec // G124: Secure はローカル開発(http)を許容するため設定値に従う。
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     o.Path,
		Domain:   o.Domain,
		MaxAge:   o.MaxAge,
		Secure:   o.Secure,
		HttpOnly: o.HTTPOnly,
		SameSite: o.SameSite,
	}
}
