package session

import (
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

// Store は、セッションの保存先です。
//
// 実体はサーバー側にあり、クッキーが運ぶのは不透明な ID だけです。だから署名も
// 暗号化も要らず、セッション鍵を配る必要もありません。代わりに、失効・ログアウト・
// セッション固定対策が実際に効きます。
type Store interface {
	// Get は、リクエストのクッキーが指すセッションを読み出します。
	// 見つからない・期限切れの場合も空のセッションを返し、nil は返しません。
	//
	// ★ 保存されていない ID をそのまま採用してはいけません。ID は
	// クッキー経由で攻撃者が指定できるので、採用すると「攻撃者が選んだ ID の
	// セッションを被害者が使う」状態を作れます（セッション固定）。見つからない
	// ときは ID を空のままにし、Save に振り直させてください。
	Get(r *http.Request, name string) (*Session, error)

	// Save は、セッションを保存してクッキーを応答へ書きます。
	//
	// s.ID が空なら、新しい ID を振ってから保存します。
	// s.Options.MaxAge が負なら、保存ではなく破棄です（保存済みの実体も消します）。
	Save(r *http.Request, w http.ResponseWriter, s *Session) error
}

// Session は、1 リクエスト分のセッションです。
type Session struct {
	// ID は、ストアがセッションを識別する値です。クッキーが運ぶのはこれだけです。
	ID string

	// Values は、セッションが持つ値です。
	//
	// 文字列に限っているのは、この kit が保存するのがメールアドレス・CSRF トークン・
	// ログイン後の戻り先の 3 つだけだからです。任意の型を許すと保存形式ごとの
	// 詰め替えが要り、読み出しは毎回型アサーションになります。
	Values map[string]string

	// Options は、発行するクッキーの属性です。
	Options *Options

	// IsNew は、既存のセッションを読めなかったことを表します。
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

// StoreConfig は、Store 実装に共通のクッキー設定です。
type StoreConfig struct {
	// MaxAge はセッションの有効期間です。0 なら 7 日。
	// クッキーの属性であると同時に、保存した実体の期限でもあります。
	MaxAge time.Duration
	// Secure は https 限定にするかどうかです。ローカル開発以外では true にします。
	Secure bool
	// Path は既定で "/" です。
	Path string
	// SameSite は既定で Lax です。Strict にすると、Google からのコールバックが
	// クロスサイトのトップレベル遷移なのでクッキーが送られません。
	SameSite http.SameSite
}

func (c StoreConfig) options() Options {
	maxAge := c.MaxAge
	if maxAge <= 0 {
		maxAge = defaultSessionMaxAge
	}
	path := c.Path
	if path == "" {
		path = "/"
	}
	sameSite := c.SameSite
	// ゼロ値は「未指定」です。http.SameSite の名前付き定数は 1 から始まるので、
	// SameSiteDefaultMode と比べると既定が一度も効かず、SameSite 属性の無い
	// クッキーが出ます（明示された SameSiteDefaultMode はそのまま尊重します）。
	if sameSite == 0 {
		sameSite = http.SameSiteLaxMode
	}
	return Options{
		Path:     path,
		MaxAge:   int(maxAge.Seconds()),
		Secure:   c.Secure,
		HTTPOnly: true,
		SameSite: sameSite,
	}
}

// newSessionID は、推測できないセッション ID を返します。
//
// 中身を持たない不透明な値なので、必要な性質は「推測できないこと」だけです
// （crypto/rand の 32 バイト）。
func newSessionID() (string, error) {
	return randomToken(base64.RawURLEncoding)
}

// newCookie は Options からクッキーを組み立てます。
// MaxAge が負なら、ブラウザはその場で破棄します。
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

// memoryStore は、プロセス内にセッションを保持する Store です。
type memoryStore struct {
	opts Options

	mu      sync.Mutex
	entries map[string]memoryEntry
}

type memoryEntry struct {
	values    map[string]string
	expiresAt time.Time
}

// NewMemoryStore は、プロセス内にセッションを保持する Store を返します。
//
// ★ 本番では使えません。Cloud Run のインスタンスごとに別のストアになるため、
// インスタンスが替わった時点で利用者はログアウトされます。ローカル開発と、
// Firestore を立てずに認証済みの画面を確かめるテストのための実装です。
func NewMemoryStore(cfg StoreConfig) Store {
	return &memoryStore{opts: cfg.options(), entries: map[string]memoryEntry{}}
}

func (s *memoryStore) Get(r *http.Request, name string) (*Session, error) {
	session := NewSession(name)
	opts := s.opts
	session.Options = &opts

	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		return session, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[cookie.Value]
	if !ok {
		return session, nil
	}
	if time.Now().After(entry.expiresAt) {
		delete(s.entries, cookie.Value)
		return session, nil
	}

	// 実体が見つかったときだけ ID を採用します（Store の約束）。
	session.ID = cookie.Value
	for k, v := range entry.values {
		session.Values[k] = v
	}
	session.IsNew = false
	return session, nil
}

func (s *memoryStore) Save(_ *http.Request, w http.ResponseWriter, session *Session) error {
	opts := session.Options
	if opts == nil {
		o := s.opts
		opts = &o
	}

	if opts.MaxAge < 0 {
		s.mu.Lock()
		delete(s.entries, session.ID)
		s.mu.Unlock()
		http.SetCookie(w, newCookie(session.Name(), "", opts))
		return nil
	}

	if session.ID == "" {
		id, err := newSessionID()
		if err != nil {
			return err
		}
		session.ID = id
	}

	values := make(map[string]string, len(session.Values))
	for k, v := range session.Values {
		values[k] = v
	}

	s.mu.Lock()
	s.entries[session.ID] = memoryEntry{
		values:    values,
		expiresAt: time.Now().Add(time.Duration(opts.MaxAge) * time.Second),
	}
	s.mu.Unlock()

	http.SetCookie(w, newCookie(session.Name(), session.ID, opts))
	return nil
}
