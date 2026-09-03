package session

import (
	"encoding/base64"
	"errors"
	"maps"
	"net/http"
	"sync"
	"time"
)

// ErrStoreUnavailable は、保存先そのものへ到達できなかったことを示します
// （Firestore の一時障害など）。Store の実装は、この種の失敗を返すときだけ
// これでラップしてください。
//
// 壊れたセッションと区別するのは、処置が正反対だからです。壊れた実体はクッキーを
// 消せば次のログインで直りますが、到達できないだけの相手に同じことをすると、
// バックエンドの瞬断がその瞬間の利用者全員のログアウトになります。しかも復旧後も
// 元に戻りません。Handler.Challenge はこれを 503 で返し、クッキーには触れません。
var ErrStoreUnavailable = errors.New("session: session store is unavailable")

// Store は、セッションの保存先です。実体はサーバー側にあり、クッキーが運ぶのは
// 不透明な ID だけです。
type Store interface {
	// Get は、リクエストのクッキーが指すセッションを読み出します。
	// 見つからない・期限切れの場合も空のセッションを返し、nil は返しません。
	//
	// ★ 保存先へ到達できなかった場合は ErrStoreUnavailable でラップしてください。
	// ラップしないエラーは「実体が壊れている」と解釈され、クッキーが破棄されます。
	//
	// ★ 保存されていない ID を採用してはいけません。ID はクッキー経由で攻撃者が
	// 指定できるので、採用すると攻撃者が被害者のセッション識別子を選べます
	// （セッション固定）。ID は空のままにし、Save に振り直させてください。
	Get(r *http.Request, name string) (*Session, error)

	// Save は、セッションを保存してクッキーを応答へ書きます。
	// s.ID が空なら新しい ID を振ります。s.Options.MaxAge が負なら、保存ではなく
	// 破棄です（保存済みの実体も消します）。
	Save(r *http.Request, w http.ResponseWriter, s *Session) error
}

// Session は、1 リクエスト分のセッションです。
type Session struct {
	// ID は、ストアがセッションを識別する値です。クッキーが運ぶのはこれだけです。
	ID string

	// Values は、セッションが持つ値です。文字列に限っているのは、保存するのが
	// メールアドレス・CSRF トークン・戻り先の 3 つだけだからです。
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

// newSessionID は、推測できないセッション ID を返します。中身を持たない値なので、
// 必要な性質は推測できないことだけです（crypto/rand の 32 バイト）。
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
// ★ 本番では使えません。Cloud Run のインスタンスごとに別のストアになるので、
// インスタンスが替わった時点で利用者はログアウトされます。ローカル開発と、
// Firestore を立てずに認証済みの画面を確かめるテスト向けです。
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
	maps.Copy(session.Values, entry.values)
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

	s.mu.Lock()
	s.entries[session.ID] = memoryEntry{
		values:    maps.Clone(session.Values),
		expiresAt: time.Now().Add(time.Duration(opts.MaxAge) * time.Second),
	}
	s.mu.Unlock()

	http.SetCookie(w, newCookie(session.Name(), session.ID, opts))
	return nil
}
