package session

import (
	"context"
	"encoding/base64"
	"errors"
	"maps"
	"strings"
	"sync"
	"time"
)

var (
	// ErrNotFound は、Load が id の実体を見つけられなかったことを示します
	// （保存されていない、または期限切れ）。
	ErrNotFound = errors.New("session: not found")

	// ErrStoreUnavailable は、保存先そのものへ到達できなかったことを示します
	// （Firestore の一時障害など）。Store の実装は、この種の失敗を返すときだけ
	// これでラップしてください。
	//
	// 壊れたセッションと区別するのは、処置が正反対だからです。壊れた実体はクッキーを
	// 消せば次のログインで直りますが、到達できないだけの相手に同じことをすると、
	// バックエンドの瞬断がその瞬間の利用者全員のログアウトになります。しかも復旧後も
	// 元に戻りません。Handler.Challenge はこれを 503 で返し、クッキーには触れません。
	ErrStoreUnavailable = errors.New("session: session store is unavailable")
)

// Store は、セッションの実体の保存先です。ID をキーにした値の読み書きだけを持ち、
// HTTP には触れません。クッキーの発行と読み取り、ID を採用するかどうかの判断は
// Handler が行います。
//
// 以前はクッキーの発行まで Store が担っていて、Secure などの属性が Handler と Store の
// 2 か所に分かれ、「MaxAge が負なら削除」という規約と Options の複製が両実装にありました。
// 偽物を書くにも httptest が要りました。責務を値の永続化に絞ると、この 3 つで足ります。
type Store interface {
	// Load は id の値を返します。無い・期限切れなら ErrNotFound です。
	//
	// ★ 保存先へ到達できなかった場合は ErrStoreUnavailable でラップしてください。
	// それ以外のエラーは「実体が壊れている」と解釈され、クッキーが破棄されます。
	Load(ctx context.Context, id string) (map[string]string, error)

	// Save は values を id の下に ttl の期限で保存します。既にあれば上書きです。
	Save(ctx context.Context, id string, values map[string]string, ttl time.Duration) error

	// Delete は id の実体を消します。無くてもエラーにしません。
	Delete(ctx context.Context, id string) error
}

// sessionIDLen は newSessionID が返す長さです（32 バイトを base64 RawURL で表した 43 文字）。
const sessionIDLen = 43

// newSessionID は、推測できないセッション ID を返します。中身を持たない値なので、
// 必要な性質は推測できないことだけです（crypto/rand の 32 バイト）。
//
// 発行したものが isValidSessionID を通ることを、ここで確かめてから返します。乱数が
// "__…__"（Firestore の予約形）を引く確率は 6×10⁻⁸ ほどですが、引いた回だけ保存が
// 失敗してログインが 500 になるうえ、再現しないので原因にたどり着けません。
func newSessionID() (string, error) {
	for range 4 {
		id, err := randomToken(base64.RawURLEncoding)
		if err != nil {
			return "", err
		}
		if isValidSessionID(id) {
			return id, nil
		}
	}
	return "", errors.New("session: could not mint a usable session ID")
}

// isValidSessionID は、newSessionID が発行しうる形かどうかを返します。
//
// ID はクッキーで届くので、中身は相手が決められます。Handler は Load へ渡す前に
// これで確かめ、ID を保存先の識別子に使う実装（Firestore ストアはドキュメントのパス
// に使います）も自分で確かめます。"/" を含む値は Doc() がサブコレクションのパスとして
// 解釈するため、素通しにすると本来のコレクションの外を指せます。
//
// 判定は発行側の形そのもの（43 文字の base64 RawURL）に固定します。保存先ごとの
// 禁則を数え上げるより、自分が出す形だけを通すほうが取りこぼしません。43 文字である
// 時点で Firestore の "."、".."、1500 バイト上限は満たせなくなります。
//
// ただし "__…__" だけは長さでも文字種でも排除できないので、明示的に落とします。
// newSessionID もこの判定を通るまで振り直すので、発行と検証が食い違いません。
func isValidSessionID(id string) bool {
	if len(id) != sessionIDLen {
		return false
	}
	if strings.HasPrefix(id, "__") && strings.HasSuffix(id, "__") {
		return false
	}
	for _, r := range id {
		if !isSessionIDChar(r) {
			return false
		}
	}
	return true
}

// isSessionIDChar は base64 RawURL の文字集合です。
func isSessionIDChar(r rune) bool {
	return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_'
}

// memoryStore は、プロセス内にセッションを保持する Store です。
type memoryStore struct {
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
func NewMemoryStore() Store {
	return &memoryStore{entries: map[string]memoryEntry{}}
}

func (s *memoryStore) Load(_ context.Context, id string) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[id]
	if !ok {
		return nil, ErrNotFound
	}
	if time.Now().After(entry.expiresAt) {
		delete(s.entries, id)
		return nil, ErrNotFound
	}
	return maps.Clone(entry.values), nil
}

func (s *memoryStore) Save(_ context.Context, id string, values map[string]string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[id] = memoryEntry{
		values:    maps.Clone(values),
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (s *memoryStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, id)
	return nil
}
