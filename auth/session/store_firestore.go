package session

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// FirestoreConfig は、Firestore に置く Store の設定です。
type FirestoreConfig struct {
	StoreConfig

	// Client は接続済みの Firestore クライアントです（必須）。
	//
	// ★ ジョブ状態とは別のデータベースを指してください。データベース名は識別子で
	// 後から変えられないので、兼ねると片方で名前が実態と合わなくなります。
	Client *firestore.Client

	// Collection は、セッションを置くコレクション名です（必須）。
	Collection string
}

// sessionDoc は、セッション 1 件のドキュメント表現です。ExpiresAt は Firestore の
// TTL ポリシーが見るフィールドでもありますが、削除は最大 24 時間遅れるので、
// 読み出し側でも必ず期限を見ます。
type sessionDoc struct {
	Values    map[string]string `firestore:"values"`
	ExpiresAt time.Time         `firestore:"expiresAt"`
}

// firestoreStore は、Firestore にセッションを保持する Store です。
type firestoreStore struct {
	client     *firestore.Client
	collection string
	opts       Options
}

// NewFirestoreStore は、Firestore にセッションを保持する Store を返します。
//
// ★ 期限切れドキュメントの掃除は Firestore の TTL ポリシー（ExpiresAt が対象）に
// 任せます。設定しないとセッションが無期限に溜まります。クッキーと違い、保存した
// 実体は自分では消えません。
func NewFirestoreStore(cfg FirestoreConfig) (Store, error) {
	if cfg.Client == nil {
		return nil, errors.New("session: FirestoreConfig.Client must not be nil")
	}
	if strings.TrimSpace(cfg.Collection) == "" {
		return nil, errors.New("session: FirestoreConfig.Collection must not be empty")
	}
	return &firestoreStore{
		client:     cfg.Client,
		collection: strings.TrimSpace(cfg.Collection),
		opts:       cfg.options(),
	}, nil
}

func (s *firestoreStore) Get(r *http.Request, name string) (*Session, error) {
	session := NewSession(name)
	opts := s.opts
	session.Options = &opts

	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		return session, nil
	}
	// 発行した形でない ID は、Firestore へ問い合わせる前に捨てます。実体が
	// あるはずもなく、そのまま渡すとドキュメントのパスを相手に決めさせることに
	// なるためです（isValidSessionID を参照）。
	if !isValidSessionID(cookie.Value) {
		return session, nil
	}

	snap, err := s.client.Collection(s.collection).Doc(cookie.Value).Get(r.Context())
	if err != nil {
		switch status.Code(err) {
		case codes.NotFound:
			// 保存されていない ID は採用しません（Store の約束）。
			return session, nil
		case codes.InvalidArgument:
			// ID はクッキーで運ばれる以上、ドキュメント ID として成立しない値も
			// 届きます。障害ではないので、実体が無いのと同じ扱いにします。
			return session, nil
		}
		// ここから先は Firestore へ到達できていません（ErrStoreUnavailable を参照）。
		return session, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}

	var doc sessionDoc
	if err := snap.DataTo(&doc); err != nil {
		// 読めたが解釈できない実体は壊れたセッションです。ラップしないことで、
		// 呼び出し側にクッキーを消させて作り直させます。
		return session, err
	}
	// TTL の削除は遅れるので、期限は読み出し側でも見ます。
	if time.Now().After(doc.ExpiresAt) {
		return session, nil
	}

	session.ID = cookie.Value
	maps.Copy(session.Values, doc.Values)
	session.IsNew = false
	return session, nil
}

func (s *firestoreStore) Save(r *http.Request, w http.ResponseWriter, session *Session) error {
	// Get が採用する ID は検証済みで、空なら下で振り直します。ここへ来る他の値は
	// 呼び出し側が手で入れたものなので、書く前に止めます。
	if session.ID != "" && !isValidSessionID(session.ID) {
		return errors.New("session: refusing to write a session ID that was not minted here")
	}

	opts := session.Options
	if opts == nil {
		o := s.opts
		opts = &o
	}

	if opts.MaxAge < 0 {
		if session.ID != "" {
			// 消せなくてもクッキーは落とします。ここで戻ると、利用者から見て
			// ログアウトが失敗したのにクッキーだけ残る形になります。
			if _, err := s.client.Collection(s.collection).Doc(session.ID).Delete(r.Context()); err != nil {
				http.SetCookie(w, newCookie(session.Name(), "", opts))
				return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
			}
		}
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

	doc := sessionDoc{
		Values:    session.Values,
		ExpiresAt: time.Now().Add(time.Duration(opts.MaxAge) * time.Second),
	}
	if _, err := s.client.Collection(s.collection).Doc(session.ID).Set(r.Context(), doc); err != nil {
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}

	http.SetCookie(w, newCookie(session.Name(), session.ID, opts))
	return nil
}
