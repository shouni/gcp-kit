package session

import (
	"errors"
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
	// 後から変えられないので、jobstatus 用のものを兼ねると名前が実態と合わなく
	// なります。firestore.NewClientWithDatabase で接続先を選べます。
	Client *firestore.Client

	// Collection は、セッションを置くコレクション名です（必須）。
	Collection string
}

// sessionDoc は、セッション 1 件のドキュメント表現です。
//
// ExpiresAt は Firestore の TTL ポリシーが見るフィールドでもあります。
// ただし TTL の削除は最大 24 時間遅れるので、読み出し側でも必ず期限を見ます。
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
// クッキーが運ぶのは不透明な ID だけなので、セッション鍵は要りません。
// 代わりに、ログアウトと失効がサーバー側で実際に効きます。
//
// ★ 期限切れドキュメントの掃除は Firestore の TTL ポリシー（ExpiresAt が対象）に
// 任せます。設定しないとセッションが無期限に溜まります。クッキーと違い、
// 保存した実体は自分では消えません。
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

	snap, err := s.client.Collection(s.collection).Doc(cookie.Value).Get(r.Context())
	if err != nil {
		if status.Code(err) == codes.NotFound {
			// 保存されていない ID は採用しません（Store の約束）。
			return session, nil
		}
		return session, err
	}

	var doc sessionDoc
	if err := snap.DataTo(&doc); err != nil {
		return session, err
	}
	// TTL の削除は遅れるので、期限は読み出し側でも見ます。
	if time.Now().After(doc.ExpiresAt) {
		return session, nil
	}

	session.ID = cookie.Value
	for k, v := range doc.Values {
		session.Values[k] = v
	}
	session.IsNew = false
	return session, nil
}

func (s *firestoreStore) Save(r *http.Request, w http.ResponseWriter, session *Session) error {
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
				return err
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
		return err
	}

	http.SetCookie(w, newCookie(session.Name(), session.ID, opts))
	return nil
}
