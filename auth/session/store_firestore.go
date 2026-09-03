package session

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// FirestoreConfig は、Firestore に置く Store の設定です。
type FirestoreConfig struct {
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
	}, nil
}

// errForeignID は、この実装が発行していない形の ID を受け取ったときのエラーです。
// ID はドキュメントのパスになるので、形を確かめずに渡すと相手にパスを決めさせることに
// なります（isValidSessionID を参照）。
var errForeignID = errors.New("session: refusing a session ID that was not minted here")

func (s *firestoreStore) Load(ctx context.Context, id string) (map[string]string, error) {
	// 発行した形でない ID は、Firestore へ問い合わせる前に「無い」と答えます。
	// 実体があるはずもなく、問い合わせればパスを相手に決めさせることになります。
	if !isValidSessionID(id) {
		return nil, ErrNotFound
	}

	snap, err := s.client.Collection(s.collection).Doc(id).Get(ctx)
	if err != nil {
		switch status.Code(err) {
		case codes.NotFound, codes.InvalidArgument:
			return nil, ErrNotFound
		}
		// ここから先は Firestore へ到達できていません（ErrStoreUnavailable を参照）。
		return nil, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}

	var doc sessionDoc
	if err := snap.DataTo(&doc); err != nil {
		// 読めたが解釈できない実体は壊れたセッションです。ラップしないことで、
		// 呼び出し側にクッキーを消させて作り直させます。
		return nil, fmt.Errorf("session: decode stored session: %w", err)
	}
	// TTL の削除は遅れるので、期限は読み出し側でも見ます。
	if time.Now().After(doc.ExpiresAt) {
		return nil, ErrNotFound
	}
	return doc.Values, nil
}

func (s *firestoreStore) Save(ctx context.Context, id string, values map[string]string, ttl time.Duration) error {
	if !isValidSessionID(id) {
		return errForeignID
	}
	doc := sessionDoc{Values: values, ExpiresAt: time.Now().Add(ttl)}
	if _, err := s.client.Collection(s.collection).Doc(id).Set(ctx, doc); err != nil {
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	return nil
}

func (s *firestoreStore) Delete(ctx context.Context, id string) error {
	if !isValidSessionID(id) {
		return errForeignID
	}
	if _, err := s.client.Collection(s.collection).Doc(id).Delete(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	return nil
}
