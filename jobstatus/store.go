package jobstatus

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/shouni/go-utils/jobid"
)

// Store は、Firestore を裏付けとしたジョブ状態の読み書きを行います。
//
// 型引数 T にはサービス固有の状態型（Status を埋め込んだ構造体）を指定します。
// ドキュメント ID はジョブ ID そのもので、1 ジョブ 1 ドキュメントです。
type Store[T any] struct {
	client     *firestore.Client
	collection string
	now        func() time.Time
}

// mustNotBePointer は、型引数にポインタ型を渡す誤用を構築時に弾きます。
//
// Status の埋め込みは値型 T のメソッド集合を通して見つけます（Save は any(&status) を
// Stamper へアサートします）。T が *X だとアサート対象が **X になり、Stamper も
// Carrier も IsTerminal も満たしません。その結果、打刻されず・引き継がれず・
// 再実行ガードが常に false になったドキュメントが、エラーもログも無しに書かれます。
//
// Store[*X] は Go として自然に書けてしまい、しかも壊れ方が静かなので、データを
// 書く前に落とします。埋め込みの無い型（T = X で Stamper を満たさない）は doc の
// とおり引き続き許容します。そちらは打刻も引き継ぎも行われないだけで、誤って
// 静かに壊れるわけではないためです。
func mustNotBePointer[T any](fn string) {
	if t := reflect.TypeFor[T](); t.Kind() == reflect.Pointer {
		panic(fmt.Sprintf(
			"jobstatus: %s[%s]: 型引数にポインタ型を渡さないでください。"+
				"打刻・引き継ぎ・再実行ガードが無効になります（値型で instantiate してください）", fn, t))
	}
}

// NewStore は Store を構築します。
//
// collection はジョブ状態を置くコレクションのパスです（例: "jobs"）。
// 型引数にポインタ型を渡した場合は panic します（mustNotBePointer を参照）。
func NewStore[T any](client *firestore.Client, collection string) *Store[T] {
	mustNotBePointer[T]("NewStore")

	return &Store[T]{
		client:     client,
		collection: collection,
		now:        func() time.Time { return time.Now().UTC() },
	}
}

// Save はジョブ状態を保存します。
//
// ドキュメントは常に最新の 1 世代だけを保持し、上書きで更新します。
// status が Status を埋め込んでいれば、JobID と UpdatedAt はここで打刻されます
// （引数の値は変更しません）。
func (s *Store[T]) Save(ctx context.Context, jobID string, status T) error {
	doc, safeJobID, err := s.doc(jobID)
	if err != nil {
		return err
	}

	if stamper, ok := any(&status).(Stamper); ok {
		stamper.Stamp(safeJobID, s.now())
	}

	if _, err := doc.Set(ctx, status); err != nil {
		return classify(safeJobID, err)
	}
	return nil
}

// Get はジョブ状態を取得します。未記録の場合は ErrNotFound を返します。
//
// デコードに失敗した記録は未記録ではなくエラーとして返します。未記録と同じ扱いに
// すると、破損に気づかないまま再生成が走り続けるためです。
func (s *Store[T]) Get(ctx context.Context, jobID string) (T, error) {
	var out T

	doc, safeJobID, err := s.doc(jobID)
	if err != nil {
		return out, err
	}

	snap, err := doc.Get(ctx)
	if err != nil {
		return out, classify(safeJobID, err)
	}
	return decode[T](snap, safeJobID)
}

// decode はスナップショットを T へ読み出します。Get と Modify で読み方を揃えます。
func decode[T any](snap *firestore.DocumentSnapshot, safeJobID string) (T, error) {
	var out T
	if err := snap.DataTo(&out); err != nil {
		return out, fmt.Errorf("ジョブ状態のデコードに失敗しました (%s): %w", safeJobID, err)
	}

	// job_id を持たない古い記録を読んだときに、ID 無しの構造体を返さない。
	if e, ok := any(&out).(interface{ EnsureJobID(string) }); ok {
		e.EnsureJobID(safeJobID)
	}
	return out, nil
}

// Modify は、記録を読んでから書くまでを Firestore のトランザクションで行います。
// Modifier を満たし、Recorder.Begin はこれがあれば使います。
//
// fn は前回の記録（未記録なら nil）を受け取り、書く値と、書くかどうかを返します。
// Get と Save を別々に呼ぶと、その間に別の書き込みが入りえます。Cloud Tasks の
// 再配信が、完了を記録した直後の succeeded を running で上書きするのがその例です。
// トランザクションの中なら、読んだ後に記録が変わっていれば Firestore が fn を
// やり直させるので、fn は必ず最新の記録を見て判断します。
//
// fn はやり直しで複数回呼ばれることがあります。外へ副作用を出さず、引数だけから
// 結果を決めてください。
//
// 読み取りやデコードに失敗した場合は、fn を呼ばずにそのエラーを返します（Get と
// 同じ分類です）。fn のエラーは包まずにそのまま返します。
func (s *Store[T]) Modify(ctx context.Context, jobID string, fn func(prev *T) (next T, write bool, err error)) error {
	doc, safeJobID, err := s.doc(jobID)
	if err != nil {
		return err
	}

	// デコード失敗と fn のエラーは、Firestore のエラーと一緒に classify へ通さないよう
	// ここに退避し、素のまま返します。
	var innerErr error
	err = s.client.RunTransaction(ctx, func(_ context.Context, tx *firestore.Transaction) error {
		innerErr = nil

		var prev *T
		snap, getErr := tx.Get(doc)
		switch {
		case grpcstatus.Code(getErr) == codes.NotFound:
		case getErr != nil:
			return getErr
		default:
			v, decErr := decode[T](snap, safeJobID)
			if decErr != nil {
				innerErr = decErr
				return decErr
			}
			prev = &v
		}

		next, write, fnErr := fn(prev)
		if fnErr != nil {
			innerErr = fnErr
			return fnErr
		}
		if !write {
			return nil
		}
		if stamper, ok := any(&next).(Stamper); ok {
			stamper.Stamp(safeJobID, s.now())
		}
		return tx.Set(doc, next)
	})
	if innerErr != nil {
		return innerErr
	}
	if err != nil {
		return classify(safeJobID, err)
	}
	return nil
}

// Delete はジョブ状態を削除します。不在はエラーになりません。
func (s *Store[T]) Delete(ctx context.Context, jobID string) error {
	doc, safeJobID, err := s.doc(jobID)
	if err != nil {
		return err
	}

	if _, err := doc.Delete(ctx); err != nil {
		return classify(safeJobID, err)
	}
	return nil
}

// doc は、正規化済みのジョブ ID を ID とするドキュメント参照を返します。
//
// ジョブ ID は URL パスとドキュメント ID の双方に現れるため、検証はセキュリティ
// 境界を兼ねます。呼び出し側で正規化する必要はありません。
func (s *Store[T]) doc(jobID string) (*firestore.DocumentRef, string, error) {
	safeJobID, err := jobid.Sanitize(jobID)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrInvalidJobID, err)
	}
	if s.client == nil {
		return nil, "", errors.New("jobstatus: client is not configured")
	}
	if s.collection == "" {
		return nil, "", errors.New("jobstatus: collection is not configured")
	}
	return s.client.Collection(s.collection).Doc(safeJobID), safeJobID, nil
}
