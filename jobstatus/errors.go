package jobstatus

import (
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// このパッケージが返すエラーです。いずれも原因を包んだまま返すので、errors.Is の
// 判定はそのままに、ログには元の失敗理由が残ります。
//
// 読み書きの結果は次の 3 つ（と、どれにも当てはまらないもの）に分かれます。HTTP
// ハンドラーはこう対応づけてください。呼び出し側が取るべき判断が分類ごとに違うため、
// まとめると必ずどちらかを取り違えます。
//
//	ErrInvalidJobID → 400  入力が不正。再試行しても直らない
//	ErrNotFound     → 404  未記録。処理を先へ進めてよい
//	ErrUnavailable  → 503  読めなかっただけ。あとで読めるかもしれない
//	その他          → 500  デコード失敗など
//
// ErrClosed だけは別で、ファクトリの寿命の話です（1 回のリクエストの結果ではなく、
// クライアントを閉じた後に取り出そうとしたことを表します）。
var (
	// ErrNotFound は、ジョブ状態がまだ記録されていないことを表します。
	// 記録前の投入や、この機能より前に作られたジョブでも起こる正常な状態です。
	ErrNotFound = errors.New("job status not found")

	// ErrUnavailable は、ジョブ状態が「存在するはずなのに読めなかった」ことを
	// 表します。
	//
	// ErrNotFound と分けているのは、両者で取るべき判断が正反対だからです。記録が
	// 無いなら処理を進めてよい一方、読めなかっただけの場合に「無い」とみなすと、
	// 完了済みのジョブを未完了と誤認して生成をまるごとやり直します
	// （Recorder.AlreadySucceeded を参照）。
	ErrUnavailable = errors.New("job status unavailable")

	// ErrInvalidJobID は、渡されたジョブ ID が正規化を通らなかったことを表します。
	//
	// これが独立していないと、ハンドラーは URL に紛れ込んだ不正な ID をストレージ
	// 障害と同じ 5xx で返すことになり、再試行しても直らないリクエストを再試行
	// させます。原因は jobid のエラーとして残るので、errors.Is で jobid.ErrEmpty /
	// jobid.ErrTooLong / jobid.ErrInvalidFormat まで辿れます。
	ErrInvalidJobID = errors.New("invalid job id")

	// ErrClosed は、ファクトリが既に閉じられていることを表します。
	ErrClosed = errors.New("firestore client is closed")
)

// classify は Firestore が返したエラーを、呼び出し側の判断が分かれる 3 つへ畳みます。
//
// 権限不足を ErrNotFound へ寄せないことが要点です。寄せると、権限設定を誤った瞬間に
// 全ジョブが「未記録」に見え、再実行ガードが完了済みのジョブを未完了と誤認します。
// 読めなかったのか無いのかは、ここでしか区別できません。
func classify(jobID string, err error) error {
	if err == nil {
		return nil
	}

	switch grpcstatus.Code(err) {
	case codes.NotFound:
		return fmt.Errorf("%w (%s): %w", ErrNotFound, jobID, err)

	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted,
		codes.Internal, codes.Aborted, codes.PermissionDenied, codes.Unauthenticated:
		return fmt.Errorf("%w (%s): %w", ErrUnavailable, jobID, err)

	default:
		return fmt.Errorf("ジョブ状態の操作に失敗しました (%s): %w", jobID, err)
	}
}
