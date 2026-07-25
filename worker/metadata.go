package worker

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

// Cloud Tasks がワーカーへのリクエストに付与するヘッダー。
// 詳細: https://cloud.google.com/tasks/docs/creating-http-target-tasks
const (
	HeaderTaskName       = "X-CloudTasks-TaskName"
	HeaderQueueName      = "X-CloudTasks-QueueName"
	HeaderRetryCount     = "X-CloudTasks-TaskRetryCount"
	HeaderExecutionCount = "X-CloudTasks-TaskExecutionCount"
	HeaderTaskETA        = "X-CloudTasks-TaskETA"
)

// Metadata は Cloud Tasks がリクエストヘッダーで渡す配信情報です。
//
// Cloud Tasks は at-least-once 配信であり、同じタスクが複数回ワーカーに届く可能性があります。
// RetryCount / ExecutionCount を見ることで、再配信時に処理をスキップする、あるいは
// 一定回数を超えたら諦める、といった冪等な実装が書けます。
type Metadata struct {
	// TaskName は完全修飾のタスク名です（projects/.../tasks/...）。
	// 決定的な名前で投入している場合、冪等キーとして利用できます。
	TaskName string
	// QueueName は完全修飾のキュー名です。
	QueueName string
	// RetryCount は 5xx 応答等による再試行の回数です。
	RetryCount int
	// ExecutionCount はワーカーが応答を返した回数（5xx 応答を含む）です。
	ExecutionCount int
	// ETA はタスクの実行予定時刻です。取得できない場合はゼロ値になります。
	ETA time.Time
}

type metadataContextKey struct{}

// WithMetadata は Cloud Tasks の配信情報をコンテキストに格納します。
// ProcessTask が自動的に呼び出すため、通常は利用側が直接呼ぶ必要はありません。
func WithMetadata(ctx context.Context, md Metadata) context.Context {
	return context.WithValue(ctx, metadataContextKey{}, md)
}

// MetadataFromContext は TaskExecutor に渡されたコンテキストから Cloud Tasks の
// 配信情報を取り出します。Cloud Tasks 以外からの呼び出しでは ok=false になります。
func MetadataFromContext(ctx context.Context) (Metadata, bool) {
	md, ok := ctx.Value(metadataContextKey{}).(Metadata)
	return md, ok && md.TaskName != ""
}

func metadataFromHeader(header http.Header) Metadata {
	md := Metadata{
		TaskName:       header.Get(HeaderTaskName),
		QueueName:      header.Get(HeaderQueueName),
		RetryCount:     atoiOrZero(header.Get(HeaderRetryCount)),
		ExecutionCount: atoiOrZero(header.Get(HeaderExecutionCount)),
	}
	if eta := header.Get(HeaderTaskETA); eta != "" {
		// ETA は Unix 秒（小数部つき）で送られてきます。
		if seconds, err := strconv.ParseFloat(eta, 64); err == nil {
			md.ETA = time.UnixMicro(int64(seconds * 1e6)).UTC()
		}
	}
	return md
}

func atoiOrZero(value string) int {
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return n
}
