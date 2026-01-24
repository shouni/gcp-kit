package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

// TaskExecutor は、デコードされたペイロードを受け取って実際の処理を行うインターフェースです。
// ライブラリ利用者は、このインターフェースを実装してビジネスロジックを注入します。
type TaskExecutor[T any] interface {
	Execute(ctx context.Context, payload T) error
}

// Handler は Cloud Tasks からの HTTP リクエストを受け取る汎用ハンドラーです。
type Handler[T any] struct {
	executor TaskExecutor[T]
}

// NewHandler は新しいワーカーハンドラーを生成します。
func NewHandler[T any](executor TaskExecutor[T]) *Handler[T] {
	return &Handler[T]{
		executor: executor,
	}
}

// ProcessTask は Cloud Tasks からの POST リクエストを処理する http.HandlerFunc です。
func (h *Handler[T]) ProcessTask(w http.ResponseWriter, r *http.Request) {
	// 1. メソッドチェック
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 2. ペイロードを T 型にデコード
	var payload T
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		slog.Error("Failed to decode worker task payload", "error", err)
		// 400系を返すと、Cloud Tasks は「リトライ不能なエラー」と判断してタスクを捨てることが多いです。
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	slog.Info("Worker received task", "type", fmt.Sprintf("%T", payload))

	// 3. 注入されたエグゼキューターを実行
	// r.Context() を渡すことで、Cloud Tasks のリクエストタイムアウト設定を伝搬させます。
	if err := h.executor.Execute(r.Context(), payload); err != nil {
		slog.Error("Worker task execution failed",
			"error", err,
			"payload", payload,
		)
		// 500系を返すと、Cloud Tasks はキューの設定に基づき自動で指数バックオフリトライを行います。
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 4. 成功を返却
	slog.Info("Worker task completed successfully")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "OK")
}
