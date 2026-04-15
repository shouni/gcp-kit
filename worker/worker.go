package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

// TaskExecutor は、デコードされたペイロードを受け取って実際の処理を行うインターフェースです。
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
	// リソースリーク防止のためボディをクローズ
	defer r.Body.Close()

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload T
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		slog.Error("Failed to decode worker task payload", "error", err)
		// 400系を返すと、Cloud Tasks は通常リトライを行わずタスクを破棄します。
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	slog.Info("Worker received task", "type", fmt.Sprintf("%T", payload))

	// r.Context() を渡すことで、Cloud Tasks のリクエストタイムアウト設定を伝搬させます。
	if err := h.executor.Execute(r.Context(), payload); err != nil {
		// セキュリティリスクを回避するため、payload そのものではなく型情報のみを記録します。
		slog.Error("Worker task execution failed",
			"error", err,
			"payload_type", fmt.Sprintf("%T", payload),
		)
		// 500系を返すと、Cloud Tasks は設定に基づき指数バックオフリトライを行います。
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 4. 成功を返却
	slog.Info("Worker task completed successfully")
	w.WriteHeader(http.StatusOK)
}
