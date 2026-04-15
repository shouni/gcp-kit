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

	if !isPostRequest(r) {
		writeMethodNotAllowed(w)
		return
	}

	payload, err := decodePayload[T](r)
	if err != nil {
		handleDecodeError(w, err)
		return
	}

	slog.Info("Worker received task", "type", fmt.Sprintf("%T", payload))

	if err := h.executeTask(r.Context(), payload); err != nil {
		handleExecutionError(w, payload, err)
		return
	}

	writeSuccess(w)
}

func isPostRequest(r *http.Request) bool {
	return r.Method == http.MethodPost
}

func decodePayload[T any](r *http.Request) (T, error) {
	var payload T
	err := json.NewDecoder(r.Body).Decode(&payload)
	return payload, err
}

func handleDecodeError(w http.ResponseWriter, err error) {
	slog.Error("Failed to decode worker task payload", "error", err)
	// 400系を返すと、Cloud Tasks は通常リトライを行わずタスクを破棄します。
	http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
}

func (h *Handler[T]) executeTask(ctx context.Context, payload T) error {
	// r.Context() を渡すことで、Cloud Tasks のリクエストタイムアウト設定を伝搬させます。
	return h.executor.Execute(ctx, payload)
}

func handleExecutionError[T any](w http.ResponseWriter, payload T, err error) {
	// セキュリティリスクを回避するため、payload そのものではなく型情報のみを記録します。
	slog.Error("Worker task execution failed",
		"error", err,
		"payload_type", fmt.Sprintf("%T", payload),
	)
	// 500系を返すと、Cloud Tasks は設定に基づき指数バックオフリトライを行います。
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

func writeMethodNotAllowed(w http.ResponseWriter) {
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func writeSuccess(w http.ResponseWriter) {
	slog.Info("Worker task completed successfully")
	w.WriteHeader(http.StatusOK)
}
