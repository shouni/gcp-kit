// Package worker は、Cloud Tasks / Cloud Run 等から呼び出される HTTP ハンドラーで
// JSONペイロードをデコードし、型安全にタスク実行を行うユーティリティを提供します。
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"runtime/pprof"
)

// ErrPermanent は、リトライしても成功し得ない恒久的な失敗を示すセンチネルエラーです。
//
// TaskExecutor がこのエラーでラップしたエラーを返した場合、Handler は 2xx を返して
// Cloud Tasks にタスクを完了扱いさせ、無駄なリトライを止めます（内容は ERROR ログに残ります）。
// 一時的な失敗（外部APIのタイムアウト等）では返さないでください。
//
//	if errors.Is(err, domain.ErrInvalidInput) {
//	    return fmt.Errorf("%w: %v", worker.ErrPermanent, err)
//	}
var ErrPermanent = errors.New("worker: permanent failure, task must not be retried")

// defaultMaxBodyBytes は受け付けるリクエストボディの既定上限です。
// Cloud Tasks の HTTP ターゲットはタスク全体で 1MB 上限のため、既定値もそれに合わせます。
const defaultMaxBodyBytes int64 = 1 << 20

// TaskExecutor は、デコードされたペイロードを受け取って実際の処理を行うインターフェースです。
type TaskExecutor[T any] interface {
	Execute(ctx context.Context, payload T) error
}

// Option は Handler の任意設定です。
type Option func(*options)

type options struct {
	maxBodyBytes int64
	strictJSON   bool
	logger       *slog.Logger
}

// WithMaxBodyBytes はリクエストボディの上限を変更します。0 以下を指定すると無制限になります。
func WithMaxBodyBytes(n int64) Option {
	return func(o *options) { o.maxBodyBytes = n }
}

// WithStrictJSON は、ペイロードに未知のフィールドが含まれる場合にデコードを失敗させます。
// 送信側と受信側の型定義のずれを早期に検知したい場合に使います。
func WithStrictJSON() Option {
	return func(o *options) { o.strictJSON = true }
}

// WithLogger は本パッケージが使うロガーを差し替えます。未指定の場合は slog.Default() です。
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) { o.logger = logger }
}

// Handler は Cloud Tasks からの HTTP リクエストを受け取る汎用ハンドラーです。
type Handler[T any] struct {
	executor TaskExecutor[T]
	opts     options
}

// NewHandler は新しいワーカーハンドラーを生成します。
func NewHandler[T any](executor TaskExecutor[T], opts ...Option) *Handler[T] {
	cfg := options{maxBodyBytes: defaultMaxBodyBytes}
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Handler[T]{
		executor: executor,
		opts:     cfg,
	}
}

func (h *Handler[T]) log() *slog.Logger {
	if h != nil && h.opts.logger != nil {
		return h.opts.logger
	}
	return slog.Default()
}

// ServeHTTP は Handler を http.Handler として利用可能にします。
func (h *Handler[T]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.ProcessTask(w, r)
}

// ProcessTask は Cloud Tasks からの POST リクエストを処理する http.HandlerFunc です。
func (h *Handler[T]) ProcessTask(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.executor == nil {
		slog.ErrorContext(r.Context(), "Worker task executor is not configured")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	md := metadataFromHeader(r.Header)
	ctx := WithMetadata(r.Context(), md)

	// タスク名を pprof のゴルーチンラベルに載せます。Go 1.27 以降、ラベルは
	// パニックのトレースバックの見出し行にも出ます。ワーカーが落ちたときに
	// どのタスクだったかがスタックだけで分かるようにするためで、ログの相関
	// （slogctx）が使えない panic の経路を埋めるのがここの役目です。
	// ラベルは executor が起こす子ゴルーチンへも継承されます。
	//
	// pprof.SetGoroutineLabels ではなく pprof.Do を使います。前者は復帰時に
	// ラベルを戻さないため、net/http が 1 本の接続ゴルーチンで keep-alive の
	// 複数リクエストを順に捌く構成では、次のリクエストが前のタスク名を背負った
	// ままになります。トレースバックが無関係のタスクを指すのは、名前が
	// 載っていないより悪い状態です。
	name := path.Base(md.TaskName)
	if name == "" || name == "." || name == "/" {
		h.process(ctx, w, r)
		return
	}
	pprof.Do(ctx, pprof.Labels("cloudtask", name), func(ctx context.Context) {
		h.process(ctx, w, r)
	})
}

// process はボディをデコードして executor を呼び、その結果を Cloud Tasks の
// リトライ仕様に沿った状態コードへ写します。
//
// ProcessTask から切り出しているのは、pprof.Do がラベルを関数の実行中だけに
// 限るためです（ラベルの復元はこの関数からの復帰と対応します）。
func (h *Handler[T]) process(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	body := r.Body
	if h.opts.maxBodyBytes > 0 {
		body = http.MaxBytesReader(w, r.Body, h.opts.maxBodyBytes)
	}

	decoder := json.NewDecoder(body)
	if h.opts.strictJSON {
		decoder.DisallowUnknownFields()
	}

	var payload T
	if err := decoder.Decode(&payload); err != nil {
		h.log().ErrorContext(ctx, "Failed to decode worker task payload", "error", err)
		// 400系を返すと、Cloud Tasks は通常リトライを行わずタスクを破棄します。
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	h.log().DebugContext(ctx, "Worker received task", "type", fmt.Sprintf("%T", payload))

	// ctx はリクエストのものを土台にしているため、Cloud Tasks の応答待ち上限が
	// そのまま executor まで伝わります（配信メタデータとラベルを足してあります）。
	if err := h.executor.Execute(ctx, payload); err != nil {
		// セキュリティリスクを回避するため、payload そのものではなく型情報のみを記録します。
		h.log().ErrorContext(ctx, "Worker task execution failed",
			"error", err,
			"payload_type", fmt.Sprintf("%T", payload),
			"permanent", errors.Is(err, ErrPermanent),
		)

		if errors.Is(err, ErrPermanent) {
			// 恒久的な失敗をリトライさせても成功しないため、成功扱いで打ち切ります。
			w.WriteHeader(http.StatusOK)
			return
		}

		// 500系を返すと、Cloud Tasks は設定に基づき指数バックオフリトライを行います。
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.log().DebugContext(ctx, "Worker task completed successfully")
	w.WriteHeader(http.StatusOK)
}
