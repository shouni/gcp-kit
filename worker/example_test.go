package worker_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/shouni/gcp-kit/worker"
)

// Job は producer (tasks.Enqueuer) と共有する JSON ペイロード契約です。
type Job struct {
	JobID string `json:"job_id"`
	Step  int    `json:"step"`
}

// ErrUnknownStep は、リトライしても直らない入力エラーの例です。
var ErrUnknownStep = errors.New("unknown step")

type jobRunner struct{}

func (jobRunner) Execute(ctx context.Context, job Job) error {
	// Cloud Tasks は at-least-once 配信のため、同じタスクが複数回届くことがあります。
	if md, ok := worker.MetadataFromContext(ctx); ok && md.RetryCount > 0 {
		slog.WarnContext(ctx, "retrying task", "task", md.TaskName, "retry", md.RetryCount)
	}

	if job.Step < 0 {
		// ErrPermanent でラップすると 2xx を返して打ち切り、無駄なリトライを止めます。
		return fmt.Errorf("%w: %w (step=%d)", worker.ErrPermanent, ErrUnknownStep, job.Step)
	}
	return nil
}

func ExampleNewHandler() {
	h := worker.NewHandler(jobRunner{},
		worker.WithMaxBodyBytes(1<<20),
		worker.WithStrictJSON(),
	)

	mux := http.NewServeMux()
	// Handler は http.Handler を実装しているためそのまま登録できます。
	// 実運用では oidc.New で作った Verifier を auth.Require で被せてください
	// （サービスしか来ないルートなので、失敗はフォールバックせず止めます）。
	mux.Handle("POST /tasks/run", h)
}
