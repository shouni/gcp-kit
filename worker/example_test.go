package worker_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/shouni/gcp-kit/worker"
)

// Job is the JSON payload contract shared with the producer (tasks.Enqueuer).
type Job struct {
	JobID string `json:"job_id"`
	Step  int    `json:"step"`
}

// ErrUnknownStep is an example of an input error that retrying will not fix.
var ErrUnknownStep = errors.New("unknown step")

type jobRunner struct{}

func (jobRunner) Execute(ctx context.Context, job Job) error {
	// Cloud Tasks delivers at least once, so the same task may arrive more than once.
	if md, ok := worker.MetadataFromContext(ctx); ok && md.RetryCount > 0 {
		slog.WarnContext(ctx, "retrying task", "task", md.TaskName, "retry", md.RetryCount)
	}

	if job.Step < 0 {
		// Marking it permanent returns 2xx and stops pointless retries.
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
	// Handler implements http.Handler, so it can be registered as is. In
	// production, wrap it in auth.Require with a Verifier made by oidc.New
	// (only services call this route, so failures stop instead of falling back).
	mux.Handle("POST /tasks/run", h)
}
