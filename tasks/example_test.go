package tasks_test

import (
	"context"
	"log/slog"
	"time"

	"github.com/shouni/gcp-kit/tasks"
)

// Job is the JSON payload contract between producer and worker.
type Job struct {
	JobID string `json:"job_id"`
	Step  int    `json:"step"`
}

func ExampleNewEnqueuer() {
	ctx := context.Background()

	enqueuer, err := tasks.NewEnqueuer[Job](ctx, tasks.Config{
		ProjectID:           "my-project",
		LocationID:          "asia-northeast1",
		QueueID:             "jobs",
		WorkerURL:           "https://worker.example.com/tasks/run",
		ServiceAccountEmail: "tasks@my-project.iam.gserviceaccount.com",
		// Audience falls back to WorkerURL when omitted.
	})
	if err != nil {
		slog.Error("failed to create enqueuer", "error", err)
		return
	}
	// It holds a gRPC connection, so reuse it as a singleton and close it on exit.
	defer func() { _ = enqueuer.Close() }()

	if err := enqueuer.Enqueue(ctx, Job{JobID: "job-1", Step: 1}); err != nil {
		slog.Error("enqueue failed", "error", err)
	}
}

// newExampleEnqueuer is a helper standing for "an Enqueuer already created" in the examples below.
func newExampleEnqueuer() *tasks.Enqueuer[Job] {
	enqueuer, err := tasks.NewEnqueuer[Job](context.Background(), tasks.Config{
		ProjectID:           "my-project",
		LocationID:          "asia-northeast1",
		QueueID:             "jobs",
		WorkerURL:           "https://worker.example.com/tasks/run",
		ServiceAccountEmail: "tasks@my-project.iam.gserviceaccount.com",
	})
	if err != nil {
		return nil
	}
	return enqueuer
}

// When the same logical task must not be created twice, enqueue under a deterministic name.
func ExampleEnqueuer_EnqueueWithName() {
	ctx := context.Background()
	enqueuer := newExampleEnqueuer()
	if enqueuer == nil {
		return
	}
	defer func() { _ = enqueuer.Close() }()

	// A second enqueue with the same taskID gets ALREADY_EXISTS, treated as success.
	taskID := "job-1-step-2"
	if err := enqueuer.EnqueueWithName(ctx, taskID, Job{JobID: "job-1", Step: 2}); err != nil {
		slog.Error("enqueue failed", "error", err)
	}
}

// An example setting a delay, a dispatch deadline and an extra header.
func ExampleEnqueuer_EnqueueWithOptions() {
	ctx := context.Background()
	enqueuer := newExampleEnqueuer()
	if enqueuer == nil {
		return
	}
	defer func() { _ = enqueuer.Close() }()

	name, err := enqueuer.EnqueueWithOptions(ctx, Job{JobID: "job-1", Step: 3},
		tasks.WithTaskID("job-1-step-3"),
		tasks.WithDelay(30*time.Second),
		tasks.WithDispatchDeadline(10*time.Minute),
		tasks.WithHeader("X-Trace-Id", "trace-123"),
	)
	if err != nil {
		slog.Error("enqueue failed", "error", err)
		return
	}
	slog.Info("task enqueued", "name", name)
}
