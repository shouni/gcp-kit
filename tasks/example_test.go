package tasks_test

import (
	"context"
	"log/slog"
	"time"

	"github.com/shouni/gcp-kit/tasks"
)

// Job は producer と worker の間の JSON ペイロード契約です。
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
		// Audience は省略すると WorkerURL が使われます。
	})
	if err != nil {
		slog.Error("failed to create enqueuer", "error", err)
		return
	}
	// gRPC コネクションを保持するため、シングルトンとして再利用し終了時に閉じます。
	defer func() { _ = enqueuer.Close() }()

	if err := enqueuer.Enqueue(ctx, Job{JobID: "job-1", Step: 1}); err != nil {
		slog.Error("enqueue failed", "error", err)
	}
}

// newExampleEnqueuer は、以降の例で「生成済みの Enqueuer」を表すヘルパーです。
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

// 同じ論理タスクを二重に作らせたくない場合は、決定的な名前で投入します。
func ExampleEnqueuer_EnqueueWithName() {
	ctx := context.Background()
	enqueuer := newExampleEnqueuer()
	if enqueuer == nil {
		return
	}
	defer func() { _ = enqueuer.Close() }()

	// 同じ taskID での2回目以降は ALREADY_EXISTS となり、成功として扱われます。
	taskID := "job-1-step-2"
	if err := enqueuer.EnqueueWithName(ctx, taskID, Job{JobID: "job-1", Step: 2}); err != nil {
		slog.Error("enqueue failed", "error", err)
	}
}

// 遅延実行・応答待ち時間・追加ヘッダーを指定する例です。
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
