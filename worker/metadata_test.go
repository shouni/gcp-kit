package worker

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestMetadataFromHeader(t *testing.T) {
	t.Parallel()

	header := http.Header{}
	header.Set(HeaderTaskName, "projects/p/locations/l/queues/q/tasks/task-1")
	header.Set(HeaderQueueName, "projects/p/locations/l/queues/q")
	header.Set(HeaderRetryCount, "3")
	header.Set(HeaderExecutionCount, "4")
	header.Set(HeaderTaskETA, "1700000000.5")

	md := metadataFromHeader(header)

	if md.TaskName != "projects/p/locations/l/queues/q/tasks/task-1" {
		t.Fatalf("TaskName = %q", md.TaskName)
	}
	if md.QueueName != "projects/p/locations/l/queues/q" {
		t.Fatalf("QueueName = %q", md.QueueName)
	}
	if md.RetryCount != 3 {
		t.Fatalf("RetryCount = %d, want 3", md.RetryCount)
	}
	if md.ExecutionCount != 4 {
		t.Fatalf("ExecutionCount = %d, want 4", md.ExecutionCount)
	}
	if want := time.UnixMicro(1700000000500000).UTC(); !md.ETA.Equal(want) {
		t.Fatalf("ETA = %v, want %v", md.ETA, want)
	}
}

// TestMetadataFromHeaderMalformed は、Cloud Tasks 以外からの呼び出しや壊れた
// ヘッダーでもパニックせずゼロ値になることを確認します。
func TestMetadataFromHeaderMalformed(t *testing.T) {
	t.Parallel()

	header := http.Header{}
	header.Set(HeaderRetryCount, "not-a-number")
	header.Set(HeaderTaskETA, "not-a-timestamp")

	md := metadataFromHeader(header)

	if md.RetryCount != 0 {
		t.Fatalf("RetryCount = %d, want 0", md.RetryCount)
	}
	if !md.ETA.IsZero() {
		t.Fatalf("ETA = %v, want zero", md.ETA)
	}
}

func TestMetadataFromContext(t *testing.T) {
	t.Parallel()

	t.Run("absent", func(t *testing.T) {
		t.Parallel()
		if _, ok := MetadataFromContext(context.Background()); ok {
			t.Fatal("MetadataFromContext() ok = true, want false")
		}
	})

	t.Run("present", func(t *testing.T) {
		t.Parallel()
		ctx := WithMetadata(context.Background(), Metadata{TaskName: "task-1", RetryCount: 2})
		md, ok := MetadataFromContext(ctx)
		if !ok {
			t.Fatal("MetadataFromContext() ok = false, want true")
		}
		if md.RetryCount != 2 {
			t.Fatalf("RetryCount = %d, want 2", md.RetryCount)
		}
	})

	// Cloud Tasks 以外からの呼び出しではタスク名が無いため ok=false になります。
	t.Run("empty metadata is not reported as present", func(t *testing.T) {
		t.Parallel()
		ctx := WithMetadata(context.Background(), Metadata{})
		if _, ok := MetadataFromContext(ctx); ok {
			t.Fatal("MetadataFromContext() ok = true, want false")
		}
	})
}

// metadataCapturingExecutor は Execute に渡されたコンテキストのメタデータを記録します。
type metadataCapturingExecutor struct {
	md Metadata
	ok bool
}

func (e *metadataCapturingExecutor) Execute(ctx context.Context, _ samplePayload) error {
	e.md, e.ok = MetadataFromContext(ctx)
	return nil
}

func TestProcessTaskExposesMetadataToExecutor(t *testing.T) {
	t.Parallel()

	exec := &metadataCapturingExecutor{}
	h := NewHandler[samplePayload](exec)

	req := newTaskRequest(strings.NewReader(`{"name":"alice"}`))
	req.Header.Set(HeaderTaskName, "projects/p/locations/l/queues/q/tasks/task-1")
	req.Header.Set(HeaderRetryCount, "5")

	h.ServeHTTP(newRecorder(), req)

	if !exec.ok {
		t.Fatal("executor did not receive Cloud Tasks metadata")
	}
	if exec.md.RetryCount != 5 {
		t.Fatalf("RetryCount = %d, want 5", exec.md.RetryCount)
	}
}
