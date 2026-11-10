package worker

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

// Headers Cloud Tasks attaches to requests to the worker.
// Details: https://cloud.google.com/tasks/docs/creating-http-target-tasks
const (
	HeaderTaskName       = "X-CloudTasks-TaskName"
	HeaderQueueName      = "X-CloudTasks-QueueName"
	HeaderRetryCount     = "X-CloudTasks-TaskRetryCount"
	HeaderExecutionCount = "X-CloudTasks-TaskExecutionCount"
	HeaderTaskETA        = "X-CloudTasks-TaskETA"
)

// Metadata is the delivery information Cloud Tasks passes in request headers.
//
// Cloud Tasks delivers at least once, so the same task may reach the worker
// more than once. RetryCount and ExecutionCount let you write idempotent code
// that skips work on redelivery or gives up after a number of attempts.
type Metadata struct {
	// TaskName is the fully qualified task name (projects/.../tasks/...).
	// When tasks are enqueued under deterministic names, it can serve as an
	// idempotency key.
	TaskName string
	// QueueName is the fully qualified queue name.
	QueueName string
	// RetryCount is the number of retries caused by 5xx responses and the like.
	RetryCount int
	// ExecutionCount is the number of times the worker responded (5xx responses included).
	ExecutionCount int
	// ETA is when the task was scheduled to run, or the zero value if unavailable.
	ETA time.Time
}

type metadataContextKey struct{}

// WithMetadata stores Cloud Tasks delivery information in the context.
// ProcessTask calls it automatically, so callers normally need not.
func WithMetadata(ctx context.Context, md Metadata) context.Context {
	return context.WithValue(ctx, metadataContextKey{}, md)
}

// MetadataFromContext extracts Cloud Tasks delivery information from the
// context passed to a TaskExecutor. Without the headers, ok is false.
//
// The values are the request headers as they are, so this is "what the caller
// claims", not "who called". Anyone can set X-CloudTasks-TaskName. Confirming
// the caller is auth.Require's job, and TaskName may serve as an idempotency
// key only on routes that verification covers.
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
		// ETA arrives as Unix seconds (with a fractional part).
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
