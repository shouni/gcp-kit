// Package worker provides utilities for HTTP handlers called by Cloud Tasks,
// Cloud Run and the like: decoding the JSON payload and running the task in a
// type-safe way.
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

// ErrPermanent is the sentinel error for a permanent failure that no retry
// can fix.
//
// When a TaskExecutor returns an error matching it under errors.Is, the
// Handler answers 2xx so that Cloud Tasks treats the task as done and stops
// pointless retries (the details stay in an ERROR log). Do not return it for
// transient failures (an external API timing out, for example).
//
// Mark an error with Permanent.
//
//	if errors.Is(err, domain.ErrInvalidInput) {
//	    return worker.Permanent(err)
//	}
var ErrPermanent = errors.New("worker: permanent failure, task must not be retried")

// Permanent marks err as "redelivery will not fix this" and returns it. A nil
// err returns nil.
//
// Unlike fmt.Errorf("%w: %v", ErrPermanent, err), Error() stays the cause's
// text. The sentinel's wording is an implementation detail and means nothing
// to users when it shows up in a job status record or a notification. The
// Handler reports permanence separately in the structured log's permanent
// field, so there is no need to mix it into the text.
//
// errors.Is(err, ErrPermanent) is true and Unwrap returns the cause, so checks
// against the cause (errors.Is / errors.As) keep working.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return permanentError{cause: err}
}

// permanentError is the mark Permanent returns.
type permanentError struct{ cause error }

func (e permanentError) Error() string        { return e.cause.Error() }
func (e permanentError) Unwrap() error        { return e.cause }
func (e permanentError) Is(target error) bool { return target == ErrPermanent }

// defaultMaxBodyBytes is the default limit on the accepted request body.
// Cloud Tasks HTTP targets cap a whole task at 1MB, so the default matches.
const defaultMaxBodyBytes int64 = 1 << 20

// TaskExecutor receives the decoded payload and does the actual work.
type TaskExecutor[T any] interface {
	Execute(ctx context.Context, payload T) error
}

// Option is an optional setting of a Handler.
type Option func(*options)

type options struct {
	maxBodyBytes int64
	strictJSON   bool
	logger       *slog.Logger
}

// WithMaxBodyBytes changes the request body limit. 0 or less means no limit.
func WithMaxBodyBytes(n int64) Option {
	return func(o *options) { o.maxBodyBytes = n }
}

// WithStrictJSON makes decoding fail when the payload has unknown fields.
// Use it to catch drift between the sender's and receiver's type definitions
// early. A task that fails this is stopped with 2xx like any unparsable
// payload, and left in an ERROR log.
func WithStrictJSON() Option {
	return func(o *options) { o.strictJSON = true }
}

// WithLogger replaces the logger this package uses. It defaults to slog.Default().
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) { o.logger = logger }
}

// Handler is a generic handler receiving HTTP requests from Cloud Tasks.
type Handler[T any] struct {
	executor TaskExecutor[T]
	opts     options
}

// NewHandler creates a new worker handler.
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

// ServeHTTP makes Handler usable as an http.Handler.
func (h *Handler[T]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.ProcessTask(w, r)
}

// ProcessTask is an http.HandlerFunc that processes POST requests from Cloud Tasks.
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

	// Put the task name on a pprof goroutine label. Since Go 1.27 labels also
	// appear in the header line of a panic traceback, so when the worker
	// crashes the stack alone says which task it was. This fills the panic
	// path, where log correlation (slogctx) does not work. Labels are
	// inherited by child goroutines the executor starts.
	//
	// It uses pprof.Do, not pprof.SetGoroutineLabels. The latter does not
	// restore labels on return, so when net/http serves several keep-alive
	// requests in turn on one connection goroutine, the next request carries
	// the previous task's name. A traceback pointing at an unrelated task is
	// worse than one naming none.
	name := path.Base(md.TaskName)
	if name == "" || name == "." || name == "/" {
		h.process(ctx, w, r)
		return
	}
	pprof.Do(ctx, pprof.Labels("cloudtask", name), func(ctx context.Context) {
		h.process(ctx, w, r)
	})
}

// process decodes the body, calls the executor, and maps the result to a
// status code that follows Cloud Tasks' retry behaviour.
//
// It is split out of ProcessTask because pprof.Do limits the labels to the
// function's execution (restoring them corresponds to returning from this
// function).
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
		// An unparsable body (over the limit included) gives the same result
		// however often it is redelivered, so it stops with 2xx, like
		// ErrPermanent.
		//
		// 4xx does not stop it. Cloud Tasks treats anything but 2xx as a
		// failure and redelivers per the queue's retry settings (see the
		// HttpRequest reference). This used to return 400, which did not show
		// on a max_attempts = 1 queue, but once max_attempts is raised a broken
		// payload is redelivered up to the limit.
		h.log().ErrorContext(ctx, "Failed to decode worker task payload; dropping the task",
			"error", err,
			"payload_type", fmt.Sprintf("%T", payload),
			"permanent", true,
		)
		w.WriteHeader(http.StatusOK)
		return
	}

	h.log().DebugContext(ctx, "Worker received task", "type", fmt.Sprintf("%T", payload))

	// ctx is built on the request's, so Cloud Tasks' response deadline reaches
	// the executor as is (with the delivery metadata and labels added). No
	// run-time limit is applied here: it has to sit inside the recording of
	// the outcome, and that order belongs to Lifecycle (Lifecycle.Timeout).
	if err := h.executor.Execute(ctx, payload); err != nil {
		// Log only the type, not the payload itself, to avoid a security risk.
		h.log().ErrorContext(ctx, "Worker task execution failed",
			"error", err,
			"payload_type", fmt.Sprintf("%T", payload),
			"permanent", errors.Is(err, ErrPermanent),
		)

		if errors.Is(err, ErrPermanent) {
			// Retrying a permanent failure cannot succeed, so stop by treating it as success.
			w.WriteHeader(http.StatusOK)
			return
		}

		// On a 5xx, Cloud Tasks retries with exponential backoff per its settings.
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.log().DebugContext(ctx, "Worker task completed successfully")
	w.WriteHeader(http.StatusOK)
}
