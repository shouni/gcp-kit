package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"runtime/pprof"
	"time"
)

// ErrPanicked is the sentinel error reporting that Validate or Run ended in a
// panic.
//
// Lifecycle recovers the panic, folds it into this error and passes it to
// Finish. Unfolded, the outcome is never recorded and the HTTP-side Recoverer
// answers 500. The state stays running, no notification goes out, and a
// max_attempts = 1 queue never retries, so the job is running forever.
var ErrPanicked = errors.New("worker: run panicked")

// ErrTimedOut is the sentinel error reporting that Run was cut off by
// Lifecycle.Timeout.
//
// A single downstream call expiring (an HTTP client timeout, for example) and
// the whole pipeline being cut off both come back as the same
// context.DeadlineExceeded. Without this mark, a caller switching its
// notification to "timed out" would have to decide on DeadlineExceeded and
// could not tell the two apart. Check it with errors.Is(err, ErrTimedOut);
// Unwrap returns the original error from Run (its text unchanged).
var ErrTimedOut = errors.New("worker: run exceeded Lifecycle.Timeout")

// DefaultFinishTimeout is the default limit given to Finish (recording and notifying the outcome).
const DefaultFinishTimeout = 30 * time.Second

// Lifecycle is a TaskExecutor that fixes the life of one job.
//
// The order is Prepare → Begin → Validate → Run → Finish, and the app supplies
// only what each step does. The library owns the order because the order
// itself is what keeps past incidents from recurring.
//
//   - Begin comes before Validate. Every attempt reaches the record, and
//     every job passes through running on its way to a terminal state.
//     Reversed, a job rejected by validation vanishes while still queued.
//   - Timeout wraps Run only. Wrapping the caller's ctx would run even the
//     Finish right after the cut-off on an expired ctx, losing the record
//     exactly when it matters most.
//   - Finish is called exactly once, on a detached ctx
//     (context.WithoutCancel), on success, failure and panic alike. For a
//     while three of five apps detached only the failure path and recorded
//     the success path on the raw ctx, and jobs finishing around the
//     deadline got stuck at running. Routing success and failure through
//     one function makes forgetting one of them impossible to write.
//
// Unused hooks can stay nil; only Run is required.
type Lifecycle[T, R any] struct {
	// Prepare is a hook for adding correlation keys (job_id and so on) to ctx
	// for the log lines that follow. The returned ctx is passed to every later
	// hook. nil does nothing.
	Prepare func(ctx context.Context, task T) context.Context

	// Labels are the keys and values put on pprof goroutine labels (job_id,
	// command and so on). Since Go 1.27 labels also appear in the header line
	// of a panic traceback, so the stack alone says which job crashed. Log
	// correlation does not work on the panic path, and labels fill that gap.
	// Labels are inherited by child goroutines.
	Labels func(task T) map[string]string

	// Begin is the redelivery guard and the running record.
	//
	// With done=true neither Run nor Finish is called and it returns success
	// (a finished job delivered again under at-least-once delivery). Returning
	// err likewise calls nothing and returns that error as is. Whether to "go
	// ahead" or "leave it to redelivery" when the status cannot be read is
	// this hook's decision. nil always runs.
	Begin func(ctx context.Context, task T) (done bool, err error)

	// Validate checks input that redelivery cannot fix.
	//
	// A failure is wrapped in Permanent and passed to Finish. If Finish
	// returns it as is, the Handler answers 2xx and redelivery stops. It runs
	// after Begin, so a job rejected by validation also passes through running
	// on its way to failed. A panic is recovered and folded into ErrPanicked
	// as in Run (not wrapped in Permanent: it is a defect in the
	// implementation, not bad input).
	Validate func(task T) error

	// Run is the body. With a Timeout, it is called on a ctx bounded by it. A
	// panic is recovered, folded into ErrPanicked, its stack logged, and
	// passed to Finish.
	Run func(ctx context.Context, task T) (R, error)

	// Finish records and notifies the outcome.
	//
	// On a Validate failure or a panic there is no result from Run, so result
	// is R's zero value. Take what notifications need (the job ID and so on)
	// from task, not from result.
	//
	// On success (cause == nil) and on failure alike, it is called exactly
	// once, on a ctx detached from the caller's. Its return value becomes
	// Execute's result. Returning a failure as is makes Cloud Tasks redeliver;
	// returning Permanent (or a cause from Validate) stops with 2xx. nil
	// returns cause as is.
	Finish func(ctx context.Context, task T, result R, cause error) error

	// Timeout is the run-time limit given to Run; 0 or less is unlimited.
	// When it fires, Run's error reaches Finish marked so that
	// errors.Is(err, ErrTimedOut) is true.
	//
	// Keep it shorter than the Cloud Tasks dispatch deadline. The app giving
	// up first leaves Finish room to record and notify the failure. In the
	// reverse order Cloud Tasks cuts the request first, and neither a record
	// nor a notification survives.
	Timeout time.Duration

	// FinishTimeout is the limit given to Finish; 0 or less means DefaultFinishTimeout.
	FinishTimeout time.Duration

	// Logger reports panic stacks and the like. nil means slog.Default().
	Logger *slog.Logger
}

// Execute satisfies TaskExecutor.
func (l Lifecycle[T, R]) Execute(ctx context.Context, task T) error {
	if l.Run == nil {
		return errors.New("worker: Lifecycle.Run is required")
	}
	if l.Prepare != nil {
		ctx = l.Prepare(ctx, task)
	}

	var err error
	l.withLabels(ctx, task, func(ctx context.Context) {
		err = l.execute(ctx, task)
	})
	return err
}

func (l Lifecycle[T, R]) execute(ctx context.Context, task T) error {
	if l.Begin != nil {
		done, err := l.Begin(ctx, task)
		if err != nil {
			return err
		}
		if done {
			l.log().InfoContext(ctx, "Skipping a job that has already succeeded")
			return nil
		}
	}

	if err := l.validate(ctx, task); err != nil {
		var zero R
		return l.finish(ctx, task, zero, err)
	}

	result, err := l.run(ctx, task)
	return l.finish(ctx, task, result, err)
}

// withLabels runs fn under pprof labels when Labels is set.
//
// It uses pprof.Do, not pprof.SetGoroutineLabels. The latter does not restore
// the labels on return, so when the same goroutine serves the next request
// over keep-alive, it still carries the previous job's labels.
func (l Lifecycle[T, R]) withLabels(ctx context.Context, task T, fn func(ctx context.Context)) {
	if l.Labels == nil {
		fn(ctx)
		return
	}
	labels := l.Labels(task)
	if len(labels) == 0 {
		fn(ctx)
		return
	}
	pairs := make([]string, 0, len(labels)*2)
	for key, value := range labels {
		pairs = append(pairs, key, value)
	}
	pprof.Do(ctx, pprof.Labels(pairs...), fn)
}

// validate calls Validate, wraps a failure in Permanent, and folds a panic
// into an error.
//
// It runs after Begin has recorded running, so an unrecovered panic here
// would never reach Finish, and the "running forever" described on
// ErrPanicked would happen exactly.
func (l Lifecycle[T, R]) validate(ctx context.Context, task T) (err error) {
	if l.Validate == nil {
		return nil
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = l.panicked(ctx, "Worker validate panicked", recovered)
		}
	}()
	if err := l.Validate(task); err != nil {
		return Permanent(err)
	}
	return nil
}

// run calls Run on a bounded ctx and folds a panic into an error.
func (l Lifecycle[T, R]) run(ctx context.Context, task T) (result R, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			var zero R
			result, err = zero, l.panicked(ctx, "Worker run panicked", recovered)
		}
	}()

	if l.Timeout <= 0 {
		return l.Run(ctx, task)
	}

	runCtx, cancel := context.WithTimeoutCause(ctx, l.Timeout, ErrTimedOut)
	defer cancel()

	result, err = l.Run(runCtx, task)
	if err != nil && errors.Is(context.Cause(runCtx), ErrTimedOut) {
		l.log().ErrorContext(ctx, "Worker run exceeded its timeout", "timeout", l.Timeout, "error", err)
		err = timedOutError{cause: err}
	}
	return result, err
}

// timedOutError marks that Run was cut off by Timeout. It has the same shape
// as permanentError: the text stays the cause's, and only
// errors.Is(err, ErrTimedOut) becomes true.
type timedOutError struct{ cause error }

func (e timedOutError) Error() string        { return e.cause.Error() }
func (e timedOutError) Unwrap() error        { return e.cause }
func (e timedOutError) Is(target error) bool { return target == ErrTimedOut }

// panicked logs the stack of a recovered panic and returns it folded into
// ErrPanicked. Call it from inside the deferred function that recovered, so
// the stack is captured.
func (l Lifecycle[T, R]) panicked(ctx context.Context, msg string, recovered any) error {
	l.log().ErrorContext(ctx, msg,
		"panic", recovered,
		"stack", string(debug.Stack()),
	)
	return fmt.Errorf("%w: %v", ErrPanicked, recovered)
}

// finish calls Finish on a ctx detached from the caller's.
//
// When a cut-off is the very reason for ending (Timeout firing, or the request
// cancelled past the dispatch deadline), ctx is already Done, and using it
// would fail both the record and the notification. It is detached and given a
// fresh limit so that an unresponsive record store cannot occupy the worker
// indefinitely.
func (l Lifecycle[T, R]) finish(ctx context.Context, task T, result R, cause error) error {
	if l.Finish == nil {
		return cause
	}
	timeout := l.FinishTimeout
	if timeout <= 0 {
		timeout = DefaultFinishTimeout
	}
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	return l.Finish(finishCtx, task, result, cause)
}

func (l Lifecycle[T, R]) log() *slog.Logger {
	if l.Logger != nil {
		return l.Logger
	}
	return slog.Default()
}
