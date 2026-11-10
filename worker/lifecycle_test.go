package worker

import (
	"context"
	"errors"
	"fmt"
	"runtime/pprof"
	"strings"
	"testing"
	"time"
)

type lifecycleTask struct{ ID string }

// lifecycleTrace records the order hooks were called in and the values passed to Finish.
type lifecycleTrace struct {
	order  []string
	result string
	cause  error
	// finishCtxErr is the state of the ctx passed to Finish; nil when detached.
	finishCtxErr error
}

func (tr *lifecycleTrace) lifecycle(run func(ctx context.Context, task lifecycleTask) (string, error)) Lifecycle[lifecycleTask, string] {
	return Lifecycle[lifecycleTask, string]{
		Begin: func(_ context.Context, _ lifecycleTask) (bool, error) {
			tr.order = append(tr.order, "begin")
			return false, nil
		},
		Validate: func(_ lifecycleTask) error {
			tr.order = append(tr.order, "validate")
			return nil
		},
		Run: func(ctx context.Context, task lifecycleTask) (string, error) {
			tr.order = append(tr.order, "run")
			return run(ctx, task)
		},
		Finish: func(ctx context.Context, _ lifecycleTask, result string, cause error) error {
			tr.order = append(tr.order, "finish")
			tr.result, tr.cause, tr.finishCtxErr = result, cause, ctx.Err()
			return cause
		},
	}
}

// TestLifecycleRunsHooksInOrder checks that the order is fixed at Begin →
// Validate → Run → Finish. The order itself is what prevents recurrences, so
// this is the core of the contract.
func TestLifecycleRunsHooksInOrder(t *testing.T) {
	t.Parallel()

	tr := &lifecycleTrace{}
	l := tr.lifecycle(func(context.Context, lifecycleTask) (string, error) { return "ok", nil })

	if err := l.Execute(context.Background(), lifecycleTask{ID: "j1"}); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := strings.Join(tr.order, ">"); got != "begin>validate>run>finish" {
		t.Errorf("order = %s", got)
	}
	if tr.result != "ok" || tr.cause != nil {
		t.Errorf("Finish got (%q, %v), want (ok, nil)", tr.result, tr.cause)
	}
}

// TestLifecycleSkipsWhenBeginSaysDone checks that on redelivery of a finished
// job neither Run nor Finish runs, and it returns success.
func TestLifecycleSkipsWhenBeginSaysDone(t *testing.T) {
	t.Parallel()

	tr := &lifecycleTrace{}
	l := tr.lifecycle(func(context.Context, lifecycleTask) (string, error) { return "ran", nil })
	l.Begin = func(context.Context, lifecycleTask) (bool, error) { return true, nil }

	if err := l.Execute(context.Background(), lifecycleTask{}); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(tr.order) != 0 {
		t.Errorf("hooks ran after done: %v", tr.order)
	}
}

// TestLifecycleReturnsBeginErrorWithoutRunning checks that when the status
// cannot be read, nothing runs and the error comes back as is (whether to go
// ahead or defer is Begin's decision).
func TestLifecycleReturnsBeginErrorWithoutRunning(t *testing.T) {
	t.Parallel()

	want := errors.New("status unavailable")
	tr := &lifecycleTrace{}
	l := tr.lifecycle(func(context.Context, lifecycleTask) (string, error) { return "ran", nil })
	l.Begin = func(context.Context, lifecycleTask) (bool, error) { return false, want }

	if err := l.Execute(context.Background(), lifecycleTask{}); !errors.Is(err, want) {
		t.Fatalf("Execute() error = %v, want %v", err, want)
	}
	if len(tr.order) != 0 {
		t.Errorf("hooks ran after begin error: %v", tr.order)
	}
}

// TestLifecycleValidationFailureIsPermanentAndFinished checks that a
// validation failure reaches Finish as Permanent and Run does not run. A job
// rejected by validation still reaches failed.
func TestLifecycleValidationFailureIsPermanentAndFinished(t *testing.T) {
	t.Parallel()

	invalid := errors.New("bad input")
	tr := &lifecycleTrace{}
	l := tr.lifecycle(func(context.Context, lifecycleTask) (string, error) { return "ran", nil })
	l.Validate = func(lifecycleTask) error { tr.order = append(tr.order, "validate"); return invalid }

	err := l.Execute(context.Background(), lifecycleTask{})
	if !errors.Is(err, ErrPermanent) || !errors.Is(err, invalid) {
		t.Fatalf("Execute() error = %v, want permanent wrapping %v", err, invalid)
	}
	if got := strings.Join(tr.order, ">"); got != "begin>validate>finish" {
		t.Errorf("order = %s", got)
	}
	if !errors.Is(tr.cause, ErrPermanent) {
		t.Errorf("Finish cause = %v, want permanent", tr.cause)
	}
}

// TestLifecycleTurnsPanicIntoFailure checks that a panic in Run reaches Finish
// as ErrPanicked. Otherwise the state gets stuck at running.
func TestLifecycleTurnsPanicIntoFailure(t *testing.T) {
	t.Parallel()

	tr := &lifecycleTrace{}
	l := tr.lifecycle(func(context.Context, lifecycleTask) (string, error) { panic("boom") })

	err := l.Execute(context.Background(), lifecycleTask{})
	if !errors.Is(err, ErrPanicked) {
		t.Fatalf("Execute() error = %v, want ErrPanicked", err)
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("panic value is missing from the error: %v", err)
	}
	if tr.order[len(tr.order)-1] != "finish" {
		t.Errorf("Finish did not run after panic: %v", tr.order)
	}
}

// TestLifecycleTurnsValidatePanicIntoFailure checks that a panic in Validate
// also reaches Finish as ErrPanicked. It runs after Begin recorded running, so
// otherwise it would get stuck at running just like a panic in Run.
func TestLifecycleTurnsValidatePanicIntoFailure(t *testing.T) {
	t.Parallel()

	tr := &lifecycleTrace{}
	l := tr.lifecycle(func(context.Context, lifecycleTask) (string, error) { return "unreachable", nil })
	l.Validate = func(lifecycleTask) error {
		tr.order = append(tr.order, "validate")
		panic("boom")
	}

	err := l.Execute(context.Background(), lifecycleTask{})
	if !errors.Is(err, ErrPanicked) {
		t.Fatalf("Execute() error = %v, want ErrPanicked", err)
	}
	if errors.Is(err, ErrPermanent) {
		t.Errorf("a panic is a defect, not invalid input; it must not be Permanent: %v", err)
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("panic value is missing from the error: %v", err)
	}
	if got := strings.Join(tr.order, ">"); got != "begin>validate>finish" {
		t.Errorf("order = %s, want begin>validate>finish", got)
	}
	if tr.result != "" {
		t.Errorf("Finish result = %q, want the zero value", tr.result)
	}
}

// TestLifecycleTimesOutRunButNotFinish checks that Timeout applies to Run
// only, and Finish is called on a detached ctx. This is the wiring that keeps
// the record when a cut-off is the very reason for ending.
func TestLifecycleTimesOutRunButNotFinish(t *testing.T) {
	t.Parallel()

	tr := &lifecycleTrace{}
	l := tr.lifecycle(func(ctx context.Context, _ lifecycleTask) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	})
	l.Timeout = 20 * time.Millisecond

	err := l.Execute(context.Background(), lifecycleTask{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Execute() error = %v, want deadline exceeded", err)
	}
	// Cutting off the whole pipeline is marked so it can be told from one downstream call expiring.
	if !errors.Is(err, ErrTimedOut) {
		t.Errorf("Execute() error = %v, want errors.Is(..., ErrTimedOut)", err)
	}
	if !errors.Is(tr.cause, ErrTimedOut) {
		t.Errorf("Finish cause = %v, want the ErrTimedOut mark to reach Finish", tr.cause)
	}
	if tr.finishCtxErr != nil {
		t.Errorf("Finish ctx was already done: %v", tr.finishCtxErr)
	}
}

// TestLifecycleDownstreamDeadlineIsNotTimedOut checks that ErrTimedOut is not
// marked when a downstream call inside Run merely hit its own deadline. Both
// come back as DeadlineExceeded, so without the mark a notification could not
// tell them apart.
func TestLifecycleDownstreamDeadlineIsNotTimedOut(t *testing.T) {
	t.Parallel()

	tr := &lifecycleTrace{}
	l := tr.lifecycle(func(context.Context, lifecycleTask) (string, error) {
		return "", fmt.Errorf("voicevox: %w", context.DeadlineExceeded)
	})
	l.Timeout = time.Minute

	err := l.Execute(context.Background(), lifecycleTask{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Execute() error = %v, want deadline exceeded", err)
	}
	if errors.Is(err, ErrTimedOut) {
		t.Errorf("a downstream deadline must not be marked as the pipeline timeout: %v", err)
	}
}

// TestLifecycleFinishRunsOnCancelledParent checks that Finish is called on a
// live ctx even when the caller's ctx is done (the dispatch deadline passing).
func TestLifecycleFinishRunsOnCancelledParent(t *testing.T) {
	t.Parallel()

	tr := &lifecycleTrace{}
	l := tr.lifecycle(func(ctx context.Context, _ lifecycleTask) (string, error) { return "", ctx.Err() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = l.Execute(ctx, lifecycleTask{})

	if tr.finishCtxErr != nil {
		t.Errorf("Finish ctx inherited the cancellation: %v", tr.finishCtxErr)
	}
}

// TestLifecycleFinishDecidesTheResult checks that Finish's return value becomes
// Execute's result (rewrapping a failure in Permanent to stop redelivery, for
// example).
func TestLifecycleFinishDecidesTheResult(t *testing.T) {
	t.Parallel()

	tr := &lifecycleTrace{}
	l := tr.lifecycle(func(context.Context, lifecycleTask) (string, error) { return "", errors.New("transient") })
	l.Finish = func(_ context.Context, _ lifecycleTask, _ string, cause error) error { return Permanent(cause) }

	if err := l.Execute(context.Background(), lifecycleTask{}); !errors.Is(err, ErrPermanent) {
		t.Fatalf("Execute() error = %v, want the Finish result", err)
	}
}

// TestLifecycleLabelsGoroutine checks that Labels are visible from Run as
// pprof goroutine labels.
func TestLifecycleLabelsGoroutine(t *testing.T) {
	t.Parallel()

	var got string
	l := Lifecycle[lifecycleTask, string]{
		Labels: func(task lifecycleTask) map[string]string { return map[string]string{"job_id": task.ID} },
		Run: func(ctx context.Context, _ lifecycleTask) (string, error) {
			got, _ = pprof.Label(ctx, "job_id")
			return "", nil
		},
	}
	if err := l.Execute(context.Background(), lifecycleTask{ID: "j-42"}); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got != "j-42" {
		t.Errorf("job_id label = %q, want j-42", got)
	}
}

// TestLifecycleRequiresRun checks that a Lifecycle without Run fails as a configuration error.
func TestLifecycleRequiresRun(t *testing.T) {
	t.Parallel()

	if err := (Lifecycle[lifecycleTask, string]{}).Execute(context.Background(), lifecycleTask{}); err == nil {
		t.Fatal("Execute() error = nil, want an error for the missing Run")
	}
}
