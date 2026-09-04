package worker

import (
	"context"
	"errors"
	"runtime/pprof"
	"strings"
	"testing"
	"time"
)

type lifecycleTask struct{ ID string }

// lifecycleTrace は、フックが呼ばれた順序と、Finish に渡された値を記録します。
type lifecycleTrace struct {
	order  []string
	result string
	cause  error
	// finishCtxErr は Finish に渡された ctx の状態です。切り離されていれば nil です。
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

// TestLifecycleRunsHooksInOrder は、順序が Begin → Validate → Run → Finish で固定されて
// いることを確かめます。順序自体が再発防止なので、ここが規約の本体です。
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

// TestLifecycleSkipsWhenBeginSaysDone は、完了済みの再配信では Run も Finish も
// 走らず、成功として返ることを確かめます。
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

// TestLifecycleReturnsBeginErrorWithoutRunning は、状態を読めないときに何も走らせず
// エラーをそのまま返すことを確かめます（進むか委ねるかは Begin が決めます）。
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

// TestLifecycleValidationFailureIsPermanentAndFinished は、検証の失敗が Permanent として
// Finish に届き、Run は走らないことを確かめます。検証で落ちたジョブも failed に至ります。
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

// TestLifecycleTurnsPanicIntoFailure は、Run の panic が ErrPanicked として Finish に
// 届くことを確かめます。届かないと状態が running のまま固着します。
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

// TestLifecycleTimesOutRunButNotFinish は、Timeout が Run にだけ効き、Finish は
// 切り離した ctx で呼ばれることを確かめます。打ち切りこそが終端の理由である場面で
// 記録が残るための配線です。
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
	if tr.finishCtxErr != nil {
		t.Errorf("Finish ctx was already done: %v", tr.finishCtxErr)
	}
}

// TestLifecycleFinishRunsOnCancelledParent は、呼び出し元の ctx が切れていても Finish が
// 生きた ctx で呼ばれることを確かめます（dispatch deadline 超過の場面）。
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

// TestLifecycleFinishDecidesTheResult は、Finish の返り値が Execute の結果になること
// （失敗を Permanent に包み直して再配信を止める、など）を確かめます。
func TestLifecycleFinishDecidesTheResult(t *testing.T) {
	t.Parallel()

	tr := &lifecycleTrace{}
	l := tr.lifecycle(func(context.Context, lifecycleTask) (string, error) { return "", errors.New("transient") })
	l.Finish = func(_ context.Context, _ lifecycleTask, _ string, cause error) error { return Permanent(cause) }

	if err := l.Execute(context.Background(), lifecycleTask{}); !errors.Is(err, ErrPermanent) {
		t.Fatalf("Execute() error = %v, want the Finish result", err)
	}
}

// TestLifecycleLabelsGoroutine は、Labels が pprof のゴルーチンラベルとして Run から
// 見えることを確かめます。
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

// TestLifecycleRequiresRun は、Run の無い Lifecycle を設定ミスとして落とすことを確かめます。
func TestLifecycleRequiresRun(t *testing.T) {
	t.Parallel()

	if err := (Lifecycle[lifecycleTask, string]{}).Execute(context.Background(), lifecycleTask{}); err == nil {
		t.Fatal("Execute() error = nil, want an error for the missing Run")
	}
}
