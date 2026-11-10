package worker

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"runtime/pprof"
	"strings"
	"testing"
)

// TestProcessTaskLabelsGoroutineWithTaskName checks that the Cloud Tasks task
// name is put on a pprof goroutine label.
//
// This wiring is for panic tracebacks, not logs. Since Go 1.27 labels appear
// in the traceback's header line, so when the worker crashes the stack alone
// identifies the task. Correlation through slogctx does not work on the panic
// path, and this label fills that gap.
func TestProcessTaskLabelsGoroutineWithTaskName(t *testing.T) {
	var got string
	var found bool

	h := NewHandler[map[string]string](execFunc(func(ctx context.Context, _ map[string]string) error {
		// Read the labels on the running goroutine.
		pprof.ForLabels(ctx, func(key, value string) bool {
			if key == "cloudtask" {
				got, found = value, true
				return false
			}
			return true
		})
		return nil
	}))

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	req.Header.Set(HeaderTaskName, "projects/p/locations/l/queues/q/tasks/task-42")
	rec := httptest.NewRecorder()

	h.ProcessTask(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !found {
		t.Fatal("no cloudtask label on the goroutine")
	}
	if got != "task-42" {
		t.Errorf("cloudtask = %q, want %q (the trailing task name, not the fully qualified one)", got, "task-42")
	}
}

// TestProcessTaskWithoutTaskNameSetsNoLabel checks that calls not from Cloud
// Tasks get no empty label.
func TestProcessTaskWithoutTaskNameSetsNoLabel(t *testing.T) {
	labeled := false

	h := NewHandler[map[string]string](execFunc(func(ctx context.Context, _ map[string]string) error {
		pprof.ForLabels(ctx, func(key, _ string) bool {
			if key == "cloudtask" {
				labeled = true
			}
			return true
		})
		return nil
	}))

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h.ProcessTask(rec, req)

	if labeled {
		t.Error("set a label although there is no task name")
	}
}

// execFunc is a test adapter satisfying TaskExecutor with a function.
type execFunc func(context.Context, map[string]string) error

func (f execFunc) Execute(ctx context.Context, p map[string]string) error { return f(ctx, p) }

// TestProcessTaskDoesNotLeakLabelIntoNextRequest checks that a request handled
// next on the same goroutine does not inherit the previous task name.
//
// net/http serves several keep-alive requests in turn on one connection
// goroutine. pprof.SetGoroutineLabels does not restore labels on return, so
// calling it directly makes the second request's traceback name the first
// task. The label is wiring for knowing "which task it was when it crashed",
// so an unrelated name is worse than none. pprof.Do restores the original
// labels on return.
//
// There is no public API to read a goroutine's labels, so this checks through
// the goroutine profile (debug=1 includes label lines).
func TestProcessTaskDoesNotLeakLabelIntoNextRequest(t *testing.T) {
	// The profile covers every goroutine, so use a name no other test uses.
	const canary = "task-keepalive-canary"

	var profiles []string
	h := NewHandler[map[string]string](execFunc(func(context.Context, map[string]string) error {
		profiles = append(profiles, goroutineProfile(t))
		return nil
	}))

	// First: from Cloud Tasks (with a task name).
	first := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	first.Header.Set(HeaderTaskName, "projects/p/locations/l/queues/q/tasks/"+canary)
	h.ProcessTask(httptest.NewRecorder(), first)

	// Second: on the same goroutine, a call without a task name.
	second := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	h.ProcessTask(httptest.NewRecorder(), second)

	if len(profiles) != 2 {
		t.Fatalf("executor calls = %d, want 2", len(profiles))
	}
	// If the label was never set, the checks below would pass vacuously.
	if !strings.Contains(profiles[0], canary) {
		t.Fatalf("no label while handling the first request:\n%s", labelLines(profiles[0]))
	}
	if strings.Contains(profiles[1], canary) {
		t.Errorf("the first task name remains while handling the second request:\n%s", labelLines(profiles[1]))
	}
	if profile := goroutineProfile(t); strings.Contains(profile, canary) {
		t.Errorf("a label remains after returning from ProcessTask:\n%s", labelLines(profile))
	}
}

// goroutineProfile returns the profile of every running goroutine as a
// string. The debug=1 output includes label lines ("# labels: {...}").
func goroutineProfile(t *testing.T) string {
	t.Helper()

	var buf bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&buf, 1); err != nil {
		t.Fatalf("failed to get goroutine profile: %v", err)
	}
	return buf.String()
}

// labelLines extracts just the label lines to put in a failure message.
func labelLines(profile string) string {
	var lines []string
	for line := range strings.SplitSeq(profile, "\n") {
		if strings.Contains(line, "# labels:") {
			lines = append(lines, strings.TrimSpace(line))
		}
	}
	if len(lines) == 0 {
		return "(no label lines)"
	}
	return strings.Join(lines, "\n")
}
