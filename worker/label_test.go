package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime/pprof"
	"strings"
	"testing"
)

// TestProcessTaskLabelsGoroutineWithTaskName は、Cloud Tasks のタスク名が
// pprof のゴルーチンラベルに載ることを検証します。
//
// これはログではなくパニックのトレースバックのための配線です。 Go 1.27 以降、
// ラベルはトレースバックの見出し行に出るため、ワーカーが落ちたときに
// どのタスクだったかがスタックだけで特定できます。slogctx による相関は
// panic の経路では効かないので、そこを埋めるのがこのラベルです。
func TestProcessTaskLabelsGoroutineWithTaskName(t *testing.T) {
	var got string
	var found bool

	h := NewHandler[map[string]string](execFunc(func(ctx context.Context, _ map[string]string) error {
		// 実行中のゴルーチンに載っているラベルを読む。
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
		t.Fatal("cloudtask ラベルがゴルーチンに載っていません")
	}
	if got != "task-42" {
		t.Errorf("cloudtask = %q, want %q（完全修飾名ではなく末尾のタスク名）", got, "task-42")
	}
}

// TestProcessTaskWithoutTaskNameSetsNoLabel は、Cloud Tasks 以外からの呼び出しで
// 空のラベルを載せないことを検証します。
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
		t.Error("タスク名が無いのにラベルを載せています")
	}
}

// execFunc は TaskExecutor を関数で満たすためのテスト用アダプターです。
type execFunc func(context.Context, map[string]string) error

func (f execFunc) Execute(ctx context.Context, p map[string]string) error { return f(ctx, p) }
