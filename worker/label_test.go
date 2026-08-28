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

// TestProcessTaskLabelsGoroutineWithTaskName は、Cloud Tasks のタスク名が
// pprof のゴルーチンラベルに載ることを検証します。
//
// これはログではなくパニックのトレースバックのための配線です。Go 1.27 以降、
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

// TestProcessTaskDoesNotLeakLabelIntoNextRequest は、同じゴルーチンで続けて
// 処理したリクエストが直前のタスク名を引き継がないことを検証します。
//
// net/http は 1 本の接続ゴルーチンで keep-alive の複数リクエストを順に捌きます。
// pprof.SetGoroutineLabels は復帰時にラベルを戻さないため、これを直接呼ぶと
// 2 本目のトレースバックが 1 本目のタスク名を指します。ラベルは「落ちたときに
// どのタスクだったか」を知るための配線なので、無関係の名前が出るのは
// 何も出ないより悪い状態です。pprof.Do は復帰時に元のラベルへ戻します。
//
// ゴルーチンのラベルを読む公開 API は無いため、goroutine プロファイル
// （debug=1 はラベル行を含む）を経由して確認します。
func TestProcessTaskDoesNotLeakLabelIntoNextRequest(t *testing.T) {
	// プロファイルは全ゴルーチンを含むため、他のテストと衝突しない名前を使います。
	const canary = "task-keepalive-canary"

	var profiles []string
	h := NewHandler[map[string]string](execFunc(func(context.Context, map[string]string) error {
		profiles = append(profiles, goroutineProfile(t))
		return nil
	}))

	// 1 本目: Cloud Tasks 由来（タスク名あり）。
	first := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	first.Header.Set(HeaderTaskName, "projects/p/locations/l/queues/q/tasks/"+canary)
	h.ProcessTask(httptest.NewRecorder(), first)

	// 2 本目: 同じゴルーチンで、タスク名を持たない呼び出し。
	second := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
	h.ProcessTask(httptest.NewRecorder(), second)

	if len(profiles) != 2 {
		t.Fatalf("executor の呼び出し回数 = %d, want 2", len(profiles))
	}
	// ラベルがそもそも載っていなければ、以降の検証は空振りします。
	if !strings.Contains(profiles[0], canary) {
		t.Fatalf("1 本目の処理中にラベルが載っていません:\n%s", labelLines(profiles[0]))
	}
	if strings.Contains(profiles[1], canary) {
		t.Errorf("2 本目の処理中に 1 本目のタスク名が残っています:\n%s", labelLines(profiles[1]))
	}
	if profile := goroutineProfile(t); strings.Contains(profile, canary) {
		t.Errorf("ProcessTask から復帰した後もラベルが残っています:\n%s", labelLines(profile))
	}
}

// goroutineProfile は、いま動いている全ゴルーチンのプロファイルを文字列で返します。
// debug=1 の出力にはラベル行（"# labels: {...}"）が含まれます。
func goroutineProfile(t *testing.T) string {
	t.Helper()

	var buf bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&buf, 1); err != nil {
		t.Fatalf("goroutine プロファイルの取得に失敗: %v", err)
	}
	return buf.String()
}

// labelLines は、失敗時のメッセージに載せるラベル行だけを抜き出します。
func labelLines(profile string) string {
	var lines []string
	for line := range strings.SplitSeq(profile, "\n") {
		if strings.Contains(line, "# labels:") {
			lines = append(lines, strings.TrimSpace(line))
		}
	}
	if len(lines) == 0 {
		return "(ラベル行なし)"
	}
	return strings.Join(lines, "\n")
}
