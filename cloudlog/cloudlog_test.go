package cloudlog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/shouni/go-utils/slogctx"

	"github.com/shouni/gcp-kit/cloudlog"
)

// newTestLogger は、Cloud Logging 互換の JSON を buf へ書く context 対応ロガーを返します。
// アプリケーション側で行う想定の組み立てをそのまま再現しています。
func newTestLogger(buf *bytes.Buffer, level slog.Level) *slog.Logger {
	base := slog.NewJSONHandler(buf, cloudlog.HandlerOptions(level))
	return slog.New(slogctx.NewHandler(base))
}

func decodeLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()

	var entries []map[string]any
	decoder := json.NewDecoder(buf)
	for decoder.More() {
		var entry map[string]any
		if err := decoder.Decode(&entry); err != nil {
			t.Fatalf("decode log line: %v", err)
		}
		entries = append(entries, entry)
	}
	return entries
}

// Cloud Logging は level/msg ではなく severity/message を読むため、詰め替えが必須。
func TestHandlerOptionsWritesCloudLoggingFields(t *testing.T) {
	var buf bytes.Buffer
	newTestLogger(&buf, slog.LevelInfo).Warn("something happened", "job_id", "job-1")

	entries := decodeLines(t, &buf)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0]["severity"] != "WARNING" {
		t.Errorf("severity = %v, want WARNING", entries[0]["severity"])
	}
	if entries[0]["message"] != "something happened" {
		t.Errorf("message = %v", entries[0]["message"])
	}
	if entries[0]["job_id"] != "job-1" {
		t.Errorf("job_id = %v", entries[0]["job_id"])
	}
	if _, ok := entries[0]["level"]; ok {
		t.Error("level キーが残っている（severity へ詰め替えられていない）")
	}
	if _, ok := entries[0]["msg"]; ok {
		t.Error("msg キーが残っている（message へ詰め替えられていない）")
	}
}

// グループ内の属性はアプリ固有のデータなので詰め替えないこと。
func TestHandlerOptionsLeavesGroupedAttrsAlone(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, slog.LevelInfo).WithGroup("payload")
	logger.Info("msg", "level", "high")

	entries := decodeLines(t, &buf)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	group, ok := entries[0]["payload"].(map[string]any)
	if !ok {
		t.Fatalf("グループ payload が出力されていない: %v", entries[0])
	}
	if group["level"] != "high" {
		t.Errorf("payload.level = %v, want high（グループ内は詰め替えない）", group["level"])
	}
}

func TestSeverityOf(t *testing.T) {
	tests := map[slog.Level]string{
		slog.LevelDebug: "DEBUG",
		slog.LevelInfo:  "INFO",
		// slog では Warn だが Cloud Logging では WARNING。
		slog.LevelWarn:  "WARNING",
		slog.LevelError: "ERROR",
	}
	for level, want := range tests {
		if got := cloudlog.SeverityOf(level); got != want {
			t.Errorf("SeverityOf(%v) = %q, want %q", level, got, want)
		}
	}
}

// Cloud Run が実際に送る形の X-Cloud-Trace-Context です。
// SPAN_ID がヘッダー上は 10 進数（"/1"）で、Cloud Logging の spanId が期待する
// 16 進 16 桁（"0000000000000001"）とは表現が違う点がこのテスト群の要点です。
const (
	testTraceHeader = "105445aa7843bc8bf206b12000100000/1;o=1"
	testTraceID     = "105445aa7843bc8bf206b12000100000"
	testSpanID      = "0000000000000001"
)

func TestParseTraceContext(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantTrace string
		wantSpan  string
	}{
		{
			name:      "Cloud Run が送る形。10 進数の SPAN_ID を 16 進 16 桁へ直す",
			header:    testTraceHeader,
			wantTrace: testTraceID,
			wantSpan:  testSpanID,
		},
		{
			name:      "サンプリング指定なし",
			header:    testTraceID + "/456",
			wantTrace: testTraceID,
			wantSpan:  "00000000000001c8",
		},
		{
			name:      "32 桁に満たない TRACE_ID は 0 で左詰めする",
			header:    "abc123/1",
			wantTrace: "00000000000000000000000000abc123",
			wantSpan:  testSpanID,
		},
		{
			name:      "大文字の 16 進数は小文字へ揃える",
			header:    "ABC123/1",
			wantTrace: "00000000000000000000000000abc123",
			wantSpan:  testSpanID,
		},
		{
			name:      "SPAN_ID なし",
			header:    testTraceID,
			wantTrace: testTraceID,
		},
		{
			name:      "SPAN_ID が無く、サンプリング指定だけある形",
			header:    testTraceID + ";o=1",
			wantTrace: testTraceID,
		},
		{
			name:   "16 進数でない TRACE_ID は相関に使わない",
			header: "trace-abc/1",
		},
		{
			name:   "32 桁を超える TRACE_ID は相関に使わない",
			header: strings.Repeat("a", 33) + "/1",
		},
		{
			name:      "10 進数でない SPAN_ID は捨てるが、TRACE_ID は残す",
			header:    testTraceID + "/span-1",
			wantTrace: testTraceID,
		},
		{
			name:      "SPAN_ID 0 は「スパンなし」の意味",
			header:    testTraceID + "/0",
			wantTrace: testTraceID,
		},
		{
			name:      "64 ビットに収まらない SPAN_ID は捨てる",
			header:    testTraceID + "/18446744073709551616",
			wantTrace: testTraceID,
		},
		{
			name:   "空",
			header: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trace, span := cloudlog.ParseTraceContext(tt.header)
			if trace != tt.wantTrace || span != tt.wantSpan {
				t.Errorf("ParseTraceContext(%q) = (%q, %q), want (%q, %q)",
					tt.header, trace, span, tt.wantTrace, tt.wantSpan)
			}
		})
	}
}

func TestTraceAttrs(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(cloudlog.TraceHeader, testTraceHeader)

	attrs := cloudlog.TraceAttrs("my-project", req)
	if len(attrs) != 2 {
		t.Fatalf("attrs = %v, want 2 件", attrs)
	}
	if attrs[0].Key != cloudlog.TraceKey || attrs[0].Value.String() != "projects/my-project/traces/"+testTraceID {
		t.Errorf("attrs[0] = %v", attrs[0])
	}
	if attrs[1].Key != cloudlog.SpanKey || attrs[1].Value.String() != testSpanID {
		t.Errorf("attrs[1] = %v", attrs[1])
	}

	// projectID 未設定・ヘッダー無し・nil リクエストはいずれも相関しない。
	if got := cloudlog.TraceAttrs("", req); got != nil {
		t.Errorf("TraceAttrs(projectID 空) = %v, want nil", got)
	}
	if got := cloudlog.TraceAttrs("my-project", httptest.NewRequest(http.MethodGet, "/", nil)); got != nil {
		t.Errorf("TraceAttrs(ヘッダー無し) = %v, want nil", got)
	}
	if got := cloudlog.TraceAttrs("my-project", nil); got != nil {
		t.Errorf("TraceAttrs(nil リクエスト) = %v, want nil", got)
	}
}

// TestTraceAttrsIgnoresForgedHeader は、呼び出し元が細工したヘッダーを
// Cloud Logging の予約フィールドへ書かないことを検証します。
//
// このヘッダーは誰でも付けられ、Cloud Run は提示された値を引き継ぎます。
// 検証せずに書くと、trace フィールドに任意の文字列を仕込めるうえ、
// 他リクエストのトレースへ相乗りする経路にもなります。
func TestTraceAttrsIgnoresForgedHeader(t *testing.T) {
	forged := []string{
		`" injected`,
		"../../other-project/traces/deadbeef",
		"not-hex-at-all/1",
		strings.Repeat("f", 64) + "/1",
	}

	for _, header := range forged {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(cloudlog.TraceHeader, header)

		if got := cloudlog.TraceAttrs("my-project", req); got != nil {
			t.Errorf("TraceAttrs(%q) = %v, want nil（相関に使わない）", header, got)
		}
	}
}

func TestTraceMiddlewareAttachesTrace(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, slog.LevelInfo)

	handler := cloudlog.TraceMiddleware("my-project")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		logger.InfoContext(r.Context(), "handled")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(cloudlog.TraceHeader, testTraceHeader)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	entries := decodeLines(t, &buf)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0][cloudlog.TraceKey] != "projects/my-project/traces/"+testTraceID {
		t.Errorf("trace = %v", entries[0][cloudlog.TraceKey])
	}
	if entries[0][cloudlog.SpanKey] != testSpanID {
		t.Errorf("span = %v", entries[0][cloudlog.SpanKey])
	}
}

// projectID 未設定（ローカル実行）では完全修飾名を組めないため何も付与しない。
func TestTraceMiddlewareSkipsWithoutProjectID(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, slog.LevelInfo)

	handler := cloudlog.TraceMiddleware("")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		logger.InfoContext(r.Context(), "handled")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(cloudlog.TraceHeader, testTraceHeader)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	entries := decodeLines(t, &buf)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if _, ok := entries[0][cloudlog.TraceKey]; ok {
		t.Error("projectID 未設定なのにトレースが付与されている")
	}
}

// トレース相関と、アプリが後から積む属性が併存すること。
func TestTraceMiddlewareComposesWithApplicationAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, slog.LevelInfo)

	handler := cloudlog.TraceMiddleware("my-project")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ctx := slogctx.With(r.Context(), slog.String("job_id", "job-1"))
		logger.InfoContext(ctx, "handled")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(cloudlog.TraceHeader, testTraceID+"/1")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	entries := decodeLines(t, &buf)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0][cloudlog.TraceKey] == nil || entries[0]["job_id"] != "job-1" {
		t.Errorf("entry = %v, want トレースと job_id を両方含む", entries[0])
	}
}

func TestHandlerOptionsRespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	newTestLogger(&buf, slog.LevelWarn).InfoContext(context.Background(), "filtered out")
	if buf.Len() != 0 {
		t.Errorf("レベル未満のログが出力された: %s", buf.String())
	}
}

// TestNewHandlerMatchesManualComposition は、NewHandler が兄弟アプリの main.go に
// 書かれていた 3 行と同じ出力になることを固定します。
//
// 引き上げの要点は、slogctx.NewHandler で包み忘れても何のエラーも出ず、
// context に載せた属性が黙って消えるだけ、という点です。等価であることを
// ここで押さえておかないと、移行したときに気付けません。
func TestNewHandlerMatchesManualComposition(t *testing.T) {
	var fromKit, manual bytes.Buffer

	ctx := slogctx.With(context.Background(), slog.String("job_id", "job-1"))

	slog.New(cloudlog.NewHandler(&fromKit, slog.LevelInfo)).
		WarnContext(ctx, "handled", "attempt", 2)

	// これまで各アプリが手で書いていた組み立て。
	base := slog.NewJSONHandler(&manual, cloudlog.HandlerOptions(slog.LevelInfo))
	slog.New(slogctx.NewHandler(base)).
		WarnContext(ctx, "handled", "attempt", 2)

	kit, man := decodeLines(t, &fromKit), decodeLines(t, &manual)
	if len(kit) != 1 || len(man) != 1 {
		t.Fatalf("entries = %d / %d, want 1 / 1", len(kit), len(man))
	}

	// 中身が空でも一致してしまうため、期待する形を先に確かめる。
	if kit[0]["severity"] != "WARNING" || kit[0]["message"] != "handled" || kit[0]["job_id"] != "job-1" {
		t.Fatalf("entry = %v, want severity/message/job_id が揃っていること", kit[0])
	}

	// 時刻だけは一致しない。
	delete(kit[0], slog.TimeKey)
	delete(man[0], slog.TimeKey)
	if !reflect.DeepEqual(kit[0], man[0]) {
		t.Errorf("NewHandler の出力が従来の組み立てと違います:\n kit    = %v\n manual = %v", kit[0], man[0])
	}
}

func TestNewHandlerRespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	slog.New(cloudlog.NewHandler(&buf, slog.LevelWarn)).
		InfoContext(context.Background(), "filtered out")

	if buf.Len() != 0 {
		t.Errorf("レベル未満のログが出力された: %s", buf.String())
	}
}
