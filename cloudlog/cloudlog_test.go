package cloudlog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

func TestParseTraceContext(t *testing.T) {
	tests := []struct {
		header    string
		wantTrace string
		wantSpan  string
	}{
		{"abc123/456;o=1", "abc123", "456"},
		{"abc123/456", "abc123", "456"},
		{"abc123", "abc123", ""},
		{"", "", ""},
	}

	for _, tt := range tests {
		trace, span := cloudlog.ParseTraceContext(tt.header)
		if trace != tt.wantTrace || span != tt.wantSpan {
			t.Errorf("ParseTraceContext(%q) = (%q, %q), want (%q, %q)",
				tt.header, trace, span, tt.wantTrace, tt.wantSpan)
		}
	}
}

func TestTraceAttrs(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(cloudlog.TraceHeader, "trace-abc/span-1;o=1")

	attrs := cloudlog.TraceAttrs("my-project", req)
	if len(attrs) != 2 {
		t.Fatalf("attrs = %v, want 2 件", attrs)
	}
	if attrs[0].Key != cloudlog.TraceKey || attrs[0].Value.String() != "projects/my-project/traces/trace-abc" {
		t.Errorf("attrs[0] = %v", attrs[0])
	}
	if attrs[1].Key != cloudlog.SpanKey || attrs[1].Value.String() != "span-1" {
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

func TestTraceMiddlewareAttachesTrace(t *testing.T) {
	var buf bytes.Buffer
	logger := newTestLogger(&buf, slog.LevelInfo)

	handler := cloudlog.TraceMiddleware("my-project")(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		logger.InfoContext(r.Context(), "handled")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(cloudlog.TraceHeader, "trace-abc/span-1;o=1")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	entries := decodeLines(t, &buf)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if entries[0][cloudlog.TraceKey] != "projects/my-project/traces/trace-abc" {
		t.Errorf("trace = %v", entries[0][cloudlog.TraceKey])
	}
	if entries[0][cloudlog.SpanKey] != "span-1" {
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
	req.Header.Set(cloudlog.TraceHeader, "trace-abc/span-1;o=1")
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
	req.Header.Set(cloudlog.TraceHeader, "trace-abc/span-1")
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
