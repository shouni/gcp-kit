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

// newTestLogger returns a context-aware logger writing Cloud Logging-compatible
// JSON to buf. It reproduces the composition an application is expected to do.
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

// Cloud Logging reads severity/message, not level/msg, so the keys must be moved.
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
		t.Error("level key remains (not moved to severity)")
	}
	if _, ok := entries[0]["msg"]; ok {
		t.Error("msg key remains (not moved to message)")
	}
}

// Attributes inside groups are app-specific data and must not be moved.
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
		t.Fatalf("group payload missing from output: %v", entries[0])
	}
	if group["level"] != "high" {
		t.Errorf("payload.level = %v, want high (keys inside groups are not moved)", group["level"])
	}
}

func TestSeverityOf(t *testing.T) {
	tests := map[slog.Level]string{
		slog.LevelDebug: "DEBUG",
		slog.LevelInfo:  "INFO",
		// Warn in slog, but WARNING in Cloud Logging.
		slog.LevelWarn:  "WARNING",
		slog.LevelError: "ERROR",
	}
	for level, want := range tests {
		if got := cloudlog.SeverityOf(level); got != want {
			t.Errorf("SeverityOf(%v) = %q, want %q", level, got, want)
		}
	}
}

// X-Cloud-Trace-Context in the form Cloud Run actually sends. The point of
// these tests is that SPAN_ID is decimal in the header ("/1"), unlike the 16
// hex digits ("0000000000000001") Cloud Logging's spanId expects.
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
			name:      "Cloud Run form: decimal SPAN_ID becomes 16 hex digits",
			header:    testTraceHeader,
			wantTrace: testTraceID,
			wantSpan:  testSpanID,
		},
		{
			name:      "no sampling flag",
			header:    testTraceID + "/456",
			wantTrace: testTraceID,
			wantSpan:  "00000000000001c8",
		},
		{
			name:      "TRACE_ID shorter than 32 digits is zero-padded",
			header:    "abc123/1",
			wantTrace: "00000000000000000000000000abc123",
			wantSpan:  testSpanID,
		},
		{
			name:      "uppercase hex is lowercased",
			header:    "ABC123/1",
			wantTrace: "00000000000000000000000000abc123",
			wantSpan:  testSpanID,
		},
		{
			name:      "no SPAN_ID",
			header:    testTraceID,
			wantTrace: testTraceID,
		},
		{
			name:      "sampling flag without SPAN_ID",
			header:    testTraceID + ";o=1",
			wantTrace: testTraceID,
		},
		{
			name:   "non-hex TRACE_ID is not correlated",
			header: "trace-abc/1",
		},
		{
			name:   "TRACE_ID longer than 32 digits is not correlated",
			header: strings.Repeat("a", 33) + "/1",
		},
		{
			name:      "non-decimal SPAN_ID is dropped but TRACE_ID kept",
			header:    testTraceID + "/span-1",
			wantTrace: testTraceID,
		},
		{
			name:      "SPAN_ID 0 means no span",
			header:    testTraceID + "/0",
			wantTrace: testTraceID,
		},
		{
			name:      "SPAN_ID overflowing 64 bits is dropped",
			header:    testTraceID + "/18446744073709551616",
			wantTrace: testTraceID,
		},
		{
			name:   "empty",
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
		t.Fatalf("attrs = %v, want 2 entries", attrs)
	}
	if attrs[0].Key != cloudlog.TraceKey || attrs[0].Value.String() != "projects/my-project/traces/"+testTraceID {
		t.Errorf("attrs[0] = %v", attrs[0])
	}
	if attrs[1].Key != cloudlog.SpanKey || attrs[1].Value.String() != testSpanID {
		t.Errorf("attrs[1] = %v", attrs[1])
	}

	// No projectID, no header and a nil request all give no correlation.
	if got := cloudlog.TraceAttrs("", req); got != nil {
		t.Errorf("TraceAttrs(empty projectID) = %v, want nil", got)
	}
	if got := cloudlog.TraceAttrs("my-project", httptest.NewRequest(http.MethodGet, "/", nil)); got != nil {
		t.Errorf("TraceAttrs(no header) = %v, want nil", got)
	}
	if got := cloudlog.TraceAttrs("my-project", nil); got != nil {
		t.Errorf("TraceAttrs(nil request) = %v, want nil", got)
	}
}

// TestTraceAttrsIgnoresForgedHeader checks that a header crafted by the caller
// is never written into Cloud Logging's reserved fields.
//
// Anyone can set this header, and Cloud Run passes on what it was handed.
// Writing it unchecked would let arbitrary strings into the trace field, and
// would also be a way to ride on another request's trace.
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
			t.Errorf("TraceAttrs(%q) = %v, want nil (not used for correlation)", header, got)
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

// Without a projectID (running locally) the fully qualified name cannot be built, so nothing is attached.
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
		t.Error("trace attached although projectID is unset")
	}
}

// Trace correlation coexists with attributes the app adds later.
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
		t.Errorf("entry = %v, want both the trace and job_id", entries[0])
	}
}

func TestHandlerOptionsRespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	newTestLogger(&buf, slog.LevelWarn).InfoContext(context.Background(), "filtered out")
	if buf.Len() != 0 {
		t.Errorf("a log below the level was written: %s", buf.String())
	}
}

// TestNewHandlerMatchesManualComposition pins NewHandler to the same output as
// the three lines that were in the sibling apps' main.go.
//
// The point of moving it here is that forgetting to wrap in
// slogctx.NewHandler raises no error; the context attributes just vanish
// silently. Without pinning the equivalence here, a migration would not
// notice.
func TestNewHandlerMatchesManualComposition(t *testing.T) {
	var fromKit, manual bytes.Buffer

	ctx := slogctx.With(context.Background(), slog.String("job_id", "job-1"))

	slog.New(cloudlog.NewHandler(&fromKit, slog.LevelInfo)).
		WarnContext(ctx, "handled", "attempt", 2)

	// The composition each app used to write by hand.
	base := slog.NewJSONHandler(&manual, cloudlog.HandlerOptions(slog.LevelInfo))
	slog.New(slogctx.NewHandler(base)).
		WarnContext(ctx, "handled", "attempt", 2)

	kit, man := decodeLines(t, &fromKit), decodeLines(t, &manual)
	if len(kit) != 1 || len(man) != 1 {
		t.Fatalf("entries = %d / %d, want 1 / 1", len(kit), len(man))
	}

	// Empty output would match too, so check the expected shape first.
	if kit[0]["severity"] != "WARNING" || kit[0]["message"] != "handled" || kit[0]["job_id"] != "job-1" {
		t.Fatalf("entry = %v, want severity, message and job_id all present", kit[0])
	}

	// Only the time differs.
	delete(kit[0], slog.TimeKey)
	delete(man[0], slog.TimeKey)
	if !reflect.DeepEqual(kit[0], man[0]) {
		t.Errorf("NewHandler output differs from the manual composition:\n kit    = %v\n manual = %v", kit[0], man[0])
	}
}

func TestNewHandlerRespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	slog.New(cloudlog.NewHandler(&buf, slog.LevelWarn)).
		InfoContext(context.Background(), "filtered out")

	if buf.Len() != 0 {
		t.Errorf("a log below the level was written: %s", buf.String())
	}
}
