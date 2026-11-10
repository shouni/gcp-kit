package cloudlog

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/shouni/go-utils/slogctx"
)

// TraceHeader is the trace header Cloud Run and Cloud Load Balancing attach.
const TraceHeader = "X-Cloud-Trace-Context"

// TraceAttrs builds Cloud Logging's trace-correlation fields from the
// request's X-Cloud-Trace-Context. It returns nil when no correlation is
// possible.
//
// It is a pure conversion that does not decide how values ride in the
// context, so applications carrying attributes by means other than slogctx can
// use it too.
func TraceAttrs(projectID string, r *http.Request) []slog.Attr {
	if strings.TrimSpace(projectID) == "" || r == nil {
		return nil
	}

	traceID, spanID := ParseTraceContext(r.Header.Get(TraceHeader))
	if traceID == "" {
		return nil
	}

	attrs := []slog.Attr{
		slog.String(TraceKey, "projects/"+projectID+"/traces/"+traceID),
	}
	if spanID != "" {
		attrs = append(attrs, slog.String(SpanKey, spanID))
	}
	return attrs
}

// TraceMiddleware parses X-Cloud-Trace-Context and adds the trace ID to the
// log lines that follow, so Logs Explorer groups them per request.
//
// It attaches them through slogctx, so the logger must be wrapped in
// slogctx.NewHandler. With an empty projectID it cannot build the fully
// qualified name Cloud Logging ties to a trace, so it does nothing and passes
// the request through (when running locally, for example).
func TraceMiddleware(projectID string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if strings.TrimSpace(projectID) == "" {
			return next
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attrs := TraceAttrs(projectID, r)
			if len(attrs) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(slogctx.With(r.Context(), attrs...)))
		})
	}
}

// Digit counts Cloud Logging's reserved fields require: trace is 32 hex digits
// (128 bits) and spanId is 16 hex digits (64 bits).
const (
	traceIDHexLen = 32
	spanIDHexLen  = 16
)

// ParseTraceContext splits a header of the form
// "TRACE_ID[/SPAN_ID][;o=TRACE_TRUE]" into values that can go straight into
// Cloud Logging's reserved fields. A value unusable for correlation comes back
// empty.
//
// It does not return the header's values as they are. SPAN_ID is decimal in
// the header (Cloud Run sends values like ".../1;o=1"), but the spanId field
// expects the 8-byte hex form. Written raw, Cloud Logging cannot match it to
// the span, so it is converted to 16 hex digits here. TRACE_ID can also be a
// hex number shorter than 32 digits, so it is left-padded with zeros.
//
// Values that do not fit the format are dropped. Callers can set this header
// freely, and Cloud Run passes on what it was handed. Writing it unchecked
// into the reserved fields would be a way to plant arbitrary strings in Cloud
// Logging's trace/spanId, and to ride on another request's trace.
func ParseTraceContext(header string) (traceID string, spanID string) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", ""
	}

	// ";o=TRACE_TRUE" is optional, and "TRACE_ID;o=1" without a SPAN_ID is
	// possible. Unless it is dropped before cutting at "/", that form leaks
	// into TRACE_ID.
	header, _, _ = strings.Cut(header, ";")

	rawTrace, rawSpan, hasSpan := strings.Cut(header, "/")
	traceID = normalizeTraceID(rawTrace)
	if traceID == "" || !hasSpan {
		return traceID, ""
	}
	return traceID, normalizeSpanID(rawSpan)
}

// normalizeTraceID normalises TRACE_ID to 32 hex digits. Anything not hex, or
// longer than 32 digits, is unusable for correlation and comes back empty.
func normalizeTraceID(raw string) string {
	if raw == "" || len(raw) > traceIDHexLen || !isHex(raw) {
		return ""
	}
	return strings.Repeat("0", traceIDHexLen-len(raw)) + strings.ToLower(raw)
}

// normalizeSpanID converts a decimal SPAN_ID to 16 hex digits. 0 means "no
// span", so like an unparsable value it comes back empty.
func normalizeSpanID(raw string) string {
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || id == 0 {
		return ""
	}
	return fmt.Sprintf("%0*x", spanIDHexLen, id)
}

// isHex reports whether s consists of hex digits only.
func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
