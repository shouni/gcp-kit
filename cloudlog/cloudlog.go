// Package cloudlog provides the slog settings for writing structured logs
// Cloud Logging can interpret, and the Cloud Run trace-correlation middleware.
//
// slog's default JSON output uses the `level`/`msg` keys, but Cloud Logging
// reads `severity`/`message`. Left at the defaults, every entry shows as INFO
// in Logs Explorer and nothing can be filtered by severity. HandlerOptions
// bridges the difference.
//
// NewHandler takes care of the composition. The destination and the level do
// not depend on GCP, so they stay with the caller as arguments.
//
//	level := slogctx.ParseLevel(os.Getenv("LOG_LEVEL"))
//	slog.SetDefault(slog.New(cloudlog.NewHandler(os.Stdout, level)))
package cloudlog

import (
	"io"
	"log/slog"

	"github.com/shouni/go-utils/slogctx"
)

// Reserved field names Cloud Logging uses to correlate entries with traces.
const (
	// TraceKey is the field holding the trace's fully qualified name.
	TraceKey = "logging.googleapis.com/trace"
	// SpanKey is the field holding the span ID.
	SpanKey = "logging.googleapis.com/spanId"
)

// NewHandler builds a slog.Handler that writes Cloud Logging-compatible JSON
// to w and also outputs the attributes carried in the context.
//
// The composition order lives here because it is the part that breaks
// silently when gotten wrong. Forgetting to wrap in slogctx.NewHandler raises
// no error; job_id and the trace ID simply vanish from the logs, which is why
// six sibling apps were copying the same three lines verbatim.
//
// Usage is in the package documentation. slog.SetDefault is not called in
// here because replacing the default logger affects the whole process; it
// stays where the caller can see it. For a different composition, pass
// HandlerOptions directly to slog.NewJSONHandler.
func NewHandler(w io.Writer, level slog.Level) slog.Handler {
	return slogctx.NewHandler(slog.NewJSONHandler(w, HandlerOptions(level)))
}

// HandlerOptions returns slog.HandlerOptions that output Cloud
// Logging-compatible attribute names. Pass it to slog.NewJSONHandler.
func HandlerOptions(level slog.Level) *slog.HandlerOptions {
	return &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: replaceAttr,
	}
}

// replaceAttr moves slog's standard keys onto Cloud Logging's reserved fields.
// Attributes inside groups are app-specific data and are left alone.
func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return a
	}

	switch a.Key {
	case slog.LevelKey:
		a.Key = "severity"
		if level, ok := a.Value.Any().(slog.Level); ok {
			a.Value = slog.StringValue(SeverityOf(level))
		}
	case slog.MessageKey:
		a.Key = "message"
	}
	return a
}

// SeverityOf maps a slog level to a Cloud Logging severity string.
// Note that slog.LevelWarn is "WARNING" in Cloud Logging.
func SeverityOf(level slog.Level) string {
	switch {
	case level < slog.LevelInfo:
		return "DEBUG"
	case level < slog.LevelWarn:
		return "INFO"
	case level < slog.LevelError:
		return "WARNING"
	default:
		return "ERROR"
	}
}
