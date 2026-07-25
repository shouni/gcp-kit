package cloudlog

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/shouni/go-utils/slogctx"
)

// TraceHeader は Cloud Run / Cloud Load Balancing が付与するトレースヘッダーです。
const TraceHeader = "X-Cloud-Trace-Context"

// TraceAttrs は、リクエストの X-Cloud-Trace-Context から Cloud Logging の
// トレース相関フィールドを組み立てます。相関できない場合は nil を返します。
//
// context への載せ方を持たない純粋な変換なので、slogctx 以外の仕組みで属性を
// 引き回しているアプリケーションでも利用できます。
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

// TraceMiddleware は X-Cloud-Trace-Context を解析し、以降のログへトレース ID を付与します。
// これにより Logs Explorer 上でリクエスト単位にログがまとまります。
//
// 付与には slogctx を使うため、ロガーは slogctx.NewHandler で包んでおく必要があります。
// projectID が空の場合、Cloud Logging がトレースと紐付けられる完全修飾名を組み立てられ
// ないため、何もせず素通しします（ローカル実行時など）。
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

// ParseTraceContext は "TRACE_ID/SPAN_ID;o=1" 形式のヘッダーを分解します。
// 解析できない場合は空文字を返します。
func ParseTraceContext(header string) (traceID string, spanID string) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", ""
	}

	traceID, remainder, found := strings.Cut(header, "/")
	if !found {
		return traceID, ""
	}
	spanID, _, _ = strings.Cut(remainder, ";")
	return traceID, spanID
}
