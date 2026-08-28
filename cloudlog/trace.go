package cloudlog

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
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

// Cloud Logging の予約フィールドが要求する桁数です。
// trace は 16 進 32 桁（128 ビット）、spanId は 16 進 16 桁（64 ビット）です。
const (
	traceIDHexLen = 32
	spanIDHexLen  = 16
)

// ParseTraceContext は "TRACE_ID[/SPAN_ID][;o=TRACE_TRUE]" 形式のヘッダーを、
// Cloud Logging の予約フィールドへそのまま載せられる表現へ分解します。
// 相関に使えない値は空文字を返します。
//
// **ヘッダーの値をそのまま返しません。** ヘッダー上の SPAN_ID は 10 進数
// （Cloud Run が送るのは ".../1;o=1" のような値）ですが、spanId フィールドは
// 8 バイトの 16 進表現を期待します。生のまま入れても Cloud Logging はスパンと
// 突き合わせられないため、ここで 16 桁の 16 進数へ直します。TRACE_ID も
// 32 桁に満たない 16 進数がありうるので 0 で左詰めします。
//
// **形式に合わない値は捨てます。** このヘッダーは呼び出し元が自由に付けられ、
// Cloud Run は提示された値を引き継ぎます。検証せずに予約フィールドへ書くと、
// 任意の文字列を Cloud Logging の trace/spanId に仕込む入口になり、
// 他リクエストのトレースへ相乗りすることもできてしまいます。
func ParseTraceContext(header string) (traceID string, spanID string) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", ""
	}

	// ";o=TRACE_TRUE" は省略可能で、SPAN_ID が無い "TRACE_ID;o=1" もありえます。
	// "/" で切る前に落としておかないと、この形が TRACE_ID に紛れ込みます。
	header, _, _ = strings.Cut(header, ";")

	rawTrace, rawSpan, hasSpan := strings.Cut(header, "/")
	traceID = normalizeTraceID(rawTrace)
	if traceID == "" || !hasSpan {
		return traceID, ""
	}
	return traceID, normalizeSpanID(rawSpan)
}

// normalizeTraceID は TRACE_ID を 16 進 32 桁へ正規化します。
// 16 進数でないもの、32 桁を超えるものは相関に使えないため空文字を返します。
func normalizeTraceID(raw string) string {
	if raw == "" || len(raw) > traceIDHexLen || !isHex(raw) {
		return ""
	}
	return strings.Repeat("0", traceIDHexLen-len(raw)) + strings.ToLower(raw)
}

// normalizeSpanID は 10 進数の SPAN_ID を 16 進 16 桁へ直します。
// 0 は「スパンなし」を意味するため、解析できない値と同じく空文字を返します。
func normalizeSpanID(raw string) string {
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || id == 0 {
		return ""
	}
	return fmt.Sprintf("%0*x", spanIDHexLen, id)
}

// isHex は、文字列が 16 進数字だけで構成されているかを返します。
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
