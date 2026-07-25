// Package cloudlog は、Cloud Logging が解釈できる構造化ログを出力するための
// slog 設定と、Cloud Run のトレース相関ミドルウェアを提供します。
//
// slog の既定 JSON 出力は `level`/`msg` キーを使いますが、Cloud Logging が参照するのは
// `severity`/`message` です。既定のままだと Logs Explorer 上ですべてのエントリが
// INFO 扱いになり、重大度での絞り込みができません。HandlerOptions がこの差を吸収します。
//
// 出力先やレベルの決定、context 属性の付与といった GCP に依存しない部分は
// 意図的に持ちません。アプリケーション側で組み立ててください。
//
//	level := slogctx.ParseLevel(os.Getenv("LOG_LEVEL"))
//	base := slog.NewJSONHandler(os.Stdout, cloudlog.HandlerOptions(level))
//	slog.SetDefault(slog.New(slogctx.NewHandler(base)))
package cloudlog

import (
	"log/slog"
)

// Cloud Logging がトレースとの相関に使う予約フィールド名です。
const (
	// TraceKey はトレースの完全修飾名を入れるフィールドです。
	TraceKey = "logging.googleapis.com/trace"
	// SpanKey はスパン ID を入れるフィールドです。
	SpanKey = "logging.googleapis.com/spanId"
)

// HandlerOptions は、Cloud Logging 互換の属性名で出力する slog.HandlerOptions を返します。
// slog.NewJSONHandler へ渡して使います。
func HandlerOptions(level slog.Level) *slog.HandlerOptions {
	return &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: replaceAttr,
	}
}

// replaceAttr は slog の標準キーを Cloud Logging の予約フィールドへ詰め替えます。
// グループ内の属性はアプリ固有のデータなので触りません。
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

// SeverityOf は slog のレベルを Cloud Logging の severity 文字列へ対応付けます。
// slog.LevelWarn は Cloud Logging では "WARNING" である点に注意してください。
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
