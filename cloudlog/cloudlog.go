// Package cloudlog は、Cloud Logging が解釈できる構造化ログを出力するための
// slog 設定と、Cloud Run のトレース相関ミドルウェアを提供します。
//
// slog の既定 JSON 出力は `level`/`msg` キーを使いますが、Cloud Logging が参照するのは
// `severity`/`message` です。既定のままだと Logs Explorer 上ですべてのエントリが
// INFO 扱いになり、重大度での絞り込みができません。HandlerOptions がこの差を吸収します。
//
// 組み立ては NewHandler が引き受けます。出力先とレベルは GCP に依存しないため、
// 引数として呼び出し側に残します。
//
//	level := slogctx.ParseLevel(os.Getenv("LOG_LEVEL"))
//	slog.SetDefault(slog.New(cloudlog.NewHandler(os.Stdout, level)))
package cloudlog

import (
	"io"
	"log/slog"

	"github.com/shouni/go-utils/slogctx"
)

// Cloud Logging がトレースとの相関に使う予約フィールド名です。
const (
	// TraceKey はトレースの完全修飾名を入れるフィールドです。
	TraceKey = "logging.googleapis.com/trace"
	// SpanKey はスパン ID を入れるフィールドです。
	SpanKey = "logging.googleapis.com/spanId"
)

// NewHandler は、Cloud Logging 互換の JSON を w へ書き、context に載せた属性も
// 出力する slog.Handler を組み立てます。
//
// 組み立ての順番をここに置くのは、外しても何も言わずに壊れる部分だからです。
// slogctx.NewHandler で包み忘れてもエラーは出ず、job_id やトレース ID がログから
// 消えるだけなので、6 つの兄弟アプリが同じ 3 行を逐語で写していました。
//
// 使い方はパッケージのドキュメントにあります。slog.SetDefault をこの中でやらないのは、
// 既定ロガーの差し替えがプロセス全体に効くためです。呼び出し側から見える場所に残します。
// 別の組み立てをしたい場合は HandlerOptions を直接 slog.NewJSONHandler へ渡してください。
func NewHandler(w io.Writer, level slog.Level) slog.Handler {
	return slogctx.NewHandler(slog.NewJSONHandler(w, HandlerOptions(level)))
}

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
