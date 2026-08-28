package negotiate

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
)

// contentTypeJSON は JSON 応答に付ける Content-Type です。
//
// charset まで固定するのは、5 つの兄弟アプリが "application/json" と
// "application/json; charset=utf-8" に割れていたためです。RFC 8259 が JSON を
// UTF-8 と定めている以上どちらでも解釈は変わりませんが、値が混ざっていると
// 応答を突き合わせる側（同じクライアントが 4 つのバックエンドを呼びます）が
// 両方を書くことになります。片方に倒します。
const contentTypeJSON = "application/json; charset=utf-8"

// errorBody は、JSON を求めた呼び出し元へ返すエラー本文です。
//
// 形は {"error": "..."} です。兄弟アプリが既にこの形へ揃えており、
// 以前 1 つだけ text/plain を返していたときは、同じクライアントから呼ぶのに
// そこだけ本文の読み方が変わっていました。
type errorBody struct {
	Error string `json:"error"`
}

// JSON は payload を JSON として書き出します。
//
// エンコードに失敗しても応答は差し替えられません。ヘッダーと状態コードを
// 送った後だからです。記録だけ残して返ります。出力先が slog.Default() なのは、
// cloudlog と slogctx を噛ませてあるアプリで severity とトレース相関が
// そのまま効くためです。
//
// Vary: Accept は立てません。表現を出し分けるかどうかを知っているのは
// WantsJSON を呼んだ側で、JSON しか返さない経路に Vary は要らないためです。
func JSON(w http.ResponseWriter, r *http.Request, status int, payload any) {
	if w == nil {
		return
	}

	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.ErrorContext(requestContext(r), "negotiate: JSON 応答のエンコードに失敗しました",
			"error", err, "status", status)
	}
}

// Error は、呼び出し元が JSON を求めていれば JSON で、そうでなければ
// text/plain でエラーを返します。
//
// 画面と API が同じ URL を共有するルート用です。JSON 固定にしないのは、画面側の
// JS がエラー本文を resp.text() で読んでいるためで、逆に text/plain 固定にすると、
// 通したエージェントが本文を構造化して読めません。どちらを返すかの判定は WantsJSON に
// 委ねるので、Vary: Accept もそこで立ちます。
//
// JSON しか返さないルートでは ErrorJSON を使ってください。
func Error(w http.ResponseWriter, r *http.Request, status int, message string) {
	if WantsJSON(w, r) {
		ErrorJSON(w, r, status, message)
		return
	}
	http.Error(w, message, status)
}

// ErrorJSON は、相手が何を求めていても JSON でエラーを返します。
//
// JSON しか返さないルート用です。そういうルートは成功時も無条件に JSON を返すので、
// エラーだけ Accept で形が変わると、呼び出し側は成功と失敗で本文の読み方を変えることに
// なります。実際、Accept を送らないブラウザの fetch がエラー本文を JSON として読んでおり、
// text/plain へ倒した結果サーバーの文言が届かなくなった、ということが起きました。
//
// Vary: Accept は立てません。この応答は Accept で変わらないためです。
func ErrorJSON(w http.ResponseWriter, r *http.Request, status int, message string) {
	JSON(w, r, status, errorBody{Error: message})
}

// requestContext は、r が nil でも使えるコンテキストを返します。
// このパッケージの他の関数と同じく、ゼロ値・nil で落ちないようにするためです。
func requestContext(r *http.Request) context.Context {
	if r == nil {
		return context.Background()
	}
	return r.Context()
}
