// Package negotiate は、1 本のルートで人（ブラウザ）と機械（エージェント）の
// 両方へ応答するための判定を提供します。
//
// 画面用と API 用にルートを分けると、同じリソースの取得処理を 2 本持つことになり、
// 片方だけ直したときに画面の表示と機械可読な結果が食い違います。ルートは 1 本に保ち、
// 表現だけを Accept で選びます。
//
// ただし「JSON で答えられる画面」と「画面にしか無いもの」は別です。入力フォームや
// 一覧ページのように JSON の対応物が無いものは、別のリソースなので分けたままにします。
package negotiate

import (
	"net/http"
	"strings"
)

// mediaTypeJSON は JSON を求めていると判断する media type です。
const mediaTypeJSON = "application/json"

// WantsJSON は、呼び出し元が JSON を求めているかを返します。
//
// 同時にレスポンスへ Vary: Accept を立てます。判定と宣言を 1 つの関数にまとめて
// あるのは、同じ URL が Accept で中身を変えるのにそれをキャッシュへ伝えない
// という取りこぼしを塞ぐためです。共有キャッシュや CDN を前に置いたとき、
// Vary が無いと JSON を求めたクライアントへ HTML が返りえます。
//
// 判定は Accept に "application/json" が含まれるかだけを見ます。したがって
// curl の既定である "*/*" は HTML 側に倒れ、"application/json;q=0"（JSON は要らない）
// も JSON と見なします。q 値まで解釈しないのは、利用側がいずれも
// 明示的に Accept を送っているためです。
//
// w が nil の場合は Vary を立てず、判定だけを行います。r が nil の場合は false です。
func WantsJSON(w http.ResponseWriter, r *http.Request) bool {
	if w != nil {
		AddVaryAccept(w.Header())
	}
	if r == nil {
		return false
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), mediaTypeJSON)
}

// AddVaryAccept は Vary: Accept を追加します。既に含まれている場合は何もしません。
//
// 判定を挟まずに応答を出し分ける経路（テンプレート側で分岐する等）から、
// Vary だけを立てたい場合に使います。
func AddVaryAccept(h http.Header) {
	if h == nil {
		return
	}
	for _, value := range h.Values("Vary") {
		for field := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(strings.TrimSpace(field), "Accept") {
				return
			}
		}
	}
	h.Add("Vary", "Accept")
}
