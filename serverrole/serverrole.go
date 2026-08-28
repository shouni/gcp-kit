// Package serverrole は、1つのイメージを Web 面と Worker 面の2サービスとして
// デプロイするときに、そのプロセスがどちらを担うかを表す語彙を提供します。
//
// 語彙と検証だけを持ち、役割ごとに何を提供するかは利用側が決めます。
// キットは役割で分岐しないため、4つ目の役割や役割ごとの属性が要るアプリは、
// このパッケージを変更せずに自分の側で足せます（Role は定義済み文字列型なので、
// 独自の定数を宣言し、Parse を自前の解釈で包めば済みます）。
package serverrole

import (
	"fmt"
	"strings"
)

// Role は、プロセスが担う役割です。
type Role string

const (
	// Both は Web 面と Worker 面の両方を提供します（ローカル開発用）。
	Both Role = "both"
	// Web は Web 面（ブラウザ向け UI とサービス間 API）だけを提供します。
	Web Role = "web"
	// Worker は Worker 面（Cloud Tasks から呼ばれる実行系）だけを提供します。
	Worker Role = "worker"
)

// Parse は SERVER_ROLE 等の設定値を役割に変換します。空文字も未知の値もエラーです。
// 大文字小文字と前後の空白は正規化して受け付けます。
//
// 未設定を Both とみなしません。そう扱うと、本番の環境変数が1つ欠けただけで
// 公開している Web 面に Worker のルートが復活します。未知の値を黙って受け入れるのも
// 同じく危険で、今度は何のルートも提供しないサービスがデプロイされます。
// どちらも起動時に落とすほうが安全です。
func Parse(raw string) (Role, error) {
	role := Role(strings.ToLower(strings.TrimSpace(raw)))
	switch role {
	case Both, Web, Worker:
		return role, nil
	default:
		return "", fmt.Errorf("server role (%q) は %q, %q, %q のいずれかである必要があります",
			raw, Web, Worker, Both)
	}
}

// ServesWeb は、この役割が Web 面を提供するかを返します。
func (r Role) ServesWeb() bool { return r == Both || r == Web }

// ServesWorker は、この役割が Worker 面を提供するかを返します。
func (r Role) ServesWorker() bool { return r == Both || r == Worker }

// UnmarshalText は encoding.TextUnmarshaler を実装します。
//
// 環境変数や JSON をデコードする時点で Parse を通すためにあります。これが無いと、
// デコーダは Role が定義済み文字列型であることだけを見て未知の値でも代入でき、
// アプリが後から Parse を呼び忘れると ServesWeb も ServesWorker も false のまま
// 起動して、何のルートも提供しないサービスがデプロイされます。
//
// 値が与えられなかった場合、多くのデコーダはこのメソッドを呼びません。
// 未設定を弾くのはタグ側の役目です（例: env:"SERVER_ROLE,required"）。
func (r *Role) UnmarshalText(text []byte) error {
	role, err := Parse(string(text))
	if err != nil {
		return err
	}
	*r = role
	return nil
}
