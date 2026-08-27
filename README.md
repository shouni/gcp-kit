# ✍️ GCP Kit

[![CI](https://github.com/shouni/gcp-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/shouni/gcp-kit/actions/workflows/ci.yml)
[![Language](https://img.shields.io/badge/Language-Go-blue)](https://golang.org/)
[![Go Version](https://img.shields.io/github/go-mod/go-version/shouni/gcp-kit)](https://golang.org/)
[![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/shouni/gcp-kit)](https://github.com/shouni/gcp-kit/tags)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Reference](https://pkg.go.dev/badge/github.com/shouni/gcp-kit.svg)](https://pkg.go.dev/github.com/shouni/gcp-kit)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen)](#)

## 🚀 概要 (About) - Cloud Run と Cloud Tasks を使った開発を最速の軌道へ

**GCP Kit** は、Google Cloud Platform (GCP) を活用したWebアプリケーションや非同期ワーカーの開発をシンプルかつ堅牢にするためのGo言語向けツールキットです。

Cloud Run や Cloud Tasks を用いたアーキテクチャにおいて、ボイラープレートになりがちな **「Google OAuth2 認証とセッション管理」「Cloud Logging 互換の構造化ログ」「Web / Worker の役割判定」「型安全なタスク投入と受信」** を抽象化し、ビジネスロジックに集中できる環境を提供します。

---

## ✨ 提供機能 (Features)

パッケージは独立しており、必要なものだけを import できます。

* **`auth`**: **「誰として通すか」の契約と合成**（標準ライブラリのみ）
  * **方式は 2 つの子パッケージに実装があります。** 人は `auth/session`、サービスは `auth/oidc` です。
    どちらも `Authenticator` を満たすので、合成は `Require`（サービス専用ルート）と
    `Protected`（人もサービスも来るルート）が引き受けます。
  * **「未着手」と「未設定」を別のエラーにしています。** 前者は「自分の担当ではない」で次の方式へ譲り、
    後者は設定ミスです。混ぜると、設定漏れがフォールバックに隠れて
    「なぜかエージェントだけログイン画面に飛ばされる」という形で現れます。
  * **応答を決めるのは、資格情報を提示したうえで落ちた方式です。** 最後の方式に答えさせると、
    **JSON を求めたエージェントに HTML のログイン画面が返ります**。
  * **ログイン画面へ送るのは、相手がページを求めている場合だけです。** `Accept` が JSON なら 401 を
    返します。ブラウザは `text/html` を送るので、挙動は変わりません。

| 状況 | `auth.Protected(verifier, session)` | `auth.Require(verifier)` |
| --- | --- | --- |
| 資格情報なし・ページを求めている | 302 ログイン画面へ | 401 `WWW-Authenticate: Bearer` |
| 資格情報なし・JSON を求めている | 401 | 401 `WWW-Authenticate: Bearer` |
| トークンが不正 | 401 `error="invalid_token"` | 同左 |
| 呼び出し元が許可リストに無い | 403 `error="insufficient_scope"` | 同左 |
| 検証器が未設定 | 302 / 401（ログに記録） | 500 |

状態コードは RFC 6750 §3.1、`WWW-Authenticate` の付与は RFC 9110 §15.5.2 に従います。
**「取り直せば直る（401）」と「取り直しても直らない（403）」を分けている**ので、
エージェント側は再取得すべきかどうかを応答から判断できます。

* **`auth/session`**: **Google OAuth2 ログインとセッション・CSRF**
  * **PKCE 対応**: 認可コードの横取りに備え、`S256` チャレンジを標準で組み込んでいます。
  * **署名(HMAC)・暗号化(AES)の分離キー設計**: セッションの改ざん防止と秘匿化を別の鍵で保護します。
  * **差し替え可能なセッションストア**: 既定は Cookie ストア。`WithStore` に Redis 等を注入すれば、
    サーバー側でのセッション失効（確実なログアウト）にも対応できます。
  * **柔軟な認可**: 許可ドメイン・メールアドレスのリストで絞り込みます。空のリストは「全部拒否」です。
    判定は**毎リクエスト**行うため、許可リストから外せばその場で締め出せます。
  * **CSRF 対策**: 定数時間比較（`subtle.ConstantTimeCompare`）でトークン推測を防ぎ、ヘッダー検証を
    優先することで JSON API のボディが `ParseForm` に読み切られるのを回避します。
    **CSRF や Origin の検証に落ちた場合は 403 で止めます**（リダイレクトにすると、
    偽装リクエストが弾かれたのか通ったのかを区別できません）。
* **`auth/oidc`**: **サービス間呼び出しの受信検証**
  * **署名と audience だけでは呼び出し元を認証したことになりません。** audience は誰でも指定できる
    文字列に過ぎないため、**サービスアカウント許可リスト**まで照合します。
  * **検証器は 1 つです。** Cloud Tasks 用と他サービス用で型を分けません。違うのは合成のされ方
    （拒否して止めるか、セッションへ譲るか）だけで、それは `Require` と `Protected` の差です。
  * **OAuth 設定を要求しません。** Web UI を持たない Worker が、使わないクライアントシークレットへの
    アクセス権を持たずに受信検証できます。設定漏れは `Configured()` で**起動時に**検出できます。
* **`cloudlog`**: **Cloud Logging 互換の構造化ログ**
  * **severity への詰め替え**: slog 既定の `level`/`msg` は Cloud Logging に読まれず、
    Logs Explorer 上で全エントリが INFO 扱いになります。`HandlerOptions` がこの差を吸収します。
  * **トレース相関**: `TraceMiddleware` が `X-Cloud-Trace-Context` を解析し、リクエスト単位で
    ログをまとめます。context への載せ方を持たない `TraceAttrs` も公開しています。
  * **出力先とレベルは持たない**: GCP に依存しない部分は意図的にアプリケーション側へ残します。
* **`negotiate`**: **通した相手に合わせて表現を選ぶ**（`auth` と対になります）
  * `WantsJSON` が `Accept` を見て表現を選び、**同時に `Vary: Accept` を立てます**。
    判定と宣言を1つの関数にまとめてあるのは、同じ URL が `Accept` で中身を変えるのに
    それをキャッシュへ伝えない、という取りこぼしを塞ぐためです。
  * **`auth` が「誰として通すか」を決め、`negotiate` が「何を返すか」を決めます。** 片方だけでは
    足りません。`auth.Protected` でエージェントを通しても、応答が HTML のままでは意味がありません。
  * 画面用と API 用にルートを分けると同じ取得処理を2本持つことになり、片方だけ直したときに
    表示と機械可読な結果が食い違います。ただし**入力フォームのように JSON の対応物が無いもの**は
    別のリソースなので、分けたままにします。
* **`serverrole`**: **Web / Worker の役割判定**
  * 1つのイメージを2つの Cloud Run サービス（公開 web / 非公開 worker）としてデプロイする構成向けに、
    `web` / `worker` / `both` の語彙と `Parse` を提供します。
  * **未設定と未知の値はエラーです。** 未設定を `both` に落とすと、環境変数が1つ欠けただけで
    公開側に worker のルートが復活します。役割ごとに何を提供するかは利用側の router が決めるため、
    キットは役割で分岐しません（4つ目の役割はアプリ側で足せます）。
* **`tasks`**: **型安全な Cloud Tasks エンキュー**
  * **Generics 対応**: `[T any]` で独自の構造体を型安全に投入できます。`T` は `worker` との契約です。
  * **認証のカプセル化**: サービスアカウントによる OIDC トークン認証の設定を内側に隠します。
  * **冪等なタスク投入**: `EnqueueWithName` は決定的な名前で投入し、`ALREADY_EXISTS` を成功として扱います。
  * **柔軟なオプション**: `EnqueueWithOptions` でタスク ID・実行時刻・遅延・応答待ち時間・追加ヘッダーを
    指定でき、作成されたタスク名を受け取れます。
  * **`DispatchDeadline` は「ワーカーの実行時間の実効上限」です**: キュー単位（`Config`）でも
    タスク単位（`WithDispatchDeadline`、こちらが優先）でも指定できます。未指定だと Cloud Tasks の
    既定 10 分が上限になり、Cloud Run の `timeout` をいくら伸ばしても超えられません。
    アプリ側の全体タイムアウトは**これより短く**取ってください（でないと、失敗を記録する前に
    context ごと打ち切られます）。
  * **後始末**: `Close()` で内部の gRPC クライアントを解放します。
* **`worker`**: **Cloud Tasks 向け Worker ハンドラー**
  * **自動デコード**: 受信したタスクのペイロードを目的の型へデコードし、ビジネスロジックへ渡します。
  * **リトライフレンドリー**: エラー時の HTTP ステータスを Cloud Tasks の再試行仕様に沿って返します。
    リトライしても直らない失敗は `worker.ErrPermanent` でラップして打ち切れます。
  * **配信メタデータ**: `worker.MetadataFromContext` で再試行回数やタスク名を参照でき、
    at-least-once 配信に対する冪等な処理を書けます。

---

## 🚦 使い方 (Usage)

```go
// 1. 人（ブラウザ）の方式
sessionHandler, err := session.New(session.Config{
    ClientID:          os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret:      os.Getenv("GOOGLE_CLIENT_SECRET"),
    RedirectURL:       serviceURL + "/auth/callback",
    SessionAuthKey:    os.Getenv("SESSION_SECRET"),        // 16バイト以上
    SessionEncryptKey: os.Getenv("SESSION_ENCRYPT_KEY"),   // 16/24/32バイト
    SessionName:       "app-session",
    IsSecureCookie:    true,
    AllowedDomains:    []string{"example.com"},
})

// 2. サービスの方式。audience と許可SAの両方が必須です（片方だけでは常に検証失敗）。
apiVerifier := oidc.New(serviceURL, allowedCallerSAs)
taskVerifier := oidc.New(workerURL, allowedCallerSAs)

// 設定漏れは起動時に落とします（リクエスト時だと、Cloud Tasks がリトライを
// 重ねた末にタスクを破棄してしまいます）。
if !taskVerifier.Configured() || !apiVerifier.Configured() {
    return errors.New("OIDC verification is not configured")
}

// 3. ルーティング（役割は明示が必須。未設定を both に落とすと、公開側に worker のルートが復活します）
role, err := serverrole.Parse(os.Getenv("SERVER_ROLE"))
mux := http.NewServeMux()
mux.Handle("GET /auth/login", http.HandlerFunc(sessionHandler.Login))
mux.Handle("GET /auth/callback", http.HandlerFunc(sessionHandler.Callback))

// 人だけが来るルート
mux.Handle("/private", auth.Protected(sessionHandler)(privateHandler))
// 人もエージェントも来るルート。有効な Bearer はセッションと CSRF をバイパスし、
// それ以外はログインへ回ります（人向けの方式が最後だから）。
mux.Handle("/api/", auth.Protected(apiVerifier, sessionHandler)(http.HandlerFunc(apiHandler)))
if role.ServesWorker() {
    // サービスしか来ないルート。失敗はフォールバックせず 401/403 で止まります。
    mux.Handle("POST /tasks/run", auth.Require(taskVerifier)(workerHandler))
}
```

**誰を通すかは `auth` が決め、その相手に何を返すかは `negotiate` が決めます。** 通したエージェントに
HTML を返しては意味がないので、保護したハンドラーの中では対で使います。

```go
func apiHandler(w http.ResponseWriter, r *http.Request) {
    // セッションを開き直さずに、認証済みユーザーを参照できます。
    email, _ := session.EmailFromContext(r.Context())
    comics := store.List(r.Context(), email)

    if negotiate.WantsJSON(w, r) { // Vary: Accept もここで立ちます
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(comics)
        return
    }
    // 人にはページを返します。CSRF トークンはセッション経路でのみ載ります。
    _ = tmpl.Execute(w, page{Comics: comics, CSRFToken: session.CSRFTokenFromContext(r.Context())})
}
```

より詳しい例は [pkg.go.dev の Example](https://pkg.go.dev/github.com/shouni/gcp-kit) を参照してください。

---

## 🏗 プロジェクトレイアウト (Project Layout)

```text
gcp-kit/
├── auth/           # 認証の契約（Authenticator）と合成（Require / Protected）
│   ├── session/    # 人: OAuth2 ログイン・セッション・CSRF
│   └── oidc/       # サービス: 受信 OIDC Bearer の検証
├── cloudlog/       # Cloud Logging 互換の slog 設定とトレース相関
├── negotiate/      # Accept による表現の選択と Vary: Accept
├── serverrole/     # web / worker / both の語彙と Parse
├── tasks/          # Cloud Tasks への型安全な投入（Generics）
└── worker/         # Cloud Tasks からの受信ハンドラー（Generics）
```

---

## 🤝 主な依存関係 (Dependencies)

* `cloud.google.com/go/cloudtasks`: Cloud Tasks 操作
* `golang.org/x/oauth2`: Google OAuth2 フロー
* `github.com/gorilla/sessions`: セッション管理の実装
* `google.golang.org/api/idtoken`: Google OIDC トークンの検証
* `github.com/shouni/go-utils`: `slogctx` によるログ属性の引き回し（`cloudlog`）

---

## 📜 ライセンス (License)

このプロジェクトは [MIT License](https://opensource.org/licenses/MIT) の下で公開されています。
