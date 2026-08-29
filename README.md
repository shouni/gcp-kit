# ✍️ GCP Kit

[![CI](https://github.com/shouni/gcp-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/shouni/gcp-kit/actions/workflows/ci.yml)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen)](#)
[![Language](https://img.shields.io/badge/Language-Go-blue)](https://go.dev/)
[![Go Version](https://img.shields.io/github/go-mod/go-version/shouni/gcp-kit)](https://go.dev/)
[![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/shouni/gcp-kit)](https://github.com/shouni/gcp-kit/tags)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Reference](https://pkg.go.dev/badge/github.com/shouni/gcp-kit.svg)](https://pkg.go.dev/github.com/shouni/gcp-kit)

## 🚀 概要 (About) - Cloud Run と Cloud Tasks を使った開発を最速の軌道へ

**GCP Kit** は、Cloud Run 上の Go サービスが毎回書く定型（認証・レスポンスヘッダー・起動と正常停止・Cloud Tasks の投入と受信）を引き受けるツールキットです。

---

## ✨ 提供機能 (Features)

パッケージは独立しており、必要なものだけを import できます。ここに挙げるのは
**知らずに踏むと高くつく前提**だけです。API の詳細と個々の判断理由は各パッケージの godoc にあります。

* **`auth`**: 「誰として通すか」の契約（`Authenticator`）と合成（標準ライブラリのみ）
  * 人は `auth/session`、サービスは `auth/oidc` が実装します。合成は `Require`（サービス専用ルート）と
    `Protected`（人もサービスも来るルート）が引き受けます。
  * 落ち方の一覧は「認証の応答」を参照してください。
* **`auth/session`**: Google OAuth2 ログイン（PKCE）・セッション・CSRF
  * 許可はドメイン / メールアドレスのリストで、**空のリストは「全部拒否」です**。判定は毎リクエスト
    行うため、リストから外せばその場で締め出せます。
  * 既定は Cookie ストア。サーバー側で失効させたい場合は `WithStore` にサーバーサイドのストアを渡します。
  * **`SessionKeys` の先頭が現行の鍵で、2 つ目以降は読み出し専用の旧鍵です。** 鍵を差し替えるときは
    旧鍵を残してください。1 組しか渡さずに値を変えると、**その瞬間に全利用者が強制ログアウト**します。
    入れ替えが行き渡った後（クッキーの有効期間、既定 7 日）に旧鍵を外します。
  * **`WithPrompt(session.PromptSelectAccount)` を渡さないと、ログアウトが効いて見えません。**
    `Logout` が消せるのはこのアプリのクッキーだけで、Google 側のセッションは残るためです。
* **`auth/oidc`**: サービス間呼び出しの受信検証（`Verifier`）
  * audience は誰でも指定できる文字列なので、**サービスアカウント許可リストまで照合**します。
    両方揃わないと常に検証失敗で、設定漏れは `Configured()` が起動時に検出できます。
  * OAuth 設定は要りません。Web UI を持たない Worker が、クライアントシークレット無しで検証できます。
* **`cloudlog`**: Cloud Logging 互換の構造化ログ
  * `NewHandler(w, level)` が組み立てを持ちます（`slogctx` で包み忘れると context 属性が黙って消えます）。
    出力先とレベルは引数で受け取り、`slog.SetDefault` は呼び出し側に残します。
  * `TraceMiddleware` が `X-Cloud-Trace-Context` を解析し、リクエスト単位でログをまとめます。
* **`cloudrun`**: ヘルスチェックと、起動から正常停止まで
  * ヘルスチェックは `HealthPath`（`/health`）です。**`/healthz` は `*.run.app` の GFE が横取りします。**
  * `Serve` は ctx が終わるまで動かし、猶予内に止まらなければ強制的に閉じます。
    テストでは `Listener` にポート 0 のリスナーを渡せます（空きポートを探して接続できるまで
    待つ、という迂回が要りません）。
  * `WriteTimeout` に既定値を置きません（worker は数分かかることがあるため）。`ReadHeaderTimeout` は 5 秒です。
* **`tasks`**: 型安全な Cloud Tasks エンキュー（`Enqueuer[T]`。`T` は `worker` との契約）
  * OIDC トークンの設定を内側に隠します。`EnqueueWithName` は決定的な名前で投入し、`ALREADY_EXISTS` を
    成功として扱います（防げるのは重複した「投入」までで、重複「配信」は worker 側の冪等性が受け持ちます）。
  * **`DispatchDeadline` は「ワーカーの実行時間の実効上限」です。** 未指定だと Cloud Tasks の既定 10 分が
    上限になり、Cloud Run の `timeout` を伸ばしても超えられません。アプリ側の全体タイムアウトは
    これより短く取ってください。
* **`worker`**: Cloud Tasks 向けハンドラー（`Handler[T]`）
  * ペイロードをデコードして `TaskExecutor[T]` へ渡し、エラーを Cloud Tasks の再試行仕様に沿った
    状態コードへ写します。リトライしても直らない失敗は `worker.ErrPermanent` でラップして打ち切れます。
  * `MetadataFromContext` で再試行回数やタスク名を参照でき、at-least-once 配信に対して冪等に書けます。

---

## 🔐 認証の応答 (Auth responses)

資格情報を提示したうえで落ちた方式が応答を決めます。提示すらしていない方式には答えさせません。

| 状況 | `auth.Protected(verifier, session)` | `auth.Require(verifier)` |
| --- | --- | --- |
| 資格情報なし・ページを求めている | 302 ログイン画面へ | 401 `WWW-Authenticate: Bearer` |
| 資格情報なし・JSON を求めている | 401 | 401 `WWW-Authenticate: Bearer` |
| トークンが不正 | 401 `error="invalid_token"` | 同左 |
| 呼び出し元が許可リストに無い | 403 `error="insufficient_scope"` | 同左 |
| 検証器が未設定 | 302 / 401（ログに記録） | 500 |

状態コードは RFC 6750, Section 3.1、`WWW-Authenticate` の付与は RFC 9110, Section 15.5.2 に従います。

---

## 🚦 使い方 (Usage)

1 つの関数の中身を順に分けたものです。上から連結すればそのまま動きます。

### 1. 人（ブラウザ）を通す

```go
sessionHandler, err := session.New(session.Config{
    ClientID:          os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret:      os.Getenv("GOOGLE_CLIENT_SECRET"),
    RedirectURL:       serviceURL + "/auth/callback",
    SessionKeys: []session.SessionKey{
        // 先頭が現行の鍵。新しいセッションはこれで発行されます。
        {Auth: []byte(os.Getenv("SESSION_SECRET")), Encrypt: []byte(os.Getenv("SESSION_ENCRYPT_KEY"))},
        // 鍵の入れ替え中だけ、旧鍵を読み出し用に残します。
        // {Auth: []byte(os.Getenv("SESSION_SECRET_OLD")), Encrypt: []byte(os.Getenv("SESSION_ENCRYPT_KEY_OLD"))},
    },
    SessionName:    "app-session",
    IsSecureCookie: true,
    AllowedDomains: []string{"example.com"},
})
```

### 2. サービスを通す

audience と許可 SA は両方が必須です。片方だけでは常に検証失敗になります。

```go
apiVerifier := oidc.New(serviceURL, allowedCallerSAs)
taskVerifier := oidc.New(workerURL, allowedCallerSAs)

// 設定漏れは起動時に落とします（リクエスト時だと、Cloud Tasks がリトライを
// 重ねた末にタスクを破棄してしまいます）。
if !taskVerifier.Configured() || !apiVerifier.Configured() {
    return errors.New("OIDC verification is not configured")
}
```

### 3. ルーティング

役割は明示が必須です。未設定を `both` に落とすと、公開側に worker のルートが復活します。

```go
role, err := serverrole.Parse(os.Getenv("SERVER_ROLE")) // go-serve-kit
mux := http.NewServeMux()
mux.HandleFunc(cloudrun.HealthPath, cloudrun.Health) // "/healthz" は Cloud Run に横取りされます
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

### 4. 起動

ctx が終わるまで動かし、猶予内に止まらなければ強制的に閉じます。

```go
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer stop()

handler := secureheaders.Middleware(secureheaders.Config{ // go-serve-kit
    MediaSources: []string{"https://storage.googleapis.com"}, // 署名付き URL へ 302 する場合
})(mux)

return cloudrun.Serve(ctx, cloudrun.Config{Port: os.Getenv("PORT"), Handler: handler})
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
├── cloudrun/       # /health の公開と、起動から正常停止まで
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
