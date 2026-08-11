# ✍️ GCP Kit

[![CI](https://github.com/shouni/gcp-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/shouni/gcp-kit/actions/workflows/ci.yml)
[![Language](https://img.shields.io/badge/Language-Go-blue)](https://golang.org/)
[![Go Version](https://img.shields.io/github/go-mod/go-version/shouni/gcp-kit)](https://golang.org/)
[![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/shouni/gcp-kit)](https://github.com/shouni/gcp-kit/tags)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Reference](https://pkg.go.dev/badge/github.com/shouni/gcp-kit.svg)](https://pkg.go.dev/github.com/shouni/gcp-kit)
[![Status](https://img.shields.io/badge/Status-Completed-brightgreen)](#)

## 🚀 概要 (About) - Cloud Run と Cloud Tasks を使った開発を最速の軌道へ

**GCP Kit** は、Google Cloud Platform (GCP) を活用したWebアプリケーションや非同期ワーカーの開発をシンプルかつ堅牢にするためのGo言語向けツールキットです。

Cloud Run や Cloud Tasks を用いたアーキテクチャにおいて、ボイラープレートになりがちな **「Google OAuth2 認証とセッション管理」「Cloud Logging 互換の構造化ログ」「Web / Worker の役割判定」「型安全なタスク投入と受信」** を抽象化し、ビジネスロジックに集中できる環境を提供します。

---

## ✨ 提供機能 (Features)

パッケージは独立しており、必要なものだけを import できます。

* **`auth`**: **Google OAuth2 認証 & セッション管理**
  * **PKCE 対応**: 認可コードの横取りに備え、`S256` チャレンジを標準で組み込んでいます。
  * **署名(HMAC)・暗号化(AES)の分離キー設計**: セッションの改ざん防止と秘匿化を別の鍵で保護します。
  * **差し替え可能なセッションストア**: 既定は Cookie ストア。`Config.Store` に Redis 等を注入すれば、
    サーバー側でのセッション失効（確実なログアウト）にも対応できます。
  * **柔軟な認可**: 許可ドメイン・メールアドレスのリストで絞り込みます。空のリストは「全部拒否」です。
  * **CSRF 対策**: 定数時間比較（`subtle.ConstantTimeCompare`）でトークン推測を防ぎ、ヘッダー検証を
    優先することで JSON API のボディが `ParseForm` に読み切られるのを回避します。
  * **呼び出し元の認証**: Cloud Tasks / 他サービスからの OIDC トークンは、署名と audience だけでなく
    **サービスアカウント許可リスト**まで照合します（audience は誰でも指定できる文字列に過ぎないため）。
    入口は `TaskVerifier`（Cloud Tasks 用）と `M2MVerifier`（他サービス用）の 2 つで、検証実装は共有です。
    どちらも OAuth 設定を要求せず、設定漏れは `Configured()` で**起動時に**検出できます。
  * **二経路のルート保護**: `Handler.ProtectedMiddleware` は、有効な OIDC Bearer を提示した呼び出しに
    セッション認証と CSRF をバイパスさせ、それ以外はブラウザのログインへフォールバックさせます。
* **`cloudlog`**: **Cloud Logging 互換の構造化ログ**
  * **severity への詰め替え**: slog 既定の `level`/`msg` は Cloud Logging に読まれず、
    Logs Explorer 上で全エントリが INFO 扱いになります。`HandlerOptions` がこの差を吸収します。
  * **トレース相関**: `TraceMiddleware` が `X-Cloud-Trace-Context` を解析し、リクエスト単位で
    ログをまとめます。context への載せ方を持たない `TraceAttrs` も公開しています。
  * **出力先とレベルは持たない**: GCP に依存しない部分は意図的にアプリケーション側へ残します。
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
// 1. 認証ハンドラー（ブラウザのログインとセッション）
authHandler, err := auth.NewHandler(auth.Config{
    ClientID:          os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret:      os.Getenv("GOOGLE_CLIENT_SECRET"),
    RedirectURL:       serviceURL + "/auth/callback",
    SessionAuthKey:    os.Getenv("SESSION_SECRET"),        // 16バイト以上
    SessionEncryptKey: os.Getenv("SESSION_ENCRYPT_KEY"),   // 16/24/32バイト
    SessionName:       "app-session",
    IsSecureCookie:    true,
    AllowedDomains:    []string{"example.com"},
})

// 受信 OIDC の検証器。audience と許可SAの両方が必須です（片方だけでは常に検証失敗）。
m2mVerifier := auth.NewM2MVerifier(serviceURL, allowedCallerSAs)
taskVerifier := auth.NewTaskVerifier(workerURL, allowedCallerSAs)

// 設定漏れは起動時に落とします（リクエスト時だと、Cloud Tasks がリトライを
// 重ねた末にタスクを破棄してしまいます）。
if !taskVerifier.Configured() || !m2mVerifier.Configured() {
    return errors.New("OIDC verification is not configured")
}

// 2. ルーティング（役割は明示が必須。未設定を both に落とすと、公開側に worker のルートが復活します）
role, err := serverrole.Parse(os.Getenv("SERVER_ROLE"))
mux := http.NewServeMux()
mux.Handle("/auth/", authHandler.Routes())                       // login / callback / logout
mux.Handle("/private", authHandler.Middleware(privateHandler))   // セッション + CSRF
// ブラウザと他サービスの両方から叩かれるルートは ProtectedMiddleware 一枚で守れます
// （有効な OIDC Bearer はセッションと CSRF をバイパスし、それ以外はログインへ）
mux.Handle("/api/", authHandler.ProtectedMiddleware(m2mVerifier)(apiHandler))
if role.ServesWorker() {
    mux.Handle("POST /tasks/run",
        taskVerifier.Middleware(workerHandler))                  // Cloud Tasks 専用
}

// 3. 保護されたハンドラー内では、セッションを開き直さずにユーザーを参照できます
email, ok := auth.EmailFromContext(r.Context())
```

より詳しい例は [pkg.go.dev の Example](https://pkg.go.dev/github.com/shouni/gcp-kit) を参照してください。

---

## 🏗 プロジェクトレイアウト (Project Layout)

```text
gcp-kit/
├── auth/           # OAuth2 ログイン・セッション・CSRF と受信 OIDC の検証
├── cloudlog/       # Cloud Logging 互換の slog 設定とトレース相関
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
