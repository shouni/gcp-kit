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

Cloud Run や Cloud Tasks を用いたアーキテクチャにおいて、ボイラープレートになりがちな **「Google OAuth2 認証」「セッション管理」「型安全なタスク処理」** を抽象化し、ビジネスロジックに集中できる環境を提供します。

---

## ✨ 提供機能 (Features)

* **`auth`**: **Google OAuth2 認証 & セッション管理**
  * **PKCE 対応**: 認可コードの横取りに備え、`S256` チャレンジをログインフローに標準で組み込んでいます。
  * **署名(HMAC)・暗号化(AES)の分離キー設計**: セッションデータの改ざん防止と秘匿化を二重の鍵で保護します。
  * **厳格なバリデーション**: セキュリティ事故を未然に防ぐため、AESキーの長さ（16/24/32 bytes）や
    Cloud Tasks 検証の設定漏れを**起動時に**検出します。
  * **柔軟な認可**: 許可ドメインやメールアドレスによるホワイトリスト形式の認可フィルタリング機能を搭載。
  * **差し替え可能なセッションストア**: 既定は Cookie ストア。`Config.Store` に Redis 等を注入すれば、
    サーバー側でのセッション失効（確実なログアウト）にも対応できます。
  * **堅牢な CSRF 対策**:
    * **定数時間比較**: `subtle.ConstantTimeCompare` を使用し、タイミング攻撃によるトークン推測を防止します。
    * **Body-Safe 検証**: ヘッダー検証を優先することで、JSON API 等におけるリクエストボディの暗号的な二重消費（ParseFormによる消費）を回避します。
    * **URLセーフ・エンコーディング**: `base64.RawURLEncoding` を採用し、HTML属性やURLパラメータ内での取り回しを容易にしています。
  * **呼び出し元の認証**: Cloud Tasks / 他サービスからの OIDC トークンは、署名と audience だけでなく
    **サービスアカウント許可リスト**まで照合します（audience は誰でも指定できる文字列に過ぎないため）。
    `TaskOIDCVerificationMiddleware` と `M2MVerifier` は同一の検証実装を共有しています。
* **`tasks`**: **型安全な Cloud Tasks エンキュー**
  * **Generics 対応**: `[T any]` を用いて、独自の構造体を型安全にシリアライズしてキューへ投入できます。
  * **認証のカプセル化**: サービスアカウントを利用した OIDC トークンベースの認証設定をシンプルに実装。
  * **冪等なタスク投入**: `EnqueueWithName` は決定的な名前で投入し、`ALREADY_EXISTS` を成功として扱います。
  * **柔軟なオプション**: `EnqueueWithOptions` で遅延実行・応答待ち時間・追加ヘッダーを指定できます。
* **`cloudlog`**: **Cloud Logging 互換の構造化ログ**
  * **severity への詰め替え**: slog 既定の `level`/`msg` は Cloud Logging に読まれず、
    Logs Explorer 上で全エントリが INFO 扱いになります。`HandlerOptions` が
    `severity`/`message` へ詰め替えてこの差を吸収します。
  * **トレース相関**: `TraceMiddleware` が `X-Cloud-Trace-Context` を解析し、
    リクエスト単位でログをまとめます（属性の引き回しは `go-utils/slogctx` を利用）。
    context への載せ方を持たない `TraceAttrs` も公開しているため、別の仕組みで
    属性を引き回しているアプリケーションでも利用できます。
  * **出力先とレベルは持たない**: GCP に依存しない部分は意図的に持たず、
    アプリケーション側で組み立てます。
* **`worker`**: **Cloud Tasks 向け Worker ハンドラー**
  * **自動デコード**: 受信したタスクのペイロードを目的の型へ自動的にデコードし、ビジネスロジックへ渡します。
  * **リトライフレンドリー**: Cloud Tasks の標準仕様に基づき、エラー時の適切な HTTP ステータス管理を自動化。
    リトライしても直らない失敗は `worker.ErrPermanent` でラップすることで打ち切れます。
  * **配信メタデータ**: `worker.MetadataFromContext` で再試行回数やタスク名を参照でき、
    at-least-once 配信に対する冪等な処理を書けます。

---

## 🚦 使い方 (Usage)

```go
// 1. 認証ハンドラー（ブラウザログイン + Cloud Tasks 検証）
authHandler, err := auth.NewHandler(auth.Config{
    ClientID:          os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret:      os.Getenv("GOOGLE_CLIENT_SECRET"),
    RedirectURL:       serviceURL + "/auth/callback",
    SessionAuthKey:    os.Getenv("SESSION_SECRET"),        // 16バイト以上
    SessionEncryptKey: os.Getenv("SESSION_ENCRYPT_KEY"),   // 16/24/32バイト
    SessionName:       "app-session",
    IsSecureCookie:    true,
    AllowedDomains:    []string{"example.com"},

    // Cloud Tasks からの呼び出しを検証する場合、audience と許可SAの両方が必須です
    TaskAudienceURL:            serviceURL,
    AllowedTaskServiceAccounts: []string{os.Getenv("SERVICE_ACCOUNT_EMAIL")},
})

// 2. ルーティング
mux := http.NewServeMux()
mux.Handle("/auth/", authHandler.Routes())                       // login / callback / logout
mux.Handle("/private", authHandler.Middleware(privateHandler))   // セッション + CSRF
mux.Handle("POST /tasks/run",
    authHandler.TaskOIDCVerificationMiddleware(workerHandler))   // Cloud Tasks 専用

// 3. 保護されたハンドラー内では、セッションを開き直さずにユーザーを参照できます
email, ok := auth.EmailFromContext(r.Context())
```

より詳しい例は [pkg.go.dev の Example](https://pkg.go.dev/github.com/shouni/gcp-kit) を参照してください。

---

## ⚠️ v1.3.x からの移行 (Migration)

**`TaskAudienceURL` を設定しているサービスは、`AllowedTaskServiceAccounts` の追加が必須です。**

v1.3.x までの `TaskOIDCVerificationMiddleware` は audience しか検証していませんでした。audience は
署名対象に含まれるだけの単なる文字列であり、**任意の GCP プロジェクトの任意のサービスアカウントが
同じ audience のトークンを発行できる**ため、これだけでは呼び出し元を認証したことになりません。

```go
 auth.Config{
     TaskAudienceURL:            cfg.GCP.TaskAudienceURL,
+    AllowedTaskServiceAccounts: []string{cfg.GCP.ServiceAccountEmail}, // tasks.Config と同じSA
 }
```

設定漏れは **`NewHandler` が起動時にエラーを返します**（リクエスト時に 403 を返すと、Cloud Tasks が
リトライを重ねた末にタスクを破棄してしまうため）。

その他の変更点:

| 変更 | 影響 |
| --- | --- |
| ログインフローが PKCE 対応 | デプロイ中にログイン中だったユーザーは再ログインが必要 |
| IDトークンの `email_verified` を必須化 | Google の通常アカウントでは影響なし |
| `tasks.Config.Audience` が任意に（既定は `WorkerURL`） | 影響なし（後方互換） |
| `worker.Handler` が `http.Handler` を実装 | `ProcessTask` は存置。影響なし |
| リクエストボディ上限（既定 1MB） | Cloud Tasks のタスク上限と同じため影響なし |
| CSRF検証に Origin チェックを追加 | Origin が無いリクエストは従来どおり通過 |

---

## 🏗 プロジェクトレイアウト (Project Layout)

機能ごとにパッケージが独立しており、必要なコンポーネントのみをインポートして利用可能です。

```text
gcp-kit/
├── auth/           # OAuth2, Session & OIDC Verification Middleware
├── tasks/          # Cloud Tasks Enqueuer (Generics)
└── worker/         # Task Worker Handler (Generics)
```

---

## 🤝 主な依存関係 (Dependencies)

* `cloud.google.com/go/cloudtasks`: Cloud Tasks 操作
* `golang.org/x/oauth2`: Google OAuth2 フロー
* `github.com/gorilla/sessions`: セッション管理の実装
* `google.golang.org/api/idtoken`: Google OIDC トークンの検証

---

## 📜 ライセンス (License)

このプロジェクトは [MIT License](https://opensource.org/licenses/MIT) の下で公開されています。
