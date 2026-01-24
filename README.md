# ✍️ GCP Kit

[![Language](https://img.shields.io/badge/Language-Go-blue)](https://golang.org/)
[![Go Version](https://img.shields.io/github/go-mod/go-version/shouni/gcp-kit)](https://golang.org/)
[![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/shouni/gcp-kit)](https://github.com/shouni/gcp-kit/tags)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚀 概要 (About) - GCP上でのWeb開発を加速させるツールキット

---

**GCP Kit** は、Google Cloud Platform (GCP) を活用したWebアプリケーションや非同期ワーカーの開発をシンプルかつ堅牢にするためのGo言語向けライブラリ集なのだ。

Cloud Run や App Engine 上で動くWebサービスにおいて、ボイラープレートになりがちな認証、セッション管理、そして Cloud Tasks による非同期処理のハンドリングを Generics を用いて抽象化し、ビジネスロジックに集中できる環境を提供するのだ。

---

## ✨ 提供機能 (Features)

* **`auth`**: Google OAuth2 認証 & セッション管理
    * 署名用・暗号化用の分離キーによる堅牢なセッション設計。
    * 許可ドメイン・メールアドレスによる認可フィルタリングと、オープンリダイレクト対策済みミドルウェア。
* **`tasks`**: 汎用 Cloud Tasks エンキュー
    * Generics (`[T any]`) を用いて、任意の構造体を型安全にキューへ投入。
    * OIDC トークンベースの認証設定（サービスアカウント連携）をカプセル化。
* **`worker`**: Cloud Tasks 向け HTTP ハンドラー
    * 受信したタスクの自動デコードと、インターフェースによる実行ロジックの注入。
    * 失敗時の 5xx 返却による Cloud Tasks 標準リトライとのシームレスな連携。

---

## 🏗 プロジェクトレイアウト (Project Layout)

ライブラリとして各機能が独立しており、必要なものだけをインポートして利用できるのだ。

```text
gcp-kit/
├── auth/           # Google OAuth2 & Session Middleware
├── tasks/          # Cloud Tasks Enqueuer (Generics)
└── worker/         # Cloud Tasks Worker Handler (Generics)
```

---

## 🤝 依存関係 (Dependencies)

* `cloud.google.com/go/cloudtasks`: Cloud Tasks 操作
* `golang.org/x/oauth2`: Google 認証
* `github.com/gorilla/sessions`: セッション管理
* `google.golang.org/api`: IDトークンの検証など

---

## 📜 ライセンス (License)

このプロジェクトは [MIT License](https://opensource.org/licenses/MIT) の下で公開されています。

---
