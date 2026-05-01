# ✍️ GCP Kit

[![Language](https://img.shields.io/badge/Language-Go-blue)](https://golang.org/)
[![Go Version](https://img.shields.io/github/go-mod/go-version/shouni/gcp-kit)](https://golang.org/)
[![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/shouni/gcp-kit)](https://github.com/shouni/gcp-kit/tags)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status](https://img.shields.io/badge/Status-Completed-brightgreen)](#)

## 🚀 概要 (About) - Cloud Run と Cloud Tasks を使った開発を最速の軌道へ

**GCP Kit** は、Google Cloud Platform (GCP) を活用したWebアプリケーションや非同期ワーカーの開発をシンプルかつ堅牢にするためのGo言語向けツールキットです。

Cloud Run や Cloud Tasks を用いたアーキテクチャにおいて、ボイラープレートになりがちな **「Google OAuth2 認証」「セッション管理」「型安全なタスク処理」** を抽象化し、ビジネスロジックに集中できる環境を提供します。

---

## ✨ 提供機能 (Features)

* **`auth`**: **Google OAuth2 認証 & セッション管理**
  * **署名(HMAC)・暗号化(AES)の分離キー設計**: セッションデータの改ざん防止と秘匿化を二重の鍵で保護します。
  * **厳格なバリデーション**: セキュリティ事故を未然に防ぐため、AESキーの長さ（16/24/32 bytes）を起動時に自動検証します。
  * **柔軟な認可**: 許可ドメインやメールアドレスによるホワイトリスト形式の認可フィルタリング機能を搭載。
  * **堅牢な CSRF 対策**:
    * **定数時間比較**: `subtle.ConstantTimeCompare` を使用し、タイミング攻撃によるトークン推測を防止します。
    * **Body-Safe 検証**: ヘッダー検証を優先することで、JSON API 等におけるリクエストボディの暗号的な二重消費（ParseFormによる消費）を回避します。
    * **URLセーフ・エンコーディング**: `base64.RawURLEncoding` を採用し、HTML属性やURLパラメータ内での取り回しを容易にしています。
  * **OIDC 検証ミドルウェア**: Cloud Tasks からのワーカーリクエストを安全に受け入れるための OIDC トークン検証をサポート。
* **`tasks`**: **型安全な Cloud Tasks エンキュー**
  * **Generics 対応**: `[T any]` を用いて、独自の構造体を型安全にシリアライズしてキューへ投入できます。
  * **認証のカプセル化**: サービスアカウントを利用した OIDC トークンベースの認証設定をシンプルに実装。
* **`worker`**: **Cloud Tasks 向け Worker ハンドラー**
  * **自動デコード**: 受信したタスクのペイロードを目的の型へ自動的にデコードし、ビジネスロジックへ渡します。
  * **リトライフレンドリー**: Cloud Tasks の標準仕様に基づき、エラー時の適切な HTTP ステータス管理を自動化。

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

---
