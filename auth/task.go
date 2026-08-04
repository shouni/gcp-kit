package auth

import (
	"errors"
	"log/slog"
	"net/http"
)

// TaskVerifier は Cloud Tasks からの OIDC トークン検証だけを担います。
//
// Handler も同じ検証を提供しますが、あちらは OAuth ログインとセッションを前提とするため
// ClientID / ClientSecret / SessionAuthKey / SessionEncryptKey が揃わないと構築できません。
// Web UI を持たない Worker プロセスがタスクを受けるためだけにそれらを要求されると、
// 使いもしない認証情報へのアクセス権を配ることになります。TaskVerifier はその依存を切り、
// audience と許可サービスアカウントだけで検証を成立させます。
//
// 検証ロジックは Handler.TaskOIDCVerificationMiddleware と共有しており、
// 片方だけが強化される事故は起きません。
type TaskVerifier struct {
	verifier *oidcVerifier
	logger   *slog.Logger
}

// NewTaskVerifier は TaskVerifier を初期化します。allowedServiceAccounts が空の場合、
// 検証は安全側に倒して常に失敗します（fail-closed）。
func NewTaskVerifier(audience string, allowedServiceAccounts []string) *TaskVerifier {
	return &TaskVerifier{verifier: newOIDCVerifier(audience, allowedServiceAccounts)}
}

// WithLogger はログ出力先を差し替えた TaskVerifier を返します。
// 未指定の場合は slog.Default() を使います。
func (v *TaskVerifier) WithLogger(logger *slog.Logger) *TaskVerifier {
	if v == nil {
		return nil
	}
	return &TaskVerifier{verifier: v.verifier, logger: logger}
}

// Configured は、検証に必要な設定（audience と許可リスト）が揃っているかを返します。
// 呼び出し側が起動時に構成ミスへ気付けるよう公開しています。
func (v *TaskVerifier) Configured() bool {
	return v != nil && v.verifier.configured()
}

// Middleware は Cloud Tasks からの OIDC トークンを検証するミドルウェアを返します。
// 検証済みペイロードは OIDCPayloadFromContext で下流のハンドラーから参照できます。
func (v *TaskVerifier) Middleware(next http.Handler) http.Handler {
	return taskOIDCMiddleware(v.verifier, v.log(), next)
}

func (v *TaskVerifier) log() *slog.Logger {
	if v != nil && v.logger != nil {
		return v.logger
	}
	return slog.Default()
}

// taskOIDCMiddleware は Cloud Tasks 検証ミドルウェアの実体です。
// Handler と TaskVerifier の双方から呼ばれます。
func taskOIDCMiddleware(v *oidcVerifier, logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !v.configured() {
			logger.ErrorContext(r.Context(), "Task OIDC verification is not configured: "+
				"both TaskAudienceURL and AllowedTaskServiceAccounts are required")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		payload, err := v.verifyRequest(r)
		if err != nil {
			if errors.Is(err, ErrOIDCNotAttempted) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			logger.WarnContext(r.Context(), "Taskトークン検証失敗", "error", err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		logger.DebugContext(r.Context(), "Task認証成功", "sub", payload.Subject)
		next.ServeHTTP(w, r.WithContext(WithOIDCPayload(r.Context(), payload)))
	})
}
