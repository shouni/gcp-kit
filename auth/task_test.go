package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNewTaskVerifierConfigured は、TaskVerifier が OAuth 設定なしで構成でき、
// audience と許可リストの両方が揃ったときだけ有効になることを確認します。
// 許可リストが空のまま検証を通してしまうと、audience を知る誰もが
// Worker を呼べてしまうため fail-closed であることが要件です。
func TestNewTaskVerifierConfigured(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		audience string
		accounts []string
		want     bool
	}{
		{"audience と許可リストが揃えば有効", testTaskAudience, []string{testTaskAccount}, true},
		{"許可リストが空なら無効", testTaskAudience, nil, false},
		{"audience が空なら無効", "", []string{testTaskAccount}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := NewTaskVerifier(tt.audience, tt.accounts).Configured(); got != tt.want {
				t.Fatalf("Configured() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("nil レシーバーは未設定として扱う", func(t *testing.T) {
		t.Parallel()
		var v *TaskVerifier
		if v.Configured() {
			t.Fatal("nil TaskVerifier must not be configured")
		}
	})
}

// TestTaskVerifierMiddleware は、Handler 版と同じ判定を行うことを確認します。
// 両者は taskOIDCMiddleware を共有しているため、片方だけが緩むことはありません。
func TestTaskVerifierMiddleware(t *testing.T) {
	t.Parallel()

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("未設定なら 500", func(t *testing.T) {
		t.Parallel()
		v := NewTaskVerifier(testTaskAudience, nil)

		req := httptest.NewRequest(http.MethodPost, "/tasks", nil)
		rr := httptest.NewRecorder()
		v.Middleware(next).ServeHTTP(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
		}
	})

	t.Run("Bearer トークンが無ければ 401", func(t *testing.T) {
		t.Parallel()
		v := NewTaskVerifier(testTaskAudience, []string{testTaskAccount})

		req := httptest.NewRequest(http.MethodPost, "/tasks", nil)
		rr := httptest.NewRecorder()
		v.Middleware(next).ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
		}
	})

	t.Run("許可されないサービスアカウントは 403", func(t *testing.T) {
		t.Parallel()
		v := NewTaskVerifier(testTaskAudience, []string{testTaskAccount})
		v.verifier.validate = stubM2MValidate("intruder@example.iam.gserviceaccount.com", nil)

		req := httptest.NewRequest(http.MethodPost, "/tasks", nil)
		req.Header.Set("Authorization", "Bearer token")
		rr := httptest.NewRecorder()
		v.Middleware(next).ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusForbidden)
		}
	})

	t.Run("許可済みなら通過しペイロードを文脈に載せる", func(t *testing.T) {
		t.Parallel()
		v := NewTaskVerifier(testTaskAudience, []string{testTaskAccount})
		v.verifier.validate = stubM2MValidate(testTaskAccount, nil)

		var gotSubject string
		inspect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if payload, ok := OIDCPayloadFromContext(r.Context()); ok {
				gotSubject = payload.Subject
			}
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodPost, "/tasks", nil)
		req.Header.Set("Authorization", "Bearer token")
		rr := httptest.NewRecorder()
		v.Middleware(inspect).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
		}
		if gotSubject == "" {
			t.Fatal("OIDC payload was not attached to the request context")
		}
	})
}

// TestTaskVerifierWithLogger は、ロガー差し替えが元のインスタンスを壊さないことを確認します。
func TestTaskVerifierWithLogger(t *testing.T) {
	t.Parallel()

	v := NewTaskVerifier(testTaskAudience, []string{testTaskAccount})
	if got := v.WithLogger(nil); got == nil || !got.Configured() {
		t.Fatal("WithLogger must keep the verifier configured")
	}

	var nilVerifier *TaskVerifier
	if nilVerifier.WithLogger(nil) != nil {
		t.Fatal("WithLogger on a nil receiver must return nil")
	}
}
