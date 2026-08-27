package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeAuth は、結果を固定した Authenticator です。
type fakeAuth struct {
	err       error
	challenge func(w http.ResponseWriter, r *http.Request, err error)
	calls     int
}

func (f *fakeAuth) Authenticate(_ http.ResponseWriter, r *http.Request) (context.Context, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return context.WithValue(r.Context(), testCtxKey, "ok"), nil
}

// challenger は Challenger も満たす fakeAuth です。
type challenger struct{ fakeAuth }

func (c *challenger) Challenge(w http.ResponseWriter, r *http.Request, err error) {
	c.challenge(w, r, err)
}

type ctxKey int

const testCtxKey ctxKey = 0

func okHandler(reached *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	})
}

// Require は、方式が Challenger でない場合に失敗の種類を状態コードへ写します。
// 設定漏れを 401/403 に混ぜると、呼び出し元の落ち度に見えて調査が逸れます。
func TestRequireStatusMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want int
	}{
		{"成功", nil, http.StatusOK},
		{"資格情報が無い", ErrNotAttempted, http.StatusUnauthorized},
		{"検証に失敗", errors.New("bad signature"), http.StatusForbidden},
		{"方式が未設定", ErrNotConfigured, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reached := false
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)

			Require(&fakeAuth{err: tt.err})(okHandler(&reached)).ServeHTTP(rec, req)

			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			if reached != (tt.err == nil) {
				t.Fatalf("次のハンドラー到達 = %v, want %v", reached, tt.err == nil)
			}
		})
	}
}

// 方式が Challenger なら、失敗時の応答はその方式が決めます。
func TestRequireDelegatesToChallenger(t *testing.T) {
	t.Parallel()

	var gotErr error
	c := &challenger{fakeAuth{err: errors.New("nope")}}
	c.challenge = func(w http.ResponseWriter, _ *http.Request, err error) {
		gotErr = err
		w.WriteHeader(http.StatusTeapot)
	}

	rec := httptest.NewRecorder()
	reached := false
	Require(c)(okHandler(&reached)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want %d（Challenge に委ねていない）", rec.Code, http.StatusTeapot)
	}
	if gotErr == nil {
		t.Fatal("Challenge に失敗理由が渡っていない")
	}
}

func TestProtected(t *testing.T) {
	t.Parallel()

	t.Run("最初に成立した方式で通す", func(t *testing.T) {
		t.Parallel()

		first := &fakeAuth{}
		second := &fakeAuth{}
		reached := false

		rec := httptest.NewRecorder()
		Protected(first, second)(okHandler(&reached)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if !reached {
			t.Fatal("成立した方式があるのに次へ進んでいない")
		}
		if second.calls != 0 {
			t.Fatalf("後続の方式が %d 回呼ばれた, want 0", second.calls)
		}
	})

	t.Run("未着手なら次の方式を試す", func(t *testing.T) {
		t.Parallel()

		first := &fakeAuth{err: ErrNotAttempted}
		second := &fakeAuth{}
		reached := false

		rec := httptest.NewRecorder()
		Protected(first, second)(okHandler(&reached)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if !reached {
			t.Fatalf("2 番目の方式で通るはずが status = %d", rec.Code)
		}
		if second.calls != 1 {
			t.Fatalf("2 番目の方式の呼び出し = %d, want 1", second.calls)
		}
	})

	// 設定漏れはフォールバックを止めません。止めると、片方の設定を直すまで
	// 人までログインできなくなります。ただしログには残ります。
	t.Run("未設定でも次の方式へ進む", func(t *testing.T) {
		t.Parallel()

		reached := false
		rec := httptest.NewRecorder()
		Protected(&fakeAuth{err: ErrNotConfigured}, &fakeAuth{})(okHandler(&reached)).
			ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if !reached {
			t.Fatalf("未設定の方式がフォールバックを止めている status = %d", rec.Code)
		}
	})

	// 資格情報を提示していない方式しか無ければ、最後の方式が応答を決めます。
	// 人向けの方式を最後に置くと、ブラウザはログイン画面へ送られます。
	t.Run("誰も提示していなければ最後の方式が応答を決める", func(t *testing.T) {
		t.Parallel()

		last := &challenger{fakeAuth{err: errors.New("no session")}}
		last.challenge = func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusFound)
		}

		reached := false
		rec := httptest.NewRecorder()
		Protected(&fakeAuth{err: ErrNotAttempted}, last)(okHandler(&reached)).
			ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if reached {
			t.Fatal("どの方式も成立していないのに保護ルートへ到達している")
		}
		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want %d（最後の方式の Challenge）", rec.Code, http.StatusFound)
		}
	})

	// 提示したうえで落ちた方式が応答します。ここを最後の方式に答えさせると、
	// JSON を求めたエージェントに HTML のログイン画面が返ります。
	t.Run("提示して落ちた方式が応答を決める", func(t *testing.T) {
		t.Parallel()

		presented := &fakeAuth{err: errors.New("bad signature")}
		last := &challenger{fakeAuth{err: errors.New("no session")}}
		last.challenge = func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusFound)
		}

		reached := false
		rec := httptest.NewRecorder()
		Protected(presented, last)(okHandler(&reached)).
			ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if reached {
			t.Fatal("どの方式も成立していないのに保護ルートへ到達している")
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d（提示して落ちた方式の応答）", rec.Code, http.StatusForbidden)
		}
	})

	// 不正な資格情報と有効なセッションを同時に持つ呼び出しを締め出さないため、
	// 確定的な失敗があっても走査は続けます。
	t.Run("提示して落ちても、後続が成立すれば通す", func(t *testing.T) {
		t.Parallel()

		reached := false
		rec := httptest.NewRecorder()
		Protected(&fakeAuth{err: errors.New("bad signature")}, &fakeAuth{})(okHandler(&reached)).
			ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if !reached {
			t.Fatalf("後続の方式が成立しているのに拒否されている status = %d", rec.Code)
		}
	})

	// 設定漏れは確定的な失敗として扱いません。止めると、サービス側の設定を
	// 直すまで人までログインできなくなります。
	t.Run("未設定は応答役にならない", func(t *testing.T) {
		t.Parallel()

		last := &challenger{fakeAuth{err: errors.New("no session")}}
		last.challenge = func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusFound)
		}

		reached := false
		rec := httptest.NewRecorder()
		Protected(&fakeAuth{err: ErrNotConfigured}, last)(okHandler(&reached)).
			ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want %d（人向けの方式が応答すべき）", rec.Code, http.StatusFound)
		}
		_ = reached
	})

	t.Run("nil の方式は読み飛ばす", func(t *testing.T) {
		t.Parallel()

		reached := false
		rec := httptest.NewRecorder()
		Protected(nil, &fakeAuth{})(okHandler(&reached)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if !reached {
			t.Fatalf("nil を挟んだだけで通らなくなっている status = %d", rec.Code)
		}
	})

	t.Run("方式が1つも無ければ 401", func(t *testing.T) {
		t.Parallel()

		reached := false
		rec := httptest.NewRecorder()
		Protected(nil)(okHandler(&reached)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if reached {
			t.Fatal("方式が無いのに保護ルートへ到達している")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})
}
