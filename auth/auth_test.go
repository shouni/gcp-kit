package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeAuth is an Authenticator with a fixed result.
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

// challenger is a fakeAuth that also satisfies Challenger.
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

// Require maps the kind of failure to a status code when the method is not a
// Challenger. Mixing a missing setting into 401/403 makes it look like the
// caller's fault and sends the investigation the wrong way.
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
				t.Fatalf("reached next handler = %v, want %v", reached, tt.err == nil)
			}
		})
	}
}

// When the method is a Challenger, it decides the failure response.
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
		t.Fatalf("status = %d, want %d (not delegated to Challenge)", rec.Code, http.StatusTeapot)
	}
	if gotErr == nil {
		t.Fatal("Challenge did not receive the failure reason")
	}
}

func TestProtected(t *testing.T) {
	t.Parallel()

	t.Run("passes on the first method that succeeds", func(t *testing.T) {
		t.Parallel()

		first := &fakeAuth{}
		second := &fakeAuth{}
		reached := false

		rec := httptest.NewRecorder()
		Protected(first, second)(okHandler(&reached)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if !reached {
			t.Fatal("a method succeeded but the next handler was not reached")
		}
		if second.calls != 0 {
			t.Fatalf("later method called %d times, want 0", second.calls)
		}
	})

	t.Run("tries the next method when not attempted", func(t *testing.T) {
		t.Parallel()

		first := &fakeAuth{err: ErrNotAttempted}
		second := &fakeAuth{}
		reached := false

		rec := httptest.NewRecorder()
		Protected(first, second)(okHandler(&reached)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if !reached {
			t.Fatalf("expected to pass on the second method, status = %d", rec.Code)
		}
		if second.calls != 1 {
			t.Fatalf("second method calls = %d, want 1", second.calls)
		}
	})

	// A missing setting does not stop the fallback. Stopping it would lock even
	// people out until the other setting is fixed. It is still logged.
	t.Run("moves to the next method when unconfigured", func(t *testing.T) {
		t.Parallel()

		reached := false
		rec := httptest.NewRecorder()
		Protected(&fakeAuth{err: ErrNotConfigured}, &fakeAuth{})(okHandler(&reached)).
			ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if !reached {
			t.Fatalf("an unconfigured method stopped the fallback, status = %d", rec.Code)
		}
	})

	// When no method was presented with credentials, the last method decides
	// the response. With the browser-facing method last, a browser is sent to
	// the login page.
	t.Run("last method decides the response when none was presented", func(t *testing.T) {
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
			t.Fatal("reached the protected route although no method succeeded")
		}
		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want %d (the last method's Challenge)", rec.Code, http.StatusFound)
		}
	})

	// The method that was presented and failed answers. Letting the last
	// method answer here would send an HTML login page to an agent that asked
	// for JSON.
	t.Run("method that was presented and failed decides the response", func(t *testing.T) {
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
			t.Fatal("reached the protected route although no method succeeded")
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d (the response of the method that was presented and failed)", rec.Code, http.StatusForbidden)
		}
	})

	// Scanning continues past a decisive failure, so a call holding both bad
	// credentials and a valid session is not locked out.
	t.Run("passes when a later method succeeds after a failed one", func(t *testing.T) {
		t.Parallel()

		reached := false
		rec := httptest.NewRecorder()
		Protected(&fakeAuth{err: errors.New("bad signature")}, &fakeAuth{})(okHandler(&reached)).
			ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if !reached {
			t.Fatalf("rejected although a later method succeeded, status = %d", rec.Code)
		}
	})

	// A missing setting is not treated as a decisive failure. Stopping on it
	// would lock even people out until the service configuration is fixed.
	t.Run("unconfigured method does not decide the response", func(t *testing.T) {
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
			t.Fatalf("status = %d, want %d (the browser-facing method should answer)", rec.Code, http.StatusFound)
		}
		_ = reached
	})

	t.Run("skips nil methods", func(t *testing.T) {
		t.Parallel()

		reached := false
		rec := httptest.NewRecorder()
		Protected(nil, &fakeAuth{})(okHandler(&reached)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if !reached {
			t.Fatalf("a nil in the list stopped the request, status = %d", rec.Code)
		}
	})

	t.Run("401 with no methods", func(t *testing.T) {
		t.Parallel()

		reached := false
		rec := httptest.NewRecorder()
		Protected(nil)(okHandler(&reached)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		if reached {
			t.Fatal("reached the protected route with no methods")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})
}
