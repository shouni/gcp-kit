package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type samplePayload struct {
	Name string `json:"name"`
}

// newTaskRequest / newRecorder are shared helpers building a POST to the worker.
func newTaskRequest(body io.Reader) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/tasks", body)
}

func newRecorder() *httptest.ResponseRecorder {
	return httptest.NewRecorder()
}

type executorMock struct {
	called  bool
	payload samplePayload
	err     error
}

func (m *executorMock) Execute(_ context.Context, payload samplePayload) error {
	m.called = true
	m.payload = payload
	return m.err
}

func TestProcessTask_MethodNotAllowed(t *testing.T) {
	t.Parallel()

	exec := &executorMock{}
	h := NewHandler[samplePayload](exec)

	req := httptest.NewRequest(http.MethodGet, "/tasks", nil)
	rr := httptest.NewRecorder()

	h.ProcessTask(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
	if exec.called {
		t.Fatalf("executor should not be called")
	}
}

func TestProcessTask_MissingExecutor(t *testing.T) {
	t.Parallel()

	h := NewHandler[samplePayload](nil)

	req := httptest.NewRequest(http.MethodPost, "/tasks", strings.NewReader(`{"name":"alice"}`))
	rr := httptest.NewRecorder()

	h.ProcessTask(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestProcessTask_InvalidJSON(t *testing.T) {
	t.Parallel()

	exec := &executorMock{}
	h := NewHandler[samplePayload](exec)

	req := httptest.NewRequest(http.MethodPost, "/tasks", strings.NewReader("{invalid-json"))
	rr := httptest.NewRecorder()

	h.ProcessTask(rr, req)

	// Cloud Tasks redelivers on 4xx, so it stops with 2xx.
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if exec.called {
		t.Fatalf("executor should not be called")
	}
}

func TestProcessTask_ExecutorError(t *testing.T) {
	t.Parallel()

	exec := &executorMock{err: errors.New("boom")}
	h := NewHandler[samplePayload](exec)

	req := httptest.NewRequest(http.MethodPost, "/tasks", strings.NewReader(`{"name":"alice"}`))
	rr := httptest.NewRecorder()

	h.ProcessTask(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
	if !exec.called {
		t.Fatalf("executor should be called")
	}
}

func TestProcessTask_Success(t *testing.T) {
	t.Parallel()

	exec := &executorMock{}
	h := NewHandler[samplePayload](exec)

	req := httptest.NewRequest(http.MethodPost, "/tasks", strings.NewReader(`{"name":"alice"}`))
	rr := httptest.NewRecorder()

	h.ProcessTask(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if !exec.called {
		t.Fatalf("executor should be called")
	}
	if exec.payload.Name != "alice" {
		t.Fatalf("payload.Name = %q, want %q", exec.payload.Name, "alice")
	}
}

// TestProcessTask_PermanentError checks that a failure retries cannot fix is
// stopped with 2xx, keeping Cloud Tasks from resending it up to the maximum
// attempts.
// TestPermanent checks that Permanent only adds the mark and leaves the text unchanged.
func TestPermanent(t *testing.T) {
	t.Parallel()

	if Permanent(nil) != nil {
		t.Fatal("Permanent(nil) != nil")
	}

	cause := errors.New("unknown command")
	err := Permanent(cause)

	if !errors.Is(err, ErrPermanent) {
		t.Error("errors.Is(err, ErrPermanent) = false")
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is(err, cause) = false: the cause must stay reachable")
	}
	// The sentinel's wording must not leak into records or notifications.
	if got := err.Error(); got != cause.Error() {
		t.Errorf("Error() = %q, want the cause's text %q", got, cause.Error())
	}
	// The mark survives one more level of wrapping.
	if !errors.Is(fmt.Errorf("run job: %w", err), ErrPermanent) {
		t.Error("the mark must survive further wrapping")
	}
}

func TestProcessTask_PermanentError(t *testing.T) {
	t.Parallel()

	exec := &executorMock{err: Permanent(errors.New("unknown command"))}
	h := NewHandler[samplePayload](exec)

	rr := newRecorder()
	h.ServeHTTP(rr, newTaskRequest(strings.NewReader(`{"name":"alice"}`)))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (permanent failures must not be retried)", rr.Code, http.StatusOK)
	}
	if !exec.called {
		t.Fatal("executor should be called")
	}
}

func TestProcessTask_BodyTooLarge(t *testing.T) {
	t.Parallel()

	exec := &executorMock{}
	h := NewHandler[samplePayload](exec, WithMaxBodyBytes(16))

	body := fmt.Sprintf(`{"name":%q}`, strings.Repeat("a", 128))
	rr := newRecorder()
	h.ServeHTTP(rr, newTaskRequest(strings.NewReader(body)))

	// Cloud Tasks redelivers on 4xx, so it stops with 2xx.
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if exec.called {
		t.Fatal("executor should not be called")
	}
}

// The default limit matches Cloud Tasks' task size limit (1MB), so normal
// payloads are never rejected.
func TestProcessTask_DefaultBodyLimitAcceptsTypicalPayload(t *testing.T) {
	t.Parallel()

	exec := &executorMock{}
	h := NewHandler[samplePayload](exec)

	body := fmt.Sprintf(`{"name":%q}`, strings.Repeat("a", 256<<10))
	rr := newRecorder()
	h.ServeHTTP(rr, newTaskRequest(strings.NewReader(body)))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestProcessTask_StrictJSON(t *testing.T) {
	t.Parallel()

	body := `{"name":"alice","unexpected":1}`

	t.Run("lenient by default", func(t *testing.T) {
		t.Parallel()
		h := NewHandler[samplePayload](&executorMock{})
		rr := newRecorder()
		h.ServeHTTP(rr, newTaskRequest(strings.NewReader(body)))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
		}
	})

	t.Run("rejects unknown fields with WithStrictJSON", func(t *testing.T) {
		t.Parallel()
		exec := &executorMock{}
		h := NewHandler[samplePayload](exec, WithStrictJSON())
		rr := newRecorder()
		h.ServeHTTP(rr, newTaskRequest(strings.NewReader(body)))
		// Cloud Tasks redelivers on 4xx, so it stops with 2xx.
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
		}
		if exec.called {
			t.Fatal("executor should not be called")
		}
	})
}

// TestHandlerImplementsHTTPHandler guarantees it can be passed straight to a router.
func TestHandlerImplementsHTTPHandler(t *testing.T) {
	t.Parallel()

	var _ http.Handler = NewHandler[samplePayload](&executorMock{})
}
