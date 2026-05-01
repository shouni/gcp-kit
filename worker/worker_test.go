package worker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type samplePayload struct {
	Name string `json:"name"`
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

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
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
