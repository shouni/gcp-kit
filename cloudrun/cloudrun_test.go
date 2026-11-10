package cloudrun_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/shouni/gcp-kit/cloudrun"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHealth(t *testing.T) {
	rec := httptest.NewRecorder()
	cloudrun.Health(rec, httptest.NewRequest(http.MethodGet, cloudrun.HealthPath, nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "ok" {
		t.Errorf("body = %q, want %q", got, "ok")
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
}

// TestHealthPath pins that /healthz, which Cloud Run's GFE swallows, is not
// chosen. It works locally and 404s once deployed, so only a test can guard it.
func TestHealthPath(t *testing.T) {
	if cloudrun.HealthPath != "/health" {
		t.Errorf("HealthPath = %q, want /health (/healthz is intercepted by the GFE on *.run.app)",
			cloudrun.HealthPath)
	}
}

func TestNewServerDefaults(t *testing.T) {
	srv := cloudrun.NewServer(cloudrun.Config{Port: "8080", Handler: http.NotFoundHandler()})

	if srv.Addr != ":8080" {
		t.Errorf("Addr = %q, want :8080", srv.Addr)
	}
	if srv.ReadHeaderTimeout != cloudrun.DefaultReadHeaderTimeout {
		t.Errorf("ReadHeaderTimeout = %v, want %v", srv.ReadHeaderTimeout, cloudrun.DefaultReadHeaderTimeout)
	}
	if srv.IdleTimeout != cloudrun.DefaultIdleTimeout {
		t.Errorf("IdleTimeout = %v, want %v", srv.IdleTimeout, cloudrun.DefaultIdleTimeout)
	}
	// A default WriteTimeout would cut a worker response that takes minutes in half.
	if srv.WriteTimeout != 0 {
		t.Errorf("WriteTimeout = %v, want 0 (no limit by default)", srv.WriteTimeout)
	}
	if srv.ReadTimeout != 0 {
		t.Errorf("ReadTimeout = %v, want 0 (no limit by default)", srv.ReadTimeout)
	}
}

func TestNewServerOverrides(t *testing.T) {
	srv := cloudrun.NewServer(cloudrun.Config{
		Port:              "9090",
		Handler:           http.NotFoundHandler(),
		ReadHeaderTimeout: time.Second,
		IdleTimeout:       2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      4 * time.Second,
	})

	for _, tt := range []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"ReadHeaderTimeout", srv.ReadHeaderTimeout, time.Second},
		{"IdleTimeout", srv.IdleTimeout, 2 * time.Second},
		{"ReadTimeout", srv.ReadTimeout, 3 * time.Second},
		{"WriteTimeout", srv.WriteTimeout, 4 * time.Second},
	} {
		if tt.got != tt.want {
			t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}

func TestServeRejectsIncompleteConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  cloudrun.Config
	}{
		{"Handler なし", cloudrun.Config{Port: "8080"}},
		{"Port なし", cloudrun.Config{Handler: http.NotFoundHandler()}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := cloudrun.Serve(context.Background(), tt.cfg); err == nil {
				t.Error("Serve = nil, want an error")
			}
		})
	}
}

// TestServeShutsDownOnContextCancel checks that the server stops and Serve
// returns once ctx is done.
func TestServeShutsDownOnContextCancel(t *testing.T) {
	ln, addr := testListener(t)
	ctx, cancel := context.WithCancel(context.Background())

	served := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- cloudrun.Serve(ctx, cloudrun.Config{
			Listener: ln,
			Logger:   discardLogger(),
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				close(served)
				w.WriteHeader(http.StatusOK)
			}),
		})
	}()

	// The listener is already open, so there is no need to wait for it to start.
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler was not reached")
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after ctx was cancelled")
	}
}

// TestServeReportsListenFailure checks that a failure to listen returns
// without waiting for ctx. Carrying on silently with the port taken would make
// a deployment fail as "started but not answering".
//
// The real trigger is a port in use, but occupying 127.0.0.1 to reproduce it
// did not fail on macOS, where binding to all interfaces still succeeded. What
// is being checked is "a listen failure comes back from Serve", so it is
// caused with an invalid port number that does not depend on OS behaviour.
func TestServeReportsListenFailure(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		done <- cloudrun.Serve(context.Background(), cloudrun.Config{
			Port:    "99999", // above 65535
			Handler: http.NotFoundHandler(),
			Logger:  discardLogger(),
		})
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("Serve = nil, want a listen failure error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after failing to listen")
	}
}

// TestServeForcesCloseOnSlowHandler checks that Serve returns even with a
// connection that does not finish within the grace period. Otherwise it would
// wait for Cloud Run's SIGKILL.
func TestServeForcesCloseOnSlowHandler(t *testing.T) {
	ln, addr := testListener(t)
	ctx, cancel := context.WithCancel(context.Background())

	handling := make(chan struct{})
	release := make(chan struct{})
	defer close(release)

	done := make(chan error, 1)
	go func() {
		done <- cloudrun.Serve(ctx, cloudrun.Config{
			Listener:        ln,
			Logger:          discardLogger(),
			ShutdownTimeout: 50 * time.Millisecond,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				close(handling)
				<-release // hold on past the grace period
				w.WriteHeader(http.StatusOK)
			}),
		})
	}()

	go func() {
		// No response comes back. The request only exists to hold a
		// connection, so it gets a timeout to give up once the test ends.
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get("http://" + addr + "/slow")
		if err == nil {
			_ = resp.Body.Close()
		}
	}()

	select {
	case <-handling:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler was not reached")
	}

	cancel()

	select {
	case err := <-done:
		// The error shows a force close happened. What matters is that it returns.
		if err == nil {
			t.Log("stopped within the grace period (the held connection was already gone)")
		} else if !errors.Is(err, context.DeadlineExceeded) {
			t.Logf("force-closed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve does not return while a connection is held")
	}
}

// testListener returns a listener opened on port 0 and its address.
//
// Serve closes the listener when it returns, so it is not closed here (avoiding a double close).
func testListener(t *testing.T) (net.Listener, string) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln, ln.Addr().String()
}

// TestServeUsesDefaultLogger checks that an unset Logger falls back to
// slog.Default(). Like the other settings, it has to work at the zero value.
func TestServeUsesDefaultLogger(t *testing.T) {
	var buf syncBuffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(restore) })

	ln, _ := testListener(t)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- cloudrun.Serve(ctx, cloudrun.Config{Listener: ln, Handler: http.NotFoundHandler()})
	}()

	// Wait for the startup log before stopping.
	deadline := time.Now().Add(5 * time.Second)
	for buf.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
	if buf.Len() == 0 {
		t.Error("nothing was written to slog.Default()")
	}
}

// TestServeReportsListenFailureBeforeLogging checks that a listen failure does
// not log "started". If it did, someone reading only the logs would think the
// server was running.
func TestServeReportsListenFailureBeforeLogging(t *testing.T) {
	var buf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(restore) })

	if err := cloudrun.Serve(context.Background(), cloudrun.Config{
		Port:    "99999",
		Handler: http.NotFoundHandler(),
	}); err == nil {
		t.Fatal("Serve = nil, want an error")
	}
	if buf.Len() != 0 {
		t.Errorf("a log line was written although listening failed: %s", buf.String())
	}
}

// syncBuffer is a buffer both the goroutine writing logs and the test reading
// them can touch. Sharing a bytes.Buffer directly would race.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
