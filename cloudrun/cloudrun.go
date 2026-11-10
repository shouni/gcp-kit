// Package cloudrun holds the parts of running an HTTP server on Cloud Run
// whose answer is the same every time: serving the health check, and looking
// after everything from startup to shutdown.
//
// The vocabulary (web / worker) lives in serverrole and logging in cloudlog.
// What is here is only "how the process takes requests and how it stops".
package cloudrun

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// HealthPath is the path the health check is served on.
//
// It is not "/healthz". On Cloud Run's default domain (*.run.app) the GFE
// treats that path as reserved and replaces the request with a generic 404
// before it reaches the container. It only shows up as "works locally, 404s
// once deployed", so the name is pinned here.
const HealthPath = "/health"

// Health is a health check handler that returns 200 and "ok".
//
// It does not look at whether dependencies are alive. A failing Cloud Run
// health check gets the whole instance replaced, so reporting a downstream
// outage here would only restart it over and over until the downstream
// recovers. It answers only that the process can respond.
func Health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// Defaults, decided by how Cloud Run behaves.
const (
	// DefaultReadHeaderTimeout is how long reading the headers may take.
	//
	// Cloud Run scales on concurrent requests, so a few connections that keep
	// trickling headers are enough to jam an instance (Slowloris). A value
	// short enough is still more than enough for a well-behaved client.
	DefaultReadHeaderTimeout = 5 * time.Second

	// DefaultIdleTimeout is the longest a keep-alive connection is held.
	DefaultIdleTimeout = 120 * time.Second

	// DefaultShutdownTimeout is the longest to wait for shutdown after SIGTERM.
	//
	// Cloud Run sends SIGKILL 10 seconds after SIGTERM (the container runtime
	// contract). With a limit at or above that, the process disappears before
	// the wait ends, so shutdown's force-close branch (cutting held
	// connections to finish) never runs in production. It is 8 seconds to
	// leave 2 seconds for the force close and the last log lines. On a
	// deployment with a longer grace period, override it with
	// Config.ShutdownTimeout.
	DefaultShutdownTimeout = 8 * time.Second
)

// Config configures Serve. Only Port and Handler are required.
type Config struct {
	// Port is the port to listen on, which Cloud Run passes in the PORT
	// environment variable. It is unused when Listener is set.
	Port string
	// Handler is the router.
	Handler http.Handler

	// Listener, when set, is used instead of listening on Port.
	//
	// It exists for tests. Passing a listener opened on port 0 starts the
	// server without the detour of finding a free port and polling until it
	// accepts connections. Since the kit owns startup and graceful shutdown,
	// making them testable is the kit's job too (otherwise an app that wants
	// to test them keeps carrying its own serve loop).
	//
	// Serve closes both a listener it opened itself and one passed here.
	Listener net.Listener

	// ReadHeaderTimeout and IdleTimeout use the defaults when 0.
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration

	// ReadTimeout and WriteTimeout are not set when 0 (no limit).
	//
	// Having no default for WriteTimeout is deliberate. Worker handlers can
	// take from minutes to tens of minutes, and a default would cut a healthy
	// response in half. The run-time limit belongs to Cloud Tasks'
	// DispatchDeadline and the app's own timeout, so nothing is bound here by
	// default.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// ShutdownTimeout is DefaultShutdownTimeout when 0.
	ShutdownTimeout time.Duration

	// Logger defaults to slog.Default().
	Logger *slog.Logger
}

// Serve starts the server, runs it until ctx is done, and then shuts it down
// gracefully.
//
// It does not subscribe to signals. Pass a ctx made with signal.NotifyContext
// or similar. What counts as a reason to stop (a signal, or a failure higher
// up) is the caller's decision.
//
//	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
//	defer stop()
//	return cloudrun.Serve(ctx, cloudrun.Config{Port: port, Handler: router})
func Serve(ctx context.Context, cfg Config) error {
	if cfg.Handler == nil {
		return errors.New("cloudrun: Handler must not be nil")
	}
	if cfg.Port == "" && cfg.Listener == nil {
		return errors.New("cloudrun: either Port or Listener is required")
	}

	ln := cfg.Listener
	if ln == nil {
		// ListenConfig is used so that ctx is honoured: if a stop arrives right
		// after startup, it can give up without waiting for the listener.
		var lc net.ListenConfig
		var err error
		if ln, err = lc.Listen(ctx, "tcp", net.JoinHostPort("", cfg.Port)); err != nil {
			return fmt.Errorf("cloudrun: cannot listen on port %s: %w", cfg.Port, err)
		}
	}

	srv := cfg.newServer()
	log := cfg.logger()

	serverErrors := make(chan error, 1)
	go func() {
		log.InfoContext(ctx, "HTTP server started", "addr", ln.Addr().String())
		// Serve closes the listener when it returns, so a passed-in listener is closed here too.
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()

	select {
	case err := <-serverErrors:
		return fmt.Errorf("cloudrun: server exited unexpectedly: %w", err)
	case <-ctx.Done():
		log.InfoContext(ctx, "received stop signal, starting graceful shutdown")
		return shutdown(srv, cfg.shutdownTimeout(), log)
	}
}

// NewServer builds the *http.Server Serve uses. It is exported so a caller
// that wants to own the lifecycle can still borrow the defaults.
func NewServer(cfg Config) *http.Server {
	return cfg.newServer()
}

func (c Config) newServer() *http.Server {
	return &http.Server{
		Addr:              net.JoinHostPort("", c.Port),
		Handler:           c.Handler,
		ReadHeaderTimeout: orDefault(c.ReadHeaderTimeout, DefaultReadHeaderTimeout),
		IdleTimeout:       orDefault(c.IdleTimeout, DefaultIdleTimeout),
		// 0 means "not set", so the values are passed through as is.
		ReadTimeout:  c.ReadTimeout,
		WriteTimeout: c.WriteTimeout,
	}
}

// shutdown force-closes the server if it does not stop within the grace
// period.
//
// Returning while Shutdown has failed leaves the process holding connections
// until Cloud Run's SIGKILL. It finishes even if that means cutting the held
// connections.
func shutdown(srv *http.Server, timeout time.Duration, log *slog.Logger) error {
	// The grace period is taken separately from the already-cancelled ctx.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.ErrorContext(ctx, "graceful shutdown failed, force-closing", "error", err)
		if closeErr := srv.Close(); closeErr != nil {
			return errors.Join(err, fmt.Errorf("cloudrun: force close failed too: %w", closeErr))
		}
		return fmt.Errorf("cloudrun: graceful shutdown failed, force-closed: %w", err)
	}

	log.InfoContext(ctx, "server stopped gracefully")
	return nil
}

func (c Config) shutdownTimeout() time.Duration {
	return orDefault(c.ShutdownTimeout, DefaultShutdownTimeout)
}

func (c Config) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

func orDefault(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}
