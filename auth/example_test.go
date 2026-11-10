package auth_test

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/shouni/gcp-kit/auth"
	"github.com/shouni/gcp-kit/auth/oidc"
	"github.com/shouni/gcp-kit/auth/session"
)

// Protecting a worker endpoint that accepts calls from Cloud Tasks only.
//
// The allowed service accounts are the same as tasks.Config.ServiceAccountEmail.
// Empty, verification always fails (see oidc.New for why).
//
// oidc needs no OAuth configuration, so a worker process without a web UI can
// use it, without being granted access to an OAuth secret it would never use.
func ExampleRequire() {
	// A missing setting fails at startup, not at request time.
	verifier, err := oidc.New(
		"https://worker.example.com",
		[]string{"tasks@my-project.iam.gserviceaccount.com"},
	)
	if err != nil {
		slog.Error("task verification is not configured", "error", err)
		return
	}

	worker := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if payload, ok := oidc.PayloadFromContext(r.Context()); ok {
			slog.Info("task accepted", "caller", payload.Claims["email"])
		}
		w.WriteHeader(http.StatusOK)
	})

	mux := http.NewServeMux()
	mux.Handle("POST /tasks/run", auth.Require(verifier)(worker))
}

// The setup for a route that people (browsers) and services (agents) share.
//
// A call presenting a valid OIDC Bearer token bypasses session authentication
// and CSRF verification, and everything else goes to the browser login. With
// the browser-facing method last, a request where nothing succeeded is sent to
// the login page.
func ExampleProtected() {
	handler, err := session.New(session.Config{
		ClientID:       "xxxxx.apps.googleusercontent.com",
		ClientSecret:   "secret",
		ServiceURL:     "https://app.example.com",
		SessionName:    "app-session",
		Store:          session.NewMemoryStore(),
		AllowedDomains: []string{"example.com"},
	})
	if err != nil {
		slog.Error("failed to build session handler", "error", err)
		return
	}

	verifier, err := oidc.New(
		"https://app.example.com",
		[]string{"caller@other-project.iam.gserviceaccount.com"},
	)
	if err != nil {
		slog.Error("failed to build verifier", "error", err)
		return
	}

	page := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The CSRF token is in the context only on the session path.
		_, _ = fmt.Fprintf(w, "<input name=%q value=%q>", "csrf_token", session.CSRFTokenFromContext(r.Context()))
	})

	mux := http.NewServeMux()
	mux.Handle("GET /auth/login", http.HandlerFunc(handler.Login))
	mux.Handle("GET /auth/callback", http.HandlerFunc(handler.Callback))
	mux.Handle("/private", auth.Protected(verifier, handler)(page))
}
