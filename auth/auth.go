// Package auth holds only the contract for "who to let a request through as"
// and the ways of composing it.
//
// The implementations live in two child packages: people (browsers) in
// auth/session, service-to-service calls in auth/oidc. Both satisfy
// Authenticator, so composing them is left to this package's Require and
// Protected.
//
//	// For a worker: a route only services call
//	r.Use(auth.Require(verifier))
//
//	// For the web: a route both people and agents call
//	r.Use(auth.Protected(verifier, handler))
//
// Dependencies run one way only, session → auth ← oidc, and this package
// itself uses the standard library alone. The point is to keep the
// composition decisions in one place: when each app writes the same assembly
// by hand, the auth paths scatter and only one of them ends up hardened.
package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
)

// Authenticator confirms who made a request, using one method.
//
// When the request carries no credentials for this method it returns
// ErrNotAttempted, so the composer tries the next method. On success it
// returns a context carrying the values downstream handlers read.
//
// It takes w because some methods need to write to the response while
// verifying (clearing a broken session cookie, for example). It never writes
// the response itself (a redirect or a 401); that is Challenge's job.
//
// Headers written here stay on the response even when verification fails.
// Protected does not stop scanning at a failed method, so they are not undone
// when a later method succeeds and returns 200. Write only what is harmless in
// that case.
type Authenticator interface {
	Authenticate(w http.ResponseWriter, r *http.Request) (context.Context, error)
}

// Challenger is an Authenticator that decides its own response when
// authentication does not succeed.
//
// What to return on failure differs by method, the way the session method
// redirects to the login page. If it is not implemented, Require and Protected
// return the default response.
type Challenger interface {
	Challenge(w http.ResponseWriter, r *http.Request, err error)
}

var (
	// ErrNotAttempted reports that the request did not even attempt this
	// method (no Bearer token, no session cookie, and so on).
	//
	// It means "not mine to handle" rather than a failure, so Protected moves
	// on to the next method and callers need not log it.
	ErrNotAttempted = errors.New("auth: no credentials for this method")

	// ErrNotConfigured reports that the method itself is not configured.
	//
	// It is kept apart from ErrNotAttempted so that a missing setting is not
	// hidden behind a fallback. Mixed together, it shows up in the confusing
	// form of "for some reason only agents get sent to the login page".
	ErrNotConfigured = errors.New("auth: authenticator is not configured")
)

// Require returns middleware that stops the request unless a confirms it.
// Use it on routes only services call (a Cloud Tasks worker, for example).
//
// If a is a Challenger, the failure response is left to it; otherwise it
// returns:
//
//   - ErrNotConfigured: 500. A missing setting is not the caller's fault
//   - ErrNotAttempted:  401. No credentials
//   - anything else:    403. Credentials were presented but did not pass
func Require(a Authenticator, opts ...Option) func(http.Handler) http.Handler {
	o := newOptions(opts)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, err := a.Authenticate(w, r)
			if err == nil {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			if errors.Is(err, ErrNotConfigured) {
				o.logger().ErrorContext(r.Context(), "authenticator is not configured", "error", err, "path", r.URL.Path)
			} else if !errors.Is(err, ErrNotAttempted) {
				o.logger().WarnContext(r.Context(), "authentication failed", "error", err, "path", r.URL.Path)
			}

			challenge(w, r, a, err)
		})
	}
}

// Protected returns middleware that tries the methods in order and lets the
// request through on the first that succeeds. Use it on routes both people and
// services call.
//
// When none succeeds, the response is decided by the method whose presented
// credentials failed. "Presented a Bearer and it did not pass" is a decisive
// failure, with nothing to hope for from the next method. Letting the last
// method answer instead sends an HTML login page to an agent that asked for
// JSON. If every method was simply not attempted, the last one answers.
//
// ErrNotConfigured alone does not count as a decisive failure. Stopping the
// fallback on a missing setting would lock even people out until the service
// configuration is fixed.
//
// The order of the methods affects the response on success too, not only when
// all fail: headers an Authenticate wrote to the response stay even if that
// method failed (scanning goes on, so there is nothing to roll back to). Put
// the browser-facing method last. With auth/session first, a call that passed
// on a Bearer while carrying a broken cookie gets a Set-Cookie deleting the
// session on its 200 response.
func Protected(first Authenticator, rest ...Authenticator) func(http.Handler) http.Handler {
	return ProtectedWith(nil, append([]Authenticator{first}, rest...)...)
}

// ProtectedWith is Protected with options.
func ProtectedWith(opts []Option, authenticators ...Authenticator) func(http.Handler) http.Handler {
	o := newOptions(opts)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// decisive is the first method that failed after credentials were
			// presented. last answers when no method was presented at all.
			var decisiveAuth, lastAuth Authenticator
			var decisiveErr, lastErr error

			for _, a := range authenticators {
				if a == nil {
					continue
				}
				ctx, err := a.Authenticate(w, r)
				if err == nil {
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}

				// Calls that never attempted the method are noise, so they are not logged.
				if !errors.Is(err, ErrNotAttempted) {
					o.logger().InfoContext(r.Context(), "authenticator did not succeed, falling back to the next one",
						"error", err, "path", r.URL.Path)
				}
				// Remember the method that was presented and failed, but keep
				// scanning, so a call holding both a bad Bearer and a valid
				// session is not locked out.
				if decisiveAuth == nil && !errors.Is(err, ErrNotAttempted) && !errors.Is(err, ErrNotConfigured) {
					decisiveAuth, decisiveErr = a, err
				}
				lastAuth, lastErr = a, err
			}

			switch {
			case decisiveAuth != nil:
				challenge(w, r, decisiveAuth, decisiveErr)
			case lastAuth != nil:
				challenge(w, r, lastAuth, lastErr)
			default:
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			}
		})
	}
}

// challenge defers to the method when it can decide the response, and returns the default otherwise.
func challenge(w http.ResponseWriter, r *http.Request, a Authenticator, err error) {
	if c, ok := a.(Challenger); ok {
		c.Challenge(w, r, err)
		return
	}

	switch {
	case errors.Is(err, ErrNotConfigured):
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	case errors.Is(err, ErrNotAttempted):
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	default:
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
	}
}

// Option adjusts the behaviour of Require and ProtectedWith.
type Option func(*options)

type options struct {
	log *slog.Logger
}

func newOptions(opts []Option) *options {
	o := &options{}
	for _, opt := range opts {
		if opt != nil {
			opt(o)
		}
	}
	return o
}

func (o *options) logger() *slog.Logger {
	if o != nil && o.log != nil {
		return o.log
	}
	return slog.Default()
}

// WithLogger sets the logger that records the composition's decisions.
// It defaults to slog.Default().
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) { o.log = logger }
}
