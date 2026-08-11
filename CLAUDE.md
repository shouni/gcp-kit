# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

GCP Kit (`github.com/shouni/gcp-kit`) is a Go library (not a service) of five independent packages for
building Cloud Run + Cloud Tasks apps on GCP: Google OAuth2 session auth plus inbound OIDC verification,
a generic Cloud Tasks enqueuer, a generic Cloud Tasks worker handler, Cloud Logging-compatible
structured logging, and the web/worker role vocabulary those deployments split on. Each package is meant
to be imported independently.

## Commands

```bash
go build ./...                  # build
go vet ./...                    # vet
gofmt -l .                      # must print nothing (CI fails otherwise)
go test ./...                   # test
go test -race ./...             # test with race detector (what CI runs)
go test ./auth/... -run TestName -v   # run a single test
go test ./... -cover            # per-package coverage summary
golangci-lint run ./...         # lint (config: .golangci.yml, pinned to v2.12.2 in CI)
govulncheck ./...               # vulnerability scan (CI runs this too)
```

CI (`.github/workflows/ci.yml`) runs three parallel jobs on every push/PR to `main`/`develop`: build+vet+gofmt+race-tests,
golangci-lint, and govulncheck. `go-version-file: go.mod` is used everywhere, so bumping the Go version only
requires editing `go.mod`.

## Architecture

### Package boundaries and why they're separate

- **`auth`**: browser-facing OAuth2 login (with PKCE) + session management + CSRF, and two *inbound*
  verification entry points: `TaskVerifier` (Cloud Tasks' own OIDC calls into a worker) and `M2MVerifier`
  (OIDC Bearer tokens from other services). Both check a service-account allowlist through the shared
  `oidcVerifier`. Neither needs OAuth2 config, so a worker-only service can verify inbound tokens without
  ever holding OAuth client secrets — `Handler` used to offer a third entry point for the same check
  (`Config.TaskAudienceURL` + `TaskOIDCVerificationMiddleware`), which forced web-only processes to carry
  worker configuration; it was removed in favour of `TaskVerifier`.
  - `Handler.ProtectedMiddleware(m2m)` composes the two worlds for a route that serves both browsers and
    services: a valid OIDC Bearer token bypasses session auth and CSRF, anything else falls back to the
    session chain. Every consuming app had written this same composition by hand — `ErrM2MNotAttempted`
    exists precisely to make that fallback expressible, so the composition itself belongs here.
  - `Handler.CSRFContextMiddleware` puts the session's CSRF token on the request context
    (`CSRFTokenFromContext`) and mints one on GET when absent. Generation is GET-only on purpose: minting
    on a state-changing request would hand a valid token to a request that arrived without one.
- **`cloudlog`**: `slog.HandlerOptions` that rename `level`/`msg` to Cloud Logging's `severity`/`message`,
  plus `TraceMiddleware` for `X-Cloud-Trace-Context` correlation. Deliberately owns nothing that is not
  GCP-specific — the output destination and level come from the application.
- **`tasks`**: `Enqueuer[T]` — generic, type-safe Cloud Tasks producer. Pairs with a `worker.Handler[T]` on
  the receiving service; `T` is the JSON payload contract between the two.
- **`serverrole`**: the `Role` vocabulary (`web` / `worker` / `both`) for deployments that run one image as
  two Cloud Run services. It holds the words and `Parse`'s strictness, nothing else — the kit never branches
  on a role, so which routes each face serves stays in the consuming app's router. Three apps had a
  byte-identical copy of this type; the reason to share it is not the duplication but the decision inside
  it (below), which is easier to keep right in one place than in three. Because `Role` is a defined string
  type and nothing here dispatches on it, an app that wants a fourth role declares its own constant and
  wraps `Parse` — no kit release needed.
- **`worker`**: `Handler[T]` — generic HTTP handler (implements `http.Handler`) that decodes a JSON body into
  `T` and calls a user-supplied `TaskExecutor[T]`. Deliberately has no dependency on `tasks` or `auth` — a
  worker endpoint is typically wrapped in `auth.TaskVerifier.Middleware` at the router level, not internally. Executor errors wrapping `worker.ErrPermanent` return 2xx so Cloud Tasks stops retrying;
  everything else returns 500 to trigger backoff.

### File layout inside `auth`

Files are named for the concern they hold, not for being a leftover bin: `auth.go` (Config/Handler
construction + allowlist normalisation), `handlers.go` (OAuth login/callback/logout), `session.go`
(session cookie, UserInfo lookup, authorization check, random tokens), `middleware.go` (session auth +
CSRF verification), `protected.go` (the M2M/session composition and CSRF context), `oidc.go` (the single
inbound token verifier + bearer extraction), `m2m.go` / `task.go` (the two entry points onto it),
`context.go` (all context keys). There is no `utils.go` — put a new helper next to what it serves.

### Conventions used throughout

- **Fail-closed by default**: empty allowlists (`auth.Handler.allowedEmails`/`allowedDomains`,
  `oidcVerifier.allowed`) deny everything rather than allow everything. Preserve this when touching
  authorization logic. `toLowerMap` drops whitespace-only entries so a list can't be "non-empty but allows
  nobody".
- **Optional config gets defaults, not errors**: `Config` fields like `LoginPath`, `SessionMaxAge`, `Store`,
  and `Logger` are zero-value-safe. Tests build `Handler{}` struct literals directly, so read these through
  the accessors (`h.LoginPath()`, `h.log()`) rather than the raw fields.
- **Config structs + `validateConfig`**: every package entry point (`auth.NewHandler`, `tasks.NewEnqueuer`)
  takes a `Config` struct and validates required fields / URL shape eagerly at construction time, not at
  first use.
- **Client interfaces for testability**: `tasks.Enqueuer` depends on an internal `taskClient` interface
  (not the concrete `*cloudtasks.Client`) specifically so tests can inject a fake via the unexported
  `newEnqueuerWithClient` constructor. `M2MVerifier.validate` is a swappable func field for the same reason.
  Follow this pattern (interface/func-field seam + unexported constructor) rather than adding mocking
  frameworks.
- **Tests live in-package** (`package auth`, not `auth_test`) and build structs like `Handler{}` or
  `M2MVerifier{}` directly via struct literals to reach unexported fields — there's no test-only exported
  constructor. Do the same for new tests rather than exporting fields just for testability.
- **`google.golang.org/grpc/status`/`codes`**: Cloud Tasks errors are matched by gRPC status code (see
  `tasks.EnqueueWithName`'s `codes.AlreadyExists` handling), not by string matching or sentinel errors from
  the client library.
- **Errors distinguish "not attempted" from "failed"**: e.g. `auth.ErrM2MNotAttempted` lets callers use
  `errors.Is` to treat "no bearer token presented" as a normal fallback path (skip logging) versus an actual
  verification failure (log it).

### Security invariants worth preserving

- **An unset server role is an error, never `both`.** `serverrole.Parse` rejects the empty string and any
  unknown value. Defaulting to `both` would put worker routes back on a publicly reachable service the
  moment one environment variable goes missing; accepting an unknown value deploys a service that serves
  nothing. Both are startup failures on purpose — this is the same fail-closed stance as the empty
  allowlists above.

- **A verified OIDC signature does not identify the caller.** `audience` is an arbitrary string, so any
  service account in any GCP project can mint a token for it. Every inbound OIDC path therefore checks the
  `email` claim against an allowlist. Both entry points (`M2MVerifier` and `TaskVerifier`) share one
  implementation — `oidcVerifier` in `auth/oidc.go` — specifically so one can't be hardened while the other
  drifts. Don't reintroduce a second verification path, and don't add a third entry point.
- **An empty allowlist means "verify nothing successfully", not "allow everyone".** `oidcVerifier.configured()`
  reports false without both an audience and a non-empty allowlist, and `TaskVerifier.Middleware` then answers
  500 rather than letting the request through. Callers check `TaskVerifier.Configured()` at startup so a
  misconfiguration surfaces before Cloud Tasks retries a task to exhaustion and drops it.
- **`email_verified` is required everywhere** an email is accepted as an identity — ID token login, UserInfo
  API fallback, and OIDC verification. `verifiedEmailFromClaims` (`auth/oidc.go`) is the single gate.
- **Redirect targets go through `isSafeRelativePath`** (`auth/middleware.go`) on both write and read. It
  rejects raw `//`-prefixed strings rather than trusting `url.Parse` (`//@/` parses to an empty host but is
  protocol-relative to browsers), plus backslashes and control characters. `FuzzIsSafeRelativePath` and
  `FuzzBuildLoginRedirectURL` guard the invariant; `auth/testdata/fuzz/` holds regression seeds.

### Testing notes

Coverage is roughly auth 92% / tasks 82% / worker 95%. The uncovered remainder in `tasks` is the thin
`*cloudtasks.Client` wrapper and `NewEnqueuer`, which need real GCP credentials.

Fuzz targets live in `auth/fuzz_test.go` and run for 20s each in CI. Run them longer when touching redirect
or header parsing: `go test ./auth/... -run '^$' -fuzz FuzzIsSafeRelativePath -fuzztime 2m`.
