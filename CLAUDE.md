# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

GCP Kit (`github.com/shouni/gcp-kit`) is a Go library (not a service) of three independent packages for
building Cloud Run + Cloud Tasks apps on GCP: Google OAuth2 session auth, a generic Cloud Tasks enqueuer,
and a generic Cloud Tasks worker handler. Each package is meant to be imported independently.

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

- **`auth`**: browser-facing OAuth2 login (with PKCE) + session management, CSRF protection, and two
  *inbound* verification paths: `TaskOIDCVerificationMiddleware` (verifies Cloud Tasks' own OIDC calls into
  a worker) and `M2MVerifier` (verifies OIDC Bearer tokens from other services). Both check a service-account
  allowlist through the shared `oidcVerifier`. They are deliberately decoupled from the session-based
  `Handler` flow — a service can use M2M/task verification without ever setting up OAuth2 login.
- **`tasks`**: `Enqueuer[T]` — generic, type-safe Cloud Tasks producer. Pairs with a `worker.Handler[T]` on
  the receiving service; `T` is the JSON payload contract between the two.
- **`worker`**: `Handler[T]` — generic HTTP handler (implements `http.Handler`) that decodes a JSON body into
  `T` and calls a user-supplied `TaskExecutor[T]`. Deliberately has no dependency on `tasks` or `auth` — a
  worker endpoint is typically wrapped in `auth.Handler.TaskOIDCVerificationMiddleware` at the router level,
  not internally. Executor errors wrapping `worker.ErrPermanent` return 2xx so Cloud Tasks stops retrying;
  everything else returns 500 to trigger backoff.

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

- **A verified OIDC signature does not identify the caller.** `audience` is an arbitrary string, so any
  service account in any GCP project can mint a token for it. Every inbound OIDC path therefore checks the
  `email` claim against an allowlist. Both paths (`M2MVerifier` and `Handler.TaskOIDCVerificationMiddleware`)
  share one implementation — `oidcVerifier` in `auth/oidc.go` — specifically so one can't be hardened while
  the other drifts. Don't reintroduce a second verification path.
- **`AllowedTaskServiceAccounts` is validated at construction, not per request.** Returning 403 at request
  time would make Cloud Tasks retry to exhaustion and silently drop tasks, so a missing allowlist fails in
  `NewHandler` instead.
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
