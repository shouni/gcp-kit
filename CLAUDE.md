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

- **`auth`**: browser-facing OAuth2 login + session management, CSRF protection, and two independent
  *inbound* verification paths: `TaskOIDCVerificationMiddleware` (verifies Cloud Tasks' own OIDC calls into
  a worker) and `M2MVerifier` (verifies OIDC Bearer tokens from other services against an allowlist). These
  two verifiers are deliberately decoupled from the session-based `Handler` flow — a service can use M2M/task
  verification without ever setting up OAuth2 login.
- **`tasks`**: `Enqueuer[T]` — generic, type-safe Cloud Tasks producer. Pairs with a `worker.Handler[T]` on
  the receiving service; `T` is the JSON payload contract between the two.
- **`worker`**: `Handler[T]` — generic HTTP handler that decodes a JSON body into `T` and calls a
  user-supplied `TaskExecutor[T]`. Deliberately has no dependency on `tasks` or `auth` — a worker endpoint is
  typically wrapped in `auth.Handler.TaskOIDCVerificationMiddleware` at the router level, not internally.

### Conventions used throughout

- **Fail-closed by default**: empty allowlists (`auth.Handler.allowedEmails`/`allowedDomains`,
  `M2MVerifier.allowed`) deny everything rather than allow everything. Preserve this when touching
  authorization logic.
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

### Known gap

The `auth` package has substantially lower test coverage than `tasks`/`worker`, concentrated in
`handlers.go` (`Login`, `Callback`, `exchangeCode`, `resolveUserEmail`, `extractEmailFromIDToken`) and the
CSRF functions in `middleware.go` (`validateCSRF`, `GenerateAndSaveCSRFToken`, `GetCSRFTokenFromSession`) —
all currently untested despite being the most security-sensitive code in the repo. When touching this area,
add tests following the existing in-package struct-literal pattern (see `utils_middleware_test.go`).
