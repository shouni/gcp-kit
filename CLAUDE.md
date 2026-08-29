# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

GCP Kit (`github.com/shouni/gcp-kit`) is a Go library (not a service) of seven independent packages for
building Cloud Run + Cloud Tasks apps on GCP: Google OAuth2 session auth plus inbound OIDC verification,
a generic Cloud Tasks enqueuer, a generic Cloud Tasks worker handler, Cloud Logging-compatible
structured logging, and the serving lifecycle and health path. Each package is meant to be imported
independently.

The three packages that never depended on GCP — response writing plus `Accept` negotiation, browser-facing
response headers, and the web/worker role vocabulary — now live in `github.com/shouni/go-serve-kit`
(`respond` / `secureheaders` / `serverrole`). **Neither module requires the other, in either direction**,
and that is a deliberate choice rather than an oversight: see `wantsJSON` under `auth/session`.

## Commands

```bash
go build ./...                  # build
go vet ./...                    # vet
gofmt -l .                      # must print nothing (CI fails otherwise)
go test ./...                   # test
go test -race ./...             # test with race detector (what CI runs)
go test ./auth/... -run TestName -v   # run a single test
go test ./... -cover            # per-package coverage summary
golangci-lint run ./...         # lint (config: .golangci.yml; CI uses the shared workflow's pin)
govulncheck ./...               # vulnerability scan (CI runs this too)
go run golang.org/x/exp/cmd/gorelease@latest   # what broke since the last tag, and the next version
```

CI (`.github/workflows/ci.yml`) is a thin caller of the shared `shouni/workflows/.github/workflows/go-ci.yml@v1`:
build+vet+gofmt+race-tests, golangci-lint, govulncheck, and a fuzz job. **The fuzz targets are listed by
package path in `ci.yml`** — move a fuzz test to another package and the job silently stops covering it, so
update that list in the same commit. The Go version comes from `go.mod` (currently 1.27).

**Run `gorelease` before tagging.** It compares the module against its last tag and says both what broke
and what the next version has to be. v1.12.0 shipped with `session.WithCSRFToken` unexported -- the symbol
looked unused because the count had excluded `_test.go`, and nobody saw it go until after the tag; this is
the output that would have said so. It is a release step rather than a CI job because it only means
anything at the moment the version is chosen, and because every repo here keeps `ci.yml` to the shared
workflow and nothing else.

## Architecture

### Package boundaries and why they're separate

- **`auth`**: the contract and the composition only — `Authenticator` (`Authenticate(w, r) (context.Context, error)`),
  the optional `Challenger`, the two sentinels, and `Require` / `Protected`. **Stdlib only**; the implementations
  live in the two child packages and depend on it, never the other way round. `VerifiedEmail` is here rather
  than in either child because login and service verification must apply the *same* standard to the
  `email_verified` claim — if one side loosens, that side can be used to claim someone else's address.
  - **`ErrNotAttempted` and `ErrNotConfigured` are separate on purpose.** The first means "not my caller"
    and lets `Protected` move on quietly. The second is a config error and must not hide inside a fallback:
    it surfaces as 500 under `Require`, and as a logged line under `Protected` (which still falls through,
    because stopping there would lock humans out until the service config is fixed).
  - **`Protected` lets the authenticator that was *actually attempted* answer.** A caller that presented a
    Bearer token and failed gets `oidc`'s RFC 6750 challenge; a browser that presented nothing falls through to the
    session handler's login redirect. Answering with the last one instead — which is what the old
    `ProtectedMiddleware` did — sends an HTML login page to an agent that asked for JSON.
  - Scanning continues past a decisive failure so that a caller holding both a bad token and a valid session
    is not locked out; the failure is only remembered, in case nothing else succeeds.
  - **That scan makes the order matter for successful requests too, not just failed ones.** `Authenticate`
    takes the `ResponseWriter` and some methods write to it (`session` clears a broken cookie), and those
    headers survive a later success — there is nothing to roll back to. Keep the browser-facing method
    last, or a Bearer call that also carries a stale cookie gets a `Set-Cookie` deleting it on its 200.
  - **Both challenges follow the specs rather than a house style.** `oidc` sends `WWW-Authenticate` on every
    401 (RFC 9110, Section 15.5.2 makes it a MUST — without it a client cannot learn the route takes Bearer) and
    splits `invalid_token` (401, refetch and retry) from `insufficient_scope` (403, refetching won't help),
    per RFC 6750, Section 3.1. `session` redirects only when the caller asked for a page; a JSON caller gets 401,
    because an HTML login form is not something an agent can act on. Rails, Spring Security and ASP.NET Core
    all negotiate the challenge the same way. `session`'s 401 carries no `WWW-Authenticate` — cookie auth has
    no registered scheme, and the Bearer challenge belongs to whoever accepts Bearer.
- **`auth/session`**: browser-facing OAuth2 login (with PKCE) + session + CSRF. `Handler` implements both
  `Authenticator` and `Challenger`; `Authenticate` folds in what used to be three separate middlewares
  (session auth, CSRF verification, CSRF context), and `Challenge` decides the response — a redirect when
  the session is missing or the address fell off the allowlist, **403 when Origin or CSRF verification
  failed**. Redirecting the latter would hide whether a forged request was rejected or waved through.
  - Authorization is re-evaluated on **every** request, not once at login (see the security invariants below
    for why the default `CookieStore` forces this).
  - CSRF tokens are minted on GET only. Minting on a state-changing request would hand a valid token to a
    request that arrived without one.
  - Required settings are `Config` fields; everything optional is a `With*` option, matching how
    `netarmor` and `go-http-kit` are configured.
  - **`wantsJSON` in `authenticate.go` is a deliberate copy of `go-serve-kit`'s `respond.WantsJSON`.**
    `Challenge` needs it to answer a JSON caller with 401 instead of an HTML login redirect. Taking the
    dependency for this one call site was rejected on purpose, so the two are allowed to drift — this copy
    only has to keep answering "page or JSON" for this one branch, and it must keep setting `Vary: Accept`
    (`TestChallengeMatrix` asserts it). Do not re-import go-serve-kit here to "fix" the duplication.
  - `WithCSRFToken` is exported for tests that render a template without running a full authentication
    round-trip. It looked unused when the surface was trimmed because that count excluded `_test.go`;
    six sibling test files use it. **Count test files too before unexporting something.**
- **`auth/oidc`**: inbound OIDC Bearer verification for service-to-service calls, `Verifier`. **One type,
  not two** — `TaskVerifier` and `M2MVerifier` were two wrappers over one verifier whose only difference
  was how they were composed, and that difference now lives in `Require` vs `Protected`. It requires no
  OAuth2 config, so a worker-only process verifies inbound tokens without ever holding client secrets.
  An empty allowlist is `ErrNotConfigured`, never "allow everyone".
- **`cloudlog`**: Cloud Logging-compatible `slog.HandlerOptions`, plus the trace-correlation middleware.
  slog's default `level`/`msg` keys are not the ones Cloud Logging reads (`severity`/`message`), so without
  `HandlerOptions` every entry shows as INFO in Logs Explorer and `slog.Error` never reaches a log-based
  alert. It deliberately does not choose the destination or the level — that part is not GCP-specific.
  - **`NewHandler` owns the composition order, because getting it wrong fails silently.** Drop the
    `slogctx.NewHandler` wrapper and nothing errors — `job_id` and the trace ID just stop appearing. Six
    apps were copying the same three lines, which is exactly the kind of thing a copy cannot keep right.
    `TestNewHandlerMatchesManualComposition` pins it against the hand-written form.
  - **It does not call `slog.SetDefault`.** Replacing the default logger is process-wide, so that line
    stays visible in the app's `main`.
  - **`ParseTraceContext` returns Cloud Logging's representation, not the header's.** `SPAN_ID` arrives in
    decimal (`.../1;o=1`) but `logging.googleapis.com/spanId` expects 16 hex digits, so passing the raw
    value through means span correlation silently never matches. Trace IDs are zero-padded to 32 hex digits.
  - **A trace context that isn't valid hex is dropped, never written.** The header is caller-controlled and
    Cloud Run forwards what it was handed; writing it unchecked into a reserved field lets anyone inject an
    arbitrary string or ride another request's trace.
- **`cloudrun`**: `Health` plus `Serve` — how a process takes requests and how it stops.
  - **`/healthz` is not the path.** On the default `*.run.app` domain the GFE treats it as reserved and
    answers a generic 404 before the request reaches the container. It works locally and 404s only once
    deployed, so `HealthPath` pins it and `TestHealthPath` guards it.
  - **`Health` reports the process, not its dependencies.** A failing health check gets the instance
    replaced, so reporting a downstream outage here just restarts the pod until the downstream recovers.
  - **Shutdown force-closes when the grace period runs out.** Returning while `Shutdown` is still stuck
    leaves the process holding connections until Cloud Run sends SIGKILL.
  - **No default `WriteTimeout`.** Worker handlers run for minutes; a default there cuts a healthy
    response in half. `ReadHeaderTimeout` does get one — Cloud Run scales on concurrency, so a few
    slow-header connections are enough to jam an instance.
  - It does not subscribe to signals. The caller passes a `signal.NotifyContext` ctx, so what counts as
    "time to stop" stays with the app.
  - **`Config.Listener` exists so testing the serve loop stays the kit's job.** Once starting and stopping
    moved in here, an app that wants to test its server would otherwise have to keep its own copy of the
    loop — ap-mcp did exactly that. Handing in a port-0 listener also removes the poll-until-it-answers
    dance the tests here used to need.
- **`tasks`**: `Enqueuer[T]` — Cloud Tasks enqueue with the OIDC token setup folded in, so no caller
  assembles the auth block itself. `T` is the contract with `worker`.
  - **`EnqueueWithName` treats `ALREADY_EXISTS` as success**, so a retried enqueue creates one task. That
    covers duplicate *creation* only — delivery is still at-least-once, which the worker has to handle.
  - **`DispatchDeadline` is the worker's effective run-time limit, not a wait.** Unset means Cloud Tasks'
    10-minute default, and no amount of Cloud Run `timeout` gets past it.
  - The CreateTask RPC is given its own 20s deadline because Cloud Tasks rejects a request whose deadline is
    more than 30s out, and callers naturally pass the long job-lifetime context straight in.
- **`worker`**: `Handler[T]` — generic HTTP handler (implements `http.Handler`) that decodes a JSON body into
  `T` and calls a user-supplied `TaskExecutor[T]`. Deliberately has no dependency on `tasks` or `auth` — a
  worker endpoint is typically wrapped in `auth.Require(verifier)` at the router level, not internally. Executor errors wrapping `worker.ErrPermanent` return 2xx so Cloud Tasks stops retrying;
  everything else returns 500 to trigger backoff.
  - **The pprof goroutine label goes on with `pprof.Do`, never `SetGoroutineLabels` alone.** The latter does
    not restore on return, so net/http's keep-alive connection goroutine carries the previous task's name
    into the next request — and a traceback naming the wrong task is worse than one naming none.

### File layout inside `auth`

Three packages, and the dependency runs one way only: `session` → `auth` ← `oidc`.

- `auth/`: `auth.go` (the contract and both composers), `claims.go` (the shared `email_verified` gate).
- `auth/session/`: `handler.go` (Config/Handler construction + allowlist normalisation), `options.go`
  (every optional setting), `handlers.go` (OAuth login/callback/logout), `session.go` (session cookie,
  UserInfo lookup, authorization check, random tokens), `authenticate.go` (`Authenticate` / `Challenge`
  and what they need: origin check, CSRF verification, login redirect), `context.go` (context keys).
- `auth/oidc/`: `oidc.go` (the verifier and bearer extraction), `context.go` (the payload key).

There is no `utils.go` and no `internal/` — put a new helper next to what it serves. `internal/` would be
the right tool if the public packages shared something they wanted hidden, and they do not: what `session`
and `oidc` share is `auth`, which callers legitimately use to plug in their own methods.

### Conventions used throughout

- **Fail-closed by default**: empty allowlists (`session.Handler.allowedEmails`/`allowedDomains`,
  `oidc.Verifier.allowed`) deny everything rather than allow everything. Preserve this when touching
  authorization logic. `toLowerMap` drops whitespace-only entries so a list can't be "non-empty but allows
  nobody".
- **Optional settings get defaults, not errors**: what `WithPaths`, `WithSessionMaxAge`, `WithStore` and
  `WithLogger` set is zero-value-safe. Tests build `Handler{}` struct literals directly, so read these
  through the accessors (`h.loginPath()`, `h.log()`) rather than the raw `cfg*` fields.
- **Config structs + `validateConfig`**: every package entry point (`session.New`, `tasks.NewEnqueuer`)
  takes a `Config` struct and validates required fields / URL shape eagerly at construction time, not at
  first use.
- **Client interfaces for testability**: `tasks.Enqueuer` depends on an internal `taskClient` interface
  (not the concrete `*cloudtasks.Client`) specifically so tests can inject a fake via the unexported
  `newEnqueuerWithClient` constructor. `oidc.Verifier.validate` is a swappable func field for the same reason.
  Follow this pattern (interface/func-field seam + unexported constructor) rather than adding mocking
  frameworks.
- **Tests live in-package** and build structs like `session.Handler{}` directly via struct literals to reach
  unexported fields — there's no test-only exported constructor. Do the same for new tests rather than
  exporting fields just for testability. This is also why the path accessors resolve defaults lazily: a
  struct-literal `Handler` must still behave, matching the nil/zero-value tolerance the rest of the kit has.
- **`google.golang.org/grpc/status`/`codes`**: Cloud Tasks errors are matched by gRPC status code (see
  `tasks.EnqueueWithName`'s `codes.AlreadyExists` handling), not by string matching or sentinel errors from
  the client library.
- **Errors distinguish "not attempted" from "failed"**: `auth.ErrNotAttempted` lets callers use
  `errors.Is` to treat "no bearer token presented" as a normal fallback path (skip logging) versus an actual
  verification failure (log it).

### Security invariants worth preserving

- **A verified OIDC signature does not identify the caller.** `audience` is an arbitrary string, so any
  service account in any GCP project can mint a token for it. Every inbound OIDC path therefore checks the
  `email` claim against an allowlist. There is one
  implementation — `oidc.Verifier` — specifically so one caller shape can't be hardened while the other
  drifts. Don't reintroduce a second verification path, and don't add a third entry point.
- **Authorization is evaluated per request, not once at login.** `Handler.Authenticate` re-checks
  `isAuthorized(email)` on every request, not just in `Callback`. The default `CookieStore` makes the cookie
  itself the session, so there is nothing to revoke server-side; if the allowlist were only consulted at login,
  an address removed from `AllowedEmails`/`AllowedDomains` would keep full access until the cookie expired
  (7 days by default). Re-checking is what makes the allowlist an actual eviction mechanism, and it costs one
  map lookup. `TestMiddlewareRejectsRevokedSession` guards it. Tests that drive an authenticated request
  through `Authenticate` must therefore give their `Handler` an allowlist (`testAllowedDomains()`).
- **An empty allowlist means "verify nothing successfully", not "allow everyone".** `Verifier.Configured()`
  reports false without both an audience and a non-empty allowlist, and `auth.Require` then answers
  500 rather than letting the request through. Callers check `Verifier.Configured()` at startup so a
  misconfiguration surfaces before Cloud Tasks retries a task to exhaustion and drops it.
- **`email_verified` is required everywhere** an email is accepted as an identity — ID token login, UserInfo
  API fallback, and OIDC verification. `auth.VerifiedEmail` is the single gate.
- **Redirect targets go through `isSafeRelativePath`** (`auth/session/authenticate.go`) on both write and read. It
  rejects raw `//`-prefixed strings rather than trusting `url.Parse` (`//@/` parses to an empty host but is
  protocol-relative to browsers), plus backslashes and control characters. `FuzzIsSafeRelativePath` and
  `FuzzBuildLoginRedirectURL` guard the invariant; `auth/session/testdata/fuzz/` holds regression seeds.
- **The session ID is dropped at login so the store issues a new one.** `saveSessionAndRedirect` sets
  `session.ID = ""` before saving. The default `CookieStore` has no ID and ignores it; this exists for the
  server-side store `WithStore` advertises, where the cookie carries only an ID. Keeping the ID a login
  hands an attacker who planted one a session that is now authenticated as the victim. The old entry is
  left to expire rather than deleted — it only ever held pre-login values, and deleting it would mean
  emitting two `Set-Cookie` headers for one name, which stores handle differently.
  `TestSaveSessionAndRedirectRotatesSessionID` guards it with a store that mimics the ID contract.
- **`Logout` only ends this app's session, and by default that is barely visible.** It clears the cookie
  and redirects to `loginPath()`, which is the `Login` handler, which bounces to Google — and Google, with
  the user's SSO session still live and consent already granted, approves without asking. The user flickers
  and lands back signed in. `WithPrompt(PromptSelectAccount)` is what makes logout mean something; without
  it, "log out" does not hold on a shared machine. The kit never sends the user to Google's own logout,
  which would sign them out of Gmail and everything else.
  - **It is knowingly left without CSRF protection**, checking neither the method nor a token, so a
    cross-site request can clear someone's session. Accepted: the cost is that same round trip. It cannot
    be chained into signing a victim into another account either — `Callback` still requires the state
    cookie and PKCE verifier this server issued during that browser's own `Login`. Raise it again only
    with a consequence that outweighs the churn.

### Testing notes

Coverage is roughly auth 81% / oidc 98% / session 91% / cloudlog 97% / cloudrun 94% / tasks 87% /
worker 96%. The uncovered remainder in `tasks` is the thin `*cloudtasks.Client` wrapper and
`NewEnqueuer`, which need real GCP credentials.

Fuzz targets live in `auth/session/fuzz_test.go` (`FuzzIsSafeRelativePath`, `FuzzBuildLoginRedirectURL`) and
`auth/oidc/fuzz_test.go` (`FuzzExtractBearerToken`), and run for 20s each in CI. Run them longer when
touching redirect or header parsing:
`go test ./auth/session/ -run '^$' -fuzz FuzzIsSafeRelativePath -fuzztime 2m`.
