# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

GCP Kit (`github.com/shouni/gcp-kit`) is a Go library (not a service) of eight independent packages for
building Cloud Run + Cloud Tasks apps on GCP: Google OAuth2 session auth plus inbound OIDC verification,
a generic Cloud Tasks enqueuer, a generic Cloud Tasks worker handler, Firestore-backed job status and
history, Cloud Logging-compatible structured logging, and the serving lifecycle and health path. Each
package is meant to be imported independently.

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

**Two breaking changes shipped in minor versions**, both in `auth/session` (`WithStore`'s signature, then
its removal along with `WithSessionMaxAge` and two `Config` fields). `gorelease` said v2 both times; taking
it would have rewritten the import path in 7 apps and 58 files, for API that nothing in the fleet called.
Check what actually calls the API before using this as precedent.

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
  - Authorization is re-evaluated on **every** request, not once at login. It is what evicts an address
    removed from the allowlist without having to find that person's stored session, and it costs one map
    lookup.
  - **The session lives server-side; the cookie carries an opaque ID and nothing else.** So there are no
    session keys to configure and no cookie crypto to get wrong, and `Logout`, revocation and the ID
    rotation in `issueSession` all actually take effect. `Session.Values` is `map[string]string` because
    this package stores three values, all strings.
  - **`Config.Store` is required and has no default.** An in-process default would give each Cloud Run
    instance its own sessions and would look fine in development, where there is one instance.
    `NewMemoryStore` is opt-in and says what it is for.
  - **A store must not adopt an ID it cannot find.** The ID arrives in a cookie, so it is
    attacker-controlled; writing a session under an unknown ID lets an attacker choose the victim's session
    identifier. `Get` leaves the ID empty when there is no stored session and lets `Save` mint one.
  - **Expiry is checked on read, not left to Firestore's TTL policy**, which deletes up to 24 hours late.
    The policy still has to exist, or sessions accumulate forever — unlike cookies, stored sessions do not
    expire themselves.
  - **A store that cannot be reached is not a broken session.** `ErrStoreUnavailable` splits the two
    because the right response is opposite: a stored session that no longer decodes is cleared so the next
    login replaces it, while a Firestore blip must leave the cookie alone — clearing it turns a few seconds
    of backend trouble into a logout for everyone who happened to be browsing, and recovery does not undo
    it. `Challenge` answers 503 rather than a login redirect (the login page needs the same store), so the
    outage shows up in monitoring as a failing dependency instead of as silent churn.
    `TestStoreUnavailableKeepsTheSession` and `TestBrokenSessionClearsTheCookie` pin both halves.
  - **`Authenticate` reads the store once per request.** The session it loads is carried through CSRF
    verification and token minting. Every extra read is a billed Firestore read plus a round trip on the
    hot path, and re-reading looks harmless in tests because `NewMemoryStore` costs nothing.
    `TestAuthenticateReadsStoreOnce` fixes the count.
  - **The post-login target rides in a cookie, not the session.** `/auth/login` is open to anyone, so
    stashing `redirect_to` in the session let an unauthenticated caller create a stored session per
    request — a write anyone could repeat, kept for `MaxAge`. `DefaultRedirectCookie` has the same
    lifetime and `Path` as the state and PKCE cookies, and `Login` now touches no store at all.
    `DefaultRedirectSessionKey` went with it rather than staying as a deprecated constant plus a fallback
    branch: nothing in the fleet ever sent `redirect_to` (the only producer is `Challenge`'s own login
    redirect), so the fallback would only have covered a login that started on one revision and finished
    on the next, where dropping it costs the deep link and not the login.
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
  - **`IssueSession` is `Callback`'s save without the redirect**, exported so no caller reimplements it.
    Both entry points go through one unexported `issueSession`, so the CSRF-token drop and the ID rotation
    cannot apply to one and not the other. Without it an app's tests build their own store and write
    `DefaultUserSessionKey` by hand — a copy of this package's format that keeps passing after the format
    changes. It does not verify identity (the caller's job) but does apply the allowlist.
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
  assembles the auth block itself. **`T` is a convention shared with `worker`, not something the compiler
  enforces** — the two live in separate packages (so a worker-only process does not link the Cloud Tasks
  client), so nothing stops `NewEnqueuer[A]` from being paired with `NewHandler[B]`. What `T` does buy is
  a fixed payload type inside the app. Do not "fix" this by having `worker` import `tasks`; the realistic
  failure is revision skew between the two Cloud Run services, which no type parameter can catch.
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
  - **Decoding is lenient by default and `WithStrictJSON` must not become the default.** Web and worker are
    separate Cloud Run services, so during a rolling deploy the newer side sends fields the older side does
    not know. Strict decoding answers 400, and Cloud Tasks drops a 4xx task without retrying — the skew
    stops being survivable and starts eating tasks. The option is for pinning a payload shape on purpose,
    not for catching type drift.
  - **`Metadata` is read straight off caller-controlled headers.** `MetadataFromContext` reports `ok` for
    anything that sets `X-CloudTasks-TaskName`, so it says what the request claims, not who sent it.
    Confirming the caller is `auth.Require`'s job; treat `TaskName` as an idempotency key only on a route
    that verification already covers.
  - **The pprof goroutine label goes on with `pprof.Do`, never `SetGoroutineLabels` alone.** The latter does
    not restore on return, so net/http's keep-alive connection goroutine carries the previous task's name
    into the next request — and a traceback naming the wrong task is worse than one naming none.
- **`jobstatus`**: `Status`/`Recorder`/`StatusStore` — recording an async job's progress as a Firestore
  document, and listing history by query. Completes the trio with `tasks` (enqueue) and `worker` (receive).
  It was its own module, `go-job-firestore`, until it moved here: a Firestore adapter is GCP-specific, and
  this repo's boundary rule is exactly that — the three packages that never depended on GCP were moved
  *out*, to `go-serve-kit`.
  - **The motive is the cost of listing, not atomicity.** It uses no transactions. With
    `PIPELINE_TIMEOUT < dispatch deadline <= Cloud Run timeout` holding, redelivery arrives serially, so a
    read-then-write rerun guard has no concurrent rival. What it replaces is walking a bucket prefix,
    sorting job IDs in memory, and hiding the cost behind a cache — all workarounds for having no query.
  - **It shares its name with `go-job-kit`'s `jobstatus`, deliberately.** They are two implementations of
    one concept — Firestore here, object storage there — and the fleet splits cleanly along that line: the
    apps whose artifacts live in a bucket take the go-job-kit one, the media-generation apps take this one.
    No app uses both. Same name, different import path, is what `math/rand` and `crypto/rand` do. Check
    that "no app uses both" still holds before adding a third.

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

- **The README's feature list carries only what is expensive not to know.** Signatures belong in godoc and
  reasoning belongs in this file; a bullet that restates an API is noise, and the list stops being read at
  all once it reads like a reference. This rule used to sit in the README itself, addressed to readers who
  are not the ones it constrains.

- **Fail-closed by default**: empty allowlists (`session.Handler.allowedEmails`/`allowedDomains`,
  `oidc.Verifier.allowed`) deny everything rather than allow everything. Preserve this when touching
  authorization logic. `toLowerMap` drops whitespace-only entries so a list can't be "non-empty but allows
  nobody".
- **Optional settings get defaults, not errors**: what `WithPaths`, `WithStateMaxAge` and `WithLogger` set
  is zero-value-safe. Tests build `Handler{}` struct literals directly, so read these
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
  `isAuthorized(email)` on every request, not just in `Callback`. If the allowlist were only consulted at
  login, an address removed from `AllowedEmails`/`AllowedDomains` would keep full access until the session
  expired (7 days by default) — deleting the stored session would work, but that requires knowing which one.
  Re-checking is what makes the allowlist an eviction mechanism on its own, and it costs one map lookup. `TestMiddlewareRejectsRevokedSession` guards it. Tests that drive an authenticated request
  through `Authenticate` must therefore give their `Handler` an allowlist (`testAllowedDomains()`).
- **An empty allowlist means "verify nothing successfully", not "allow everyone".** `Verifier.Configured()`
  reports false without both an audience and a non-empty allowlist, and `auth.Require` then answers
  500 rather than letting the request through. Callers check `Verifier.Configured()` at startup so a
  misconfiguration surfaces before Cloud Tasks retries a task to exhaustion and drops it.
- **`email_verified` is required everywhere** an email is accepted as an identity — ID token login, UserInfo
  API fallback, and OIDC verification. `auth.VerifiedEmail` is the single gate, and all three paths **call
  it** rather than restate it. They did not always: `fetchUserEmail` used to check `u.VerifiedEmail` on its
  own decoded struct, and had already drifted — it accepted a verified-but-empty address that the ID token
  path rejected. Restating the rule is how one side loosens. The UserInfo API spells the claim
  `verified_email` rather than `email_verified`, so that translation happens at the call site; the judgement
  does not. `TestVerifiedEmail` covers the malformed shapes (missing, string, numeric, non-string email),
  all of which must fail closed.
- **Redirect targets go through `isSafeRelativePath`** (`auth/session/authenticate.go`) on both write and read. It
  rejects raw `//`-prefixed strings rather than trusting `url.Parse` (`//@/` parses to an empty host but is
  protocol-relative to browsers), plus backslashes and control characters. `FuzzIsSafeRelativePath` and
  `FuzzBuildLoginRedirectURL` guard the invariant; `auth/session/testdata/fuzz/` holds regression seeds.
- **The session ID is dropped at login so the store issues a new one.** `saveSessionAndRedirect` sets
  `session.ID = ""` before saving, and `Save` mints a new one. Keeping the ID a login hands an attacker who
  planted one a session that is now authenticated as the victim. The old entry is
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

Coverage is roughly auth 91% / oidc 98% / session 82% / cloudlog 97% / cloudrun 94% / jobstatus 59% /
tasks 87% / worker 96%. The uncovered remainder in `tasks` is the thin `*cloudtasks.Client` wrapper and
`NewEnqueuer`, which need real GCP credentials.

**`jobstatus` sits lower than the rest for the same reason, and that is the accepted position.** What is
uncovered there is the Firestore round trip itself — `Save`/`Get`/`Delete` and the iteration inside
`collect`/`count` — while the parts that hold judgement are covered: `filteredQuery` at 100%, `paging.go`
at 94%. Unlike `tasks`, it binds the concrete `*firestore.Client` rather than an interface, because
Firestore's fluent API returns concrete types at every step and a seam would mean abstracting the whole
query builder while changing `NewStore`'s signature for five apps. Covering the round trip means the
Firestore emulator, which needs a JRE and a gcloud component locally and has nowhere to start in the
shared CI workflow (its only injection point is `apt-packages`). Nothing in the fleet runs it today. Read
the number as "the I/O is untested", not as a gap to close by accident.

Fuzz targets live in `auth/session/fuzz_test.go` (`FuzzIsSafeRelativePath`, `FuzzBuildLoginRedirectURL`) and
`auth/oidc/fuzz_test.go` (`FuzzExtractBearerToken`), and run for 20s each in CI. Run them longer when
touching redirect or header parsing:
`go test ./auth/session/ -run '^$' -fuzz FuzzIsSafeRelativePath -fuzztime 2m`.
