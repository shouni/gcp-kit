# ✍️ GCP Kit

[![CI](https://github.com/shouni/gcp-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/shouni/gcp-kit/actions/workflows/ci.yml)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen)](#)
[![Language](https://img.shields.io/badge/Language-Go-blue)](https://go.dev/)
[![Go Version](https://img.shields.io/github/go-mod/go-version/shouni/gcp-kit)](https://go.dev/)
[![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/shouni/gcp-kit)](https://github.com/shouni/gcp-kit/tags)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Reference](https://pkg.go.dev/badge/github.com/shouni/gcp-kit.svg)](https://pkg.go.dev/github.com/shouni/gcp-kit)

English | [日本語](README.ja.md)

## 🚀 About - Put Cloud Run and Cloud Tasks development on the fastest track

**GCP Kit** is a toolkit that takes over the boilerplate every Go service on Cloud Run writes again and again: authentication, structured logging, startup and graceful shutdown, enqueuing and receiving Cloud Tasks, and recording job status.

Response writing with `Accept` negotiation, defensive headers and the web/worker role vocabulary do not depend on GCP, so they live in
[go-serve-kit](https://github.com/shouni/go-serve-kit).

---

## ✨ Features

* **`auth`**: the contract for "who to let through as" (`Authenticator`) and its composition (standard library only)
  * People are handled by `auth/session`, services by `auth/oidc`. The two compositions differ in **whether they fall back**:
    `Require` stops as soon as its one method fails, while `Protected` tries the methods in order and lets the request through on the first that succeeds
    (a single method is fine too).
  * The full list of failure responses is under [Auth responses](#-auth-responses).
* **`auth/session`**: Google OAuth2 login (PKCE), session and CSRF
  * Access is granted by a list of domains / email addresses, and **an empty list means "deny everyone"**. The check runs on every
    request, so removing an address from the list locks it out on the spot.
  * **The session lives on the server; the cookie carries only an opaque ID.** There is nothing to sign or
    encrypt, so there are no session keys to configure. In exchange, `Logout` and revocation actually take effect.
    The store is `Config.Store` and is required (`NewFirestoreStore`, or `NewMemoryStore` for tests and local runs).
    `Store` is just `Load` / `Save` / `Delete` keyed by ID and never touches HTTP. The lifetime is
    `WithSessionMaxAge` (7 days by default).
  * **Without `WithPrompt(session.PromptSelectAccount)`, logging out does not appear to work.**
    `Logout` can only clear this app's cookie; the Google-side session remains.
* **`auth/oidc`**: verification of inbound service-to-service calls (`Verifier`)
  * The audience is a string anyone can name, so it **also checks the caller against a service account allowlist**.
    `New` returns an error unless both are given, so a missing setting stops the process at startup.
  * No OAuth configuration is needed. A worker without a web UI can verify callers without a client secret.
  * In tests, `WithValidator` swaps out signature verification so the Bearer path can be exercised end to end (there is
    no reason to use it in production).
* **`cloudlog`**: Cloud Logging-compatible structured logging
  * `NewHandler(w, level)` owns the composition (forget to wrap in `slogctx` and context attributes silently disappear).
    The destination and level are arguments, and `slog.SetDefault` is left to the caller.
  * `TraceMiddleware` parses `X-Cloud-Trace-Context` and groups log lines per request.
* **`cloudrun`**: health check, and everything from startup to graceful shutdown
  * The health check is `HealthPath` (`/health`). **`/healthz` is intercepted by the GFE on `*.run.app`.**
  * `Serve` runs until ctx is done and force-closes if shutdown does not finish within the grace period.
    For tests there is `Listener` (you can pass a port-0 listener).
  * There is no default `WriteTimeout` (a worker can take minutes). `ReadHeaderTimeout` is 5 seconds.
* **`tasks`**: Cloud Tasks enqueue (`Enqueuer[T]`)
  * Hides the OIDC token setup inside. `EnqueueWithName` enqueues under a deterministic name and treats `ALREADY_EXISTS`
    as success (this prevents duplicate *enqueues* only; duplicate *deliveries* are the worker's idempotency to handle).
  * **The delivery target is built from `WorkerURL` + `WorkerPath`.** It has to match the router's registration byte for byte
    (one trailing slash turns every task into a 404), so the kit owns the joining and normalisation.
  * **`DispatchDeadline` is the worker's effective run-time limit.** Unset, Cloud Tasks' default of 10 minutes
    is the limit, and raising Cloud Run's `timeout` does not get past it. Keep the app's own overall timeout
    shorter than this (equal is not allowed either: when both fire together, the task is redelivered with no record).
  * **`T` is a convention to match with `worker.Handler[T]`, not something the type system enforces.**
    They are separate packages, so the compiler does not tie the two together.
* **`worker`**: handler for Cloud Tasks (`Handler[T]`)
  * Errors map to status codes that follow Cloud Tasks' retry behaviour. A failure that retrying will not fix can be
    marked with `worker.Permanent(err)` to return 2xx and stop (the message stays the original cause).
  * `Lifecycle[T, R]` fixes the life of one job (Prepare → Begin → Validate → Run → Finish). The run-time limit, `Lifecycle.Timeout`, applies to Run only, and Finish (recording and notifying the outcome) is detached from the caller's ctx and always runs exactly once. A panic reaches Finish as `ErrPanicked`.
  * `MetadataFromContext` exposes the retry count and task name, so you can write idempotently against at-least-once delivery.
    The values are the headers Cloud Tasks attaches, as-is, so **confirming the caller is `auth.Require`'s job**.
  * **Decoding is lenient by default so that type skew during a rolling deploy stays survivable.** Making `WithStrictJSON`
    the default turns it into a 400, and **Cloud Tasks drops a 4xx task without retrying**.
* **`jobstatus`**: recording progress and history in Firestore (`Status` / `Store[T]` / `Recorder`)
  * The "record" alongside `tasks` (enqueue) and `worker` (receive) completes the trio.
  * **`List` pages by offset.** Firestore bills for the documents it skips too, so
    use `Latest` on screens that show only an excerpt.

---

## 🔐 Auth responses

The method whose presented credentials failed decides the response. A method that was not even presented does not get to answer.

| Situation | `auth.Protected(verifier, session)` | `auth.Require(verifier)` |
| --- | --- | --- |
| No credentials, asking for a page | 302 to the login page | 401 `WWW-Authenticate: Bearer` |
| No credentials, asking for JSON | 401 | 401 `WWW-Authenticate: Bearer` |
| Invalid token | 401 `error="invalid_token"` | Same |
| Caller not on the allowlist | 403 `error="insufficient_scope"` | Same |
| Verifier not configured | 302 / 401 (logged) | 500 |
| State change with a mismatched Origin | 403 `Invalid origin` | — |
| State change with an invalid CSRF token | 403 `Invalid CSRF token` | — |
| Session store unreachable | 503 (cookie kept) | — |

The bottom three rows never redirect. State-change checks apply only to POST / PUT / DELETE / PATCH.
Status codes follow RFC 6750, Section 3.1, and `WWW-Authenticate` is sent per RFC 9110, Section 15.5.2.
Any other unexpected failure is a 500.

---

## 🚦 Usage

These are the contents of one function, split into steps. Concatenated top to bottom, they run as is.

### 1. Letting people (browsers) in

```go
// Take a separate database for sessions from the one for job status (a database name is an
// identifier that cannot be changed later, so one name would end up not matching what it holds).
fsClient, err := firestore.NewClientWithDatabase(ctx, projectID, "sessions")

// Store only persists values. Cookie attributes and lifetime belong to the Handler.
store, err := session.NewFirestoreStore(session.FirestoreConfig{
    Client:     fsClient,
    Collection: "sessions",
})

// The redirect URL and the cookie's Secure attribute are derived from ServiceURL.
sessionHandler, err := session.New(session.Config{
    ClientID:       os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret:   os.Getenv("GOOGLE_CLIENT_SECRET"),
    ServiceURL:     serviceURL, // https://app.example.com (no path)
    SessionName:    "app-session",
    Store:          store,
    AllowedDomains: []string{"example.com"},
})
```

### 2. Letting services in

The audience and the allowed service accounts are both required. If either is missing, `New` returns an error (finding out
at request time would mean Cloud Tasks retrying over and over and then dropping the task).

```go
apiVerifier, err := oidc.New(serviceURL, allowedCallerSAs)
taskVerifier, err := oidc.New(workerURL, allowedCallerSAs)
```

On a route where machine callers are optional, pass `nil` to `auth.Protected` instead of stopping on the
error. A `nil` method is skipped.

### 3. Routing

Routes come in three shapes: only people, both people and services, or only services.

```go
mux := http.NewServeMux()
mux.HandleFunc(cloudrun.HealthPath, cloudrun.Health) // "/healthz" is intercepted by Cloud Run
mux.Handle("/auth/", sessionHandler.Routes()) // login / callback / logout (with chi: r.Handle("/auth/*", ...))

// A route only people use
mux.Handle("/private", auth.Protected(sessionHandler)(privateHandler))
// A route both people and agents use. A valid Bearer bypasses the session and CSRF,
// and everything else goes to login (because the browser-facing method is last).
mux.Handle("/api/", auth.Protected(apiVerifier, sessionHandler)(http.HandlerFunc(apiHandler)))
// A route only services use. Failures do not fall back; they stop at 401/403.
mux.Handle("POST /tasks/run", auth.Require(taskVerifier)(workerHandler))
```

### 4. Starting

Runs until ctx is done and force-closes if shutdown does not finish within the grace period.

```go
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer stop()

return cloudrun.Serve(ctx, cloudrun.Config{Port: os.Getenv("PORT"), Handler: mux})
```

For more detailed examples, see the [Examples on pkg.go.dev](https://pkg.go.dev/github.com/shouni/gcp-kit).

---

## 📦 Package Structure

```text
gcp-kit/
├── auth/           # the auth contract (Authenticator) and composition (Require / Protected)
│   ├── session/    # people: OAuth2 login, session, CSRF
│   └── oidc/       # services: verifying inbound OIDC Bearer tokens
├── cloudlog/       # Cloud Logging-compatible slog setup and trace correlation
├── cloudrun/       # serving /health, and everything from startup to graceful shutdown
├── tasks/          # enqueuing to Cloud Tasks (Enqueuer[T])
├── worker/         # receiving handler for Cloud Tasks (Handler[T])
└── jobstatus/      # recording progress and history in Firestore
```

---

## 🤝 Dependencies

* `cloud.google.com/go/cloudtasks`: Cloud Tasks operations
* `golang.org/x/oauth2`: the Google OAuth2 flow
* `cloud.google.com/go/firestore`: storing sessions and job status
* `google.golang.org/api/idtoken`: verifying Google OIDC tokens
* `github.com/shouni/go-utils`: carrying log attributes through `slogctx` (`cloudlog`)

---

## 📜 License

This project is released under the [MIT License](https://opensource.org/licenses/MIT).
