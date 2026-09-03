package session

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// newTestStore returns an in-process Store usable in tests. Nothing that sits
// above the Store interface needs Firestore to be exercised.
func newTestStore() Store {
	return NewMemoryStore()
}

// seedSession stores values under a freshly minted ID and returns the cookie a
// browser would carry for it, so a test can start from "already logged in"
// without going through IssueSession.
func seedSession(t *testing.T, store Store, name string, values map[string]string) *http.Cookie {
	t.Helper()

	id, err := newSessionID()
	if err != nil {
		t.Fatalf("newSessionID() error = %v", err)
	}
	if err := store.Save(context.Background(), id, values, time.Hour); err != nil {
		t.Fatalf("store.Save() error = %v", err)
	}
	return &http.Cookie{Name: name, Value: id}
}

// testAllowedDomains returns an allowlist admitting the user@example.com
// identity that session-seeded tests use. Middleware evaluates the allowlist on
// every request, not just at login, so any Handler that must let an
// authenticated request through needs one.
func testAllowedDomains() map[string]struct{} {
	return map[string]struct{}{"example.com": {}}
}

// newRecorderForCookies / newRequestForRoutes are thin wrappers used by tests
// that only care about the response cookies or a bare request to a path.
func newRecorderForCookies() *httptest.ResponseRecorder {
	return httptest.NewRecorder()
}

func newRequestForRoutes(method, target string) *http.Request {
	return httptest.NewRequest(method, target, nil)
}

// newRewriteContext returns a context whose oauth2.HTTPClient value routes
// every outgoing request to server, regardless of the request's original
// host. This lets code with a hardcoded external URL (e.g. Google's UserInfo
// endpoint) be exercised against a local httptest.Server.
func newRewriteContext(t *testing.T, server *httptest.Server) context.Context {
	t.Helper()

	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	httpClient := &http.Client{Transport: rewriteTransport{target: target}}
	return context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
}

// countingStore counts the reads and writes an operation makes against the
// wrapped Store. Authenticate is expected to read exactly once per request:
// against Firestore each read is a billed round trip.
type countingStore struct {
	inner   Store
	gets    int
	saves   int
	deletes int
}

func (c *countingStore) Load(ctx context.Context, id string) (map[string]string, error) {
	c.gets++
	return c.inner.Load(ctx, id)
}

func (c *countingStore) Save(ctx context.Context, id string, values map[string]string, ttl time.Duration) error {
	c.saves++
	return c.inner.Save(ctx, id, values, ttl)
}

func (c *countingStore) Delete(ctx context.Context, id string) error {
	c.deletes++
	return c.inner.Delete(ctx, id)
}

func (c *countingStore) reset() { c.gets, c.saves, c.deletes = 0, 0, 0 }

// unavailableStore is a Store that cannot reach its backing service, the way a
// Firestore store reports a transient outage.
type unavailableStore struct{}

func (unavailableStore) Load(context.Context, string) (map[string]string, error) {
	return nil, fmt.Errorf("%w: deadline exceeded", ErrStoreUnavailable)
}

func (unavailableStore) Save(context.Context, string, map[string]string, time.Duration) error {
	return fmt.Errorf("%w: deadline exceeded", ErrStoreUnavailable)
}

func (unavailableStore) Delete(context.Context, string) error {
	return fmt.Errorf("%w: deadline exceeded", ErrStoreUnavailable)
}

// brokenStore is a Store that reaches its backing service but cannot make sense
// of what it read (a stored session that no longer decodes, say). Its Delete
// records the ID it was asked to remove.
type brokenStore struct{ deleted []string }

func (*brokenStore) Load(context.Context, string) (map[string]string, error) {
	return nil, errors.New("decode stored session: unexpected shape")
}

func (*brokenStore) Save(context.Context, string, map[string]string, time.Duration) error {
	return nil
}

func (b *brokenStore) Delete(_ context.Context, id string) error {
	b.deleted = append(b.deleted, id)
	return nil
}

// seedAuthenticatedSession logs email in through the handler's own IssueSession
// and returns the cookies a browser would then carry.
func seedAuthenticatedSession(t *testing.T, h *Handler, email string) []*http.Cookie {
	t.Helper()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := h.IssueSession(rr, req, email); err != nil {
		t.Fatalf("IssueSession() error = %v", err)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("IssueSession() set no cookie")
	}
	return cookies
}

// failingStore is a Store that holds nothing and whose Save always fails, used
// to exercise session-save error paths.
type failingStore struct{}

func (failingStore) Load(context.Context, string) (map[string]string, error) {
	return nil, ErrNotFound
}

func (failingStore) Save(context.Context, string, map[string]string, time.Duration) error {
	return errors.New("save failed")
}

func (failingStore) Delete(context.Context, string) error { return nil }

// rewriteTransport redirects every outgoing request to target, preserving
// path and query, so a hardcoded external URL (e.g. Google's UserInfo
// endpoint) can be pointed at a local httptest.Server.
type rewriteTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = t.target.Scheme
	req.URL.Host = t.target.Host
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// makeUnsignedJWT builds a syntactically valid but unsigned JWT so the
// idtoken package's parsing/expiry/audience checks can be exercised without
// a network call to fetch Google's real signing keys.
func makeUnsignedJWT(claims map[string]any) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT","kid":"test"}`))
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sig := base64.RawURLEncoding.EncodeToString([]byte("signature"))
	return header + "." + payload + "." + sig
}
