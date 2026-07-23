package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

// testCookieKey is a fixed 16-byte key used across tests to build
// sessions.NewCookieStore instances. Its value is irrelevant beyond meeting
// CookieStore's minimum key-length requirements.
const testCookieKey = "1234567890123456"

// newTestCookieStore returns a sessions.CookieStore usable in tests, backed
// by a fixed (non-secret) key pair.
func newTestCookieStore() *sessions.CookieStore {
	return sessions.NewCookieStore([]byte(testCookieKey), []byte(testCookieKey))
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

// failingStore is a sessions.Store whose Get/New always succeed with a fresh
// session but whose Save always fails, used to exercise session-save error
// paths.
type failingStore struct{}

func (s failingStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return s.New(r, name)
}

func (s failingStore) New(_ *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(s, name)
	session.Values = map[any]any{}
	return session, nil
}

func (s failingStore) Save(_ *http.Request, _ http.ResponseWriter, _ *sessions.Session) error {
	return errors.New("save failed")
}

// nilSessionStore is a sessions.Store whose Get/New always fail and return a
// nil session, simulating a third-party Store implementation that (unlike
// gorilla's own CookieStore) doesn't guarantee a usable session on error.
type nilSessionStore struct{}

func (nilSessionStore) Get(_ *http.Request, _ string) (*sessions.Session, error) {
	return nil, errors.New("get failed")
}

func (nilSessionStore) New(_ *http.Request, _ string) (*sessions.Session, error) {
	return nil, errors.New("new failed")
}

func (nilSessionStore) Save(_ *http.Request, _ http.ResponseWriter, _ *sessions.Session) error {
	return nil
}

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
