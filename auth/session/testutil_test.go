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
	return NewMemoryStore(StoreConfig{MaxAge: time.Hour})
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

// failingStore is a Store whose Get always succeeds with a fresh session but
// whose Save always fails, used to exercise session-save error paths.
type failingStore struct{}

func (failingStore) Get(_ *http.Request, name string) (*Session, error) {
	return NewSession(name), nil
}

func (failingStore) Save(_ *http.Request, _ http.ResponseWriter, _ *Session) error {
	return errors.New("save failed")
}

// nilSessionStore is a Store whose Get always fails and returns a nil session,
// simulating an implementation that (unlike the cookie store here) doesn't
// guarantee a usable session on error.
type nilSessionStore struct{}

func (nilSessionStore) Get(_ *http.Request, _ string) (*Session, error) {
	return nil, errors.New("get failed")
}

func (nilSessionStore) Save(_ *http.Request, _ http.ResponseWriter, _ *Session) error {
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

// idStore は、サーバーサイドのセッションストア（Firestore 等）の約束を最小限まねた
// テスト用ストアです。クッキーが運ぶのは ID だけで、中身はストア側が持ちます。
// ID が空のまま Save されたら新しい ID を振ります（Store の約束）。
type idStore struct {
	saved  map[string]map[string]string
	nextID int
}

func newIDStore() *idStore {
	return &idStore{saved: map[string]map[string]string{}}
}

func (s *idStore) Get(r *http.Request, name string) (*Session, error) {
	session := NewSession(name)
	session.Options = &Options{Path: "/"}

	cookie, err := r.Cookie(name)
	if err != nil || cookie.Value == "" {
		return session, nil
	}

	session.ID = cookie.Value
	if values, ok := s.saved[cookie.Value]; ok {
		for k, v := range values {
			session.Values[k] = v
		}
		session.IsNew = false
	}
	return session, nil
}

func (s *idStore) Save(_ *http.Request, w http.ResponseWriter, session *Session) error {
	if session.ID == "" {
		s.nextID++
		session.ID = fmt.Sprintf("sid-%d", s.nextID)
	}

	values := make(map[string]string, len(session.Values))
	for k, v := range session.Values {
		values[k] = v
	}
	s.saved[session.ID] = values

	http.SetCookie(w, newCookie(session.Name(), session.ID, session.Options))
	return nil
}
