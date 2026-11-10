package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestMemoryStoreRoundTrip checks that saved values read back under the same
// ID, and that the returned map is not shared with the stored one.
func TestMemoryStoreRoundTrip(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()
	values := map[string]string{DefaultUserSessionKey: "user@example.com"}

	if err := store.Save(ctx, "id-1", values, time.Hour); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	values[DefaultUserSessionKey] = "changed-after-save"

	back, err := store.Load(ctx, "id-1")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if back[DefaultUserSessionKey] != "user@example.com" {
		t.Errorf("Load() = %v, want the values as saved (a change made after saving leaked in)", back)
	}
	back[DefaultUserSessionKey] = "changed-after-load"
	if again, _ := store.Load(ctx, "id-1"); again[DefaultUserSessionKey] != "user@example.com" {
		t.Error("modifying the map Load() returned changes the stored values")
	}
}

// TestMemoryStoreNotFound checks that a missing ID is ErrNotFound. The Handler
// reads that as "nothing stored" and does not adopt the cookie's ID.
func TestMemoryStoreNotFound(t *testing.T) {
	t.Parallel()

	if _, err := NewMemoryStore().Load(context.Background(), "never-saved"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load() error = %v, want ErrNotFound", err)
	}
}

// TestMemoryStoreExpires checks that an expired stored session cannot be read.
func TestMemoryStoreExpires(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.Save(ctx, "id-1", map[string]string{"k": "v"}, time.Nanosecond); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	time.Sleep(time.Millisecond)

	if _, err := store.Load(ctx, "id-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load() error = %v, want ErrNotFound for an expired session", err)
	}
}

// TestMemoryStoreDeletes checks that Delete removes the stored session and does not fail on a missing ID.
func TestMemoryStoreDeletes(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.Save(ctx, "id-1", map[string]string{"k": "v"}, time.Hour); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if err := store.Delete(ctx, "id-1"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := store.Load(ctx, "id-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load() after Delete = %v, want ErrNotFound", err)
	}
	if err := store.Delete(ctx, "id-1"); err != nil {
		t.Fatalf("Delete() of a missing ID error = %v, want nil", err)
	}
}

// TestSessionCookieAttributes checks that the session cookie the Handler issues
// carries the defensive attributes. Losing an attribute goes unnoticed because
// everything still works: login passes with a cookie lacking HttpOnly, and
// only the defence against XSS is broken.
func TestSessionCookieAttributes(t *testing.T) {
	t.Parallel()

	h := &Handler{store: newTestStore(), sessionName: "s", isSecureCookie: true, cfgSessionMaxAge: time.Hour}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	s := newSession()
	s.values[DefaultUserSessionKey] = "user@example.com"

	if err := h.saveSession(rr, req, s); err != nil {
		t.Fatalf("saveSession() error = %v", err)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	got := cookies[0]
	if !got.HttpOnly || !got.Secure || got.SameSite != http.SameSiteLaxMode || got.Path != "/" || got.MaxAge != 3600 {
		t.Errorf("cookie attributes = %+v", got)
	}
	// The cookie carries only the opaque ID, never the contents.
	if got.Value != s.id || !isValidSessionID(got.Value) || strings.Contains(got.Value, "example.com") {
		t.Errorf("cookie value = %q (not the minted ID)", got.Value)
	}
}

// TestLoadSessionIgnoresUnknownID checks that an ID that is not stored is never
// adopted.
//
// This is the defence against session fixation. The attacker can choose the ID
// through the cookie, so adopting it would create "the victim using a session
// under the attacker's chosen ID". It is tested with a well-formed ID because
// malformed ones are dropped before Load.
func TestLoadSessionIgnoresUnknownID(t *testing.T) {
	t.Parallel()

	h := &Handler{store: newTestStore(), sessionName: "s"}
	planted, err := newSessionID()
	if err != nil {
		t.Fatalf("newSessionID() error = %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "s", Value: planted})

	s, err := h.loadSession(req)
	if err != nil {
		t.Fatalf("loadSession() error = %v", err)
	}
	if s.id != "" {
		t.Fatalf("id = %q, adopted an ID that is not stored", s.id)
	}

	// Saving assigns an ID the attacker does not know.
	rr := httptest.NewRecorder()
	if err := h.saveSession(rr, req, s); err != nil {
		t.Fatalf("saveSession() error = %v", err)
	}
	if s.id == "" || s.id == planted {
		t.Errorf("id = %q, want a new ID", s.id)
	}
}

// TestLoadSessionRejectsMalformedIDBeforeTheStore checks that a malformed ID
// never reaches the store. unavailableStore always returns an error when
// called, so returning without one means it was not called.
func TestLoadSessionRejectsMalformedIDBeforeTheStore(t *testing.T) {
	t.Parallel()

	h := &Handler{store: unavailableStore{}, sessionName: "s"}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "s", Value: "sessions/../other/doc"})

	s, err := h.loadSession(req)
	if err != nil {
		t.Fatalf("loadSession() error = %v, want nil (store not touched)", err)
	}
	if s.id != "" {
		t.Fatalf("id = %q, want empty", s.id)
	}
}

// TestIsValidSessionID checks that only IDs of the minted shape pass.
//
// The ID arrives in a cookie, so the other side decides it, and the Firestore
// store uses it as a document path. Letting "/" through would have Doc() read
// it as a subcollection path, pointing outside the intended collection.
func TestIsValidSessionID(t *testing.T) {
	t.Parallel()

	minted, err := newSessionID()
	if err != nil {
		t.Fatalf("newSessionID() error = %v", err)
	}
	if !isValidSessionID(minted) {
		t.Fatalf("minted ID %q was rejected", minted)
	}

	for _, id := range []string{
		"",
		"attacker-known-id",                   // wrong length
		minted[:len(minted)-1],                // one character short
		minted + "x",                          // one character long
		strings.Repeat("a", 42) + "/",         // a path into a subcollection
		strings.Repeat("a", 41) + "/./",       // likewise (relative path segments)
		strings.Repeat("a", 42) + ".",         // forbidden by Firestore
		strings.Repeat("_", 43),               // Firestore's reserved "__…__"
		"__" + strings.Repeat("a", 39) + "__", // likewise (right characters and length)
		strings.Repeat("a", 42) + " ",         // whitespace
		strings.Repeat("a", 42) + "\n",        // control character
		strings.Repeat("a", 42) + "\u00e3",    // non-ASCII
	} {
		if isValidSessionID(id) {
			t.Errorf("isValidSessionID(%q) = true、want false", id)
		}
	}
}

// TestNewSessionIDIsAlwaysValid checks that a minted ID always passes our own
// validation. Minting one that does not would fail that one save, and being
// random it would never reproduce.
func TestNewSessionIDIsAlwaysValid(t *testing.T) {
	t.Parallel()

	for range 1000 {
		id, err := newSessionID()
		if err != nil {
			t.Fatalf("newSessionID() error = %v", err)
		}
		if !isValidSessionID(id) {
			t.Fatalf("minted ID %q fails our own validation", id)
		}
	}
}

// TestFirestoreStoreRejectsMalformedIDBeforeTheRPC checks that a malformed ID
// never reaches Firestore. The Handler drops it earlier too, but Store is
// public API, so it checks for itself.
//
// The nil client is the check itself: proceeding to the query would panic on
// the nil reference, so if the ID ever slips through, this test fails.
func TestFirestoreStoreRejectsMalformedIDBeforeTheRPC(t *testing.T) {
	t.Parallel()

	store := &firestoreStore{collection: "sessions"}
	ctx := context.Background()

	if _, err := store.Load(ctx, "sessions/../other/doc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Load() error = %v, want ErrNotFound (same as nothing stored)", err)
	}
	if err := store.Save(ctx, "sessions/../other/doc", map[string]string{}, time.Hour); err == nil {
		t.Fatal("Save() error = nil, want error: a hand-made ID must not be written")
	}
	if err := store.Delete(ctx, "sessions/../other/doc"); err == nil {
		t.Fatal("Delete() error = nil, want error")
	}
}
