package session

import (
	"context"
	"encoding/base64"
	"errors"
	"maps"
	"strings"
	"sync"
	"time"
)

var (
	// ErrNotFound reports that Load found no stored session for id (never
	// saved, or expired).
	ErrNotFound = errors.New("session: not found")

	// ErrStoreUnavailable reports that the store itself could not be reached
	// (a transient Firestore outage, for example). Store implementations
	// should wrap with it only when returning that kind of failure.
	//
	// It is kept apart from a broken session because the remedies are
	// opposite. A broken stored session is fixed by the next login once the
	// cookie is cleared, but doing the same when the store is merely
	// unreachable turns a backend blip into a logout for every user at that
	// moment, and recovery does not undo it. Handler.Challenge answers it with
	// 503 and leaves the cookie alone.
	ErrStoreUnavailable = errors.New("session: session store is unavailable")
)

// Store is where sessions are kept. It only reads and writes values keyed by
// ID and never touches HTTP. Issuing and reading the cookie, and deciding
// whether to adopt an ID, are the Handler's job.
//
// The Store used to issue the cookie too, which split attributes such as
// Secure between the Handler and the Store, and put the "negative MaxAge means
// delete" convention and a copy of the Options in both implementations.
// Writing a fake needed httptest. With the responsibility narrowed to
// persisting values, these three methods are enough.
type Store interface {
	// Load returns the values for id, or ErrNotFound if missing or expired.
	//
	// When the store could not be reached, wrap the error with
	// ErrStoreUnavailable. Any other error is read as "the stored session is
	// broken", and the cookie is cleared.
	Load(ctx context.Context, id string) (map[string]string, error)

	// Save stores values under id, expiring after ttl. An existing entry is overwritten.
	Save(ctx context.Context, id string, values map[string]string, ttl time.Duration) error

	// Delete removes the stored session for id. A missing one is not an error.
	Delete(ctx context.Context, id string) error
}

// sessionIDLen is the length newSessionID returns (32 bytes as base64 RawURL, 43 characters).
const sessionIDLen = 43

// newSessionID returns an unguessable session ID. The value carries no
// content, so the only property it needs is that it cannot be guessed (32
// bytes from crypto/rand).
//
// It confirms that what it minted passes isValidSessionID before returning
// it. The chance of the random value landing on "__…__" (Firestore's reserved
// form) is about 6×10⁻⁸, but on that one occasion the save fails and the login
// is a 500, and since it never reproduces, nobody could find the cause.
func newSessionID() (string, error) {
	for range 4 {
		id, err := randomToken(base64.RawURLEncoding)
		if err != nil {
			return "", err
		}
		if isValidSessionID(id) {
			return id, nil
		}
	}
	return "", errors.New("session: could not mint a usable session ID")
}

// isValidSessionID reports whether id has a shape newSessionID can mint.
//
// The ID arrives in a cookie, so the other side decides its content. The
// Handler checks it with this before passing it to Load, and implementations
// that use the ID as a storage identifier (the Firestore store uses it as a
// document path) check it themselves too. Doc() reads a value containing "/"
// as a subcollection path, so passing one through unchecked can point outside
// the intended collection.
//
// The check is pinned to the minted shape itself (43 characters of base64
// RawURL). Admitting only the shape we produce misses less than enumerating
// each store's restrictions. At 43 characters, Firestore's ".", ".." and
// 1500-byte limit can no longer be hit.
//
// "__…__" alone cannot be excluded by length or character set, so it is
// rejected explicitly. newSessionID mints again until this check passes, so
// minting and validation cannot disagree.
func isValidSessionID(id string) bool {
	if len(id) != sessionIDLen {
		return false
	}
	if strings.HasPrefix(id, "__") && strings.HasSuffix(id, "__") {
		return false
	}
	for _, r := range id {
		if !isSessionIDChar(r) {
			return false
		}
	}
	return true
}

// isSessionIDChar is the base64 RawURL character set.
func isSessionIDChar(r rune) bool {
	return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_'
}

// memoryStore is a Store that keeps sessions in the process.
type memoryStore struct {
	mu      sync.Mutex
	entries map[string]memoryEntry
}

type memoryEntry struct {
	values    map[string]string
	expiresAt time.Time
}

// NewMemoryStore returns a Store that keeps sessions in the process.
//
// It is not usable in production. Each Cloud Run instance gets its own store,
// so users are logged out whenever the instance changes. It is for local
// development and for tests that check authenticated screens without running
// Firestore.
func NewMemoryStore() Store {
	return &memoryStore{entries: map[string]memoryEntry{}}
}

func (s *memoryStore) Load(_ context.Context, id string) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[id]
	if !ok {
		return nil, ErrNotFound
	}
	if time.Now().After(entry.expiresAt) {
		delete(s.entries, id)
		return nil, ErrNotFound
	}
	return maps.Clone(entry.values), nil
}

func (s *memoryStore) Save(_ context.Context, id string, values map[string]string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[id] = memoryEntry{
		values:    maps.Clone(values),
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

func (s *memoryStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, id)
	return nil
}
