package session

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// FirestoreConfig configures a Store kept in Firestore.
type FirestoreConfig struct {
	// Client is a connected Firestore client (required).
	//
	// Point it at a different database from the one for job status. A
	// database name is an identifier that cannot be changed later, so sharing
	// one leaves the name not matching what it holds for one of the two uses.
	Client *firestore.Client

	// Collection is the name of the collection sessions are kept in (required).
	Collection string
}

// sessionDoc is the document form of one session. ExpiresAt is also the field
// Firestore's TTL policy reads, but deletion can be up to 24 hours late, so
// the reading side always checks the expiry too.
type sessionDoc struct {
	Values    map[string]string `firestore:"values"`
	ExpiresAt time.Time         `firestore:"expiresAt"`
}

// firestoreStore is a Store that keeps sessions in Firestore.
type firestoreStore struct {
	client     *firestore.Client
	collection string
}

// NewFirestoreStore returns a Store that keeps sessions in Firestore.
//
// Cleaning up expired documents is left to a Firestore TTL policy (on
// ExpiresAt). Without one, sessions accumulate forever: unlike cookies, stored
// sessions do not expire by themselves.
func NewFirestoreStore(cfg FirestoreConfig) (Store, error) {
	if cfg.Client == nil {
		return nil, errors.New("session: FirestoreConfig.Client must not be nil")
	}
	if strings.TrimSpace(cfg.Collection) == "" {
		return nil, errors.New("session: FirestoreConfig.Collection must not be empty")
	}
	return &firestoreStore{
		client:     cfg.Client,
		collection: strings.TrimSpace(cfg.Collection),
	}, nil
}

// OwnedFirestoreStore is a Store holding a Firestore client it opened itself,
// closed by Close. Unlike NewFirestoreStore, which takes an injected client, it
// owns the client's lifetime.
type OwnedFirestoreStore struct {
	Store
	client *firestore.Client
}

// Close closes the Firestore client it opened.
func (s *OwnedFirestoreStore) Close() error {
	if s == nil || s.client == nil {
		return nil
	}
	return s.client.Close()
}

// OpenFirestoreStore opens a Firestore client and returns a session Store on it.
//
// Every service wrote "open the client → register it in Closers → pass it to
// NewFirestoreStore" in the same twelve lines, and this is that wiring in one
// place. The result is also an io.Closer, so it can be registered in Closers
// as is. Point databaseID at a different database from the one for job status
// (see the note on FirestoreConfig.Client).
func OpenFirestoreStore(ctx context.Context, projectID, databaseID, collection string, opts ...option.ClientOption) (*OwnedFirestoreStore, error) {
	if strings.TrimSpace(databaseID) == "" {
		return nil, errors.New("session: databaseID must not be empty")
	}
	client, err := firestore.NewClientWithDatabase(ctx, projectID, databaseID, opts...)
	if err != nil {
		return nil, fmt.Errorf("session: initialize firestore client: %w", err)
	}
	store, err := NewFirestoreStore(FirestoreConfig{Client: client, Collection: collection})
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return &OwnedFirestoreStore{Store: store, client: client}, nil
}

// errForeignID is the error for an ID in a shape this implementation does not
// mint. The ID becomes a document path, so passing it on unchecked would let
// the other side choose the path (see isValidSessionID).
var errForeignID = errors.New("session: refusing a session ID that was not minted here")

func (s *firestoreStore) Load(ctx context.Context, id string) (map[string]string, error) {
	// An ID not in the minted shape is answered "not found" before asking
	// Firestore. There cannot be a stored session for it, and asking would let
	// the other side choose the path.
	if !isValidSessionID(id) {
		return nil, ErrNotFound
	}

	snap, err := s.client.Collection(s.collection).Doc(id).Get(ctx)
	if err != nil {
		switch status.Code(err) {
		case codes.NotFound, codes.InvalidArgument:
			return nil, ErrNotFound
		}
		// From here on, Firestore could not be reached (see ErrStoreUnavailable).
		return nil, fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}

	var doc sessionDoc
	if err := snap.DataTo(&doc); err != nil {
		// A stored session that was read but cannot be decoded is broken.
		// Leaving it unwrapped makes the caller clear the cookie and start
		// over.
		return nil, fmt.Errorf("session: decode stored session: %w", err)
	}
	// TTL deletion runs late, so the expiry is checked on read as well.
	if time.Now().After(doc.ExpiresAt) {
		return nil, ErrNotFound
	}
	return doc.Values, nil
}

func (s *firestoreStore) Save(ctx context.Context, id string, values map[string]string, ttl time.Duration) error {
	if !isValidSessionID(id) {
		return errForeignID
	}
	doc := sessionDoc{Values: values, ExpiresAt: time.Now().Add(ttl)}
	if _, err := s.client.Collection(s.collection).Doc(id).Set(ctx, doc); err != nil {
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	return nil
}

func (s *firestoreStore) Delete(ctx context.Context, id string) error {
	if !isValidSessionID(id) {
		return errForeignID
	}
	if _, err := s.client.Collection(s.collection).Doc(id).Delete(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, err)
	}
	return nil
}
