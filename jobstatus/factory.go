package jobstatus

import (
	"context"
	"fmt"
	"sync"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/option"
)

// ClientFactory owns the lifecycle of a Firestore client.
//
// Close and Client are safe to call concurrently.
type ClientFactory struct {
	mu     sync.RWMutex
	client *firestore.Client
	// ownsClient reports whether Close may close the client. A client
	// injected with WithClient has its lifecycle with the caller.
	ownsClient bool
}

// settings is the result of resolving the Options.
type settings struct {
	client     *firestore.Client
	projectID  string
	database   string
	clientOpts []option.ClientOption
}

// Option is a functional option that changes how a ClientFactory is built.
type Option func(*settings)

// WithClient uses an already built Firestore client.
//
// The client's lifecycle stays with the caller, and ClientFactory.Close does
// not close it (with two parties closing it, the caller could no longer tell
// which one owns it).
func WithClient(client *firestore.Client) Option {
	return func(s *settings) { s.client = client }
}

// WithProjectID sets the project to connect to. If omitted, it is detected
// from the environment (firestore.DetectProjectID).
func WithProjectID(projectID string) Option {
	return func(s *settings) { s.projectID = projectID }
}

// WithDatabase selects a Firestore database other than the default.
func WithDatabase(database string) Option {
	return func(s *settings) { s.database = database }
}

// WithClientOptions sets options passed to firestore.NewClient, for swapping
// credentials and the like.
//
// The client itself interprets FIRESTORE_EMULATOR_HOST for the emulator, so
// nothing is needed here for it.
func WithClientOptions(opts ...option.ClientOption) Option {
	return func(s *settings) { s.clientOpts = append(s.clientOpts, opts...) }
}

// New creates a ClientFactory.
func New(ctx context.Context, opts ...Option) (*ClientFactory, error) {
	cfg := settings{projectID: firestore.DetectProjectID}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	if cfg.client != nil {
		return &ClientFactory{client: cfg.client, ownsClient: false}, nil
	}

	var (
		client *firestore.Client
		err    error
	)
	if cfg.database == "" {
		client, err = firestore.NewClient(ctx, cfg.projectID, cfg.clientOpts...)
	} else {
		client, err = firestore.NewClientWithDatabase(ctx, cfg.projectID, cfg.database, cfg.clientOpts...)
	}
	if err != nil {
		return nil, fmt.Errorf("initialize firestore client: %w", err)
	}
	return &ClientFactory{client: client, ownsClient: true}, nil
}

// Close releases the Firestore client it holds. It is idempotent. A client
// injected with WithClient is not closed; only the reference is dropped.
func (f *ClientFactory) Close() error {
	f.mu.Lock()
	client, owns := f.client, f.ownsClient
	f.client = nil
	f.mu.Unlock()

	if client == nil || !owns {
		return nil
	}
	return client.Close()
}

// Client returns the client after checking that it is still alive.
func (f *ClientFactory) Client() (*firestore.Client, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.client == nil {
		return nil, fmt.Errorf("firestore client is closed or was never initialized: %w", ErrClosed)
	}
	return f.client, nil
}
