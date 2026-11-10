package jobstatus

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/shouni/go-utils/jobid"
)

// Store reads and writes job statuses backed by Firestore.
//
// The type parameter T is the service-specific status type (a struct
// embedding Status). The document ID is the job ID itself: one document per
// job.
type Store[T any] struct {
	client     *firestore.Client
	collection string
	now        func() time.Time
}

// mustNotBePointer rejects, at construction, the mistake of passing a pointer
// type as the type parameter.
//
// The embedded Status is found through the method set of the value type T
// (Save asserts any(&status) to Stamper). With T = *X the assertion target
// becomes **X, which satisfies none of Stamper, Carrier and IsTerminal. The
// result is documents written unstamped, without carry-over and with the
// rerun guard always false, with no error and no log.
//
// Store[*X] is natural to write in Go and breaks quietly, so it fails before
// any data is written. A type without the embedding (T = X not satisfying
// Stamper) is still allowed, as documented: it simply gets no stamping or
// carry-over, rather than breaking quietly by mistake.
func mustNotBePointer[T any](fn string) {
	if t := reflect.TypeFor[T](); t.Kind() == reflect.Pointer {
		panic(fmt.Sprintf(
			"jobstatus: %s[%s]: do not pass a pointer type as the type parameter; "+
				"stamping, carry-over and the rerun guard would be disabled (instantiate with the value type)", fn, t))
	}
}

// NewStore builds a Store.
//
// collection is the path of the collection holding job statuses (for
// example "jobs"). It panics when given a pointer type as the type parameter
// (see mustNotBePointer).
func NewStore[T any](client *firestore.Client, collection string) *Store[T] {
	mustNotBePointer[T]("NewStore")

	return &Store[T]{
		client:     client,
		collection: collection,
		now:        func() time.Time { return time.Now().UTC() },
	}
}

// Save saves a job status.
//
// The document always holds only the latest generation and is updated by
// overwriting. If status embeds Status, JobID and UpdatedAt are stamped here
// (the argument's value is not modified).
func (s *Store[T]) Save(ctx context.Context, jobID string, status T) error {
	doc, safeJobID, err := s.doc(jobID)
	if err != nil {
		return err
	}

	if stamper, ok := any(&status).(Stamper); ok {
		stamper.Stamp(safeJobID, s.now())
	}

	if _, err := doc.Set(ctx, status); err != nil {
		return classify(safeJobID, err)
	}
	return nil
}

// Get fetches a job status, returning ErrNotFound if none is recorded.
//
// A record that fails to decode is returned as an error, not as "not
// recorded". Treating it the same as missing would keep regeneration running
// with nobody noticing the corruption.
func (s *Store[T]) Get(ctx context.Context, jobID string) (T, error) {
	var out T

	doc, safeJobID, err := s.doc(jobID)
	if err != nil {
		return out, err
	}

	snap, err := doc.Get(ctx)
	if err != nil {
		return out, classify(safeJobID, err)
	}
	return decode[T](snap, safeJobID)
}

// decode reads a snapshot into T, so Get and Modify read the same way.
func decode[T any](snap *firestore.DocumentSnapshot, safeJobID string) (T, error) {
	var out T
	if err := snap.DataTo(&out); err != nil {
		return out, fmt.Errorf("decode job status (%s): %w", safeJobID, err)
	}

	// Do not return a struct without an ID when reading an old record that has no job_id.
	if e, ok := any(&out).(interface{ EnsureJobID(string) }); ok {
		e.EnsureJobID(safeJobID)
	}
	return out, nil
}

// Modify reads a record and writes it back inside a Firestore transaction.
// It satisfies Modifier, and Recorder.Begin uses it when available.
//
// fn receives the previous record (nil if none) and returns the value to
// write and whether to write it. Calling Get and Save separately lets another
// write land in between; a Cloud Tasks redelivery overwriting a just-recorded
// succeeded with running is an example. Inside a transaction, Firestore makes
// fn run again if the record changed after it was read, so fn always decides
// on the latest record.
//
// fn may be called several times on retries. Keep it free of outside side
// effects and decide the result from its argument alone.
//
// If reading or decoding fails, that error is returned without calling fn
// (classified as in Get). An error from fn is returned as is, unwrapped.
func (s *Store[T]) Modify(ctx context.Context, jobID string, fn func(prev *T) (next T, write bool, err error)) error {
	doc, safeJobID, err := s.doc(jobID)
	if err != nil {
		return err
	}

	// Decode failures and fn's errors are kept aside here and returned as is,
	// so they do not go through classify along with Firestore's errors.
	var innerErr error
	err = s.client.RunTransaction(ctx, func(_ context.Context, tx *firestore.Transaction) error {
		innerErr = nil

		var prev *T
		snap, getErr := tx.Get(doc)
		switch {
		case grpcstatus.Code(getErr) == codes.NotFound:
		case getErr != nil:
			return getErr
		default:
			v, decErr := decode[T](snap, safeJobID)
			if decErr != nil {
				innerErr = decErr
				return decErr
			}
			prev = &v
		}

		next, write, fnErr := fn(prev)
		if fnErr != nil {
			innerErr = fnErr
			return fnErr
		}
		if !write {
			return nil
		}
		if stamper, ok := any(&next).(Stamper); ok {
			stamper.Stamp(safeJobID, s.now())
		}
		return tx.Set(doc, next)
	})
	if innerErr != nil {
		return innerErr
	}
	if err != nil {
		return classify(safeJobID, err)
	}
	return nil
}

// Delete removes a job status. A missing one is not an error.
func (s *Store[T]) Delete(ctx context.Context, jobID string) error {
	doc, safeJobID, err := s.doc(jobID)
	if err != nil {
		return err
	}

	if _, err := doc.Delete(ctx); err != nil {
		return classify(safeJobID, err)
	}
	return nil
}

// doc returns the document reference whose ID is the normalised job ID.
//
// The job ID appears both in URL paths and as a document ID, so validation
// doubles as a security boundary. Callers need not normalise it.
func (s *Store[T]) doc(jobID string) (*firestore.DocumentRef, string, error) {
	safeJobID, err := jobid.Sanitize(jobID)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrInvalidJobID, err)
	}
	if s.client == nil {
		return nil, "", errors.New("jobstatus: client is not configured")
	}
	if s.collection == "" {
		return nil, "", errors.New("jobstatus: collection is not configured")
	}
	return s.client.Collection(s.collection).Doc(safeJobID), safeJobID, nil
}
