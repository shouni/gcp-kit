package jobstatus

import (
	"errors"
	"strings"
	"testing"

	"github.com/shouni/go-utils/jobid"
)

// TestStoreRejectsInvalidJobID pins that job ID validation takes effect before
// Firestore is touched.
//
// The job ID appears both in URL paths and as a document ID, so validation
// doubles as a security boundary. If this let a value through, an
// outside-supplied value would be used as is to build a document reference.
func TestStoreRejectsInvalidJobID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		jobID     string
		wantCause error
	}{
		{name: "空", jobID: "", wantCause: jobid.ErrEmpty},
		{name: "空白のみ", jobID: "   ", wantCause: jobid.ErrEmpty},
		{name: "親ディレクトリ参照", jobID: "../..", wantCause: jobid.ErrInvalidFormat},
		{name: "ハイフン始まり", jobID: "-job", wantCause: jobid.ErrInvalidFormat},
		{name: "長すぎる", jobID: strings.Repeat("a", jobid.MaxLength+1), wantCause: jobid.ErrTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Even with a nil client, validation comes first, so the client is never reached.
			store := NewStore[testStatus](nil, "jobs")

			_, err := store.Get(t.Context(), tt.jobID)
			if !errors.Is(err, ErrInvalidJobID) {
				t.Fatalf("Get: err = %v, want errors.Is(_, ErrInvalidJobID)", err)
			}
			// Answer 400 while keeping the cause reachable.
			if !errors.Is(err, tt.wantCause) {
				t.Errorf("Get: err = %v, want errors.Is(_, %v)", err, tt.wantCause)
			}

			if err := store.Save(t.Context(), tt.jobID, testStatus{}); !errors.Is(err, ErrInvalidJobID) {
				t.Errorf("Save: err = %v, want errors.Is(_, ErrInvalidJobID)", err)
			}
			if err := store.Delete(t.Context(), tt.jobID); !errors.Is(err, ErrInvalidJobID) {
				t.Errorf("Delete: err = %v, want errors.Is(_, ErrInvalidJobID)", err)
			}
		})
	}
}

// TestStoreNormalizesJobID checks that a path-shaped value is normalised and
// passes. When the normalised result is valid, it gets as far as the
// missing-configuration error rather than failing validation.
func TestStoreNormalizesJobID(t *testing.T) {
	t.Parallel()

	store := NewStore[testStatus](nil, "jobs")

	_, err := store.Get(t.Context(), "jobs/job-1")
	if errors.Is(err, ErrInvalidJobID) {
		t.Errorf("err = %v, normalisation should give job-1", err)
	}
}

func TestStoreRequiresConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		store *Store[testStatus]
	}{
		{name: "client 未設定", store: NewStore[testStatus](nil, "jobs")},
		{name: "collection 未設定", store: NewStore[testStatus](nil, "")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := tt.store.Get(t.Context(), "job-1"); err == nil {
				t.Error("err = nil, a missing setting was let through silently")
			}
		})
	}
}

// TestNewStorePanicsOnPointerType pins that instantiating with a pointer type
// fails at construction.
//
// With T = *X the type assertion to Stamper runs against **X, and documents
// are written with stamping, carry-over and the rerun guard all disabled, with
// no error and no log.
func TestNewStorePanicsOnPointerType(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("did not panic; a pointer type breaks silently, so it must fail at construction")
		}
	}()

	NewStore[*testStatus](nil, "jobs")
}

func TestNewRecorderPanicsOnPointerType(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("did not panic")
		}
	}()

	NewRecorder[*testStatus](nil)
}
