package jobstatus

import (
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// Errors returned by this package. Each wraps its cause, so errors.Is keeps
// working while the log still carries the original reason for the failure.
//
// Reads and writes end in one of the three outcomes below (or in something
// that fits none of them). Map them in HTTP handlers like this. Each class
// calls for a different decision from the caller, so lumping them together
// always gets one of them wrong.
//
//	ErrInvalidJobID → 400  bad input; retrying will not fix it
//	ErrNotFound     → 404  not recorded; processing may go ahead
//	ErrUnavailable  → 503  just could not be read; it may be readable later
//	anything else   → 500  a decode failure and the like
//
// ErrClosed is separate: it is about the factory's lifetime (not the outcome
// of one request, but an attempt to take the client after it was closed).
var (
	// ErrNotFound reports that no job status has been recorded yet. It is a
	// normal state, which also occurs for an enqueue before recording and for
	// jobs created before this feature existed.
	ErrNotFound = errors.New("job status not found")

	// ErrUnavailable reports that a job status "should exist but could not be
	// read".
	//
	// It is kept apart from ErrNotFound because the right decisions are
	// opposite. With no record, processing may go ahead; but treating a mere
	// read failure as "no record" mistakes a finished job for an unfinished
	// one and redoes the whole generation (see Recorder.AlreadySucceeded).
	ErrUnavailable = errors.New("job status unavailable")

	// ErrInvalidJobID reports that the given job ID did not pass
	// normalisation.
	//
	// Without it as its own error, a handler would answer an invalid ID that
	// slipped into a URL with the same 5xx as a storage outage, inviting
	// retries of a request that retrying cannot fix. The cause remains as a
	// jobid error, so errors.Is reaches jobid.ErrEmpty, jobid.ErrTooLong and
	// jobid.ErrInvalidFormat.
	ErrInvalidJobID = errors.New("invalid job id")

	// ErrClosed reports that the factory has already been closed.
	ErrClosed = errors.New("firestore client is closed")
)

// classify folds an error from Firestore into the three classes the caller
// decides differently on.
//
// The point is not to fold a permission failure into ErrNotFound. Doing so
// would make every job look "not recorded" the moment permissions are
// misconfigured, and the rerun guard would mistake finished jobs for
// unfinished ones. Only here can "could not read" be told apart from "does not
// exist".
func classify(jobID string, err error) error {
	if err == nil {
		return nil
	}

	switch grpcstatus.Code(err) {
	case codes.NotFound:
		return fmt.Errorf("%w (%s): %w", ErrNotFound, jobID, err)

	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted,
		codes.Internal, codes.Aborted, codes.PermissionDenied, codes.Unauthenticated:
		return fmt.Errorf("%w (%s): %w", ErrUnavailable, jobID, err)

	default:
		return fmt.Errorf("job status operation failed (%s): %w", jobID, err)
	}
}
