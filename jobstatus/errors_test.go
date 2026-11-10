package jobstatus

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

func TestClassify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		code codes.Code
		want error
	}{
		{name: "not found is unrecorded", code: codes.NotFound, want: ErrNotFound},

		// Each of these is "should exist but could not be read". Treating them as
		// not recorded would mistake a finished job for an unfinished one and
		// redo the whole generation.
		{name: "transient outage", code: codes.Unavailable, want: ErrUnavailable},
		{name: "deadline exceeded", code: codes.DeadlineExceeded, want: ErrUnavailable},
		{name: "resource exhausted", code: codes.ResourceExhausted, want: ErrUnavailable},
		{name: "server-side failure", code: codes.Internal, want: ErrUnavailable},
		{name: "aborted by contention", code: codes.Aborted, want: ErrUnavailable},

		// Keeps every job from looking "not recorded" the moment permissions are misconfigured.
		{name: "permission denied", code: codes.PermissionDenied, want: ErrUnavailable},
		{name: "unauthenticated", code: codes.Unauthenticated, want: ErrUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cause := grpcstatus.Error(tt.code, "boom")
			err := classify("job-1", cause)

			if !errors.Is(err, tt.want) {
				t.Errorf("classify(%v) = %v, want errors.Is(_, %v)", tt.code, err, tt.want)
			}
			// The cause stays wrapped, so the log keeps the original reason.
			if !errors.Is(err, cause) {
				t.Errorf("classify(%v) did not wrap the cause: %v", tt.code, err)
			}
		})
	}
}

func TestClassifyPassesThroughUnknownFailures(t *testing.T) {
	t.Parallel()

	cause := errors.New("boom")
	err := classify("job-1", cause)

	// Do not fold the unclassifiable into not-recorded or transient (let it be a 500).
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrUnavailable) {
		t.Errorf("classify = %v, folded an unclassifiable failure", err)
	}
	if !errors.Is(err, cause) {
		t.Errorf("classify = %v, cause not wrapped", err)
	}
}

func TestClassifyNil(t *testing.T) {
	t.Parallel()

	if err := classify("job-1", nil); err != nil {
		t.Errorf("classify(nil) = %v, want nil", err)
	}
}
