package jobstatus

import (
	"testing"
	"time"
)

func TestStatusIsTerminal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state State
		want  bool
	}{
		{state: StateQueued, want: false},
		{state: StateRunning, want: false},
		{state: StateSucceeded, want: true},
		// failed may be retried by Cloud Tasks, so it is not the end.
		{state: StateFailed, want: false},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			t.Parallel()

			if got := (Status{State: tt.state}).IsTerminal(); got != tt.want {
				t.Errorf("IsTerminal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStatusStamp(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	status := Status{State: StateRunning}

	// The record holds even if the caller forgot to set UpdatedAt.
	status.Stamp("job-1", now)

	if status.JobID != "job-1" {
		t.Errorf("JobID = %q, want %q", status.JobID, "job-1")
	}
	if !status.UpdatedAt.Equal(now) {
		t.Errorf("UpdatedAt = %v, want %v", status.UpdatedAt, now)
	}
	// Listings sort by queued_at descending, so a job missing the stamp sinks to the bottom. Fill it when unset.
	if !status.QueuedAt.Equal(now) {
		t.Errorf("QueuedAt = %v, want %v (filled when zero)", status.QueuedAt, now)
	}

	queued := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	status = Status{State: StateRunning, QueuedAt: queued}
	status.Stamp("job-1", now)
	if !status.QueuedAt.Equal(queued) {
		t.Errorf("QueuedAt = %v, want the existing %v kept", status.QueuedAt, queued)
	}
}

// TestStatusPredicates pins that IsTerminal, for the rerun guard, differs from
// Finished / InFlight, for display and polling. failed is not terminal for the
// former, and is for the latter.
func TestStatusPredicates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state                        State
		terminal, finished, inFlight bool
	}{
		{StateQueued, false, false, true},
		{StateRunning, false, false, true},
		{StateSucceeded, true, true, false},
		{StateFailed, false, true, false},
	}
	for _, tt := range tests {
		s := Status{State: tt.state}
		if s.IsTerminal() != tt.terminal || s.Finished() != tt.finished || s.InFlight() != tt.inFlight {
			t.Errorf("%s: IsTerminal=%v Finished=%v InFlight=%v, want %v %v %v",
				tt.state, s.IsTerminal(), s.Finished(), s.InFlight(), tt.terminal, tt.finished, tt.inFlight)
		}
	}
}

func TestStatusEnsureJobID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		initial string
		want    string
	}{
		// Do not return a struct without an ID when reading an old record that has no job_id.
		{name: "空なら補う", initial: "", want: "job-1"},
		{name: "入っていれば触らない", initial: "job-9", want: "job-9"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			status := Status{JobID: tt.initial}
			status.EnsureJobID("job-1")

			if status.JobID != tt.want {
				t.Errorf("JobID = %q, want %q", status.JobID, tt.want)
			}
		})
	}
}

// TestStatusSatisfiesInterfaces pins that an embedding type satisfies Stamper
// and Carrier through method promotion alone. That is the premise for asking
// callers to implement nothing, so if it broke, stamping and carry-over would
// silently stop working.
func TestStatusSatisfiesInterfaces(t *testing.T) {
	t.Parallel()

	var (
		_ Stamper = (*testStatus)(nil)
		_ Carrier = (*testStatus)(nil)
	)
}
