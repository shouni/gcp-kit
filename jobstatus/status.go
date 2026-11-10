// Package jobstatus reads and writes the progress of asynchronous jobs as
// Firestore documents, and lists their history by query.
//
// It is the recording layer that fixed generation outcomes surviving only in
// notifications, with failed jobs vanishing from the UI. It is also what the
// rerun guard against Cloud Tasks' at-least-once delivery relies on.
package jobstatus

import "time"

// State is a job's state in its lifecycle.
type State string

const (
	// StateQueued means enqueued, with no worker having started on it yet.
	StateQueued State = "queued"
	// StateRunning means a worker is processing it. For work split across
	// continuation tasks, it stays in this state while being handed over.
	StateRunning State = "running"
	// StateSucceeded means everything up to saving the artifacts has completed.
	StateSucceeded State = "succeeded"
	// StateFailed means processing failed. It may be retried by Cloud Tasks.
	StateFailed State = "failed"
)

// Status holds the job progress fields shared across services.
//
// Where artifacts are stored takes a different shape per service (a single
// URI, an output directory, several URIs), so it is not held here. Define a
// type that embeds this struct. Both Firestore and encoding/json flatten
// embedded structs, so the stored document and the response JSON have the
// same shape.
//
//	type JobStatus struct {
//	    jobstatus.Status
//	    OutputDir string `json:"output_dir,omitempty" firestore:"output_dir,omitempty"`
//	}
//
// Do not omit the firestore tag. Without it, the stored field name becomes the
// Go identifier (OutputDir) and disagrees with the existing responses and
// queries built on the json tag.
type Status struct {
	JobID   string `json:"job_id" firestore:"job_id"`
	Command string `json:"command,omitempty" firestore:"command,omitempty"`
	State   State  `json:"state" firestore:"state"`
	// Title is filled once the subject of the generation is decided.
	Title string `json:"title,omitempty" firestore:"title,omitempty"`
	// Error is the reason for failure when State is failed.
	Error string `json:"error,omitempty" firestore:"error,omitempty"`
	// Attempts is how many times a worker has started processing. 2 or more
	// means it has been retried.
	//
	// Only json uses omitzero, because of encoding/json/v2. v2's omitempty
	// does not drop a numeric 0, so with omitempty, attempts:0 would appear in
	// every response the moment a caller moved to v2. v1's output is the same
	// with omitzero.
	Attempts int `json:"attempts,omitzero" firestore:"attempts,omitempty"`

	// QueuedAt and UpdatedAt are stored as Firestore Timestamps. Held as
	// strings, range queries would be lexical and the meaning of OrderBy would
	// depend on the formatting.
	QueuedAt  time.Time `json:"queued_at,omitzero" firestore:"queued_at"`
	UpdatedAt time.Time `json:"updated_at" firestore:"updated_at"`
}

// IsTerminal reports whether the rerun guard (Recorder.Begin) should decide
// "no need to run again". Only succeeded is true.
//
// failed may be retried by Cloud Tasks, so it does not count as terminal for
// the guard. Do not use this to decide "may polling stop?" or "show as in
// progress in a listing?"; those are Finished and InFlight (with a queue at
// max_attempts = 1, failed is the end too).
func (s Status) IsTerminal() bool {
	return s.State == StateSucceeded
}

// Finished reports whether the job reached succeeded or failed (it has an
// outcome, and polling may stop). Unlike IsTerminal it includes failed.
func (s Status) Finished() bool {
	return s.State == StateSucceeded || s.State == StateFailed
}

// InFlight reports whether the job is queued or running (no outcome yet).
func (s Status) InFlight() bool {
	return s.State == StateQueued || s.State == StateRunning
}

// Stamp is called by the Store on save to stamp the job ID and the update
// time, so the record holds even if the caller forgot to set UpdatedAt.
//
// If QueuedAt is unset, it is set to now. Listings sort by queued_at
// descending, so a job missing the stamp sinks to the bottom. A job whose
// enqueue-time record alone failed gets it filled by the next record (the
// Recorder carries the previous value over, so an existing one is never
// overwritten).
func (s *Status) Stamp(jobID string, now time.Time) {
	s.JobID = jobID
	s.UpdatedAt = now
	if s.QueuedAt.IsZero() {
		s.QueuedAt = now
	}
}

// Common returns the embedded common fields as they are.
//
// It extracts just the common part from a service-specific type embedding
// Status, without a type parameter (embedding promotes the method, so callers
// need not implement it).
func (s Status) Common() Status {
	return s
}

// CarryOver takes in the common fields that should carry over from the
// previous record.
//
// The worker rebuilds the status from the task at every transition, so
// without this the attempt count and the enqueue time would be lost on every
// retry. Title and Command carry over only when this build left them empty
// (some services decide the subject partway through generation, and a newly
// found title must not be overwritten by an old one).
//
// State, Error and UpdatedAt do not carry over. Each describes "this record",
// and carrying them over would leave an old failure reason in place after a
// success.
func (s *Status) CarryOver(prev Status) {
	s.Attempts = prev.Attempts
	s.QueuedAt = prev.QueuedAt
	if s.Title == "" {
		s.Title = prev.Title
	}
	if s.Command == "" {
		s.Command = prev.Command
	}
}

// EnsureJobID fills JobID only when it is empty, so that reading an old
// record without job_id does not hand the caller a struct with no ID.
func (s *Status) EnsureJobID(jobID string) {
	if s.JobID == "" {
		s.JobID = jobID
	}
}

// Stamper is the interface the Store uses to maintain the common fields.
//
// A type embedding Status satisfies it automatically through promotion of the
// pointer methods; callers need not implement it explicitly. Conversely, a
// type that does not embed Status is saved as given, with no stamping.
type Stamper interface {
	Stamp(jobID string, now time.Time)
	EnsureJobID(jobID string)
}

// Carrier is the interface the Recorder uses to carry the common fields over
// from the previous record. A type embedding Status satisfies it
// automatically.
type Carrier interface {
	Common() Status
	CarryOver(prev Status)
}
