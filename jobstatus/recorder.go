package jobstatus

import (
	"context"
	"errors"
	"log/slog"
)

// StatusStore is the minimal reading and writing the Recorder needs.
// *Store[T] satisfies it as is.
//
// The Recorder takes an interface rather than the Store type so callers can
// swap where statuses are kept (a fake in tests, or recording somewhere other
// than Firestore).
type StatusStore[T any] interface {
	Get(ctx context.Context, jobID string) (T, error)
	Save(ctx context.Context, jobID string, status T) error
}

// Modifier is a StatusStore that can read a record and write it back without
// interruption. *Store[T] satisfies it (see Store.Modify).
//
// Recorder.Begin uses it when the given StatusStore also satisfies it.
// Calling Get and Save separately lets another delivery's write land in
// between, which can roll a finished (succeeded) job back to running and run
// it once more.
//
// With a StatusStore that does not satisfy it (a fake in tests, or an app type
// wrapping *Store), Begin works with Get and Save as before. To make a type
// wrapping *Store atomic, delegate Modify to it as is.
type Modifier[T any] interface {
	Modify(ctx context.Context, jobID string, fn func(prev *T) (next T, write bool, err error)) error
}

// Recorder is a thin layer for workers to record status as a job progresses.
//
//  1. A rerun guard for finished jobs (AlreadySucceeded)
//  2. Carrying the common fields over from the previous record (Record)
//  3. Never stopping the generation itself over a failed record (only a warning log)
//
// 3 is because the status is a record for observation only, and aborting the
// generation because it could not be written does more harm.
//
// At the worker's entry 1 and 2 are always called together, so that
// combination is Begin.
type Recorder[T any] struct {
	store  StatusStore[T]
	logger *slog.Logger
}

type recorderOptions struct {
	logger *slog.Logger
}

// RecorderOption changes how a Recorder behaves.
type RecorderOption func(*recorderOptions)

// WithLogger replaces the logger that reports recording failures.
// It defaults to slog.Default().
func WithLogger(logger *slog.Logger) RecorderOption {
	return func(o *recorderOptions) { o.logger = logger }
}

// NewRecorder builds a Recorder.
//
// With a nil store nothing is recorded (Enabled returns false and the other
// methods do nothing). This lets status recording be an optional feature,
// without callers checking for nil on every call.
func NewRecorder[T any](store StatusStore[T], opts ...RecorderOption) *Recorder[T] {
	mustNotBePointer[T]("NewRecorder")

	cfg := recorderOptions{logger: slog.Default()}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if cfg.logger == nil {
		cfg.logger = slog.Default()
	}

	return &Recorder[T]{store: store, logger: cfg.logger}
}

// Enabled reports whether a destination for status records is set.
func (r *Recorder[T]) Enabled() bool {
	return r != nil && r.store != nil
}

// AlreadySucceeded reports whether the job has already finished.
//
// Cloud Tasks delivers at least once, so when a worker returns an error (a
// failed notification, for example) the same task is delivered again. Calling
// the whole generation again doubles its cost, so a worker should stop here
// when the job is finished.
//
// Not recorded (ErrNotFound) returns false, as "not finished". Having no
// record is a normal state, which also occurs for an enqueue before recording
// and for jobs older than this feature.
//
// When the status cannot be read (ErrUnavailable) it returns an error.
// Falling to false here would mistake a finished job for an unfinished one and
// redo the generation, so the guard itself would incur the cost it exists to
// prevent. Falling to true would treat an unfinished job as finished and ACK
// the task, and the job would never run again. Either way can be wrong, so it
// returns the decision to the caller, which can return an error and leave it
// to redelivery.
//
// This is a per-job guard. When processing is split across continuation
// tasks, it cannot stop a redelivery partway through (state=running).
func (r *Recorder[T]) AlreadySucceeded(ctx context.Context, jobID string) (bool, error) {
	if !r.Enabled() {
		return false, nil
	}

	status, err := r.store.Get(ctx, jobID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	if terminal, ok := any(&status).(interface{ IsTerminal() bool }); ok {
		return terminal.IsTerminal(), nil
	}
	return false, nil
}

// Record saves status after carrying the common fields over from the
// previous record.
//
// apply is called after the carry-over and before the save. Use it to
// increment the attempt count or carry over service-specific fields. prev is
// the previous record, nil when it could not be read. Not recorded
// (ErrNotFound) proceeds quietly as the first record; any other read failure
// has lost what to carry over from (Attempts and QueuedAt are reset by this
// record), so it leaves a warning log.
//
// When the previous record is terminal (IsTerminal), a running or failed
// record is not saved (queued is the exception; see rolledBack for why). The
// previous record used for that check was already read for the carry-over, so
// there is no extra round trip to Firestore.
//
// Use Begin to record the start of processing (running). It shares the read
// with the rerun guard.
//
// A failed save is not reported to the caller; it is only a warning log.
func (r *Recorder[T]) Record(ctx context.Context, jobID string, status T, apply ...func(next, prev *T)) {
	if !r.Enabled() {
		return
	}

	prev, prevCommon, err := r.previous(ctx, jobID)
	if err != nil {
		// previous swallows "not recorded", since that is the first record.
		// What reaches here is a read or decode failure: the carry-over is
		// lost and Attempts and QueuedAt are reset by this record, so leave
		// the cause rather than proceeding quietly. The record itself is
		// still written (a gap in observation is no reason to add failures).
		r.logger.WarnContext(ctx, "failed to read previous job status; carry-over skipped",
			"job_id", jobID, "error", err)
	}

	r.save(ctx, jobID, status, prev, prevCommon, apply)
}

// Begin runs the rerun guard and records the start of processing with a
// single read. It returns true when the job was already finished and nothing
// was done.
//
// Deciding with AlreadySucceeded and then writing running with Record would
// make Record re-read the previous record for the carry-over, fetching the
// same document twice in one task. The check needs exactly what the
// carry-over reads, so the two are combined here. When only the stop check is
// needed, without a record, use AlreadySucceeded.
//
// The stop decision is the same as AlreadySucceeded's. Not recorded returns
// false, as "not finished", and a failed read returns an error. When it
// returns an error it records nothing either: writing a running record with
// Attempts and QueuedAt reset for lack of a carry-over source would achieve
// nothing, since the caller just leaves it to redelivery.
//
// The status passed should represent the start of processing (running). An
// enqueue (queued) record is not subject to the rerun guard, so use Record for
// it.
//
// When store satisfies Modifier (*Store[T], for example), everything from
// read to write runs in one transaction. Even if another delivery writes
// succeeded between the check and the record, the retried check sees it and
// stops. With a store that does not, Get and Save are separate calls, and a
// write landing between them is missed.
//
// Neither path stops a redelivery arriving while the job is running; only
// finished (succeeded) jobs are stopped.
func (r *Recorder[T]) Begin(ctx context.Context, jobID string, status T, apply ...func(next, prev *T)) (bool, error) {
	if !r.Enabled() {
		return false, nil
	}
	if m, ok := r.store.(Modifier[T]); ok {
		return r.beginAtomic(ctx, m, jobID, status, apply)
	}

	prev, prevCommon, err := r.previous(ctx, jobID)
	if err != nil {
		return false, err
	}
	if prevCommon != nil && prevCommon.IsTerminal() {
		return true, nil
	}

	r.save(ctx, jobID, status, prev, prevCommon, apply)
	return false, nil
}

// beginAtomic runs Begin's check and record in one Modifier read-write.
//
// The decisions are Begin's. If the record cannot be read it returns an error
// and records nothing; if the job is finished it writes nothing and returns
// true. If only the write fails, it warns and carries on, as Begin's
// non-atomic path does (a failed record never stops the generation). decided
// records whether fn was reached, to tell those cases apart.
//
// fn may be called several times when the transaction retries, so apply may
// be too. As long as the next value is decided from the previous record
// (prev) alone, the result is the same.
func (r *Recorder[T]) beginAtomic(ctx context.Context, m Modifier[T], jobID string, status T, apply []func(next, prev *T)) (bool, error) {
	var decided, done bool
	err := m.Modify(ctx, jobID, func(prev *T) (T, bool, error) {
		decided, done = true, false

		var prevCommon *Status
		if prev != nil {
			if c, ok := common(prev); ok {
				prevCommon = &c
			}
		}
		if prevCommon != nil && prevCommon.IsTerminal() {
			done = true
			return status, false, nil
		}

		next, write := r.prepare(ctx, jobID, status, prev, prevCommon, apply)
		return next, write, nil
	})
	if err != nil {
		if !decided {
			return false, err
		}
		r.logger.WarnContext(ctx, "failed to record job status", "job_id", jobID, "error", err)
	}
	return done, nil
}

// previous reads the previous record and returns the value and its common
// fields.
//
// Not recorded (ErrNotFound) is normal for a first record, so it comes back
// as "no previous record" (both nil) rather than an error. For a type that
// does not embed Status the common fields are nil, and neither carry-over nor
// the rollback check happens.
func (r *Recorder[T]) previous(ctx context.Context, jobID string) (*T, *Status, error) {
	status, err := r.store.Get(ctx, jobID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	if c, ok := common(&status); ok {
		return &status, &c, nil
	}
	return &status, nil, nil
}

// save runs the carry-over, apply and the rollback check, then saves.
func (r *Recorder[T]) save(ctx context.Context, jobID string, status T, prev *T, prevCommon *Status, apply []func(next, prev *T)) {
	next, write := r.prepare(ctx, jobID, status, prev, prevCommon, apply)
	if !write {
		return
	}

	if err := r.store.Save(ctx, jobID, next); err != nil {
		attrs := []any{"job_id", jobID, "error", err}
		if c, ok := common(&next); ok {
			attrs = append(attrs, "state", c.State)
		}
		r.logger.WarnContext(ctx, "failed to record job status", attrs...)
	}
}

// prepare returns the value to save after the carry-over, apply and the
// rollback check. write is false when it would be a rollback. status is taken
// by value, so the caller's value does not change (beginAtomic can rebuild
// from the same status on every retry).
func (r *Recorder[T]) prepare(ctx context.Context, jobID string, status T, prev *T, prevCommon *Status, apply []func(next, prev *T)) (T, bool) {
	if prevCommon != nil {
		if next, ok := any(&status).(Carrier); ok {
			next.CarryOver(*prevCommon)
		}
	}

	for _, fn := range apply {
		if fn != nil {
			fn(&status, prev)
		}
	}

	// The rollback check runs after apply. apply can rewrite the state, so
	// the check must look at the value actually saved or it slips through.
	next, hasCommon := common(&status)
	if rolledBack(prevCommon, next, hasCommon) {
		r.logger.InfoContext(ctx, "skipped job status record; job already finished",
			"job_id", jobID, "state", next.State, "recorded_state", prevCommon.State)
		return status, false
	}
	return status, true
}

// rolledBack reports whether this record is not terminal although the
// previous one was.
//
// When a Cloud Tasks redelivery rolls a finished job back to running or
// failed, both a polling screen and the rerun guard read it as "not done
// yet". This keeps the record side from undoing what AlreadySucceeded
// protects.
//
// queued is the exception. A redelivered task writes running or failed;
// queued is written only by a new request that went through a handler, and
// resubmitting under the same job ID happens normally. Rejecting queued here
// would leave the record at succeeded, and the worker's rerun guard would read
// the redo as "finished" and stop without ever running it. The guard itself
// would cause the very loss it exists to prevent.
func rolledBack(prev *Status, next Status, hasCommon bool) bool {
	if prev == nil || !hasCommon || !prev.IsTerminal() {
		return false
	}
	return !next.IsTerminal() && next.State != StateQueued
}

// common extracts the common fields from a value embedding Status. For a type
// that does not embed it, ok is false and neither carry-over nor the rollback
// check happens.
func common[T any](status *T) (Status, bool) {
	carrier, ok := any(status).(Carrier)
	if !ok {
		return Status{}, false
	}
	return carrier.Common(), true
}
