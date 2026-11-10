package jobstatus

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"
)

// testStatus stands in for the status type a caller defines.
type testStatus struct {
	Status
	OutputDir string `json:"output_dir,omitempty" firestore:"output_dir,omitempty"`
}

// fakeStore is a fake StatusStore. The Recorder sees only the StatusStore, so
// the guard, the carry-over and the rollback check can all be tested with it.
type fakeStore struct {
	prev    testStatus
	prevSet bool
	getErr  error
	saveErr error

	saved []testStatus
}

func (f *fakeStore) Get(_ context.Context, _ string) (testStatus, error) {
	if f.getErr != nil {
		return testStatus{}, f.getErr
	}
	if !f.prevSet {
		return testStatus{}, ErrNotFound
	}
	return f.prev, nil
}

func (f *fakeStore) Save(_ context.Context, _ string, status testStatus) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saved = append(f.saved, status)
	return nil
}

// newTestRecorder returns a Recorder that discards warning logs.
func newTestRecorder(store StatusStore[testStatus]) *Recorder[testStatus] {
	return NewRecorder(store, WithLogger(slog.New(slog.DiscardHandler)))
}

func TestRecorderBegin(t *testing.T) {
	t.Parallel()

	queuedAt := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		store     *fakeStore
		wantDone  bool
		wantErr   error
		wantSaved int
	}{
		{
			// Not recorded is a normal case: an enqueue before recording, or a job older than this feature.
			name:      "continues when unrecorded",
			store:     &fakeStore{},
			wantDone:  false,
			wantSaved: 1,
		},
		{
			// Not stopping a redelivered task here would pay for the generation twice.
			name:      "stops without recording when already succeeded",
			store:     &fakeStore{prevSet: true, prev: testStatus{State: StateSucceeded}},
			wantDone:  true,
			wantSaved: 0,
		},
		{
			// failed may be retried by Cloud Tasks, so it is not the end.
			name:      "does not stop when already failed",
			store:     &fakeStore{prevSet: true, prev: testStatus{State: StateFailed}},
			wantDone:  false,
			wantSaved: 1,
		},
		{
			// Falling to "unfinished" redoes a finished job; falling to "finished"
			// never runs it again. Fall to neither: return an error and leave it
			// to redelivery.
			name:      "returns an error without recording when unreadable",
			store:     &fakeStore{getErr: ErrUnavailable},
			wantErr:   ErrUnavailable,
			wantSaved: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := newTestRecorder(tt.store)
			next := testStatus{State: StateRunning, QueuedAt: queuedAt}

			done, err := rec.Begin(t.Context(), "job-1", next)

			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want errors.Is(_, %v)", err, tt.wantErr)
			}
			if tt.wantErr == nil && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if done != tt.wantDone {
				t.Errorf("done = %v, want %v", done, tt.wantDone)
			}
			if got := len(tt.store.saved); got != tt.wantSaved {
				t.Errorf("saves = %d, want %d", got, tt.wantSaved)
			}
		})
	}
}

func TestRecorderRecordCarriesOver(t *testing.T) {
	t.Parallel()

	queuedAt := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	store := &fakeStore{prevSet: true, prev: testStatus{
		State: StateRunning, Attempts: 2, QueuedAt: queuedAt,
		Title: "作品名", Command: "generate", Error: "前回の失敗理由",
		OutputDir: "gs://bucket/jobs/job-1",
	}}

	rec := newTestRecorder(store)

	// The worker rebuilds the status from the task every time, so it has neither the attempt count nor the enqueue time.
	rec.Record(t.Context(), "job-1", testStatus{State: StateSucceeded},
		func(next, prev *testStatus) {
			if prev != nil {
				next.OutputDir = prev.OutputDir
			}
		})

	if len(store.saved) != 1 {
		t.Fatalf("saves = %d, want 1", len(store.saved))
	}
	got := store.saved[0]

	if got.Attempts != 2 {
		t.Errorf("Attempts = %d, want 2 (not lost by rebuilding)", got.Attempts)
	}
	if !got.QueuedAt.Equal(queuedAt) {
		t.Errorf("QueuedAt = %v, want %v", got.QueuedAt, queuedAt)
	}
	if got.Title != "作品名" || got.Command != "generate" {
		t.Errorf("Title/Command = %q/%q, should carry over when empty", got.Title, got.Command)
	}
	if got.Error != "" {
		t.Errorf("Error = %q, an old failure reason must not remain after success", got.Error)
	}
	if got.State != StateSucceeded {
		t.Errorf("State = %q, want %q", got.State, StateSucceeded)
	}
	if got.OutputDir != "gs://bucket/jobs/job-1" {
		t.Errorf("OutputDir = %q, carry-over through apply did not work", got.OutputDir)
	}
}

func TestRecorderRecordKeepsNewerTitle(t *testing.T) {
	t.Parallel()

	store := &fakeStore{prevSet: true, prev: testStatus{State: StateRunning, Title: "仮の題目"}}

	rec := newTestRecorder(store)
	// A title decided partway through generation is not overwritten by an old one.
	rec.Record(t.Context(), "job-1", testStatus{State: StateRunning, Title: "確定した題目"})

	if got := store.saved[0].Title; got != "確定した題目" {
		t.Errorf("Title = %q, want %q", got, "確定した題目")
	}
}

func TestRecorderRecordAppliesAfterCarryOver(t *testing.T) {
	t.Parallel()

	store := &fakeStore{prevSet: true, prev: testStatus{State: StateQueued, Attempts: 2}}

	rec := newTestRecorder(store)
	rec.Record(t.Context(), "job-1", testStatus{State: StateRunning},
		func(next, _ *testStatus) { next.Attempts++ })

	// apply runs after the carry-over (2), giving 3. In the reverse order it would be 1.
	if got := store.saved[0].Attempts; got != 3 {
		t.Errorf("Attempts = %d, want 3 (apply after the carry-over)", got)
	}
}

func TestRecorderRecordSkipsRollback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		next      State
		wantSaved int
	}{
		// If a finished job rolls back to running or failed, both the screen
		// and the rerun guard read it as "not done yet".
		{name: "does not roll back to running", next: StateRunning, wantSaved: 0},
		{name: "does not roll back to failed", next: StateFailed, wantSaved: 0},
		// Only a new request writes queued. Rejecting it here would leave a redo
		// under the same job ID recorded as succeeded forever, never run.
		{name: "allows queued as a resubmission", next: StateQueued, wantSaved: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &fakeStore{prevSet: true, prev: testStatus{State: StateSucceeded}}
			rec := newTestRecorder(store)

			rec.Record(t.Context(), "job-1", testStatus{State: tt.next})

			if got := len(store.saved); got != tt.wantSaved {
				t.Errorf("saves = %d, want %d", got, tt.wantSaved)
			}
		})
	}
}

func TestRecorderRecordChecksRollbackAfterApply(t *testing.T) {
	t.Parallel()

	store := &fakeStore{prevSet: true, prev: testStatus{State: StateSucceeded}}
	rec := newTestRecorder(store)

	// apply can rewrite the state, so the check must use the value actually saved or it slips through.
	rec.Record(t.Context(), "job-1", testStatus{State: StateQueued},
		func(next, _ *testStatus) { next.State = StateRunning })

	if len(store.saved) != 0 {
		t.Errorf("saves = %d, rollback not checked on the value after apply", len(store.saved))
	}
}

func TestRecorderRecordSavesDespiteUnreadablePrevious(t *testing.T) {
	t.Parallel()

	store := &fakeStore{getErr: ErrUnavailable}
	rec := newTestRecorder(store)

	// A gap in observation does not stop the record itself (only the carry-over is lost).
	rec.Record(t.Context(), "job-1", testStatus{State: StateFailed})

	if len(store.saved) != 1 {
		t.Errorf("saves = %d, want 1", len(store.saved))
	}
}

func TestRecorderRecordSwallowsSaveFailure(t *testing.T) {
	t.Parallel()

	store := &fakeStore{saveErr: errors.New("boom")}
	rec := newTestRecorder(store)

	// Aborting the generation because the record could not be written does more harm, so it is only a warning log.
	rec.Record(t.Context(), "job-1", testStatus{State: StateSucceeded})
}

func TestRecorderAlreadySucceeded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		store   *fakeStore
		want    bool
		wantErr error
	}{
		{name: "unrecorded is not done", store: &fakeStore{}, want: false},
		{
			name:  "succeeded",
			store: &fakeStore{prevSet: true, prev: testStatus{State: StateSucceeded}},
			want:  true,
		},
		{name: "error when unreadable", store: &fakeStore{getErr: ErrUnavailable}, wantErr: ErrUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := newTestRecorder(tt.store).AlreadySucceeded(t.Context(), "job-1")

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want errors.Is(_, %v)", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if got != tt.want {
				t.Errorf("done = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecorderDisabled(t *testing.T) {
	t.Parallel()

	// Callable even when nil, so status recording can be an optional feature.
	rec := NewRecorder[testStatus](nil)

	if rec.Enabled() {
		t.Error("Enabled() = true, want false")
	}

	done, err := rec.Begin(t.Context(), "job-1", testStatus{})
	if done || err != nil {
		t.Errorf("Begin = (%v, %v), want (false, nil)", done, err)
	}

	rec.Record(t.Context(), "job-1", testStatus{})
}

// fakeModifier is a fake that also satisfies Modifier. To reproduce a
// transaction retry, Modify rewrites the record and calls fn again when race
// is set after the first fn call (another delivery writing after the read).
type fakeModifier struct {
	fakeStore

	// race is the write that cuts in after the first fn call.
	race      *testStatus
	modErr    error // a read failure (fn is not called)
	commitErr error // a write failure (after fn)

	getCalls int
	fnCalls  int
}

func (f *fakeModifier) Get(ctx context.Context, jobID string) (testStatus, error) {
	f.getCalls++
	return f.fakeStore.Get(ctx, jobID)
}

func (f *fakeModifier) Modify(_ context.Context, _ string, fn func(prev *testStatus) (testStatus, bool, error)) error {
	if f.modErr != nil {
		return f.modErr
	}
	for {
		var prev *testStatus
		if f.prevSet {
			p := f.prev
			prev = &p
		}
		next, write, err := fn(prev)
		f.fnCalls++
		if err != nil {
			return err
		}
		if f.race != nil {
			// Another write landed between the read and the write. Firestore
			// discards this transaction and reruns fn on the latest record.
			f.prev, f.prevSet, f.race = *f.race, true, nil
			continue
		}
		if !write {
			return nil
		}
		if f.commitErr != nil {
			return f.commitErr
		}
		f.saved = append(f.saved, next)
		f.prev, f.prevSet = next, true
		return nil
	}
}

func TestRecorderBeginUsesModifier(t *testing.T) {
	t.Parallel()

	t.Run("decides and records through Modify alone", func(t *testing.T) {
		t.Parallel()
		store := &fakeModifier{}
		done, err := newTestRecorder(store).Begin(t.Context(), "job-1", testStatus{Status: Status{State: StateRunning}})
		if err != nil || done {
			t.Fatalf("Begin() = (%v, %v), want (false, nil)", done, err)
		}
		if store.getCalls != 0 {
			t.Errorf("Get called %d times (reading outside the transaction)", store.getCalls)
		}
		if len(store.saved) != 1 || store.saved[0].State != StateRunning {
			t.Errorf("saved = %+v, want one running record", store.saved)
		}
	})

	t.Run("stops on the retried check when succeeded is written after the first", func(t *testing.T) {
		t.Parallel()
		// A redelivery's Begin runs right after the previous delivery recorded
		// completion. With separate Get and Save it would overwrite with
		// running and generate again.
		store := &fakeModifier{
			fakeStore: fakeStore{prevSet: true, prev: testStatus{Status: Status{State: StateRunning}}},
			race:      &testStatus{Status: Status{State: StateSucceeded}},
		}
		done, err := newTestRecorder(store).Begin(t.Context(), "job-1", testStatus{Status: Status{State: StateRunning}})
		if err != nil || !done {
			t.Fatalf("Begin() = (%v, %v), want (true, nil)", done, err)
		}
		if len(store.saved) != 0 {
			t.Errorf("saved = %+v, want none (succeeded must not roll back)", store.saved)
		}
		if store.fnCalls != 2 {
			t.Errorf("fn calls = %d, want 2 (the retry sees the latest)", store.fnCalls)
		}
	})

	t.Run("returns an error without recording when unreadable", func(t *testing.T) {
		t.Parallel()
		store := &fakeModifier{modErr: ErrUnavailable}
		done, err := newTestRecorder(store).Begin(t.Context(), "job-1", testStatus{Status: Status{State: StateRunning}})
		if !errors.Is(err, ErrUnavailable) || done {
			t.Fatalf("Begin() = (%v, %v), want (false, ErrUnavailable)", done, err)
		}
		if len(store.saved) != 0 {
			t.Errorf("saved = %+v, want none", store.saved)
		}
	})

	t.Run("write-only failure is a warning and continues", func(t *testing.T) {
		t.Parallel()
		// The record is for observation; failing to write it does not stop the generation.
		store := &fakeModifier{commitErr: ErrUnavailable}
		done, err := newTestRecorder(store).Begin(t.Context(), "job-1", testStatus{Status: Status{State: StateRunning}})
		if err != nil || done {
			t.Fatalf("Begin() = (%v, %v), want (false, nil)", done, err)
		}
	})

	t.Run("carry-over and apply start from the previous record", func(t *testing.T) {
		t.Parallel()
		queuedAt := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
		store := &fakeModifier{
			fakeStore: fakeStore{prevSet: true, prev: testStatus{Status: Status{State: StateQueued, QueuedAt: queuedAt, Attempts: 1}}},
		}
		bump := func(next, prev *testStatus) {
			if prev != nil {
				next.Attempts = prev.Attempts + 1
			}
		}
		if _, err := newTestRecorder(store).Begin(t.Context(), "job-1", testStatus{Status: Status{State: StateRunning}}, bump); err != nil {
			t.Fatal(err)
		}
		got := store.saved[0]
		if got.Attempts != 2 || !got.QueuedAt.Equal(queuedAt) {
			t.Errorf("saved = Attempts %d / QueuedAt %v, want 2 / %v", got.Attempts, got.QueuedAt, queuedAt)
		}
	})
}
