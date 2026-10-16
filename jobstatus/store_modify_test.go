package jobstatus

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"cloud.google.com/go/firestore"
)

// newEmulatorStore は、Firestore エミュレータに向けた Store を返します。
// FIRESTORE_EMULATOR_HOST が無ければテストを飛ばします（CI では起動していません）。
//
//	gcloud emulators firestore start --host-port=localhost:8086
//	FIRESTORE_EMULATOR_HOST=localhost:8086 go test ./jobstatus/ -run Modify
func newEmulatorStore(t *testing.T) *Store[testStatus] {
	t.Helper()
	if os.Getenv("FIRESTORE_EMULATOR_HOST") == "" {
		t.Skip("FIRESTORE_EMULATOR_HOST is not set")
	}
	client, err := firestore.NewClient(t.Context(), "gcp-kit-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return NewStore[testStatus](client, "modify-"+t.Name())
}

func TestStoreModify(t *testing.T) {
	store := newEmulatorStore(t)
	ctx := t.Context()

	t.Run("未記録なら prev は nil で、書いた値が残る", func(t *testing.T) {
		err := store.Modify(ctx, "job-new", func(prev *testStatus) (testStatus, bool, error) {
			if prev != nil {
				t.Errorf("prev = %+v, want nil", prev)
			}
			return testStatus{Status: Status{State: StateRunning}}, true, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		got, err := store.Get(ctx, "job-new")
		if err != nil || got.State != StateRunning || got.JobID != "job-new" {
			t.Errorf("Get() = %+v, %v, want running を打刻済みで", got, err)
		}
	})

	t.Run("write=false なら書かない", func(t *testing.T) {
		if err := store.Save(ctx, "job-done", testStatus{Status: Status{State: StateSucceeded}}); err != nil {
			t.Fatal(err)
		}
		err := store.Modify(ctx, "job-done", func(prev *testStatus) (testStatus, bool, error) {
			if prev == nil || prev.State != StateSucceeded {
				t.Errorf("prev = %+v, want succeeded", prev)
			}
			return testStatus{Status: Status{State: StateRunning}}, false, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := store.Get(ctx, "job-done"); got.State != StateSucceeded {
			t.Errorf("state = %s, want succeeded", got.State)
		}
	})

	t.Run("fn のエラーは包まずに返す", func(t *testing.T) {
		sentinel := errors.New("stop")
		err := store.Modify(ctx, "job-err", func(*testStatus) (testStatus, bool, error) {
			return testStatus{}, false, sentinel
		})
		if !errors.Is(err, sentinel) || errors.Is(err, ErrUnavailable) {
			t.Errorf("err = %v, want sentinel のまま", err)
		}
	})

	t.Run("同時に Begin しても succeeded は巻き戻らない", func(t *testing.T) {
		// 完了の記録と、再配信の Begin が競合する状況を並行で起こす。
		rec := newTestRecorder(store)
		const jobID = "job-race"
		if err := store.Save(ctx, jobID, testStatus{Status: Status{State: StateRunning}}); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				_, _ = rec.Begin(context.WithoutCancel(ctx), jobID, testStatus{Status: Status{State: StateRunning}})
			})
		}
		if err := store.Save(ctx, jobID, testStatus{Status: Status{State: StateSucceeded}}); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		// 完了を記録した後に走った Begin は、どれも succeeded を見て打ち切っているはず。
		if got, _ := store.Get(ctx, jobID); got.State != StateSucceeded {
			t.Errorf("state = %s, want succeeded（Begin が完了を running へ巻き戻した）", got.State)
		}
	})
}
