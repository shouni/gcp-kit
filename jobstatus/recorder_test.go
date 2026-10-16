package jobstatus

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"
)

// testStatus は、利用側が定義する状態型の代わりです。
type testStatus struct {
	Status
	OutputDir string `json:"output_dir,omitempty" firestore:"output_dir,omitempty"`
}

// fakeStore は StatusStore の偽実装です。Recorder は StatusStore しか見ないので、
// ガード・引き継ぎ・巻き戻しの判定はこれで漏れなく検査できます。
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

// newTestRecorder は、警告ログを捨てる Recorder を返します。
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
			// 未記録は正常系。記録前の投入やこの機能より前のジョブで起こる。
			name:      "未記録なら処理を続ける",
			store:     &fakeStore{},
			wantDone:  false,
			wantSaved: 1,
		},
		{
			// 再配信されたタスクをここで打ち切らないと、生成コストが二重に出る。
			name:      "完了済みなら打ち切り、記録もしない",
			store:     &fakeStore{prevSet: true, prev: testStatus{State: StateSucceeded}},
			wantDone:  true,
			wantSaved: 0,
		},
		{
			// failed は Cloud Tasks が再試行しうるので終了ではない。
			name:      "失敗済みは打ち切らない",
			store:     &fakeStore{prevSet: true, prev: testStatus{State: StateFailed}},
			wantDone:  false,
			wantSaved: 1,
		},
		{
			// 「未完了」に倒すと完了済みを作り直し、「完了済み」に倒すと二度と実行
			// されない。どちらへも倒さずエラーを返し、再配信に委ねる。
			name:      "読めなければエラーを返し、記録もしない",
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
				t.Errorf("保存回数 = %d, want %d", got, tt.wantSaved)
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

	// ワーカーは毎回タスクから状態を組み立て直すので、試行回数も投入時刻も持たない。
	rec.Record(t.Context(), "job-1", testStatus{State: StateSucceeded},
		func(next, prev *testStatus) {
			if prev != nil {
				next.OutputDir = prev.OutputDir
			}
		})

	if len(store.saved) != 1 {
		t.Fatalf("保存回数 = %d, want 1", len(store.saved))
	}
	got := store.saved[0]

	if got.Attempts != 2 {
		t.Errorf("Attempts = %d, want 2（組み立て直しで失わせない）", got.Attempts)
	}
	if !got.QueuedAt.Equal(queuedAt) {
		t.Errorf("QueuedAt = %v, want %v", got.QueuedAt, queuedAt)
	}
	if got.Title != "作品名" || got.Command != "generate" {
		t.Errorf("Title/Command = %q/%q, 空のときは引き継ぐ", got.Title, got.Command)
	}
	if got.Error != "" {
		t.Errorf("Error = %q, 成功後に古い失敗理由を残してはいけない", got.Error)
	}
	if got.State != StateSucceeded {
		t.Errorf("State = %q, want %q", got.State, StateSucceeded)
	}
	if got.OutputDir != "gs://bucket/jobs/job-1" {
		t.Errorf("OutputDir = %q, apply による引き継ぎが効いていない", got.OutputDir)
	}
}

func TestRecorderRecordKeepsNewerTitle(t *testing.T) {
	t.Parallel()

	store := &fakeStore{prevSet: true, prev: testStatus{State: StateRunning, Title: "仮の題目"}}

	rec := newTestRecorder(store)
	// 生成の途中で確定した題目を、古い値で上書きしない。
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

	// 引き継ぎ（2）の後に apply が走るので 3。順序が逆なら 1 になる。
	if got := store.saved[0].Attempts; got != 3 {
		t.Errorf("Attempts = %d, want 3（引き継ぎの後に apply）", got)
	}
}

func TestRecorderRecordSkipsRollback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		next      State
		wantSaved int
	}{
		// 完了済みが running や failed へ巻き戻ると、画面も再実行ガードも
		// 「まだ終わっていない」と読む。
		{name: "running へは巻き戻さない", next: StateRunning, wantSaved: 0},
		{name: "failed へは巻き戻さない", next: StateFailed, wantSaved: 0},
		// queued を書くのは新しい依頼だけ。ここで弾くと、同じジョブ ID での
		// 作り直しが記録上ずっと succeeded のままになり、一度も実行されない。
		{name: "queued は作り直しなので通す", next: StateQueued, wantSaved: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := &fakeStore{prevSet: true, prev: testStatus{State: StateSucceeded}}
			rec := newTestRecorder(store)

			rec.Record(t.Context(), "job-1", testStatus{State: tt.next})

			if got := len(store.saved); got != tt.wantSaved {
				t.Errorf("保存回数 = %d, want %d", got, tt.wantSaved)
			}
		})
	}
}

func TestRecorderRecordChecksRollbackAfterApply(t *testing.T) {
	t.Parallel()

	store := &fakeStore{prevSet: true, prev: testStatus{State: StateSucceeded}}
	rec := newTestRecorder(store)

	// apply は状態を書き換えられるので、実際に保存される値で判定しないと素通りする。
	rec.Record(t.Context(), "job-1", testStatus{State: StateQueued},
		func(next, _ *testStatus) { next.State = StateRunning })

	if len(store.saved) != 0 {
		t.Errorf("保存回数 = %d, apply 後の値で巻き戻しを判定していない", len(store.saved))
	}
}

func TestRecorderRecordSavesDespiteUnreadablePrevious(t *testing.T) {
	t.Parallel()

	store := &fakeStore{getErr: ErrUnavailable}
	rec := newTestRecorder(store)

	// 観測の欠けを理由に記録そのものを止めない（引き継ぎだけが失われる）。
	rec.Record(t.Context(), "job-1", testStatus{State: StateFailed})

	if len(store.saved) != 1 {
		t.Errorf("保存回数 = %d, want 1", len(store.saved))
	}
}

func TestRecorderRecordSwallowsSaveFailure(t *testing.T) {
	t.Parallel()

	store := &fakeStore{saveErr: errors.New("boom")}
	rec := newTestRecorder(store)

	// 書けなかったことを理由に生成を中断するほうが害が大きいので、警告ログに留める。
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
		{name: "未記録は未完了", store: &fakeStore{}, want: false},
		{
			name:  "完了済み",
			store: &fakeStore{prevSet: true, prev: testStatus{State: StateSucceeded}},
			want:  true,
		},
		{name: "読めなければエラー", store: &fakeStore{getErr: ErrUnavailable}, wantErr: ErrUnavailable},
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

	// 状態の記録を任意機能として組み込めるようにするため、nil でも呼び出せる。
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

// fakeModifier は Modifier も満たす偽実装です。Modify は、トランザクションの
// やり直しを再現するため、fn を呼んだ後に race が立っていれば記録を書き換えて
// fn をもう一度呼びます（読んだ後に別の配信が書き込んだ状況）。
type fakeModifier struct {
	fakeStore

	// race は、1 回目の fn の後に割り込む書き込みです。
	race      *testStatus
	modErr    error // 読み取りの失敗（fn を呼ばない）
	commitErr error // 書き込みの失敗（fn の後）

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
			// 読んでから書くまでの間に別の書き込みが入った。Firestore はこの
			// トランザクションを捨て、fn を最新の記録でやり直させる。
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

	t.Run("Modify だけで判定と記録を行う", func(t *testing.T) {
		t.Parallel()
		store := &fakeModifier{}
		done, err := newTestRecorder(store).Begin(t.Context(), "job-1", testStatus{Status: Status{State: StateRunning}})
		if err != nil || done {
			t.Fatalf("Begin() = (%v, %v), want (false, nil)", done, err)
		}
		if store.getCalls != 0 {
			t.Errorf("Get が %d 回呼ばれた（トランザクションの外で読んでいる）", store.getCalls)
		}
		if len(store.saved) != 1 || store.saved[0].State != StateRunning {
			t.Errorf("saved = %+v, want running を 1 件", store.saved)
		}
	})

	t.Run("判定の後に succeeded が書かれたら、やり直した判定で打ち切る", func(t *testing.T) {
		t.Parallel()
		// 前回の配信が完了を記録した直後に、再配信の Begin が走る状況。
		// Get と Save が別々だと running で上書きし、もう一度生成してしまう。
		store := &fakeModifier{
			fakeStore: fakeStore{prevSet: true, prev: testStatus{Status: Status{State: StateRunning}}},
			race:      &testStatus{Status: Status{State: StateSucceeded}},
		}
		done, err := newTestRecorder(store).Begin(t.Context(), "job-1", testStatus{Status: Status{State: StateRunning}})
		if err != nil || !done {
			t.Fatalf("Begin() = (%v, %v), want (true, nil)", done, err)
		}
		if len(store.saved) != 0 {
			t.Errorf("saved = %+v, want none（succeeded を巻き戻さない）", store.saved)
		}
		if store.fnCalls != 2 {
			t.Errorf("fn の呼び出し = %d, want 2（やり直しで最新を見る）", store.fnCalls)
		}
	})

	t.Run("読めなければエラーを返し、記録もしない", func(t *testing.T) {
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

	t.Run("書き込みだけの失敗は警告に留めて続ける", func(t *testing.T) {
		t.Parallel()
		// 記録は観測のためのもので、書けなかったことを理由に生成を止めない。
		store := &fakeModifier{commitErr: ErrUnavailable}
		done, err := newTestRecorder(store).Begin(t.Context(), "job-1", testStatus{Status: Status{State: StateRunning}})
		if err != nil || done {
			t.Fatalf("Begin() = (%v, %v), want (false, nil)", done, err)
		}
	})

	t.Run("引き継ぎと apply は前回の記録から行う", func(t *testing.T) {
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
