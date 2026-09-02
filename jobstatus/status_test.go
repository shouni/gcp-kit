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
		// failed は Cloud Tasks が再試行しうるので終了ではない。
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

	// 呼び出し側が UpdatedAt を設定し忘れても記録が残るようにする。
	status.Stamp("job-1", now)

	if status.JobID != "job-1" {
		t.Errorf("JobID = %q, want %q", status.JobID, "job-1")
	}
	if !status.UpdatedAt.Equal(now) {
		t.Errorf("UpdatedAt = %v, want %v", status.UpdatedAt, now)
	}
}

func TestStatusEnsureJobID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		initial string
		want    string
	}{
		// job_id を持たない古い記録を読んだときに、ID 無しの構造体を返さない。
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

// TestStatusSatisfiesInterfaces は、埋め込んだ型がメソッドの昇格だけで
// Stamper と Carrier を満たすことを固定します。利用側に実装を要求しないための
// 前提なので、崩れると打刻も引き継ぎも黙って無効になります。
func TestStatusSatisfiesInterfaces(t *testing.T) {
	t.Parallel()

	var (
		_ Stamper = (*testStatus)(nil)
		_ Carrier = (*testStatus)(nil)
	)
}
