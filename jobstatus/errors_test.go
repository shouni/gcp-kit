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
		{name: "不在は未記録", code: codes.NotFound, want: ErrNotFound},

		// 以下はいずれも「あるはずなのに読めなかった」。未記録と同じ扱いにすると、
		// 完了済みのジョブを未完了と誤認して生成をまるごとやり直す。
		{name: "一時的な障害", code: codes.Unavailable, want: ErrUnavailable},
		{name: "期限切れ", code: codes.DeadlineExceeded, want: ErrUnavailable},
		{name: "上限超過", code: codes.ResourceExhausted, want: ErrUnavailable},
		{name: "サーバー側の失敗", code: codes.Internal, want: ErrUnavailable},
		{name: "競合による中断", code: codes.Aborted, want: ErrUnavailable},

		// 権限設定を誤った瞬間に全ジョブが「未記録」に見えるのを防ぐ。
		{name: "権限不足", code: codes.PermissionDenied, want: ErrUnavailable},
		{name: "未認証", code: codes.Unauthenticated, want: ErrUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cause := grpcstatus.Error(tt.code, "boom")
			err := classify("job-1", cause)

			if !errors.Is(err, tt.want) {
				t.Errorf("classify(%v) = %v, want errors.Is(_, %v)", tt.code, err, tt.want)
			}
			// 原因を包んだまま返すので、ログには元の失敗理由が残る。
			if !errors.Is(err, cause) {
				t.Errorf("classify(%v) は原因を包んでいない: %v", tt.code, err)
			}
		})
	}
}

func TestClassifyPassesThroughUnknownFailures(t *testing.T) {
	t.Parallel()

	cause := errors.New("boom")
	err := classify("job-1", cause)

	// 分類できないものを未記録や一時障害へ寄せない（500 として扱わせる）。
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrUnavailable) {
		t.Errorf("classify = %v, 分類のつかない失敗を畳んでいる", err)
	}
	if !errors.Is(err, cause) {
		t.Errorf("classify = %v, 原因を包んでいない", err)
	}
}

func TestClassifyNil(t *testing.T) {
	t.Parallel()

	if err := classify("job-1", nil); err != nil {
		t.Errorf("classify(nil) = %v, want nil", err)
	}
}
