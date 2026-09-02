package jobstatus

import (
	"errors"
	"strings"
	"testing"

	"github.com/shouni/go-utils/jobid"
)

// TestStoreRejectsInvalidJobID は、ジョブ ID の検証が Firestore へ触れる前に
// 効いていることを固定します。
//
// ジョブ ID は URL パスとドキュメント ID の双方に現れるため、検証はセキュリティ
// 境界を兼ねます。ここが通ってしまうと、外から渡された値がそのままドキュメント
// 参照の組み立てに使われます。
func TestStoreRejectsInvalidJobID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		jobID     string
		wantCause error
	}{
		{name: "空", jobID: "", wantCause: jobid.ErrEmpty},
		{name: "空白のみ", jobID: "   ", wantCause: jobid.ErrEmpty},
		{name: "親ディレクトリ参照", jobID: "../..", wantCause: jobid.ErrInvalidFormat},
		{name: "ハイフン始まり", jobID: "-job", wantCause: jobid.ErrInvalidFormat},
		{name: "長すぎる", jobID: strings.Repeat("a", jobid.MaxLength+1), wantCause: jobid.ErrTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// client が nil でも、検証はその手前で効くので到達しない。
			store := NewStore[testStatus](nil, "jobs")

			_, err := store.Get(t.Context(), tt.jobID)
			if !errors.Is(err, ErrInvalidJobID) {
				t.Fatalf("Get: err = %v, want errors.Is(_, ErrInvalidJobID)", err)
			}
			// 400 として返したうえで、原因まで辿れるようにしておく。
			if !errors.Is(err, tt.wantCause) {
				t.Errorf("Get: err = %v, want errors.Is(_, %v)", err, tt.wantCause)
			}

			if err := store.Save(t.Context(), tt.jobID, testStatus{}); !errors.Is(err, ErrInvalidJobID) {
				t.Errorf("Save: err = %v, want errors.Is(_, ErrInvalidJobID)", err)
			}
			if err := store.Delete(t.Context(), tt.jobID); !errors.Is(err, ErrInvalidJobID) {
				t.Errorf("Delete: err = %v, want errors.Is(_, ErrInvalidJobID)", err)
			}
		})
	}
}

// TestStoreNormalizesJobID は、パス形式の値が正規化されて通ることを確かめます。
// 正規化の結果が正当なら、検証ではなく設定漏れのエラーまで進みます。
func TestStoreNormalizesJobID(t *testing.T) {
	t.Parallel()

	store := NewStore[testStatus](nil, "jobs")

	_, err := store.Get(t.Context(), "jobs/job-1")
	if errors.Is(err, ErrInvalidJobID) {
		t.Errorf("err = %v, 正規化で job-1 になるはず", err)
	}
}

func TestStoreRequiresConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		store *Store[testStatus]
	}{
		{name: "client 未設定", store: NewStore[testStatus](nil, "jobs")},
		{name: "collection 未設定", store: NewStore[testStatus](nil, "")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := tt.store.Get(t.Context(), "job-1"); err == nil {
				t.Error("err = nil, 設定漏れを黙って通している")
			}
		})
	}
}

// TestNewStorePanicsOnPointerType は、ポインタ型での instantiate を構築時に
// 落とすことを固定します。
//
// T が *X だと Stamper への型アサートが **X に対して行われ、打刻も引き継ぎも
// 再実行ガードも無効になったドキュメントが、エラーもログも無しに書かれます。
func TestNewStorePanicsOnPointerType(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("panic しなかった。ポインタ型は静かに壊れるので構築時に落とす")
		}
	}()

	NewStore[*testStatus](nil, "jobs")
}

func TestNewRecorderPanicsOnPointerType(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("panic しなかった")
		}
	}()

	NewRecorder[*testStatus](nil)
}
