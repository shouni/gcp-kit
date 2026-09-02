package jobstatus

import (
	"context"
	"slices"
	"testing"

	"cloud.google.com/go/firestore"
)

// TestNewListOptions は、絞り込みの組み立てを固定します。
//
// List そのものはエミュレータが要るので、ここで確かめるのは Firestore へ渡る前の形です。
func TestNewListOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		opts []ListOption
		want listOptions
	}{
		{
			name: "既定は queued_at の降順",
			want: listOptions{orderBy: "queued_at", descending: true},
		},
		{
			// 1 つの一覧に複数のコマンドが対応することがある。
			name: "コマンドは重ねられる",
			opts: []ListOption{WithCommand("compose"), WithCommand("generate_from_recipe")},
			want: listOptions{
				commands: []string{"compose", "generate_from_recipe"},
				orderBy:  "queued_at", descending: true,
			},
		},
		{
			// 空を通すと Where("command", "==", "") になり、一覧が全部消える。
			name: "空のコマンドは無視する",
			opts: []ListOption{WithCommand("compose", "", "generate_from_recipe")},
			want: listOptions{
				commands: []string{"compose", "generate_from_recipe"},
				orderBy:  "queued_at", descending: true,
			},
		},
		{
			name: "サービス固有のフィールドは複数指定できる",
			opts: []ListOption{WithField("title_applied", false), WithField("visual_mode", "anime")},
			want: listOptions{
				fields:  []fieldFilter{{path: "title_applied", value: false}, {path: "visual_mode", value: "anime"}},
				orderBy: "queued_at", descending: true,
			},
		},
		{
			// パスが空だと Firestore がエラーを返す。オプション側で落とす。
			name: "空のパスは無視する",
			opts: []ListOption{WithField("", true)},
			want: listOptions{orderBy: "queued_at", descending: true},
		},
		{
			name: "状態と並び順は上書きできる",
			opts: []ListOption{WithState(StateFailed), WithOrderBy("updated_at", false)},
			want: listOptions{state: StateFailed, orderBy: "updated_at"},
		},
		{
			name: "nil のオプションは読み飛ばす",
			opts: []ListOption{nil, WithState(StateQueued)},
			want: listOptions{state: StateQueued, orderBy: "queued_at", descending: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := newListOptions(tt.opts)

			if got.state != tt.want.state {
				t.Errorf("state = %q, want %q", got.state, tt.want.state)
			}
			if got.orderBy != tt.want.orderBy || got.descending != tt.want.descending {
				t.Errorf("並び順 = (%q, %t), want (%q, %t)",
					got.orderBy, got.descending, tt.want.orderBy, tt.want.descending)
			}
			if !slices.Equal(got.commands, tt.want.commands) {
				t.Errorf("commands = %v, want %v", got.commands, tt.want.commands)
			}
			if !slices.Equal(got.fields, tt.want.fields) {
				t.Errorf("fields = %v, want %v", got.fields, tt.want.fields)
			}
		})
	}
}

// TestListAndLatestRejectAnUnconfiguredStore は、両方の一覧が設定不足を同じように
// 断ることを確かめます。
//
// 組み立てを共有していても、入口の検査を片方でしか通していなければ、未設定の Store が
// nil クライアントのまま Firestore を呼びに行きます。
func TestListAndLatestRejectAnUnconfiguredStore(t *testing.T) {
	t.Parallel()

	tests := map[string]*Store[Status]{
		"クライアントが無い":  {},
		"コレクション名が無い": {client: &firestore.Client{}},
	}

	for name, store := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, _, err := store.List(context.Background(), 1, 10); err == nil {
				t.Error("List() error = nil, want an error")
			}
			if _, err := store.Latest(context.Background(), 5); err == nil {
				t.Error("Latest() error = nil, want an error")
			}
		})
	}
}

// TestFilteredQueryAppliesEveryFilter は、どのオプションもクエリに反映されることを
// 確かめます。
//
// 実際に投げるにはエミュレータが要るので、組み立てたクエリを直列化して、絞り込み無しの
// ものと違う形になることで見ます。組み立てが件数集計と本体取得で別々に書かれていた頃は、
// 片方にだけ条件を足して「集計は全件・ページは絞り込み後」という食い違いを作れました。
func TestFilteredQueryAppliesEveryFilter(t *testing.T) {
	t.Parallel()

	store := &Store[Status]{client: &firestore.Client{}, collection: "jobs"}
	serialize := func(t *testing.T, opts ...ListOption) []byte {
		t.Helper()

		query, err := store.filteredQuery(newListOptions(opts))
		if err != nil {
			t.Fatalf("filteredQuery() error = %v", err)
		}
		// firestore.Query は比較可能ではないので、直列化した結果で見ます。
		encoded, err := query.Serialize()
		if err != nil {
			t.Fatalf("Serialize() error = %v", err)
		}
		return encoded
	}

	unfiltered := serialize(t)

	for name, opt := range map[string]ListOption{
		"状態":          WithState(StateSucceeded),
		"コマンド 1 つ":    WithCommand("compose"),
		"コマンド 2 つ":    WithCommand("compose", "generate_from_recipe"),
		"サービス固有フィールド": WithField("title_pending", false),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if slices.Equal(serialize(t, opt), unfiltered) {
				t.Error("オプションがクエリに反映されていません")
			}
		})
	}

	// 並べ替えは filteredQuery では付きません（件数集計は並べ替えを要求しないため）。
	if !slices.Equal(serialize(t, WithOrderBy("updated_at", false)), unfiltered) {
		t.Error("絞り込みだけのクエリに並べ替えが混ざっています")
	}
}
