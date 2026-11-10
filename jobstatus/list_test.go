package jobstatus

import (
	"context"
	"slices"
	"testing"

	"cloud.google.com/go/firestore"
)

// TestNewListOptions pins how the filters are assembled.
//
// List itself needs the emulator, so what is checked here is the shape before it reaches Firestore.
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
			// One listing can correspond to several commands.
			name: "コマンドは重ねられる",
			opts: []ListOption{WithCommand("compose"), WithCommand("generate_from_recipe")},
			want: listOptions{
				commands: []string{"compose", "generate_from_recipe"},
				orderBy:  "queued_at", descending: true,
			},
		},
		{
			// Letting empty through gives Where("command", "==", ""), and the whole listing disappears.
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
			// Firestore returns an error on an empty path, so the option drops it.
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
				t.Errorf("order = (%q, %t), want (%q, %t)",
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

// TestListAndLatestRejectAnUnconfiguredStore checks that both listings refuse
// a missing configuration the same way.
//
// Even with shared assembly, if only one of them ran the entry check, an
// unconfigured Store would go to call Firestore with a nil client.
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

// TestFilteredQueryAppliesEveryFilter checks that every option is reflected in
// the query.
//
// Running it for real needs the emulator, so the built query is serialised and
// checked to differ from the unfiltered one. When the count and the fetch were
// assembled separately, a condition could be added to only one of them,
// producing "the count covers everything, the page is filtered".
func TestFilteredQueryAppliesEveryFilter(t *testing.T) {
	t.Parallel()

	store := &Store[Status]{client: &firestore.Client{}, collection: "jobs"}
	serialize := func(t *testing.T, opts ...ListOption) []byte {
		t.Helper()

		query, err := store.filteredQuery(newListOptions(opts))
		if err != nil {
			t.Fatalf("filteredQuery() error = %v", err)
		}
		// firestore.Query is not comparable, so the serialised result is compared.
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
				t.Error("the option is not reflected in the query")
			}
		})
	}

	// filteredQuery adds no ordering (the count does not need one).
	if !slices.Equal(serialize(t, WithOrderBy("updated_at", false)), unfiltered) {
		t.Error("ordering leaked into the filter-only query")
	}
}
