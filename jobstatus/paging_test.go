package jobstatus

import (
	"testing"

	"github.com/shouni/go-utils/paging"
)

// TestNewPageMeta pins the edge values this listing returns. The
// implementation lives in go-utils/paging; what is pinned here is the contract
// that the Firestore-based listing returns these values.
func TestNewPageMeta(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		page, perPage, total int
		want                 PageMeta
	}{
		{
			name: "first page", page: 1, perPage: 2, total: 5,
			want: PageMeta{Page: 1, PerPage: 2, Total: 5, TotalPages: 3,
				HasPrev: false, HasNext: true, PrevPage: 1, NextPage: 2, From: 1, To: 2},
		},
		{
			name: "partial last page", page: 3, perPage: 2, total: 5,
			want: PageMeta{Page: 3, PerPage: 2, Total: 5, TotalPages: 3,
				HasPrev: true, HasNext: false, PrevPage: 2, NextPage: 3, From: 5, To: 5},
		},
		{
			// Jobs can be deleted mid-listing, making the page being viewed disappear.
			name: "out-of-range page clamps to the last", page: 99, perPage: 2, total: 5,
			want: PageMeta{Page: 3, PerPage: 2, Total: 5, TotalPages: 3,
				HasPrev: true, HasNext: false, PrevPage: 2, NextPage: 3, From: 5, To: 5},
		},
		{
			name: "page 0 or less clamps to the first", page: 0, perPage: 2, total: 5,
			want: PageMeta{Page: 1, PerPage: 2, Total: 5, TotalPages: 3,
				HasPrev: false, HasNext: true, PrevPage: 1, NextPage: 2, From: 1, To: 2},
		},
		{
			name: "no paging when perPage is 0 or less", page: 1, perPage: 0, total: 5,
			want: PageMeta{Page: 1, PerPage: 5, Total: 5, TotalPages: 1,
				HasPrev: false, HasNext: false, PrevPage: 1, NextPage: 1, From: 1, To: 5},
		},
		{
			// TotalPages is 1 even with zero items, so the screen never draws "page 1 of 0".
			name: "zero items", page: 1, perPage: 10, total: 0,
			want: PageMeta{Page: 1, PerPage: 10, Total: 0, TotalPages: 1,
				HasPrev: false, HasNext: false, PrevPage: 1, NextPage: 1, From: 0, To: 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := paging.New(tt.page, tt.perPage, tt.total); got != tt.want {
				t.Errorf("paging.New(%d, %d, %d) = %+v, want %+v",
					tt.page, tt.perPage, tt.total, got, tt.want)
			}
		})
	}
}

func TestPageMetaOffset(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		meta PageMeta
		want int
	}{
		{name: "first page skips nothing", meta: PageMeta{Page: 1, PerPage: 20}, want: 0},
		{name: "third page", meta: PageMeta{Page: 3, PerPage: 20}, want: 40},
		{name: "no paging", meta: PageMeta{Page: 1, PerPage: 0}, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.meta.Offset(); got != tt.want {
				t.Errorf("offset() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestStoreSatisfiesStatusStore pins that Store meets the Recorder's needs. If
// the shape of Get or Save broke, it could no longer be passed to the
// Recorder, and the worker side would break.
func TestStoreSatisfiesStatusStore(t *testing.T) {
	t.Parallel()

	var _ StatusStore[Status] = (*Store[Status])(nil)
}
