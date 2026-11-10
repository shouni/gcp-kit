package jobstatus

import "github.com/shouni/go-utils/paging"

// PageMeta is the metadata a listing screen needs to render pagination.
//
// It is go-utils' paging.PageMeta. Returning the same type as the GCS-based
// listings (go-job-kit/paging) keeps edge values such as an empty list's
// total_pages and page 1's prev_page from disagreeing for an M2M client that
// reads both through one type.
type PageMeta = paging.PageMeta
