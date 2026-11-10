package jobstatus

import (
	"context"
	"errors"
	"fmt"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/firestore/apiv1/firestorepb"
	"github.com/shouni/go-utils/paging"
	"google.golang.org/api/iterator"
)

// countAlias is the key the count aggregation result is read from.
const countAlias = "all"

// listOptions holds List's filters and ordering.
type listOptions struct {
	state      State
	commands   []string
	fields     []fieldFilter
	orderBy    string
	descending bool
}

// fieldFilter is an equality filter on one service-specific field.
type fieldFilter struct {
	path  string
	value any
}

// ListOption changes how List behaves.
type ListOption func(*listOptions)

// newListOptions applies the options on top of the defaults.
func newListOptions(opts []ListOption) listOptions {
	cfg := listOptions{orderBy: "queued_at", descending: true}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

// WithState lists only jobs in the given state.
func WithState(state State) ListOption {
	return func(o *listOptions) { o.state = state }
}

// WithCommand lists only jobs with the given commands.
//
// Given several, it returns jobs matching any of them, because one command
// does not always map to one listing (two commands may belong on the same
// history screen, for example). It becomes a Firestore in query, so at most
// 30 values. Empty strings are ignored.
func WithCommand(commands ...string) ListOption {
	return func(o *listOptions) {
		for _, command := range commands {
			if command != "" {
				o.commands = append(o.commands, command)
			}
		}
	}
}

// WithField lists only jobs whose service-specific field equals value. path
// is the Firestore field name (the firestore tag's name, not the Go
// identifier).
//
// State and Command mean the same in every service, so they have their own
// options, but every other filter differs per service. Without this, a
// caller filtering on its own field would read everything and drop rows in
// memory, losing half the point of moving listings to Firestore.
//
// Equality only. Allowing a range comparison would make Firestore require the
// inequality field first in the ordering, so combined with WithOrderBy it
// would silently produce a different order.
func WithField(path string, value any) ListOption {
	return func(o *listOptions) {
		if path != "" {
			o.fields = append(o.fields, fieldFilter{path: path, value: value})
		}
	}
}

// WithOrderBy changes the field and direction to sort by. The default is
// queued_at descending (newest first).
//
// Combined with a filter it needs a composite index. Manage indexes in code,
// with Terraform or the like (so no hand-added index ends up existing only in
// production). Sorting without a filter is served by the automatic
// single-field index.
func WithOrderBy(field string, descending bool) ListOption {
	return func(o *listOptions) {
		o.orderBy = field
		o.descending = descending
	}
}

// List returns one page of job statuses, newest first.
//
// Pages start at 1, and a perPage of 0 or less returns everything without
// paging. Total comes from a count aggregation query rather than reading
// everything, so documents outside the page are not read.
//
// A document that fails to decode is returned as an error. Dropping it from
// the listing silently would leave nobody aware of the broken record.
//
// Paging uses Offset, so deeper pages read more. Firestore bills skipped
// documents too, so page N costs N × perPage reads. That is the price of
// jumping to any page; on screens where "the latest few" is enough, use
// Latest. If a listing reaching hundreds of pages is needed, consider a
// cursor (Query.StartAfter) instead of Offset.
func (s *Store[T]) List(ctx context.Context, page, perPage int, opts ...ListOption) ([]T, PageMeta, error) {
	cfg := newListOptions(opts)

	query, err := s.filteredQuery(cfg)
	if err != nil {
		return nil, PageMeta{}, err
	}

	total, err := count(ctx, query)
	if err != nil {
		return nil, PageMeta{}, err
	}

	meta := paging.New(page, perPage, total)
	if total == 0 {
		return nil, meta, nil
	}

	query = orderedQuery(query, cfg)
	if meta.PerPage > 0 {
		query = query.Offset(meta.Offset()).Limit(meta.PerPage)
	}

	items, err := collect[T](ctx, query)
	if err != nil {
		return nil, meta, err
	}
	return items, meta, nil
}

// Latest returns limit job statuses matching the filters, newest first. A
// limit of 0 or less returns every match.
//
// **It runs no count.** List counts the total first for paging, which is of
// no use to a screen that "lists only the latest few". A screen showing only
// an excerpt would wait one extra round trip for an unused count every time
// it opens.
//
// It returns no PageMeta for the same reason. Building page information
// without knowing the total means putting 0 or a guess in Total and
// TotalPages, and the receiver cannot tell "really zero" from "not counted".
// Use List when paging is needed, and this when it is not.
func (s *Store[T]) Latest(ctx context.Context, limit int, opts ...ListOption) ([]T, error) {
	cfg := newListOptions(opts)

	query, err := s.filteredQuery(cfg)
	if err != nil {
		return nil, err
	}

	query = orderedQuery(query, cfg)
	if limit > 0 {
		query = query.Limit(limit)
	}
	return collect[T](ctx, query)
}

// filteredQuery returns the query with only the filters applied. It is built
// in one place so the count and the fetch see the same conditions.
func (s *Store[T]) filteredQuery(cfg listOptions) (firestore.Query, error) {
	if s.client == nil {
		return firestore.Query{}, errors.New("jobstatus: client is not configured")
	}
	if s.collection == "" {
		return firestore.Query{}, errors.New("jobstatus: collection is not configured")
	}

	query := s.client.Collection(s.collection).Query
	if cfg.state != "" {
		query = query.Where("state", "==", string(cfg.state))
	}
	switch len(cfg.commands) {
	case 0:
	case 1:
		query = query.Where("command", "==", cfg.commands[0])
	default:
		query = query.Where("command", "in", cfg.commands)
	}
	for _, f := range cfg.fields {
		query = query.Where(f.path, "==", f.value)
	}
	return query, nil
}

// orderedQuery applies the ordering.
func orderedQuery(query firestore.Query, cfg listOptions) firestore.Query {
	direction := firestore.Asc
	if cfg.descending {
		direction = firestore.Desc
	}
	return query.OrderBy(cfg.orderBy, direction)
}

// collect decodes the query results into T and collects them.
func collect[T any](ctx context.Context, query firestore.Query) ([]T, error) {
	iter := query.Documents(ctx)
	defer iter.Stop()

	var items []T
	for {
		snap, err := iter.Next()
		if errors.Is(err, iterator.Done) {
			return items, nil
		}
		if err != nil {
			return nil, classify("list", err)
		}

		var item T
		if err := snap.DataTo(&item); err != nil {
			return nil, fmt.Errorf("decode job status (%s): %w", snap.Ref.ID, err)
		}
		if e, ok := any(&item).(interface{ EnsureJobID(string) }); ok {
			e.EnsureJobID(snap.Ref.ID)
		}
		items = append(items, item)
	}
}

// count returns the total number of results of the filtered query.
//
// It does not read the documents themselves, so getting the whole listing's
// count needs no scan outside the page. Listings on object storage were
// forced into full scans because they had nothing equivalent.
func count(ctx context.Context, query firestore.Query) (int, error) {
	result, err := query.NewAggregationQuery().WithCount(countAlias).Get(ctx)
	if err != nil {
		return 0, classify("count", err)
	}

	value, ok := result[countAlias]
	if !ok {
		return 0, errors.New("jobstatus: count query returned no result")
	}
	counted, ok := value.(*firestorepb.Value)
	if !ok {
		return 0, fmt.Errorf("jobstatus: count query returned an unexpected type: %T", value)
	}
	return int(counted.GetIntegerValue()), nil
}
