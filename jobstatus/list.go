package jobstatus

import (
	"context"
	"errors"
	"fmt"

	"cloud.google.com/go/firestore"
	"cloud.google.com/go/firestore/apiv1/firestorepb"
	"google.golang.org/api/iterator"
)

// countAlias は件数集計クエリの結果を取り出すためのキーです。
const countAlias = "all"

// listOptions は List の絞り込みと並び順です。
type listOptions struct {
	state      State
	commands   []string
	fields     []fieldFilter
	orderBy    string
	descending bool
}

// fieldFilter は、サービス固有のフィールド 1 つに対する等値の絞り込みです。
type fieldFilter struct {
	path  string
	value any
}

// ListOption は List の挙動を変更します。
type ListOption func(*listOptions)

// newListOptions は既定値へオプションを適用します。
func newListOptions(opts []ListOption) listOptions {
	cfg := listOptions{orderBy: "queued_at", descending: true}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

// WithState は、指定した状態のジョブだけを一覧します。
func WithState(state State) ListOption {
	return func(o *listOptions) { o.state = state }
}

// WithCommand は、指定したコマンドのジョブだけを一覧します。
//
// 複数渡すと、そのいずれかに一致するジョブを返します。1 つのコマンドが 1 つの一覧に
// 対応するとは限らないためです（同じ履歴画面へ出したいコマンドが 2 つある、など）。
// Firestore の in 検索になるので値は 30 個までです。空文字は無視します。
func WithCommand(commands ...string) ListOption {
	return func(o *listOptions) {
		for _, command := range commands {
			if command != "" {
				o.commands = append(o.commands, command)
			}
		}
	}
}

// WithField は、サービス固有のフィールドが指定した値と等しいジョブだけを一覧します。
// path は Firestore のフィールド名です（Go の識別子ではなく firestore タグの名前）。
//
// State と Command はどのサービスでも同じ意味を持つので専用のオプションがありますが、
// それ以外の絞り込みはサービスごとに違います。ここが無いと、利用側は自分のフィールドで
// 絞るために全件を読んでメモリで落とすことになり、一覧を Firestore へ移した意味が
// 半分消えます。
//
// 等値だけです。範囲比較を許すと、Firestore が不等号のフィールドを並べ替えの先頭に
// 要求するため、WithOrderBy と組み合わせたときに黙って別の並び順になります。
func WithField(path string, value any) ListOption {
	return func(o *listOptions) {
		if path != "" {
			o.fields = append(o.fields, fieldFilter{path: path, value: value})
		}
	}
}

// WithOrderBy は並べ替えるフィールドと向きを変えます。
// 既定は queued_at の降順（新しい順）です。
//
// 絞り込みと組み合わせると複合索引が要ります。索引は Terraform などコードの側で
// 管理してください（手で足した索引が本番にだけ存在する状態にしないためです）。
// 絞り込みを付けない並べ替えだけなら、単一フィールドの自動索引で足ります。
func WithOrderBy(field string, descending bool) ListOption {
	return func(o *listOptions) {
		o.orderBy = field
		o.descending = descending
	}
}

// List は、ジョブ状態を新しい順に 1 ページ分返します。
//
// ページ番号は 1 始まり、perPage が 0 以下のときはページングせず全件を返します。
// Total は全件の読み込みではなく件数集計クエリで求めるため、ページの外にある
// ドキュメントは読みません。
//
// デコードに失敗したドキュメントはエラーとして返します。一覧から黙って落とすと、
// 壊れた記録があることに誰も気づきません。
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

	meta := newPageMeta(page, perPage, total)
	if total == 0 {
		return nil, meta, nil
	}

	query = orderedQuery(query, cfg)
	if meta.PerPage > 0 {
		query = query.Offset(meta.offset()).Limit(meta.PerPage)
	}

	items, err := collect[T](ctx, query)
	if err != nil {
		return nil, meta, err
	}
	return items, meta, nil
}

// Latest は、絞り込みに一致するジョブ状態を新しい順に limit 件返します。
// limit が 0 以下のときは一致するもの全件を返します。
//
// **件数集計をしません。** List が総件数を先に数えるのはページ送りのためで、
// 「最新の数件だけ並べる」画面には使い道がありません。抜粋しか出さない画面が、
// 開くたびに使わない集計クエリで 1 往復ぶん余計に待つことになります。
//
// PageMeta を返さないのも同じ理由です。総件数を知らないままページ情報を組み立てると、
// Total と TotalPages に 0 か当てずっぽうを入れることになり、受け取った側は
// 「本当に 0 件」なのか「数えていない」のかを区別できません。ページ送りが要るなら
// List を、要らないならこちらを使ってください。
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

// filteredQuery は、絞り込みだけを適用したクエリを返します。
// 件数集計と本体の取得が同じ条件を見るよう、組み立てを 1 か所に置きます。
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

// orderedQuery は並べ替えを適用します。
func orderedQuery(query firestore.Query, cfg listOptions) firestore.Query {
	direction := firestore.Asc
	if cfg.descending {
		direction = firestore.Desc
	}
	return query.OrderBy(cfg.orderBy, direction)
}

// collect はクエリの結果を T へデコードして集めます。
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
			return nil, fmt.Errorf("ジョブ状態のデコードに失敗しました (%s): %w", snap.Ref.ID, err)
		}
		if e, ok := any(&item).(interface{ EnsureJobID(string) }); ok {
			e.EnsureJobID(snap.Ref.ID)
		}
		items = append(items, item)
	}
}

// count は、絞り込みだけを適用したクエリの総件数を返します。
//
// ドキュメント本体は読まないため、一覧全体の件数を得るためにページの外を
// 走査する必要がありません。オブジェクトストレージ上の一覧が全走査を強いられて
// いたのは、これに相当する手段が無かったためです。
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
