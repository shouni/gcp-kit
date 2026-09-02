package jobstatus

// PageMeta は、一覧画面がページネーションを描画するために必要なメタデータです。
//
// JSON タグは既存サービスが返しているレスポンスと同じ形です。画面と M2M
// クライアントの双方が依存しているため、変更するときは利用側の追随が要ります。
type PageMeta struct {
	Page       int  `json:"page"`
	PerPage    int  `json:"per_page"`
	Total      int  `json:"total"`
	TotalPages int  `json:"total_pages"`
	HasPrev    bool `json:"has_prev"`
	HasNext    bool `json:"has_next"`
	PrevPage   int  `json:"prev_page"`
	NextPage   int  `json:"next_page"`
	From       int  `json:"from"`
	To         int  `json:"to"`
}

// newPageMeta は、総件数から 1 ページ分のメタデータを組み立てます。
//
// ページ番号は 1 始まりです。perPage が 0 以下のときはページングせず全件を 1 ページと
// して扱います。範囲外のページは最終ページへ丸めます（一覧の途中でジョブが削除され、
// 見ていたページが消えることがあるためです）。
func newPageMeta(page, perPage, total int) PageMeta {
	if total < 0 {
		total = 0
	}
	if perPage <= 0 {
		perPage = total
	}

	totalPages := 1
	if perPage > 0 {
		totalPages = max((total+perPage-1)/perPage, 1)
	}
	page = min(max(page, 1), totalPages)

	from, to := 0, 0
	if total > 0 && perPage > 0 {
		from = (page-1)*perPage + 1
		to = min(from+perPage-1, total)
	}

	return PageMeta{
		Page:       page,
		PerPage:    perPage,
		Total:      total,
		TotalPages: totalPages,
		HasPrev:    page > 1,
		HasNext:    page < totalPages,
		PrevPage:   max(page-1, 1),
		NextPage:   min(page+1, totalPages),
		From:       from,
		To:         to,
	}
}

// offset は、このページの先頭までに読み飛ばす件数です。
//
// Firestore は読み飛ばしたドキュメントも課金するため、深いページほどコストが
// 増えます。ページ番号を保つ代わりに払っている対価がここに集まっています。
func (m PageMeta) offset() int {
	if m.PerPage <= 0 {
		return 0
	}
	return (m.Page - 1) * m.PerPage
}
