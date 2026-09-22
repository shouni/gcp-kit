package jobstatus

import "github.com/shouni/go-utils/paging"

// PageMeta は、一覧画面がページネーションを描画するために必要なメタデータです。
//
// 実体は go-utils の paging.PageMeta です。GCS 系の一覧（go-job-kit/paging）と同じ型を
// 返すことで、両方を 1 つの型で受ける M2M クライアントに対して、空一覧の total_pages や
// 1 ページ目の prev_page といった端の値が食い違わないようにしています。
type PageMeta = paging.PageMeta
