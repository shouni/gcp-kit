// Package jobstatus は、非同期ジョブの進行状況を Firestore のドキュメントとして
// 読み書きし、履歴をクエリで一覧します。
//
// 生成の成否が通知にしか残らず、失敗したジョブが UI から消えていた問題を解消する
// ための記録層です。あわせて、Cloud Tasks の at-least-once 配信に対する再実行ガードの
// 根拠にもなります。
package jobstatus

import "time"

// State はジョブのライフサイクル上の状態です。
type State string

const (
	// StateQueued はキューへ投入済みで、まだワーカーが処理を始めていない状態です。
	StateQueued State = "queued"
	// StateRunning はワーカーが処理中の状態です。
	// 継続タスクへ分割して実行される処理では、引き継がれている間もこの状態です。
	StateRunning State = "running"
	// StateSucceeded は成果物の保存まで完了した状態です。
	StateSucceeded State = "succeeded"
	// StateFailed は処理が失敗した状態です。Cloud Tasks による再試行の対象になり得ます。
	StateFailed State = "failed"
)

// Status は、サービス間で共通するジョブ進行状況のフィールドです。
//
// 成果物の保存先はサービスごとに形が違う（単一 URI・出力ディレクトリ・複数 URI）ため、
// ここには持たせません。利用側は本構造体を埋め込んだ型を定義してください。
// Firestore も encoding/json も埋め込み構造体をフラットに展開するため、
// 保存されるドキュメントとレスポンス JSON は同じ形になります。
//
//	type JobStatus struct {
//	    jobstatus.Status
//	    OutputDir string `json:"output_dir,omitempty" firestore:"output_dir,omitempty"`
//	}
//
// firestore タグを省略しないでください。省略すると保存されるフィールド名が Go の
// 識別子（OutputDir）になり、json タグで組み立てた既存のレスポンスやクエリと
// 食い違います。
type Status struct {
	JobID   string `json:"job_id" firestore:"job_id"`
	Command string `json:"command,omitempty" firestore:"command,omitempty"`
	State   State  `json:"state" firestore:"state"`
	// Title は生成対象の題目が確定した時点で埋まります。
	Title string `json:"title,omitempty" firestore:"title,omitempty"`
	// Error は State が failed のときの失敗理由です。
	Error string `json:"error,omitempty" firestore:"error,omitempty"`
	// Attempts はワーカーが処理を開始した回数です。2 以上なら再試行されています。
	//
	// json だけ omitzero なのは encoding/json/v2 のためです。v2 の omitempty は
	// 数値の 0 を落とさないため、omitempty のままだと利用側が v2 へ移った時点で
	// attempts:0 が全応答に現れます。v1 の出力は omitzero でも変わりません。
	Attempts int `json:"attempts,omitzero" firestore:"attempts,omitempty"`

	// QueuedAt と UpdatedAt は Firestore の Timestamp として保存されます。
	// 文字列で持つと範囲クエリが辞書順になり、OrderBy の意味が表記の形式に
	// 依存するためです。
	QueuedAt  time.Time `json:"queued_at,omitzero" firestore:"queued_at"`
	UpdatedAt time.Time `json:"updated_at" firestore:"updated_at"`
}

// IsTerminal は、これ以上状態が変化しない（ポーリングを止めてよい）かどうかを返します。
//
// failed は Cloud Tasks が再試行しうるため終了とはみなしません。
func (s Status) IsTerminal() bool {
	return s.State == StateSucceeded
}

// Stamp は、Store が保存時にジョブ ID と更新時刻を打刻するために呼びます。
// 呼び出し側が UpdatedAt を設定し忘れても記録が残るようにするためのものです。
func (s *Status) Stamp(jobID string, now time.Time) {
	s.JobID = jobID
	s.UpdatedAt = now
}

// Common は、埋め込まれた共通フィールドをそのまま返します。
//
// Status を埋め込んだサービス固有の型から、共通部分だけを型引数なしで取り出すための
// ものです（埋め込みによりメソッドが昇格するため、利用側の実装は要りません）。
func (s Status) Common() Status {
	return s
}

// CarryOver は、前回の記録から引き継ぐべき共通フィールドを取り込みます。
//
// ワーカーは状態が変わるたびにタスクから状態を組み立て直すため、これが無いと
// 再試行のたびに試行回数と投入時刻が失われます。Title と Command は、今回の
// 組み立てで埋まっていない場合にだけ引き継ぎます（生成の途中で題目が確定する
// サービスがあるため、新しく判明した題目を古い値で上書きしないようにするためです）。
//
// State・Error・UpdatedAt は引き継ぎません。いずれも「今回の記録」を表す値で、
// 引き継ぐと成功後に古い失敗理由が残り続けます。
func (s *Status) CarryOver(prev Status) {
	s.Attempts = prev.Attempts
	s.QueuedAt = prev.QueuedAt
	if s.Title == "" {
		s.Title = prev.Title
	}
	if s.Command == "" {
		s.Command = prev.Command
	}
}

// EnsureJobID は、JobID が空のときだけ補います。
// job_id を持たない古い記録を読んだときに、呼び出し側が ID 無しの構造体を
// 受け取らないようにするためのものです。
func (s *Status) EnsureJobID(jobID string) {
	if s.JobID == "" {
		s.JobID = jobID
	}
}

// Stamper は、Store が共通フィールドを維持するために使うインターフェースです。
//
// Status を埋め込んだ型は、ポインタメソッドの昇格によって自動的にこれを満たします。
// 利用側が明示的に実装する必要はありません。逆に Status を埋め込んでいない型を
// Store に渡した場合、打刻は行われず渡された値がそのまま保存されます。
type Stamper interface {
	Stamp(jobID string, now time.Time)
	EnsureJobID(jobID string)
}

// Carrier は、前回の記録から共通フィールドを引き継ぐために Recorder が使う
// インターフェースです。Status を埋め込んだ型は自動的に満たします。
type Carrier interface {
	Common() Status
	CarryOver(prev Status)
}
