package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"runtime/pprof"
	"time"
)

// ErrPanicked は、Run が panic で終わったことを表すセンチネルエラーです。
//
// Lifecycle は panic を回復してこのエラーに畳み、Finish へ渡します。畳まないと
// 結末の記録まで到達せず、HTTP 側の Recoverer が 500 を返して終わります。状態は
// running のまま、通知も出ず、max_attempts = 1 のキューでは再試行も来ないので、
// そのジョブは永久に running です。
var ErrPanicked = errors.New("worker: run panicked")

// DefaultFinishTimeout は、Finish（結末の記録と通知）に与える既定の上限です。
const DefaultFinishTimeout = 30 * time.Second

// Lifecycle は、ジョブ 1 件の一生を固定した TaskExecutor です。
//
// 順序は Prepare → Begin → Validate → Run → Finish で、アプリはそれぞれの中身だけを
// 渡します。順序をライブラリが持つのは、この順序自体が過去の障害の再発防止だからです。
//
//   - Begin を Validate より前に置く。全試行が記録に載り、どのジョブも running を
//     経由して終端に至る。逆にすると、検証で落ちたジョブは queued のまま消える。
//   - Run にだけ Timeout を被せる。呼び出し元の ctx に被せると、打ち切られた直後の
//     Finish まで期限切れの ctx で走り、いちばん記録が要る場面で残らない。
//   - Finish は成功・失敗・panic のすべてで、切り離した ctx（context.WithoutCancel）で
//     必ず 1 度だけ呼ぶ。5 アプリのうち 3 つが失敗パスだけを切り離し、成功パスを
//     生の ctx で記録していた時期があり、期限と前後して完了したジョブが running の
//     まま固着した。成功と失敗が同じ関数を通る形にすると、片方だけ忘れる書き方が
//     表現できなくなる。
//
// 使わないフックは nil のままでよく、Run だけが必須です。
type Lifecycle[T, R any] struct {
	// Prepare は、以降のログに載せる相関キー（job_id など）を ctx へ足すためのフックです。
	// 返した ctx がこの先のすべてのフックに渡ります。nil なら何もしません。
	Prepare func(ctx context.Context, task T) context.Context

	// Labels は、pprof のゴルーチンラベルに載せるキーと値です（job_id / command など）。
	// Go 1.27 以降、ラベルはパニックのトレースバックの見出し行にも出るため、落ちたときに
	// どのジョブだったかがスタックだけで分かります。ログの相関は panic の経路では
	// 効かないので、そこを埋めるのがラベルの役目です。ラベルは子ゴルーチンにも継承されます。
	Labels func(task T) map[string]string

	// Begin は、再配信ガードと running の記録です。
	//
	// done=true なら Run も Finish も呼ばず、成功として返します（完了済みのジョブが
	// at-least-once 配信で再び届いた場合）。err を返すと同じく何も呼ばず、そのエラーを
	// そのまま返します。状態を読めないときに「進む」か「再配信に委ねる」かは、この
	// フックが決めます。nil なら常に実行します。
	Begin func(ctx context.Context, task T) (done bool, err error)

	// Validate は、配り直しても直らない入力の検証です。
	//
	// 失敗は Permanent に包んで Finish へ渡します。Finish がそのまま返せば、Handler は
	// 2xx を返して再配信を止めます。Begin の後に置くので、検証で落ちたジョブも
	// running を経由して failed に至ります。
	Validate func(task T) error

	// Run は本体です。Timeout があれば、その上限を被せた ctx で呼ばれます。
	// panic は回復して ErrPanicked に畳み、スタックをログへ出したうえで Finish へ渡します。
	Run func(ctx context.Context, task T) (R, error)

	// Finish は、結末の記録と通知です。
	//
	// 成功（cause == nil）でも失敗でも、呼び出し元の ctx から切り離した ctx で必ず
	// 1 度だけ呼ばれます。返り値が Execute の結果になります。失敗をそのまま返せば
	// Cloud Tasks が再配信し、Permanent（または Validate 由来の cause）を返せば
	// 2xx で打ち切られます。nil なら cause をそのまま返します。
	Finish func(ctx context.Context, task T, result R, cause error) error

	// Timeout は Run に与える実行時間の上限です。0 以下は無制限です。
	//
	// Cloud Tasks の dispatch deadline より短く取ってください。アプリが自分で先に
	// 諦めることで、Finish が失敗を記録して通知する余地が残ります。逆順だと
	// Cloud Tasks が先にリクエストを打ち切り、記録も通知も残りません。
	Timeout time.Duration

	// FinishTimeout は Finish に与える上限です。0 以下なら DefaultFinishTimeout です。
	FinishTimeout time.Duration

	// Logger は panic のスタックなどを出すロガーです。nil なら slog.Default() です。
	Logger *slog.Logger
}

// Execute は TaskExecutor を満たします。
func (l Lifecycle[T, R]) Execute(ctx context.Context, task T) error {
	if l.Run == nil {
		return errors.New("worker: Lifecycle.Run is required")
	}
	if l.Prepare != nil {
		ctx = l.Prepare(ctx, task)
	}

	var err error
	l.withLabels(ctx, task, func(ctx context.Context) {
		err = l.execute(ctx, task)
	})
	return err
}

func (l Lifecycle[T, R]) execute(ctx context.Context, task T) error {
	if l.Begin != nil {
		done, err := l.Begin(ctx, task)
		if err != nil {
			return err
		}
		if done {
			l.log().InfoContext(ctx, "Skipping a job that has already succeeded")
			return nil
		}
	}

	var zero R
	if l.Validate != nil {
		if err := l.Validate(task); err != nil {
			return l.finish(ctx, task, zero, Permanent(err))
		}
	}

	result, err := l.run(ctx, task)
	return l.finish(ctx, task, result, err)
}

// withLabels は、Labels があれば pprof のラベルを被せて fn を実行します。
//
// pprof.SetGoroutineLabels ではなく pprof.Do を使います。前者は復帰時にラベルを
// 戻さないため、keep-alive で同じゴルーチンが次のリクエストを捌くと、前のジョブの
// ラベルを背負ったままになります。
func (l Lifecycle[T, R]) withLabels(ctx context.Context, task T, fn func(ctx context.Context)) {
	if l.Labels == nil {
		fn(ctx)
		return
	}
	labels := l.Labels(task)
	if len(labels) == 0 {
		fn(ctx)
		return
	}
	pairs := make([]string, 0, len(labels)*2)
	for key, value := range labels {
		pairs = append(pairs, key, value)
	}
	pprof.Do(ctx, pprof.Labels(pairs...), fn)
}

// run は Run を上限つきの ctx で呼び、panic をエラーに畳みます。
func (l Lifecycle[T, R]) run(ctx context.Context, task T) (result R, err error) {
	defer func() {
		recovered := recover()
		if recovered == nil {
			return
		}
		l.log().ErrorContext(ctx, "Worker run panicked",
			"panic", recovered,
			"stack", string(debug.Stack()),
		)
		var zero R
		result, err = zero, fmt.Errorf("%w: %v", ErrPanicked, recovered)
	}()

	runCtx := ctx
	if l.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, l.Timeout)
		defer cancel()
	}
	return l.Run(runCtx, task)
}

// finish は Finish を、呼び出し元の ctx から切り離した ctx で呼びます。
//
// 打ち切りこそが終端の理由である場面（Timeout の発火、dispatch deadline 超過による
// リクエストのキャンセル）では ctx は既に Done です。そのまま使うと記録も通知も
// 両方失敗します。切り離したうえで上限を与え直すのは、記録先が応答しないときに
// ワーカーを無期限に占有しないためです。
func (l Lifecycle[T, R]) finish(ctx context.Context, task T, result R, cause error) error {
	if l.Finish == nil {
		return cause
	}
	timeout := l.FinishTimeout
	if timeout <= 0 {
		timeout = DefaultFinishTimeout
	}
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	return l.Finish(finishCtx, task, result, cause)
}

func (l Lifecycle[T, R]) log() *slog.Logger {
	if l.Logger != nil {
		return l.Logger
	}
	return slog.Default()
}
