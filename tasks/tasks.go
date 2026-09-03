// Package tasks は、Cloud Tasks へのタスク投入（Enqueue）を行うユーティリティを提供します。
package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"regexp"
	"strings"
	"time"

	cloudtasks "cloud.google.com/go/cloudtasks/apiv2"
	"cloud.google.com/go/cloudtasks/apiv2/cloudtaskspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// taskIDPattern は Cloud Tasks が受け付けるタスクIDの文字種と長さです。
// 不正な値を API 往復させずに検出するため、投入前にローカルで検証します。
var taskIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,500}$`)

// createTaskTimeout は CreateTask 1 回分の RPC に与える上限です。
// Cloud Tasks はリクエストのデッドラインが 30 秒より先だと InvalidArgument を返すため、
// 30 秒より短く取る必要があります。
const createTaskTimeout = 20 * time.Second

// Config は Enqueuer の初期化に必要な設定です。
type Config struct {
	ProjectID           string
	LocationID          string
	QueueID             string
	WorkerURL           string // タスクの送信先。WorkerPath を使うならサービスの URL だけ
	ServiceAccountEmail string // OIDCトークン生成用
	// WorkerPath は、WorkerURL に継ぎ足す受信側のルートです（例: "/tasks/run"）。
	//
	// Cloud Tasks の配送先はワーカーが登録したルートと一字一句一致していないと届かず、
	// 末尾のスラッシュ 1 つで全件 404 になります。それを避ける結合と正規化を、5 つの
	// アプリが同じ 20 行で持っていたので、ここに置きます。WorkerURL が既にこのパスで
	// 終わっていれば二重に継ぎ足さず、末尾のスラッシュは落とします。
	//
	// 空なら WorkerURL をそのまま配送先にします。
	WorkerPath string
	// Audience はトークン検証用の audience です。空の場合は WorkerURL（WorkerPath を
	// 継ぎ足す前の値）が使われます。受信側 (oidc.New に渡す audience) と一致させてください。
	Audience string
	// DispatchDeadline は、このキューへ投入する全タスクに適用する応答待ち時間です。
	// 未指定 (0) は Cloud Tasks の既定である 10 分を意味します。
	//
	// 「待つ時間」ではなく「ワーカーの実行時間の実効上限」である点に注意してください。
	// これを超えるとワーカーがまだ処理中でも Cloud Tasks は待受を打ち切り、
	// リトライ対象になります。Cloud Run の timeout をいくら長くしてもこの上限は動かないため、
	// 長時間ジョブでは必ず明示してください。上限は HTTP ターゲットで 30 分です。
	//
	// タスク個別に変えたい場合は WithDispatchDeadline を使ってください（そちらが優先されます）。
	DispatchDeadline time.Duration
	// Logger は本パッケージが使うロガーです。未指定の場合は slog.Default() です。
	Logger *slog.Logger
}

// maxDispatchDeadline は HTTP ターゲットのタスクに指定できる応答待ち時間の上限です。
// 超えると Cloud Tasks が InvalidArgument を返すため、投入前にローカルで弾きます。
const maxDispatchDeadline = 30 * time.Minute

// minDispatchDeadline は同じく下限です。
const minDispatchDeadline = 15 * time.Second

// Queue は Enqueuer が満たすインターフェースです。
//
// アプリの port がこれを埋め込めば、Enqueuer を包むアダプタや、テスト用の偽物を
// 書くための独自インターフェースが要りません。
type Queue[T any] interface {
	Enqueue(ctx context.Context, payload T) error
	EnqueueWithName(ctx context.Context, taskID string, payload T) error
	EnqueueWithOptions(ctx context.Context, payload T, opts ...EnqueueOption) (string, error)
}

// Enqueuer は任意の型 T のペイロードを Cloud Tasks に投入する汎用構造体です。
type Enqueuer[T any] struct {
	client    taskClient
	cfg       Config
	parent    string
	targetURL string
}

var _ Queue[struct{}] = (*Enqueuer[struct{}])(nil)

type taskClient interface {
	CreateTask(context.Context, *cloudtaskspb.CreateTaskRequest) (*cloudtaskspb.Task, error)
	Close() error
}

type cloudTasksClient struct {
	client *cloudtasks.Client
}

func (c cloudTasksClient) CreateTask(ctx context.Context, req *cloudtaskspb.CreateTaskRequest) (*cloudtaskspb.Task, error) {
	return c.client.CreateTask(ctx, req)
}

func (c cloudTasksClient) Close() error {
	return c.client.Close()
}

// NewEnqueuer は新しい Enqueuer を生成します。
// 生成されたインスタンスは内部で gRPC コネクションプールを保持するため、
// アプリケーション全体でシングルトンとして再利用することが推奨されます。
func NewEnqueuer[T any](ctx context.Context, cfg Config) (*Enqueuer[T], error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	client, err := cloudtasks.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create cloud tasks client: %w", err)
	}

	enqueuer, err := newEnqueuerWithClient[T](cfg, cloudTasksClient{client: client})
	if err != nil {
		// コネクションを取りこぼさないよう、生成済みのクライアントを閉じます。
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close cloud tasks client: %w", closeErr))
		}
		return nil, err
	}
	return enqueuer, nil
}

func newEnqueuerWithClient[T any](cfg Config, client taskClient) (*Enqueuer[T], error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("tasks client must not be nil")
	}

	if strings.TrimSpace(cfg.Audience) == "" {
		cfg.Audience = cfg.WorkerURL
	}

	targetURL, err := workerTargetURL(cfg.WorkerURL, cfg.WorkerPath)
	if err != nil {
		return nil, err
	}

	parent := fmt.Sprintf("projects/%s/locations/%s/queues/%s",
		cfg.ProjectID, cfg.LocationID, cfg.QueueID)

	return &Enqueuer[T]{
		client:    client,
		cfg:       cfg,
		parent:    parent,
		targetURL: targetURL,
	}, nil
}

// workerTargetURL は、WorkerURL に WorkerPath を継ぎ足した配送先を返します。
// 挙動は Config.WorkerPath のとおりです。
func workerTargetURL(workerURL, workerPath string) (string, error) {
	workerPath = strings.TrimSpace(workerPath)
	if workerPath == "" {
		return workerURL, nil
	}

	parsed, err := url.Parse(workerURL)
	if err != nil {
		return "", fmt.Errorf("tasks config WorkerURL is invalid: %w", err)
	}
	// 末尾スラッシュは落とします。ルータは登録どおりのパスでしか一致しません。
	if trimmed := strings.TrimSuffix(parsed.Path, "/"); strings.HasSuffix(trimmed, workerPath) {
		parsed.Path = trimmed
		return parsed.String(), nil
	}

	joined, err := url.JoinPath(workerURL, workerPath)
	if err != nil {
		return "", fmt.Errorf("tasks config WorkerURL and WorkerPath cannot be joined: %w", err)
	}
	return joined, nil
}

func (e *Enqueuer[T]) log() *slog.Logger {
	if e != nil && e.cfg.Logger != nil {
		return e.cfg.Logger
	}
	return slog.Default()
}

// EnqueueOption は個別のタスク投入時の任意設定です。
type EnqueueOption func(*enqueueOptions)

type enqueueOptions struct {
	taskID           string
	scheduleTime     time.Time
	dispatchDeadline time.Duration
	headers          map[string]string
}

// WithTaskID は、taskID から導出した決定的なタスク名を設定します。
// 同じ taskID で複数回投入しても、Cloud Tasks が2回目以降を ALREADY_EXISTS で
// 拒否するため、実際に作られるタスクは1つだけになります（成功として扱われます）。
func WithTaskID(taskID string) EnqueueOption {
	return func(o *enqueueOptions) { o.taskID = taskID }
}

// WithScheduleTime は、タスクを実行する時刻を指定します（最大30日先まで）。
func WithScheduleTime(t time.Time) EnqueueOption {
	return func(o *enqueueOptions) { o.scheduleTime = t }
}

// WithDelay は、現在時刻から d 後にタスクを実行するよう指定します。
func WithDelay(d time.Duration) EnqueueOption {
	return func(o *enqueueOptions) { o.scheduleTime = time.Now().Add(d) }
}

// WithDispatchDeadline は、このタスクに限ってワーカーの応答を待つ時間を指定し、
// Config.DispatchDeadline を上書きします。
// この時間を超えるとリトライ対象になります（HTTPターゲットは15秒〜30分）。
func WithDispatchDeadline(d time.Duration) EnqueueOption {
	return func(o *enqueueOptions) { o.dispatchDeadline = d }
}

// WithHeader は、ワーカーへのリクエストに付与するヘッダーを追加します。
//
// Content-Type の既定は application/json で、同じキーを渡せば上書きできます。
// Authorization だけは指定しても効きません。OIDC トークンを設定してあるため、
// Cloud Tasks が配送時にこのヘッダーを上書きします。
func WithHeader(key, value string) EnqueueOption {
	return func(o *enqueueOptions) {
		if o.headers == nil {
			o.headers = map[string]string{}
		}
		o.headers[key] = value
	}
}

// Enqueue はタスクを Cloud Tasks キューに投入します。名前は Cloud Tasks が自動採番するため、
// 同じ内容で複数回呼び出すと重複したタスクが作成されます。呼び出し側の再試行等で同じ論理的な
// タスクが二重に作られてはいけない場合は EnqueueWithName を使ってください。
func (e *Enqueuer[T]) Enqueue(ctx context.Context, payload T) error {
	_, err := e.EnqueueWithOptions(ctx, payload)
	return err
}

// EnqueueWithName は、taskID から導出した決定的な名前でタスクを Cloud Tasks キューに投入します。
// taskID には英数字とハイフン・アンダースコアのみを含む短い識別子を渡してください
// （例: jobID + リビジョン/次カット番号）。同じ taskID で複数回呼び出しても、Cloud Tasks が
// 2回目以降を ALREADY_EXISTS で拒否するため、実際に作られるタスクは1つだけです
// （このメソッドはその ALREADY_EXISTS を成功として扱います）。
//
// 呼び出し元が「同じ論理的な続きタスクを重複して作らない」ことを保証したい場合
// （例: Cloud Tasks の at-least-once 配信により、続きタスクを enqueue する処理自体が
// 再実行される可能性がある場合）に使います。ただし、これは重複した「タスク作成」を防ぐだけで、
// 既存タスクの重複「配信」（同じタスクが2回ワーカーに届くこと）までは防げません。
// 配信重複への対策は、ワーカー側で処理済み状態を確認してから実処理を行う（冪等な処理）
// 必要があります。worker.MetadataFromContext で再試行回数を参照できます。
//
// なお、名前付きタスクは Cloud Tasks 側で重複排除のためのインデックスが必要になるため
// キューのスループットが低下し、また削除・完了したタスクの名前はしばらく再利用できません。
func (e *Enqueuer[T]) EnqueueWithName(ctx context.Context, taskID string, payload T) error {
	_, err := e.EnqueueWithOptions(ctx, payload, WithTaskID(taskID))
	return err
}

// EnqueueWithOptions はオプション付きでタスクを投入し、作成されたタスクの完全修飾名を返します。
// WithTaskID を指定した場合、ALREADY_EXISTS は成功として扱われ、その名前が返ります。
func (e *Enqueuer[T]) EnqueueWithOptions(ctx context.Context, payload T, opts ...EnqueueOption) (string, error) {
	var options enqueueOptions
	for _, opt := range opts {
		opt(&options)
	}

	if err := validateDispatchDeadline(options.dispatchDeadline); err != nil {
		return "", fmt.Errorf("dispatch deadline is invalid: %w", err)
	}

	var name string
	if options.taskID != "" {
		if err := validateTaskID(options.taskID); err != nil {
			return "", err
		}
		name = fmt.Sprintf("%s/tasks/%s", e.parent, options.taskID)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	createdName, err := e.createTask(ctx, name, body, options)
	if status.Code(err) == codes.AlreadyExists {
		// 期待される（異常ではない）経路: 呼び出し元の再試行等で同じ taskID が
		// 2回目以降に来た状態。createTask 側は ERROR ログを出さずに返しているため、
		// ここで INFO として記録するだけでよい。
		e.log().InfoContext(ctx, "Task already enqueued, treating as success", "task", name)
		return name, nil
	}
	if err != nil {
		e.log().ErrorContext(ctx, "Cloud Tasks enqueue failed",
			"error", err,
			"target", e.targetURL,
			"queue", e.cfg.QueueID,
		)
		return "", err
	}
	return createdName, nil
}

// validateTaskID は Cloud Tasks に送る前にタスクIDの形式を検証します。
func validateTaskID(taskID string) error {
	if strings.TrimSpace(taskID) == "" {
		return errors.New("taskID must not be empty")
	}
	if !taskIDPattern.MatchString(taskID) {
		return fmt.Errorf("taskID %q is invalid: must be 1-500 characters of [A-Za-z0-9_-]", taskID)
	}
	return nil
}

func (e *Enqueuer[T]) createTask(ctx context.Context, name string, body []byte, options enqueueOptions) (string, error) {
	headers := map[string]string{"Content-Type": "application/json"}
	maps.Copy(headers, options.headers)

	task := &cloudtaskspb.Task{
		Name: name,
		MessageType: &cloudtaskspb.Task_HttpRequest{
			HttpRequest: &cloudtaskspb.HttpRequest{
				HttpMethod: cloudtaskspb.HttpMethod_POST,
				Url:        e.targetURL,
				Body:       body,
				Headers:    headers,
				// OIDC 認証の設定
				AuthorizationHeader: &cloudtaskspb.HttpRequest_OidcToken{
					OidcToken: &cloudtaskspb.OidcToken{
						ServiceAccountEmail: e.cfg.ServiceAccountEmail,
						Audience:            e.cfg.Audience,
					},
				},
			},
		},
	}
	if !options.scheduleTime.IsZero() {
		task.ScheduleTime = timestamppb.New(options.scheduleTime)
	}
	// タスク個別の指定が無ければキュー共通の設定を使います。
	deadline := options.dispatchDeadline
	if deadline <= 0 {
		deadline = e.cfg.DispatchDeadline
	}
	if deadline > 0 {
		task.DispatchDeadline = durationpb.New(deadline)
	}

	// Cloud Tasks はリクエストのデッドラインが 30 秒より先だと、タスクの内容に関係なく
	// InvalidArgument で拒否します。呼び出し元はジョブ全体の寿命を表す長い context
	// （ワーカーのパイプライン上限など）をそのまま渡してくるのが自然なので、投入 RPC
	// 用の期限はここで切り直します。元の期限のほうが早ければ WithTimeout がそちらを
	// 残すため、短い context を渡している呼び出し元の意図は変わりません。
	ctx, cancel := context.WithTimeout(ctx, createTaskTimeout)
	defer cancel()

	createdTask, err := e.client.CreateTask(ctx, &cloudtaskspb.CreateTaskRequest{
		Parent: e.parent,
		Task:   task,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create task: %w", err)
	}

	e.log().InfoContext(ctx, "Task enqueued", "task", createdTask.GetName())
	return createdTask.GetName(), nil
}

func validateConfig(cfg Config) error {
	// エラーメッセージを再現可能にするため、map ではなく順序の定まったスライスで検証します。
	required := []struct {
		name  string
		value string
	}{
		{"ProjectID", cfg.ProjectID},
		{"LocationID", cfg.LocationID},
		{"QueueID", cfg.QueueID},
		{"WorkerURL", cfg.WorkerURL},
		{"ServiceAccountEmail", cfg.ServiceAccountEmail},
	}

	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("tasks config %s must not be empty", field.name)
		}
	}

	workerURL, err := url.Parse(cfg.WorkerURL)
	if err != nil || workerURL.Scheme == "" || workerURL.Host == "" {
		return errors.New("tasks config WorkerURL must be an absolute URL")
	}

	// パスだけを受けます。クエリや別ホストを混ぜると、どちらの値が配送先を決めるのか
	// 読めなくなります。
	if p := strings.TrimSpace(cfg.WorkerPath); p != "" {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#") {
			return errors.New("tasks config WorkerPath must be an absolute path without query or fragment")
		}
	}

	// Audience は未指定なら WorkerURL を使うため必須ではありませんが、
	// 明示された場合は絶対URLである必要があります。
	if audience := strings.TrimSpace(cfg.Audience); audience != "" {
		audienceURL, err := url.Parse(audience)
		if err != nil || audienceURL.Scheme == "" || audienceURL.Host == "" {
			return errors.New("tasks config Audience must be an absolute URL")
		}
	}

	if err := validateDispatchDeadline(cfg.DispatchDeadline); err != nil {
		return fmt.Errorf("tasks config DispatchDeadline is invalid: %w", err)
	}

	return nil
}

// validateDispatchDeadline は応答待ち時間が Cloud Tasks の受け付ける範囲かを検査します。
// 0 は「指定しない」を意味するため許容します。
func validateDispatchDeadline(d time.Duration) error {
	if d == 0 {
		return nil
	}
	if d < minDispatchDeadline || d > maxDispatchDeadline {
		return fmt.Errorf("must be between %s and %s, got %s",
			minDispatchDeadline, maxDispatchDeadline, d)
	}
	return nil
}

// Close はクライアントを閉じ、保持しているリソース（コネクションなど）を解放します。
func (e *Enqueuer[T]) Close() error {
	return e.client.Close()
}
