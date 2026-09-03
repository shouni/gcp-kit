package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/cloudtasks/apiv2/cloudtaskspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeTaskClient struct {
	req    *cloudtaskspb.CreateTaskRequest
	ctx    context.Context
	err    error
	closed bool
}

func (c *fakeTaskClient) CreateTask(ctx context.Context, req *cloudtaskspb.CreateTaskRequest) (*cloudtaskspb.Task, error) {
	c.req = req
	c.ctx = ctx
	if c.err != nil {
		return nil, c.err
	}
	return &cloudtaskspb.Task{Name: "projects/project/locations/asia-northeast1/queues/queue/tasks/task-id"}, nil
}

func (c *fakeTaskClient) Close() error {
	c.closed = true
	return nil
}

type samplePayload struct {
	UserID string `json:"user_id"`
	Count  int    `json:"count"`
}

func validConfig() Config {
	return Config{
		ProjectID:           "project",
		LocationID:          "asia-northeast1",
		QueueID:             "queue",
		WorkerURL:           "https://example.com/tasks",
		ServiceAccountEmail: "worker@example.iam.gserviceaccount.com",
		Audience:            "https://example.com/tasks",
	}
}

func TestValidateConfig(t *testing.T) {
	t.Parallel()

	valid := validConfig()

	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "valid",
			cfg:     valid,
			wantErr: false,
		},
		{
			name: "missing project id",
			cfg: Config{
				LocationID:          valid.LocationID,
				QueueID:             valid.QueueID,
				WorkerURL:           valid.WorkerURL,
				ServiceAccountEmail: valid.ServiceAccountEmail,
				Audience:            valid.Audience,
			},
			wantErr: true,
		},
		{
			name: "relative worker url",
			cfg: Config{
				ProjectID:           valid.ProjectID,
				LocationID:          valid.LocationID,
				QueueID:             valid.QueueID,
				WorkerURL:           "/tasks",
				ServiceAccountEmail: valid.ServiceAccountEmail,
				Audience:            valid.Audience,
			},
			wantErr: true,
		},
		{
			// Audience は省略可能で、その場合は WorkerURL が使われます。
			name: "missing audience defaults to worker url",
			cfg: Config{
				ProjectID:           valid.ProjectID,
				LocationID:          valid.LocationID,
				QueueID:             valid.QueueID,
				WorkerURL:           valid.WorkerURL,
				ServiceAccountEmail: valid.ServiceAccountEmail,
			},
			wantErr: false,
		},
		{
			name: "relative audience",
			cfg: Config{
				ProjectID:           valid.ProjectID,
				LocationID:          valid.LocationID,
				QueueID:             valid.QueueID,
				WorkerURL:           valid.WorkerURL,
				ServiceAccountEmail: valid.ServiceAccountEmail,
				Audience:            "/tasks",
			},
			wantErr: true,
		},
		{
			name:    "worker path without leading slash",
			cfg:     func() Config { c := validConfig(); c.WorkerPath = "tasks/run"; return c }(),
			wantErr: true,
		},
		{
			name:    "worker path with query",
			cfg:     func() Config { c := validConfig(); c.WorkerPath = "/tasks/run?x=1"; return c }(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Cloud Tasks はリクエストのデッドラインが 30 秒より先だと InvalidArgument を返すため、
// ジョブ全体の寿命を表す長い context をそのまま投入 RPC に渡してはいけません。
func TestEnqueueShortensALongCallerDeadlineForTheRPC(t *testing.T) {
	t.Parallel()

	client := &fakeTaskClient{}
	enqueuer, err := newEnqueuerWithClient[samplePayload](validConfig(), client)
	if err != nil {
		t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
	}

	// ワーカーのパイプライン上限のような長い context。
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	if err := enqueuer.Enqueue(ctx, samplePayload{UserID: "user-123", Count: 7}); err != nil {
		t.Fatalf("Enqueue() returned error: %v", err)
	}

	if client.ctx == nil {
		t.Fatalf("CreateTask was not called")
	}
	deadline, ok := client.ctx.Deadline()
	if !ok {
		t.Fatalf("CreateTask context has no deadline; Cloud Tasks would receive the caller's 45m deadline")
	}
	if remaining := time.Until(deadline); remaining > createTaskTimeout {
		t.Fatalf("CreateTask deadline is %s away, want at most %s", remaining, createTaskTimeout)
	}
	if createTaskTimeout >= 30*time.Second {
		t.Fatalf("createTaskTimeout = %s, must stay under the 30s Cloud Tasks accepts", createTaskTimeout)
	}
}

// 呼び出し元がすでに短い期限を切っている場合、それを延ばしてはいけません。
func TestEnqueueKeepsAnEarlierCallerDeadline(t *testing.T) {
	t.Parallel()

	client := &fakeTaskClient{}
	enqueuer, err := newEnqueuerWithClient[samplePayload](validConfig(), client)
	if err != nil {
		t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := enqueuer.Enqueue(ctx, samplePayload{UserID: "user-123", Count: 7}); err != nil {
		t.Fatalf("Enqueue() returned error: %v", err)
	}

	if client.ctx == nil {
		t.Fatalf("CreateTask was not called")
	}
	deadline, ok := client.ctx.Deadline()
	if !ok {
		t.Fatalf("CreateTask context has no deadline")
	}
	if remaining := time.Until(deadline); remaining > 2*time.Second {
		t.Fatalf("CreateTask deadline is %s away, want the caller's 2s to be preserved", remaining)
	}
}

func TestEnqueueBuildsCreateTaskRequest(t *testing.T) {
	t.Parallel()

	client := &fakeTaskClient{}
	enqueuer, err := newEnqueuerWithClient[samplePayload](validConfig(), client)
	if err != nil {
		t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
	}

	payload := samplePayload{UserID: "user-123", Count: 7}
	if err := enqueuer.Enqueue(context.Background(), payload); err != nil {
		t.Fatalf("Enqueue() returned error: %v", err)
	}

	req := client.req
	if req == nil {
		t.Fatalf("CreateTask was not called")
	}
	if req.GetParent() != "projects/project/locations/asia-northeast1/queues/queue" {
		t.Fatalf("Parent = %q", req.GetParent())
	}

	httpReq := req.GetTask().GetHttpRequest()
	if httpReq == nil {
		t.Fatalf("HttpRequest is nil")
	}
	if httpReq.GetHttpMethod() != cloudtaskspb.HttpMethod_POST {
		t.Fatalf("HttpMethod = %v, want POST", httpReq.GetHttpMethod())
	}
	if httpReq.GetUrl() != "https://example.com/tasks" {
		t.Fatalf("Url = %q", httpReq.GetUrl())
	}
	if got := httpReq.GetHeaders()["Content-Type"]; got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}

	var gotPayload samplePayload
	if err := json.Unmarshal(httpReq.GetBody(), &gotPayload); err != nil {
		t.Fatalf("Body is not valid JSON: %v", err)
	}
	if gotPayload != payload {
		t.Fatalf("Body payload = %+v, want %+v", gotPayload, payload)
	}

	oidc := httpReq.GetOidcToken()
	if oidc == nil {
		t.Fatalf("OidcToken is nil")
	}
	if oidc.GetServiceAccountEmail() != "worker@example.iam.gserviceaccount.com" {
		t.Fatalf("ServiceAccountEmail = %q", oidc.GetServiceAccountEmail())
	}
	if oidc.GetAudience() != "https://example.com/tasks" {
		t.Fatalf("Audience = %q", oidc.GetAudience())
	}
}

func TestEnqueueWithNameSetsDeterministicTaskName(t *testing.T) {
	t.Parallel()

	client := &fakeTaskClient{}
	enqueuer, err := newEnqueuerWithClient[samplePayload](validConfig(), client)
	if err != nil {
		t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
	}

	if err := enqueuer.EnqueueWithName(context.Background(), "job-1-cut-3", samplePayload{UserID: "user-123"}); err != nil {
		t.Fatalf("EnqueueWithName() returned error: %v", err)
	}

	wantName := "projects/project/locations/asia-northeast1/queues/queue/tasks/job-1-cut-3"
	if got := client.req.GetTask().GetName(); got != wantName {
		t.Fatalf("Task.Name = %q, want %q", got, wantName)
	}
}

func TestEnqueueWithNameTreatsAlreadyExistsAsSuccess(t *testing.T) {
	t.Parallel()

	client := &fakeTaskClient{err: status.Error(codes.AlreadyExists, "task already exists")}
	enqueuer, err := newEnqueuerWithClient[samplePayload](validConfig(), client)
	if err != nil {
		t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
	}

	if err := enqueuer.EnqueueWithName(context.Background(), "job-1-cut-3", samplePayload{}); err != nil {
		t.Fatalf("EnqueueWithName() returned error: %v, want nil (ALREADY_EXISTS treated as success)", err)
	}
}

func TestEnqueueWithNamePropagatesOtherErrors(t *testing.T) {
	t.Parallel()

	client := &fakeTaskClient{err: status.Error(codes.Internal, "boom")}
	enqueuer, err := newEnqueuerWithClient[samplePayload](validConfig(), client)
	if err != nil {
		t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
	}

	if err := enqueuer.EnqueueWithName(context.Background(), "job-1-cut-3", samplePayload{}); err == nil {
		t.Fatal("EnqueueWithName() error = nil, want error for non-ALREADY_EXISTS failure")
	}
}

func TestEnqueueWithNameRejectsEmptyTaskID(t *testing.T) {
	t.Parallel()

	client := &fakeTaskClient{}
	enqueuer, err := newEnqueuerWithClient[samplePayload](validConfig(), client)
	if err != nil {
		t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
	}

	if err := enqueuer.EnqueueWithName(context.Background(), "  ", samplePayload{}); err == nil {
		t.Fatal("EnqueueWithName() error = nil, want error for empty taskID")
	}
}

// TestValidateTaskID は、Cloud Tasks に往復させる前に不正なIDを弾くことを確認します。
func TestValidateTaskID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		taskID  string
		wantErr bool
	}{
		{name: "alphanumeric with hyphen and underscore", taskID: "job-1_cut-3", wantErr: false},
		{name: "max length", taskID: strings.Repeat("a", 500), wantErr: false},
		{name: "empty", taskID: "", wantErr: true},
		{name: "whitespace only", taskID: "   ", wantErr: true},
		{name: "slash is not allowed", taskID: "job/1", wantErr: true},
		{name: "colon is not allowed", taskID: "job:1", wantErr: true},
		{name: "dot is not allowed", taskID: "job.1", wantErr: true},
		{name: "too long", taskID: strings.Repeat("a", 501), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := validateTaskID(tt.taskID); (err != nil) != tt.wantErr {
				t.Fatalf("validateTaskID(%q) error = %v, wantErr %v", tt.taskID, err, tt.wantErr)
			}
		})
	}
}

func TestEnqueueWithNameRejectsInvalidTaskIDBeforeCallingAPI(t *testing.T) {
	t.Parallel()

	client := &fakeTaskClient{}
	enqueuer, err := newEnqueuerWithClient[samplePayload](validConfig(), client)
	if err != nil {
		t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
	}

	if err := enqueuer.EnqueueWithName(context.Background(), "job/1", samplePayload{}); err == nil {
		t.Fatal("EnqueueWithName() error = nil, want error for invalid taskID")
	}
	if client.req != nil {
		t.Fatal("CreateTask must not be called for an invalid taskID")
	}
}

// TestWorkerPathBuildsTheTarget は、WorkerURL と WorkerPath から配送先が組み立てられ、
// 末尾スラッシュや二重の継ぎ足しが正規化されることを確認します。配送先はルータの
// 登録と一字一句一致していないと届かないので、この正規化が要ります。
func TestWorkerPathBuildsTheTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		workerURL  string
		workerPath string
		want       string
	}{
		{name: "no path keeps the url", workerURL: "https://w.run.app/tasks/run", workerPath: "", want: "https://w.run.app/tasks/run"},
		{name: "joins onto a bare service url", workerURL: "https://w.run.app", workerPath: "/tasks/run", want: "https://w.run.app/tasks/run"},
		{name: "joins onto a trailing slash", workerURL: "https://w.run.app/", workerPath: "/tasks/run", want: "https://w.run.app/tasks/run"},
		{name: "does not double an existing path", workerURL: "https://w.run.app/tasks/run", workerPath: "/tasks/run", want: "https://w.run.app/tasks/run"},
		{name: "drops a trailing slash after the path", workerURL: "https://w.run.app/tasks/run/", workerPath: "/tasks/run", want: "https://w.run.app/tasks/run"},
		{name: "keeps a base path prefix", workerURL: "https://w.run.app/api", workerPath: "/tasks/run", want: "https://w.run.app/api/tasks/run"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := validConfig()
			cfg.WorkerURL = tt.workerURL
			cfg.WorkerPath = tt.workerPath
			cfg.Audience = ""

			client := &fakeTaskClient{}
			enqueuer, err := newEnqueuerWithClient[samplePayload](cfg, client)
			if err != nil {
				t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
			}
			if err := enqueuer.Enqueue(context.Background(), samplePayload{}); err != nil {
				t.Fatalf("Enqueue() returned error: %v", err)
			}

			if got := client.req.GetTask().GetHttpRequest().GetUrl(); got != tt.want {
				t.Fatalf("target URL = %q, want %q", got, tt.want)
			}
			// Audience の既定は継ぎ足す前の WorkerURL のままです（受信側はサービスの URL で照合します）。
			if got := client.req.GetTask().GetHttpRequest().GetOidcToken().GetAudience(); got != tt.workerURL {
				t.Fatalf("Audience = %q, want the bare WorkerURL %q", got, tt.workerURL)
			}
		})
	}
}

func TestAudienceDefaultsToWorkerURL(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Audience = ""

	client := &fakeTaskClient{}
	enqueuer, err := newEnqueuerWithClient[samplePayload](cfg, client)
	if err != nil {
		t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
	}

	if err := enqueuer.Enqueue(context.Background(), samplePayload{}); err != nil {
		t.Fatalf("Enqueue() returned error: %v", err)
	}

	got := client.req.GetTask().GetHttpRequest().GetOidcToken().GetAudience()
	if got != cfg.WorkerURL {
		t.Fatalf("Audience = %q, want %q", got, cfg.WorkerURL)
	}
}

func TestEnqueueWithOptions(t *testing.T) {
	t.Parallel()

	client := &fakeTaskClient{}
	enqueuer, err := newEnqueuerWithClient[samplePayload](validConfig(), client)
	if err != nil {
		t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
	}

	scheduleAt := time.Now().Add(90 * time.Second).UTC().Truncate(time.Second)
	name, err := enqueuer.EnqueueWithOptions(context.Background(), samplePayload{UserID: "u"},
		WithTaskID("job-1"),
		WithScheduleTime(scheduleAt),
		WithDispatchDeadline(10*time.Minute),
		WithHeader("X-Trace-Id", "trace-123"),
	)
	if err != nil {
		t.Fatalf("EnqueueWithOptions() returned error: %v", err)
	}
	if name == "" {
		t.Fatal("EnqueueWithOptions() returned an empty task name")
	}

	task := client.req.GetTask()
	if got := task.GetName(); got != "projects/project/locations/asia-northeast1/queues/queue/tasks/job-1" {
		t.Fatalf("Task.Name = %q", got)
	}
	if got := task.GetScheduleTime().AsTime(); !got.Equal(scheduleAt) {
		t.Fatalf("ScheduleTime = %v, want %v", got, scheduleAt)
	}
	if got := task.GetDispatchDeadline().AsDuration(); got != 10*time.Minute {
		t.Fatalf("DispatchDeadline = %v, want %v", got, 10*time.Minute)
	}
	headers := task.GetHttpRequest().GetHeaders()
	if headers["X-Trace-Id"] != "trace-123" {
		t.Fatalf("X-Trace-Id = %q, want %q", headers["X-Trace-Id"], "trace-123")
	}
	// カスタムヘッダーを渡しても Content-Type は維持されます。
	if headers["Content-Type"] != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", headers["Content-Type"])
	}
}

// TestValidateDeadlines は、パイプライン上限が Cloud Tasks の打ち切りより手前に
// 来ることの検査を固定します。等号を通さないのは、同時に切れるとアプリが失敗を記録する
// 前に接続が閉じるためです。
func TestValidateDeadlines(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pipeline time.Duration
		dispatch time.Duration
		wantErr  bool
	}{
		{name: "shorter than the deadline", pipeline: 20 * time.Minute, dispatch: 25 * time.Minute},
		{name: "shorter than the default deadline", pipeline: 9 * time.Minute, dispatch: 0},
		{name: "equal to the deadline", pipeline: 25 * time.Minute, dispatch: 25 * time.Minute, wantErr: true},
		{name: "equal to the default deadline", pipeline: 10 * time.Minute, dispatch: 0, wantErr: true},
		{name: "longer than the deadline", pipeline: 30 * time.Minute, dispatch: 25 * time.Minute, wantErr: true},
		{name: "non-positive pipeline", pipeline: 0, dispatch: 25 * time.Minute, wantErr: true},
		{name: "deadline out of range", pipeline: 1 * time.Minute, dispatch: time.Hour, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateDeadlines(tt.pipeline, tt.dispatch)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateDeadlines(%v, %v) error = %v, wantErr %v", tt.pipeline, tt.dispatch, err, tt.wantErr)
			}
		})
	}
}

// TestConfigDispatchDeadlineAppliesToEveryTask は、キュー共通の応答待ち時間が
// オプション無しの投入にも乗ることを確認します。長時間ジョブでは Cloud Tasks の
// 既定 10 分が実行時間の実効上限になってしまうため、ここが効かないと
// 呼び出し側が投入のたびにオプションを付ける運用に戻ります。
func TestConfigDispatchDeadlineAppliesToEveryTask(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.DispatchDeadline = 30 * time.Minute

	client := &fakeTaskClient{}
	enqueuer, err := newEnqueuerWithClient[samplePayload](cfg, client)
	if err != nil {
		t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
	}

	if err := enqueuer.Enqueue(context.Background(), samplePayload{}); err != nil {
		t.Fatalf("Enqueue() returned error: %v", err)
	}

	if got := client.req.GetTask().GetDispatchDeadline().AsDuration(); got != 30*time.Minute {
		t.Fatalf("DispatchDeadline = %v, want %v", got, 30*time.Minute)
	}
}

// TestWithDispatchDeadlineOverridesConfig は、タスク個別の指定がキュー共通の設定に
// 優先することを確認します。
func TestWithDispatchDeadlineOverridesConfig(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.DispatchDeadline = 30 * time.Minute

	client := &fakeTaskClient{}
	enqueuer, err := newEnqueuerWithClient[samplePayload](cfg, client)
	if err != nil {
		t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
	}

	if _, err := enqueuer.EnqueueWithOptions(context.Background(), samplePayload{},
		WithDispatchDeadline(5*time.Minute)); err != nil {
		t.Fatalf("EnqueueWithOptions() returned error: %v", err)
	}

	if got := client.req.GetTask().GetDispatchDeadline().AsDuration(); got != 5*time.Minute {
		t.Fatalf("DispatchDeadline = %v, want %v", got, 5*time.Minute)
	}
}

// TestDispatchDeadlineIsUnsetByDefault は、未指定なら Cloud Tasks の既定に委ねる
// （フィールドを立てない）ことを確認します。
func TestDispatchDeadlineIsUnsetByDefault(t *testing.T) {
	t.Parallel()

	client := &fakeTaskClient{}
	enqueuer, err := newEnqueuerWithClient[samplePayload](validConfig(), client)
	if err != nil {
		t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
	}

	if err := enqueuer.Enqueue(context.Background(), samplePayload{}); err != nil {
		t.Fatalf("Enqueue() returned error: %v", err)
	}

	if got := client.req.GetTask().GetDispatchDeadline(); got != nil {
		t.Fatalf("DispatchDeadline = %v, want unset", got)
	}
}

// TestValidateDispatchDeadline は、Cloud Tasks に往復させる前に範囲外の値を弾くことを
// 確認します。0 は「指定しない」なので許容します。
func TestValidateDispatchDeadline(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		deadline time.Duration
		wantErr  bool
	}{
		{name: "unset", deadline: 0, wantErr: false},
		{name: "minimum", deadline: 15 * time.Second, wantErr: false},
		{name: "maximum", deadline: 30 * time.Minute, wantErr: false},
		{name: "below minimum", deadline: 14 * time.Second, wantErr: true},
		{name: "above maximum", deadline: 31 * time.Minute, wantErr: true},
		{name: "negative", deadline: -time.Second, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := validateDispatchDeadline(tt.deadline); (err != nil) != tt.wantErr {
				t.Fatalf("validateDispatchDeadline(%v) error = %v, wantErr %v", tt.deadline, err, tt.wantErr)
			}
		})
	}
}

// TestNewEnqueuerRejectsOutOfRangeDispatchDeadline は、範囲外の設定が起動時に
// 落ちることを確認します。投入のたびに失敗させるより、構築時に気付けるほうがよいためです。
func TestNewEnqueuerRejectsOutOfRangeDispatchDeadline(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.DispatchDeadline = 45 * time.Minute

	if _, err := newEnqueuerWithClient[samplePayload](cfg, &fakeTaskClient{}); err == nil {
		t.Fatal("newEnqueuerWithClient() error = nil, want error for a deadline above 30m")
	}
}

// TestEnqueueRejectsOutOfRangeDispatchDeadlineBeforeCallingAPI は、タスク個別の
// 指定も投入前に弾かれることを確認します。
func TestEnqueueRejectsOutOfRangeDispatchDeadlineBeforeCallingAPI(t *testing.T) {
	t.Parallel()

	client := &fakeTaskClient{}
	enqueuer, err := newEnqueuerWithClient[samplePayload](validConfig(), client)
	if err != nil {
		t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
	}

	if _, err := enqueuer.EnqueueWithOptions(context.Background(), samplePayload{},
		WithDispatchDeadline(time.Hour)); err == nil {
		t.Fatal("EnqueueWithOptions() error = nil, want error for a deadline above 30m")
	}
	if client.req != nil {
		t.Fatal("CreateTask must not be called for an out-of-range dispatch deadline")
	}
}

func TestWithDelaySetsScheduleTime(t *testing.T) {
	t.Parallel()

	client := &fakeTaskClient{}
	enqueuer, err := newEnqueuerWithClient[samplePayload](validConfig(), client)
	if err != nil {
		t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
	}

	before := time.Now()
	if _, err := enqueuer.EnqueueWithOptions(context.Background(), samplePayload{}, WithDelay(time.Hour)); err != nil {
		t.Fatalf("EnqueueWithOptions() returned error: %v", err)
	}

	got := client.req.GetTask().GetScheduleTime().AsTime()
	if got.Before(before.Add(time.Hour)) || got.After(time.Now().Add(time.Hour)) {
		t.Fatalf("ScheduleTime = %v, want roughly one hour from now", got)
	}
}

func TestEnqueueWithOptionsReturnsCreatedTaskName(t *testing.T) {
	t.Parallel()

	client := &fakeTaskClient{err: status.Error(codes.AlreadyExists, "task already exists")}
	enqueuer, err := newEnqueuerWithClient[samplePayload](validConfig(), client)
	if err != nil {
		t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
	}

	// ALREADY_EXISTS は成功扱いのため、要求した名前がそのまま返ります。
	name, err := enqueuer.EnqueueWithOptions(context.Background(), samplePayload{}, WithTaskID("job-1"))
	if err != nil {
		t.Fatalf("EnqueueWithOptions() returned error: %v", err)
	}
	if want := "projects/project/locations/asia-northeast1/queues/queue/tasks/job-1"; name != want {
		t.Fatalf("name = %q, want %q", name, want)
	}
}

func TestNewEnqueuerWithClientRejectsNilClient(t *testing.T) {
	t.Parallel()

	if _, err := newEnqueuerWithClient[samplePayload](validConfig(), nil); err == nil {
		t.Fatalf("newEnqueuerWithClient() error = nil, want error")
	}
}

func TestEnqueueReturnsCreateTaskError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("create failed")
	client := &fakeTaskClient{err: wantErr}
	enqueuer, err := newEnqueuerWithClient[samplePayload](validConfig(), client)
	if err != nil {
		t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
	}

	if err := enqueuer.Enqueue(context.Background(), samplePayload{}); err == nil {
		t.Fatalf("Enqueue() error = nil, want error")
	}
}

func TestCloseClosesClient(t *testing.T) {
	t.Parallel()

	client := &fakeTaskClient{}
	enqueuer, err := newEnqueuerWithClient[samplePayload](validConfig(), client)
	if err != nil {
		t.Fatalf("newEnqueuerWithClient() returned error: %v", err)
	}

	if err := enqueuer.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}
	if !client.closed {
		t.Fatalf("client was not closed")
	}
}
