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
	}

	for _, tt := range tests {
		tt := tt
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
