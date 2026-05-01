package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	cloudtasks "cloud.google.com/go/cloudtasks/apiv2"
	"cloud.google.com/go/cloudtasks/apiv2/cloudtaskspb"
)

// Config は Enqueuer の初期化に必要な設定です。
type Config struct {
	ProjectID           string
	LocationID          string
	QueueID             string
	WorkerURL           string // タスクの送信先エンドポイント
	ServiceAccountEmail string // OIDCトークン生成用
	Audience            string // トークン検証用 (通常は WorkerURL と同じ)
}

// Enqueuer は任意の型 T のペイロードを Cloud Tasks に投入する汎用構造体です。
type Enqueuer[T any] struct {
	client taskClient
	cfg    Config
	parent string
}

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

	return newEnqueuerWithClient[T](cfg, cloudTasksClient{client: client})
}

func newEnqueuerWithClient[T any](cfg Config, client taskClient) (*Enqueuer[T], error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("tasks client must not be nil")
	}

	parent := fmt.Sprintf("projects/%s/locations/%s/queues/%s",
		cfg.ProjectID, cfg.LocationID, cfg.QueueID)

	return &Enqueuer[T]{
		client: client,
		cfg:    cfg,
		parent: parent,
	}, nil
}

// Enqueue はタスクを Cloud Tasks キューに投入します。
func (e *Enqueuer[T]) Enqueue(ctx context.Context, payload T) error {
	// ペイロードを JSON に変換
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// タスクリクエストの構築
	req := &cloudtaskspb.CreateTaskRequest{
		Parent: e.parent,
		Task: &cloudtaskspb.Task{
			MessageType: &cloudtaskspb.Task_HttpRequest{
				HttpRequest: &cloudtaskspb.HttpRequest{
					HttpMethod: cloudtaskspb.HttpMethod_POST,
					Url:        e.cfg.WorkerURL,
					Body:       body,
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					// OIDC 認証の設定
					AuthorizationHeader: &cloudtaskspb.HttpRequest_OidcToken{
						OidcToken: &cloudtaskspb.OidcToken{
							ServiceAccountEmail: e.cfg.ServiceAccountEmail,
							Audience:            e.cfg.Audience,
						},
					},
				},
			},
		},
	}

	// Cloud Tasks への登録を実行
	createdTask, err := e.client.CreateTask(ctx, req)
	if err != nil {
		slog.Error("Cloud Tasks enqueue failed",
			"error", err,
			"target", e.cfg.WorkerURL,
			"queue", e.cfg.QueueID,
		)
		return fmt.Errorf("failed to create task: %w", err)
	}

	slog.Info("Task enqueued", "task", createdTask.GetName())
	return nil
}

func validateConfig(cfg Config) error {
	required := map[string]string{
		"ProjectID":           cfg.ProjectID,
		"LocationID":          cfg.LocationID,
		"QueueID":             cfg.QueueID,
		"WorkerURL":           cfg.WorkerURL,
		"ServiceAccountEmail": cfg.ServiceAccountEmail,
		"Audience":            cfg.Audience,
	}

	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("tasks config %s must not be empty", name)
		}
	}

	workerURL, err := url.Parse(cfg.WorkerURL)
	if err != nil || workerURL.Scheme == "" || workerURL.Host == "" {
		return fmt.Errorf("tasks config WorkerURL must be an absolute URL")
	}

	return nil
}

// Close はクライアントを閉じ、保持しているリソース（コネクションなど）を解放します。
func (e *Enqueuer[T]) Close() error {
	return e.client.Close()
}
