// Package tasks は、Cloud Tasks へのタスク投入（Enqueue）を行うユーティリティを提供します。
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

// Enqueue はタスクを Cloud Tasks キューに投入します。名前は Cloud Tasks が自動採番するため、
// 同じ内容で複数回呼び出すと重複したタスクが作成されます。呼び出し側の再試行等で同じ論理的な
// タスクが二重に作られてはいけない場合は EnqueueWithName を使ってください。
func (e *Enqueuer[T]) Enqueue(ctx context.Context, payload T) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}
	if err := e.createTask(ctx, "", body); err != nil {
		slog.Error("Cloud Tasks enqueue failed",
			"error", err,
			"target", e.cfg.WorkerURL,
			"queue", e.cfg.QueueID,
		)
		return err
	}
	return nil
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
// 必要があります。
func (e *Enqueuer[T]) EnqueueWithName(ctx context.Context, taskID string, payload T) error {
	if strings.TrimSpace(taskID) == "" {
		return fmt.Errorf("taskID must not be empty")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}
	name := fmt.Sprintf("%s/tasks/%s", e.parent, taskID)
	err = e.createTask(ctx, name, body)
	if status.Code(err) == codes.AlreadyExists {
		// 期待される（異常ではない）経路: 呼び出し元の再試行等で同じ taskID が
		// 2回目以降に来た状態。createTask 側は ERROR ログを出さずに返しているため、
		// ここで INFO として記録するだけでよい。
		slog.Info("Task already enqueued, treating as success", "task", name)
		return nil
	}
	if err != nil {
		slog.Error("Cloud Tasks enqueue failed",
			"error", err,
			"target", e.cfg.WorkerURL,
			"queue", e.cfg.QueueID,
		)
	}
	return err
}

func (e *Enqueuer[T]) createTask(ctx context.Context, name string, body []byte) error {
	req := &cloudtaskspb.CreateTaskRequest{
		Parent: e.parent,
		Task: &cloudtaskspb.Task{
			Name: name,
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
