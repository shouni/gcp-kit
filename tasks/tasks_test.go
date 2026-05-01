package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"cloud.google.com/go/cloudtasks/apiv2/cloudtaskspb"
)

type fakeTaskClient struct {
	req    *cloudtaskspb.CreateTaskRequest
	err    error
	closed bool
}

func (c *fakeTaskClient) CreateTask(_ context.Context, req *cloudtaskspb.CreateTaskRequest) (*cloudtaskspb.Task, error) {
	c.req = req
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
			name: "missing audience",
			cfg: Config{
				ProjectID:           valid.ProjectID,
				LocationID:          valid.LocationID,
				QueueID:             valid.QueueID,
				WorkerURL:           valid.WorkerURL,
				ServiceAccountEmail: valid.ServiceAccountEmail,
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
