// Package tasks provides utilities for enqueuing tasks to Cloud Tasks.
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

// taskIDPattern is the character set and length Cloud Tasks accepts for a
// task ID. It is checked locally before enqueuing, to catch a bad value
// without an API round trip.
var taskIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,500}$`)

// createTaskTimeout bounds a single CreateTask RPC. Cloud Tasks returns
// InvalidArgument when a request's deadline is more than 30 seconds out, so it
// has to be shorter than 30 seconds.
const createTaskTimeout = 20 * time.Second

// Config holds the settings needed to initialise an Enqueuer.
type Config struct {
	ProjectID           string
	LocationID          string
	QueueID             string
	WorkerURL           string // where tasks are sent; just the service URL when WorkerPath is used
	ServiceAccountEmail string // for minting the OIDC token
	// WorkerPath is the receiving route appended to WorkerURL (for example
	// "/tasks/run").
	//
	// A Cloud Tasks target must match the worker's registered route byte for
	// byte, or nothing arrives; one trailing slash turns every task into a
	// 404. Five apps carried the same 20 lines of joining and normalising to
	// avoid that, so it lives here. If WorkerURL already ends in this path it
	// is not appended twice, and a trailing slash is dropped.
	//
	// Empty means WorkerURL is the target as is.
	WorkerPath string
	// Audience is the audience for token verification. When empty, WorkerURL
	// (before WorkerPath is appended) is used. Match it to the receiving side
	// (the audience passed to oidc.New).
	Audience string
	// DispatchDeadline is how long to wait for a response, applied to every
	// task enqueued to this queue. Unset (0) means Cloud Tasks' default of 10
	// minutes.
	//
	// Note that it is not "time to wait" but the worker's effective run-time
	// limit. Past it, Cloud Tasks stops waiting even while the worker is still
	// processing, and the task becomes subject to retry. No Cloud Run timeout
	// moves this limit, so always set it explicitly for long jobs. The maximum
	// for HTTP targets is 30 minutes.
	//
	// To change it for a single task, use WithDispatchDeadline (which takes
	// precedence).
	DispatchDeadline time.Duration
	// Logger is the logger this package uses. It defaults to slog.Default().
	Logger *slog.Logger
}

// DefaultDispatchDeadline is the default Cloud Tasks applies when
// Config.DispatchDeadline is not set.
const DefaultDispatchDeadline = 10 * time.Minute

// maxDispatchDeadline is the longest dispatch deadline an HTTP-target task
// may have. Beyond it Cloud Tasks returns InvalidArgument, so it is rejected
// locally before enqueuing.
const maxDispatchDeadline = 30 * time.Minute

// minDispatchDeadline is the corresponding minimum.
const minDispatchDeadline = 15 * time.Second

// Enqueuer is a generic type that enqueues payloads of any type T to Cloud Tasks.
type Enqueuer[T any] struct {
	client    taskClient
	cfg       Config
	parent    string
	targetURL string
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

// NewEnqueuer creates a new Enqueuer. The instance holds a gRPC connection
// pool internally, so reusing it as a singleton across the application is
// recommended.
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
		// Close the client already created so the connection is not leaked.
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

// workerTargetURL returns the target built by appending WorkerPath to
// WorkerURL, behaving as described on Config.WorkerPath.
func workerTargetURL(workerURL, workerPath string) (string, error) {
	workerPath = strings.TrimSpace(workerPath)
	if workerPath == "" {
		return workerURL, nil
	}

	parsed, err := url.Parse(workerURL)
	if err != nil {
		return "", fmt.Errorf("tasks config WorkerURL is invalid: %w", err)
	}
	// Drop a trailing slash: routers match only the path exactly as registered.
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

// EnqueueOption is an optional setting for one enqueue.
type EnqueueOption func(*enqueueOptions)

type enqueueOptions struct {
	taskID           string
	scheduleTime     time.Time
	dispatchDeadline time.Duration
	headers          map[string]string
}

// WithTaskID sets a deterministic task name derived from taskID. Enqueuing
// with the same taskID several times creates only one task, because Cloud
// Tasks rejects the later ones with ALREADY_EXISTS (treated as success).
func WithTaskID(taskID string) EnqueueOption {
	return func(o *enqueueOptions) { o.taskID = taskID }
}

// WithScheduleTime sets when the task runs (up to 30 days ahead).
func WithScheduleTime(t time.Time) EnqueueOption {
	return func(o *enqueueOptions) { o.scheduleTime = t }
}

// WithDelay makes the task run d after now.
func WithDelay(d time.Duration) EnqueueOption {
	return func(o *enqueueOptions) { o.scheduleTime = time.Now().Add(d) }
}

// WithDispatchDeadline sets how long to wait for the worker's response for
// this task only, overriding Config.DispatchDeadline. Past it, the task
// becomes subject to retry (15 seconds to 30 minutes for HTTP targets).
func WithDispatchDeadline(d time.Duration) EnqueueOption {
	return func(o *enqueueOptions) { o.dispatchDeadline = d }
}

// WithHeader adds a header to the request sent to the worker.
//
// Content-Type defaults to application/json and can be overridden with the
// same key. Authorization alone has no effect: an OIDC token is configured,
// so Cloud Tasks overwrites that header on delivery.
func WithHeader(key, value string) EnqueueOption {
	return func(o *enqueueOptions) {
		if o.headers == nil {
			o.headers = map[string]string{}
		}
		o.headers[key] = value
	}
}

// Enqueue adds a task to the Cloud Tasks queue. Cloud Tasks assigns the name,
// so calling it several times with the same content creates duplicate tasks.
// When the same logical task must not be created twice (on a caller's retry,
// for example), use EnqueueWithName.
func (e *Enqueuer[T]) Enqueue(ctx context.Context, payload T) error {
	_, err := e.EnqueueWithOptions(ctx, payload)
	return err
}

// EnqueueWithName adds a task to the Cloud Tasks queue under a deterministic
// name derived from taskID. Pass a short identifier of letters, digits,
// hyphens and underscores only (for example jobID + revision / next cut
// number). Calling it several times with the same taskID creates only one
// task, because Cloud Tasks rejects the later ones with ALREADY_EXISTS (this
// method treats that ALREADY_EXISTS as success).
//
// Use it when the caller must guarantee "never create the same logical
// continuation task twice" (for example when, under Cloud Tasks'
// at-least-once delivery, the code enqueuing the continuation may itself run
// again). It prevents duplicate task *creation* only, not duplicate
// *delivery* of an existing task (the same task reaching the worker twice).
// Against duplicate delivery the worker has to check whether the work is
// already done before doing it (idempotent processing).
// worker.MetadataFromContext exposes the retry count.
//
// Named tasks need a deduplication index on the Cloud Tasks side, which
// lowers the queue's throughput, and names of deleted or completed tasks
// cannot be reused for a while.
//
// An empty taskID is an error. In EnqueueWithOptions an empty one means "no
// name", so passing it through would create an unnamed task, and a caller's
// ID computation merely returning empty would silently disable
// deduplication.
func (e *Enqueuer[T]) EnqueueWithName(ctx context.Context, taskID string, payload T) error {
	if err := validateTaskID(taskID); err != nil {
		return err
	}
	_, err := e.EnqueueWithOptions(ctx, payload, WithTaskID(taskID))
	return err
}

// EnqueueWithOptions enqueues a task with options and returns the created
// task's fully qualified name. With WithTaskID, ALREADY_EXISTS is treated as
// success and that name is returned.
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
		// An expected (not abnormal) path: the same taskID arriving a second
		// time, on a caller's retry or the like. createTask returned without
		// an ERROR log, so recording it as INFO here is enough.
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

// validateTaskID checks the task ID's format before it is sent to Cloud Tasks.
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
				// OIDC authentication
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
	// Without a per-task value, the queue-wide setting is used.
	deadline := options.dispatchDeadline
	if deadline <= 0 {
		deadline = e.cfg.DispatchDeadline
	}
	if deadline > 0 {
		task.DispatchDeadline = durationpb.New(deadline)
	}

	// Cloud Tasks rejects a request whose deadline is more than 30 seconds
	// out with InvalidArgument, whatever the task contains. Callers naturally
	// pass the long context covering the whole job's life (the worker's
	// pipeline limit, for example) straight in, so the enqueue RPC's deadline
	// is cut again here. If the original deadline is earlier, WithTimeout
	// keeps it, so a caller passing a short context gets what it intended.
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
	// Checked over an ordered slice rather than a map so the error message is reproducible.
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

	// Only a path is accepted. Mixing in a query or another host would make it
	// unclear which value decides the target.
	if p := strings.TrimSpace(cfg.WorkerPath); p != "" {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#") {
			return errors.New("tasks config WorkerPath must be an absolute path without query or fragment")
		}
	}

	// Audience is optional, since WorkerURL is used when it is unset, but
	// when given it must be an absolute URL.
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

// validateDispatchDeadline checks that the dispatch deadline is within the
// range Cloud Tasks accepts. 0 means "not set" and is allowed.
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

// Close closes the client and releases the resources it holds (connections and so on).
func (e *Enqueuer[T]) Close() error {
	return e.client.Close()
}
