package jobstatus

import (
	"context"
	"fmt"
	"sync"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/option"
)

// ClientFactory は、Firestore クライアントのライフサイクルを持ちます。
//
// Close と Client は並行に呼ばれても安全です。
type ClientFactory struct {
	mu     sync.RWMutex
	client *firestore.Client
	// ownsClient は、Close でクライアントを閉じてよいかを表します。
	// WithClient で注入されたクライアントのライフサイクルは呼び出し元にあります。
	ownsClient bool
}

// settings は Option を解決した結果です。
type settings struct {
	client     *firestore.Client
	projectID  string
	database   string
	clientOpts []option.ClientOption
}

// Option は ClientFactory の生成方法を変える Functional Option です。
type Option func(*settings)

// WithClient は生成済みの Firestore クライアントを使います。
//
// このクライアントのライフサイクルは呼び出し元に残り、ClientFactory.Close は
// 閉じません（閉じる主体が 2 つあると、どちらが所有しているのか呼び出し側から
// 分からなくなるためです）。
func WithClient(client *firestore.Client) Option {
	return func(s *settings) { s.client = client }
}

// WithProjectID は接続先のプロジェクトを指定します。
// 省略した場合は実行環境から検出します（firestore.DetectProjectID）。
func WithProjectID(projectID string) Option {
	return func(s *settings) { s.projectID = projectID }
}

// WithDatabase は既定以外の Firestore データベースを指定します。
func WithDatabase(database string) Option {
	return func(s *settings) { s.database = database }
}

// WithClientOptions は firestore.NewClient へ渡すオプションを指定します。
// 認証情報の差し替えなどに使います。
//
// エミュレータは FIRESTORE_EMULATOR_HOST をクライアント側が解釈するため、
// ここでの指定は要りません。
func WithClientOptions(opts ...option.ClientOption) Option {
	return func(s *settings) { s.clientOpts = append(s.clientOpts, opts...) }
}

// New は ClientFactory を作成します。
func New(ctx context.Context, opts ...Option) (*ClientFactory, error) {
	cfg := settings{projectID: firestore.DetectProjectID}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	if cfg.client != nil {
		return &ClientFactory{client: cfg.client, ownsClient: false}, nil
	}

	var (
		client *firestore.Client
		err    error
	)
	if cfg.database == "" {
		client, err = firestore.NewClient(ctx, cfg.projectID, cfg.clientOpts...)
	} else {
		client, err = firestore.NewClientWithDatabase(ctx, cfg.projectID, cfg.database, cfg.clientOpts...)
	}
	if err != nil {
		return nil, fmt.Errorf("firestore クライアントの初期化に失敗しました: %w", err)
	}
	return &ClientFactory{client: client, ownsClient: true}, nil
}

// Close は保持している Firestore クライアントを解放します。冪等です。
// WithClient で注入されたクライアントは閉じず、参照だけを手放します。
func (f *ClientFactory) Close() error {
	f.mu.Lock()
	client, owns := f.client, f.ownsClient
	f.client = nil
	f.mu.Unlock()

	if client == nil || !owns {
		return nil
	}
	return client.Close()
}

// Client はクライアントが存命かを確かめて返します。
func (f *ClientFactory) Client() (*firestore.Client, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if f.client == nil {
		return nil, fmt.Errorf("firestore クライアントは既にクローズされているか、初期化されていません: %w", ErrClosed)
	}
	return f.client, nil
}
