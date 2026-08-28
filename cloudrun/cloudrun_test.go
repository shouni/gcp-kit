package cloudrun_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shouni/gcp-kit/cloudrun"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestHealth(t *testing.T) {
	rec := httptest.NewRecorder()
	cloudrun.Health(rec, httptest.NewRequest(http.MethodGet, cloudrun.HealthPath, nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "ok" {
		t.Errorf("body = %q, want %q", got, "ok")
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
}

// TestHealthPath は、Cloud Run の GFE に食われる /healthz を選ばないことを固定します。
// ローカルでは通るのにデプロイすると 404 になるため、テストでしか守れません。
func TestHealthPath(t *testing.T) {
	if cloudrun.HealthPath != "/health" {
		t.Errorf("HealthPath = %q, want /health（/healthz は *.run.app の GFE が横取りする）",
			cloudrun.HealthPath)
	}
}

func TestNewServerDefaults(t *testing.T) {
	srv := cloudrun.NewServer(cloudrun.Config{Port: "8080", Handler: http.NotFoundHandler()})

	if srv.Addr != ":8080" {
		t.Errorf("Addr = %q, want :8080", srv.Addr)
	}
	if srv.ReadHeaderTimeout != cloudrun.DefaultReadHeaderTimeout {
		t.Errorf("ReadHeaderTimeout = %v, want %v", srv.ReadHeaderTimeout, cloudrun.DefaultReadHeaderTimeout)
	}
	if srv.IdleTimeout != cloudrun.DefaultIdleTimeout {
		t.Errorf("IdleTimeout = %v, want %v", srv.IdleTimeout, cloudrun.DefaultIdleTimeout)
	}
	// WriteTimeout に既定値を置くと、数分かかる worker の応答を途中で切ります。
	if srv.WriteTimeout != 0 {
		t.Errorf("WriteTimeout = %v, want 0（既定では縛らない）", srv.WriteTimeout)
	}
	if srv.ReadTimeout != 0 {
		t.Errorf("ReadTimeout = %v, want 0（既定では縛らない）", srv.ReadTimeout)
	}
}

func TestNewServerOverrides(t *testing.T) {
	srv := cloudrun.NewServer(cloudrun.Config{
		Port:              "9090",
		Handler:           http.NotFoundHandler(),
		ReadHeaderTimeout: time.Second,
		IdleTimeout:       2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      4 * time.Second,
	})

	for _, tt := range []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"ReadHeaderTimeout", srv.ReadHeaderTimeout, time.Second},
		{"IdleTimeout", srv.IdleTimeout, 2 * time.Second},
		{"ReadTimeout", srv.ReadTimeout, 3 * time.Second},
		{"WriteTimeout", srv.WriteTimeout, 4 * time.Second},
	} {
		if tt.got != tt.want {
			t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}

func TestServeRejectsIncompleteConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  cloudrun.Config
	}{
		{"Handler なし", cloudrun.Config{Port: "8080"}},
		{"Port なし", cloudrun.Config{Handler: http.NotFoundHandler()}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := cloudrun.Serve(context.Background(), tt.cfg); err == nil {
				t.Error("Serve = nil, want エラー")
			}
		})
	}
}

// TestServeShutsDownOnContextCancel は、ctx が終わったらサーバーが止まり、
// Serve が返ることを検証します。
func TestServeShutsDownOnContextCancel(t *testing.T) {
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())

	served := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- cloudrun.Serve(ctx, cloudrun.Config{
			Port:   port,
			Logger: discardLogger(),
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				close(served)
				w.WriteHeader(http.StatusOK)
			}),
		})
	}()

	// 実際に待ち受けていることを、リクエストが通ることで確かめます。
	waitForServer(t, port)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://127.0.0.1:" + port + "/")
	if err != nil {
		t.Fatalf("リクエストが通りません: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("ハンドラーに到達しませんでした")
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ctx をキャンセルしても Serve が返りません")
	}
}

// TestServeReportsListenFailure は、待ち受けに失敗したら ctx を待たずに
// 返ることを検証します。ポートが塞がっているのに黙って動き続けると、
// デプロイが「起動したのに応答しない」形で失敗します。
//
// 実際の引き金は使用中のポートですが、それを再現しようと 127.0.0.1 を占有しても
// macOS では全インターフェースへのバインドが通ってしまい、失敗しませんでした。
// 検証したいのは「待ち受けの失敗が Serve から返る」ことなので、OS の挙動に
// 依存しない不正なポート番号で起こします。
func TestServeReportsListenFailure(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		done <- cloudrun.Serve(context.Background(), cloudrun.Config{
			Port:    "99999", // 65535 を超える
			Handler: http.NotFoundHandler(),
			Logger:  discardLogger(),
		})
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("Serve = nil, want 待ち受け失敗のエラー")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("待ち受けに失敗しても Serve が返りません")
	}
}

// TestServeForcesCloseOnSlowHandler は、猶予内に終わらない接続があっても
// Serve が返ることを検証します。返らなければ Cloud Run の SIGKILL 待ちになります。
func TestServeForcesCloseOnSlowHandler(t *testing.T) {
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())

	handling := make(chan struct{})
	release := make(chan struct{})
	defer close(release)

	done := make(chan error, 1)
	go func() {
		done <- cloudrun.Serve(ctx, cloudrun.Config{
			Port:            port,
			Logger:          discardLogger(),
			ShutdownTimeout: 50 * time.Millisecond,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				close(handling)
				<-release // 猶予を超えて掴み続ける
				w.WriteHeader(http.StatusOK)
			}),
		})
	}()

	waitForServer(t, port)
	go func() {
		// 応答は返らない。接続を掴ませるためだけのリクエストなので、
		// テストが終わったら諦めるようタイムアウトを付けます。
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get("http://127.0.0.1:" + port + "/slow")
		if err == nil {
			_ = resp.Body.Close()
		}
	}()

	select {
	case <-handling:
	case <-time.After(5 * time.Second):
		t.Fatal("ハンドラーに到達しませんでした")
	}

	cancel()

	select {
	case err := <-done:
		// 強制クローズに至ったことはエラーで分かる。返ってくることが要点。
		if err == nil {
			t.Log("猶予内に停止しました（掴んでいる接続が既に切れていた）")
		} else if !errors.Is(err, context.DeadlineExceeded) {
			t.Logf("強制停止しました: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("掴んでいる接続があると Serve が返りません")
	}
}

// freePort は、空いている TCP ポート番号を返します。
func freePort(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	return port
}

// waitForServer は、待ち受けが始まるまで TCP 接続を試します。
//
// HTTP リクエストを投げないのは、意図的にブロックするハンドラーを持つテストが
// あるためです。到達確認のつもりの 1 本がそこで固まります。
func waitForServer(t *testing.T, port string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("サーバーが待ち受けを始めませんでした")
}

// TestServeUsesDefaultLogger は、Logger 未指定でも slog.Default() へ倒れて
// 落ちないことを検証します。他の設定と同じくゼロ値で動く必要があります。
func TestServeUsesDefaultLogger(t *testing.T) {
	var buf bytes.Buffer
	restore := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(restore) })

	// 不正なポートで即座に返す。起動ログはこの時点で既に出ている。
	if err := cloudrun.Serve(context.Background(), cloudrun.Config{
		Port:    "99999",
		Handler: http.NotFoundHandler(),
	}); err == nil {
		t.Fatal("Serve = nil, want エラー")
	}
	if buf.Len() == 0 {
		t.Error("slog.Default() へ出力されていません")
	}
}
