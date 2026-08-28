// Package cloudrun は、Cloud Run 上で HTTP サーバーを動かすときに毎回同じ答えに
// なる部分を持ちます。ヘルスチェックの公開と、起動から停止までの面倒です。
//
// 語彙（web / worker）は serverrole、ログは cloudlog が持ちます。ここにあるのは
// 「プロセスがどう受けて、どう止まるか」だけです。
package cloudrun

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// HealthPath は、ヘルスチェックを公開するパスです。
//
// **"/healthz" を使いません。** Cloud Run の既定ドメイン (*.run.app) では GFE 側が
// このパスを予約パス的に扱い、リクエストがコンテナへ届く前に汎用の 404 へ
// 置き換えられます。ローカルでは通るのにデプロイすると 404 になる、という形で
// しか現れないので、名前をここに固定しておきます。
const HealthPath = "/health"

// Health は、200 と "ok" を返すヘルスチェックハンドラーです。
//
// 依存の生死は見ません。Cloud Run のヘルスチェックが落ちるとインスタンスごと
// 入れ替えられるため、ここで下流の障害を伝えると、下流が復旧するまで
// 再起動を繰り返すだけになります。プロセスが応答できることだけを答えます。
func Health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// 既定値。Cloud Run の性質から決まる値です。
const (
	// DefaultReadHeaderTimeout はヘッダー読み取りに許す時間です。
	//
	// Cloud Run は同時リクエスト数でスケールするため、ヘッダーを少しずつ送り
	// 続ける接続に数本掴まれるだけでインスタンスが詰まります（Slowloris）。
	// 正常なクライアントには十分すぎる短さで足ります。
	DefaultReadHeaderTimeout = 5 * time.Second

	// DefaultIdleTimeout は keep-alive 接続を保持する上限です。
	DefaultIdleTimeout = 120 * time.Second

	// DefaultShutdownTimeout は SIGTERM 後に停止を待つ上限です。
	// Cloud Run が SIGKILL するまでの猶予より長く取っても待ち切れないため、
	// デプロイ側の設定に合わせて Config で上書きしてください。
	DefaultShutdownTimeout = 15 * time.Second
)

// Config は Serve の設定です。Port と Handler だけが必須です。
type Config struct {
	// Port は待ち受けるポートです。Cloud Run が PORT 環境変数で渡します。
	// Listener を指定した場合は使いません。
	Port string
	// Handler はルーターです。
	Handler http.Handler

	// Listener を指定すると、Port で待ち受ける代わりにこのリスナーを使います。
	//
	// テストのためにあります。ポート 0 で開いたリスナーを渡せば、空きポートを
	// 探して接続できるまでポーリングする、という迂回をせずにサーバーを起動できます。
	// 起動と正常停止をキットが持つ以上、それを試せる形にするのもキットの役目です
	// （さもないと、テストしたいアプリが自前のサーブループを抱え続けます）。
	//
	// Serve は、自分で開いたリスナーもここで渡されたリスナーも閉じます。
	Listener net.Listener

	// ReadHeaderTimeout / IdleTimeout は 0 なら既定値です。
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration

	// ReadTimeout / WriteTimeout は 0 なら設定しません（無制限）。
	//
	// **WriteTimeout に既定値を置かないのは意図的です。** worker 面のハンドラーは
	// 数分から数十分かかることがあり、既定値を置くと正常な応答を途中で切ります。
	// 実行時間の上限は Cloud Tasks の DispatchDeadline とアプリ側のタイムアウトが
	// 受け持つので、ここは既定では縛りません。
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// ShutdownTimeout は 0 なら DefaultShutdownTimeout です。
	ShutdownTimeout time.Duration

	// Logger は未指定なら slog.Default() です。
	Logger *slog.Logger
}

// Serve はサーバーを起動し、ctx が終わるまで動かしてから正常に停止します。
//
// シグナルの購読はしません。signal.NotifyContext などで作った ctx を渡して
// ください。停止の理由（シグナルか、上位の失敗か）を決めるのは呼び出し側です。
//
//	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
//	defer stop()
//	return cloudrun.Serve(ctx, cloudrun.Config{Port: port, Handler: router})
func Serve(ctx context.Context, cfg Config) error {
	if cfg.Handler == nil {
		return errors.New("cloudrun: Handler must not be nil")
	}
	if cfg.Port == "" && cfg.Listener == nil {
		return errors.New("cloudrun: Port または Listener のどちらかが要ります")
	}

	ln := cfg.Listener
	if ln == nil {
		// ListenConfig を使うのは ctx を尊重させるためです。起動直後に停止が
		// 掛かった場合、待ち受けの確立まで待たずに諦められます。
		var lc net.ListenConfig
		var err error
		if ln, err = lc.Listen(ctx, "tcp", net.JoinHostPort("", cfg.Port)); err != nil {
			return fmt.Errorf("cloudrun: ポート %s で待ち受けられません: %w", cfg.Port, err)
		}
	}

	srv := cfg.newServer()
	log := cfg.logger()

	serverErrors := make(chan error, 1)
	go func() {
		log.InfoContext(ctx, "HTTP サーバーを起動しました", "addr", ln.Addr().String())
		// Serve はリスナーを閉じて返るため、渡されたリスナーもここで閉じられます。
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()

	select {
	case err := <-serverErrors:
		return fmt.Errorf("cloudrun: サーバーが異常終了しました: %w", err)
	case <-ctx.Done():
		log.InfoContext(ctx, "停止シグナルを受け取りました。正常停止を開始します")
		return shutdown(srv, cfg.shutdownTimeout(), log)
	}
}

// NewServer は Serve が使う *http.Server を組み立てます。
// 自分でライフサイクルを持ちたい場合に、既定値だけを借りられるよう公開しています。
func NewServer(cfg Config) *http.Server {
	return cfg.newServer()
}

func (c Config) newServer() *http.Server {
	return &http.Server{
		Addr:              net.JoinHostPort("", c.Port),
		Handler:           c.Handler,
		ReadHeaderTimeout: orDefault(c.ReadHeaderTimeout, DefaultReadHeaderTimeout),
		IdleTimeout:       orDefault(c.IdleTimeout, DefaultIdleTimeout),
		// 0 は「設定しない」の意味なので、そのまま渡します。
		ReadTimeout:  c.ReadTimeout,
		WriteTimeout: c.WriteTimeout,
	}
}

// shutdown は、猶予の内に停止しなければ強制的に閉じます。
//
// Shutdown が失敗したまま返ると、接続を掴んだままプロセスが残り、Cloud Run の
// SIGKILL を待つことになります。掴んでいる接続を切ってでも終わらせます。
func shutdown(srv *http.Server, timeout time.Duration, log *slog.Logger) error {
	// 停止の猶予は、キャンセル済みの ctx とは別に取ります。
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.ErrorContext(ctx, "正常停止に失敗しました。強制的に閉じます", "error", err)
		if closeErr := srv.Close(); closeErr != nil {
			return errors.Join(err, fmt.Errorf("cloudrun: 強制クローズにも失敗しました: %w", closeErr))
		}
		return fmt.Errorf("cloudrun: 正常停止に失敗したため強制停止しました: %w", err)
	}

	log.InfoContext(ctx, "サーバーは正常に停止しました")
	return nil
}

func (c Config) shutdownTimeout() time.Duration {
	return orDefault(c.ShutdownTimeout, DefaultShutdownTimeout)
}

func (c Config) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

func orDefault(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}
