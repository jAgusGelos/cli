// Command iwa-supervisor runs the Web App runner supervisor on its unix socket. Stopping it leaves running sessions
// alone; the gateway destroys them through the API.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Infisical/infisical-merge/packages/pam/webapp/supervisor"
)

func main() {
	logger := log.New(os.Stderr, "iwa-supervisor ", log.LstdFlags|log.Lmicroseconds)
	cfg, err := supervisor.ConfigFromEnv()
	if err != nil {
		logger.Fatalf("config: %v", err)
	}
	cfg.Logger = logger
	if len(cfg.Images) == 0 {
		logger.Printf("warning: %s is empty, every launch will be refused", supervisor.EnvImages)
	}
	srv := supervisor.New(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	prepCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = srv.Prepare(prepCtx)
	cancel()
	if err != nil {
		logger.Fatalf("prepare: %v", err)
	}

	ln, err := supervisor.Listen(cfg.SocketPath)
	if err != nil {
		logger.Fatalf("listen: %v", err)
	}
	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	logger.Printf("listening on %s (allowlist %d images, max runners %d, state %s)",
		cfg.SocketPath, len(cfg.Images), cfg.MaxRunners, cfg.StateDir)

	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.Serve(ln) }()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("serve: %v", err)
		}
	case <-ctx.Done():
		logger.Printf("shutting down; running sessions are left in place")
		shutCtx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutCtx); err != nil {
			logger.Printf("shutdown: %v", err)
		}
	}
	_ = os.Remove(cfg.SocketPath)
}
