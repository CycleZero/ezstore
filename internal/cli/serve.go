package cli

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ezstore/internal/transport/httpapi"
)

func cmdServe(cfgPath string, args []string) int {
	fs := newFlagSet("serve")
	addr := fs.String("addr", "", "listen address override, for example 127.0.0.1:8787")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	application, err := openApp(cfgPath)
	if err != nil {
		return fail(err)
	}
	defer application.Close()

	listenAddr := application.cfg.Server.Addr
	if *addr != "" {
		listenAddr = *addr
	}

	router := httpapi.NewRouter(httpapi.Deps{
		Secrets: application.secrets,
		Tokens:  application.tokens,
		Audit:   application.audit,
	}, os.Getenv("EZSTORE_DEBUG") != "")

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	fmt.Fprintf(os.Stderr, "ezstore http listening on %s (driver=%s)\n", listenAddr, application.store.Dialect())

	select {
	case err := <-errCh:
		return fail(err)
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fail(err)
	}
	log.Println("ezstore http stopped")
	return 0
}
