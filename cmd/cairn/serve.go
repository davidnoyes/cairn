package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/aloisdeniel/cairn/internal/server"
)

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", envOr("CAIRN_ADDR", ":8787"), "listen address")
	dataDir := fs.String("data-dir", envOr("CAIRN_DATA_DIR", "data"), "data directory")
	baseURL := fs.String("base-url", envOr("CAIRN_BASE_URL", ""), "external base URL (https enables Secure cookies)")
	tokenTTL := fs.Duration("token-ttl", envDurationOr("CAIRN_TOKEN_TTL", 7*24*time.Hour), "JWT lifetime")
	adminEmail := fs.String("admin-email", envOr("CAIRN_ADMIN_EMAIL", ""), "bootstrap admin email (first run only)")
	adminPassword := fs.String("admin-password", envOr("CAIRN_ADMIN_PASSWORD", ""), "bootstrap admin password (first run only)")
	maxUploadMB := fs.Int64("max-upload-mb", envInt64Or("CAIRN_MAX_UPLOAD_MB", 256), "max decompressed upload size (MiB)")
	queryTimeout := fs.Duration("query-timeout", envDurationOr("CAIRN_QUERY_TIMEOUT", 10*time.Second), "shared database query timeout")
	maxQueryRows := fs.Int("max-query-rows", int(envInt64Or("CAIRN_MAX_QUERY_ROWS", 10000)), "max rows returned per query")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	srv, err := server.New(server.Config{
		Addr:          *addr,
		DataDir:       *dataDir,
		BaseURL:       *baseURL,
		TokenTTL:      *tokenTTL,
		AdminEmail:    *adminEmail,
		AdminPassword: *adminPassword,
		MaxUploadMB:   *maxUploadMB,
		QueryTimeout:  *queryTimeout,
		MaxQueryRows:  *maxQueryRows,
		Logger:        logger,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Run(ctx)
}

func envDurationOr(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envInt64Or(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}
