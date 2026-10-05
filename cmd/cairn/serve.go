package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aloisdeniel/cairn/internal/mail"
	"github.com/aloisdeniel/cairn/internal/server"
)

// stringList accumulates repeated occurrences of a flag, for --signup-domain.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", envOr("CAIRN_ADDR", ":8787"), "listen address")
	dataDir := fs.String("data-dir", envOr("CAIRN_DATA_DIR", "data"), "data directory")
	publicURL := fs.String("public-url", envOr("CAIRN_PUBLIC_URL", ""), "external public URL (https enables Secure cookies); every emailed link is built from it")
	contentDomain := fs.String("content-domain", envOr("CAIRN_CONTENT_DOMAIN", ""), "domain each artifact is served under, as <artifact ID>.<domain>; defaults to localhost for a localhost public URL, otherwise required, and must not share a registrable domain with it")
	tokenTTL := fs.Duration("token-ttl", envDurationOr("CAIRN_TOKEN_TTL", 7*24*time.Hour), "JWT lifetime")
	adminEmail := fs.String("admin-email", envOr("CAIRN_ADMIN_EMAIL", ""), "address that may always sign up, and becomes an administrator when it does")
	smtpURL := fs.String("smtp-url", envOr("CAIRN_SMTP_URL", ""), "smtp://[user:pass@]host:port, or log:// to write mail to the server log (required)")
	mailFrom := fs.String("mail-from", envOr("CAIRN_MAIL_FROM", ""), "sender address (default cairn@<public-url host>)")
	var signupDomains stringList
	for _, d := range strings.Split(envOr("CAIRN_SIGNUP_DOMAINS", ""), ",") {
		if d = strings.TrimSpace(d); d != "" {
			signupDomains = append(signupDomains, d)
		}
	}
	fs.Var(&signupDomains, "signup-domain", "an email domain that may sign up (repeatable)")
	maxUploadMB := fs.Int64("max-upload-mb", envInt64Or("CAIRN_MAX_UPLOAD_MB", 256), "max pushed version or stored file size (MiB)")
	maxDBMB := fs.Int64("max-db-mb", envInt64Or("CAIRN_MAX_DB_MB", 50), "max database revision size (MiB)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *smtpURL == "" {
		return errors.New("--smtp-url (or CAIRN_SMTP_URL) is required: sign-up and reset cannot work without mail")
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	from := *mailFrom
	if from == "" {
		host := "localhost"
		if u, err := url.Parse(*publicURL); err == nil && u.Hostname() != "" {
			host = u.Hostname()
		}
		from = "cairn@" + host
	}
	sender, err := mail.New(*smtpURL, from, logger)
	if err != nil {
		return err
	}

	clk, err := serveClock()
	if err != nil {
		return err
	}
	srv, err := server.New(server.Config{
		Addr:          *addr,
		DataDir:       *dataDir,
		PublicURL:     *publicURL,
		ContentDomain: *contentDomain,
		TokenTTL:      *tokenTTL,
		SignupDomains: []string(signupDomains),
		AdminEmail:    *adminEmail,
		Mail:          sender,
		MaxUploadMB:   *maxUploadMB,
		MaxDBMB:       *maxDBMB,
		Logger:        logger,
		Clock:         clk,
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
