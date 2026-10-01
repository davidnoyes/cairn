// Package server implements the Cairn HTTP server: APIs, artifact serving and
// the admin UI.
package server

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aloisdeniel/cairn/internal/auth"
	"github.com/aloisdeniel/cairn/internal/clock"
	"github.com/aloisdeniel/cairn/internal/mail"
	"github.com/aloisdeniel/cairn/internal/store"
	"github.com/aloisdeniel/cairn/internal/versiondb"
)

// Config carries everything `cairn serve` resolves from flags and CAIRN_* env
// vars (flags win).
type Config struct {
	Addr          string
	DataDir       string
	PublicURL     string // external URL; its scheme drives the Secure cookie flag, and every emailed link is built from it
	TokenTTL      time.Duration
	SignupDomains []string    // email domains allowed to self-signup, besides AdminEmail
	AdminEmail    string      // may always sign up, and becomes an administrator when it does
	Mail          mail.Mailer // required: sign-up and reset cannot work without it
	MaxUploadMB   int64       // decompressed size cap per uploaded version
	QueryTimeout  time.Duration
	MaxQueryRows  int
	Logger        *slog.Logger
	Clock         clock.Clock // defaults to the wall clock; tests move it without sleeping
}

func (c *Config) applyDefaults() {
	if c.Addr == "" {
		c.Addr = ":8787"
	}
	if c.DataDir == "" {
		c.DataDir = "data"
	}
	if c.TokenTTL == 0 {
		c.TokenTTL = 7 * 24 * time.Hour
	}
	if c.MaxUploadMB == 0 {
		c.MaxUploadMB = 256
	}
	if c.QueryTimeout == 0 {
		c.QueryTimeout = 10 * time.Second
	}
	if c.MaxQueryRows == 0 {
		c.MaxQueryRows = 10_000
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Clock == nil {
		c.Clock = clock.Real{}
	}
	c.AdminEmail = normalizeEmail(c.AdminEmail)
	for i, d := range c.SignupDomains {
		c.SignupDomains[i] = strings.ToLower(strings.TrimSpace(d))
	}
}

// Server is the assembled application.
type Server struct {
	cfg            Config
	log            *slog.Logger
	store          *store.Store
	layout         store.Layout
	secret         []byte
	preloginSecret []byte
	dbs            *versiondb.Manager
	mux            *http.ServeMux
	secure         bool // serve behind https (from PublicURL)
	clk            clock.Clock
	mail           mail.Mailer

	signIn    *signInLimiters
	mailLimit *limiter

	tmpl     *template.Template
	tmplOnce sync.Once
}

func New(cfg Config) (*Server, error) {
	cfg.applyDefaults()
	if cfg.Mail == nil {
		return nil, errors.New("no mail sender configured: --smtp-url is required, because sign-up and reset cannot work without mail")
	}
	layout, err := store.NewLayout(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}
	st, err := store.Open(layout.MetaDB())
	if err != nil {
		return nil, fmt.Errorf("metadata db: %w", err)
	}
	secret, err := auth.LoadOrCreateSecret(layout.SecretFile())
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("signing secret: %w", err)
	}
	preloginSecret, err := auth.LoadOrCreateSecret(layout.PreloginSecretFile())
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("prelogin secret: %w", err)
	}
	s := &Server{
		cfg:            cfg,
		log:            cfg.Logger,
		store:          st,
		layout:         layout,
		secret:         secret,
		preloginSecret: preloginSecret,
		dbs:            versiondb.NewManager(layout, cfg.QueryTimeout, cfg.MaxQueryRows),
		mux:            http.NewServeMux(),
		clk:            cfg.Clock,
		mail:           cfg.Mail,
		signIn:         newSignInLimiters(cfg.Clock),
		mailLimit:      newMailLimiter(cfg.Clock),
	}
	if u, err := url.Parse(cfg.PublicURL); err == nil && u.Scheme == "https" {
		s.secure = true
	}
	s.routes()
	return s, nil
}

// Handler wraps the route mux with request protection: every /api/ mutation
// that doesn't carry an Authorization header is checked against the server's
// own public origin (see protectMutations).
func (s *Server) Handler() http.Handler {
	return protectMutations(originOf(s.cfg.PublicURL), s.mux)
}

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("cairn listening", "addr", s.cfg.Addr, "data", s.cfg.DataDir)
		errCh <- srv.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	s.log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := srv.Shutdown(shutdownCtx)
	s.dbs.Close()
	s.store.Close()
	return err
}
