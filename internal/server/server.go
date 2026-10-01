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
	"github.com/aloisdeniel/cairn/internal/store"
	"github.com/aloisdeniel/cairn/internal/versiondb"
)

// Config carries everything `cairn serve` resolves from flags and CAIRN_* env
// vars (flags win).
type Config struct {
	Addr          string
	DataDir       string
	BaseURL       string // external base URL; its scheme drives the Secure cookie flag
	TokenTTL      time.Duration
	AdminEmail    string // bootstrap admin, used only when the user table is empty
	AdminPassword string
	MaxUploadMB   int64 // decompressed size cap per uploaded version
	QueryTimeout  time.Duration
	MaxQueryRows  int
	Logger        *slog.Logger
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
}

// Server is the assembled application.
type Server struct {
	cfg    Config
	log    *slog.Logger
	store  *store.Store
	layout store.Layout
	secret []byte
	dbs    *versiondb.Manager
	mux    *http.ServeMux
	secure bool // serve behind https (from BaseURL)

	tmpl     *template.Template
	tmplOnce sync.Once
}

func New(cfg Config) (*Server, error) {
	cfg.applyDefaults()
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
	s := &Server{
		cfg:    cfg,
		log:    cfg.Logger,
		store:  st,
		layout: layout,
		secret: secret,
		dbs:    versiondb.NewManager(layout, cfg.QueryTimeout, cfg.MaxQueryRows),
		mux:    http.NewServeMux(),
	}
	if u, err := url.Parse(cfg.BaseURL); err == nil && u.Scheme == "https" {
		s.secure = true
	}
	if err := s.bootstrapAdmin(); err != nil {
		st.Close()
		return nil, err
	}
	s.routes()
	return s, nil
}

// bootstrapAdmin creates the first admin account when the user table is
// empty. The server refuses to start without one: everything else requires an
// authenticated admin. The account is created unclaimed — the admin chooses
// the password in the browser at first sign-in — unless a bootstrap password
// is explicitly provided (tests, automation).
func (s *Server) bootstrapAdmin() error {
	n, err := s.store.CountUsers()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if s.cfg.AdminEmail == "" {
		return errors.New("no users exist yet: provide --admin-email (or CAIRN_ADMIN_EMAIL) to create the first admin; its password is chosen in the browser at first sign-in")
	}
	u, err := s.store.CreateUser(s.cfg.AdminEmail, adminNameFromEmail(s.cfg.AdminEmail), true)
	if err != nil {
		return fmt.Errorf("create bootstrap admin: %w", err)
	}
	if s.cfg.AdminPassword == "" {
		s.log.Info("created bootstrap admin; sign in to choose its password", "email", u.Email)
		return nil
	}
	hash, err := auth.HashPassword(s.cfg.AdminPassword)
	if err != nil {
		return err
	}
	if err := s.store.SetPassword(u.ID, hash, false); err != nil {
		return err
	}
	s.log.Info("created bootstrap admin", "email", u.Email)
	return nil
}

func adminNameFromEmail(email string) string {
	name, _, _ := strings.Cut(email, "@")
	return name
}

// Handler wraps the route mux with request protection: every /api/ mutation
// that doesn't carry an Authorization header is checked against the server's
// own public origin (see protectMutations).
func (s *Server) Handler() http.Handler {
	return protectMutations(originOf(s.cfg.BaseURL), s.mux)
}

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s.mux,
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
