// Command panoptes-server is the Panoptes central server.
//
//	panoptes-server [-config file] [serve]
//	panoptes-server [-config file] token create <name> | token list | token revoke <name>
//	panoptes-server [-config file] user set-password <user>   (password on stdin)
//	panoptes-server -version
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"panoptes/internal/server/api"
	"panoptes/internal/server/config"
	"panoptes/internal/server/core"
	"panoptes/internal/server/feeds"
	"panoptes/internal/server/match"
	"panoptes/internal/server/pipeline"
	"panoptes/internal/server/store"
)

// version is set at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("panoptes-server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to server.yaml (default $PANOPTES_CONFIG or /etc/panoptes/server.yaml)")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Usage = func() {
		fmt.Fprint(stderr, `usage: panoptes-server [-config file] [command]

commands:
  serve                       run the server (default)
  token create <name>         create an enrollment token (printed once)
  token list                  list enrollment tokens
  token revoke <name>         revoke an enrollment token
  user set-password <user>    set (or create) a web user; password is read from stdin
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "panoptes-server", version)
		return 0
	}
	rest := fs.Args()
	cmd := "serve"
	if len(rest) > 0 {
		cmd, rest = rest[0], rest[1:]
	}
	// allow "-config" after the subcommand too
	sub := flag.NewFlagSet(cmd, flag.ContinueOnError)
	sub.SetOutput(stderr)
	sub.StringVar(cfgPath, "config", *cfgPath, "path to server.yaml")
	if err := sub.Parse(rest); err != nil {
		return 2
	}
	rest = sub.Args()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "config:", err)
		return 1
	}
	var cerr error
	switch cmd {
	case "serve":
		cerr = serve(cfg)
	case "token":
		cerr = tokenCmd(cfg, rest, stdout, stderr)
	case "user":
		cerr = userCmd(cfg, rest, stdin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", cmd)
		fs.Usage()
		return 2
	}
	if cerr != nil {
		fmt.Fprintln(stderr, "error:", cerr)
		return 1
	}
	return 0
}

func openStore(cfg *config.Config) (*store.SQLite, error) {
	return store.OpenSQLite(cfg.DBPath())
}

// --- wiring -----------------------------------------------------------------

// components are the swappable plug points (see internal/server/core).
type components struct {
	Evaluator core.RuleEvaluator
	Notifier  core.Notifier
	Drafter   core.RuleDrafter
	// Mount lets other packages (web UI) register routes on the shared mux.
	Mount []func(mux *http.ServeMux)
}

// wire is THE place where real implementations replace the no-op defaults.
// TODO(wave 2): rules.NewEngine(...) -> Evaluator, notify.NewMatrix(...) -> Notifier,
// llm.NewDrafter(...) -> Drafter, web.Mount -> Mount.
func wire(cfg *config.Config, st store.Store, log *slog.Logger) components {
	_ = cfg
	_ = st
	_ = log
	return components{
		Evaluator: core.NoopEvaluator{},
		Notifier:  core.NoopNotifier{},
		Drafter:   core.NoopDrafter{},
	}
}

// --- serve ------------------------------------------------------------------

func serve(cfg *config.Config) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("create data_dir: %w", err)
	}
	st, err := openStore(cfg)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := ensureAdmin(ctx, cfg, st, log); err != nil {
		return err
	}

	comp := wire(cfg, st, log)
	grypeDB := match.NewGrype(cfg.GrypeDBDir(), log)
	defer grypeDB.Close()
	pipe := pipeline.New(st, grypeDB, comp.Evaluator, comp.Notifier, comp.Drafter,
		pipeline.Options{PublicURL: cfg.PublicURL, Logger: log})

	mux := api.NewMux(api.Deps{Store: st, Evaluator: comp.Evaluator, Pipeline: pipe, Logger: log})
	for _, m := range comp.Mount {
		m(mux)
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           api.LogRequests(log, mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute, // inventory uploads up to 64 MiB
		IdleTimeout:       2 * time.Minute,
	}

	updater := &feeds.Updater{
		DB: grypeDB, Store: st, Interval: cfg.Feeds.Interval, Update: cfg.Feeds.Update, Log: log,
		OnUpdated: func(ctx context.Context) {
			if err := pipe.TriggerAll(ctx); err != nil {
				log.Error("re-run pipeline after feed update", "err", err)
			}
		},
	}
	feedsDone := make(chan struct{})
	go func() { defer close(feedsDone); updater.Run(ctx) }()

	errCh := make(chan error, 1)
	go func() {
		log.Info("panoptes-server listening", "addr", cfg.Listen, "version", version, "data_dir", cfg.DataDir)
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			stop()
			<-feedsDone
			pipe.Shutdown()
			return fmt.Errorf("listen: %w", err)
		}
	case <-ctx.Done():
		log.Info("shutting down")
	}
	shCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shCtx); err != nil {
		log.Warn("http shutdown", "err", err)
	}
	<-feedsDone
	pipe.Shutdown()
	return nil
}

// ensureAdmin creates user "admin" from the configured env var when no users exist yet.
func ensureAdmin(ctx context.Context, cfg *config.Config, st store.Store, log *slog.Logger) error {
	n, err := st.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 || cfg.Admin.InitialPasswordEnv == "" {
		return nil
	}
	pw := os.Getenv(cfg.Admin.InitialPasswordEnv)
	if pw == "" {
		log.Warn("no web users exist; set the admin password env var or run 'user set-password admin'", "env", cfg.Admin.InitialPasswordEnv)
		return nil
	}
	hash, err := store.HashPassword(pw)
	if err != nil {
		return err
	}
	if err := st.CreateUser(ctx, "admin", hash); err != nil && !errors.Is(err, store.ErrExists) {
		return err
	}
	log.Info("created initial admin user", "user", "admin")
	return nil
}

// --- token / user commands --------------------------------------------------

func tokenCmd(cfg *config.Config, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: token create <name> | token list | token revoke <name>")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return err
	}
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	switch args[0] {
	case "create":
		if len(args) != 2 || strings.TrimSpace(args[1]) == "" {
			return errors.New("usage: token create <name>")
		}
		secret, hash, err := store.NewSecret("pt_")
		if err != nil {
			return err
		}
		if err := st.CreateEnrollToken(ctx, args[1], hash); err != nil {
			if errors.Is(err, store.ErrExists) {
				return fmt.Errorf("a token named %q already exists", args[1])
			}
			return err
		}
		fmt.Fprintln(stderr, "Enrollment token created. It is shown only once:")
		fmt.Fprintln(stdout, secret)
	case "list":
		toks, err := st.ListEnrollTokens(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tCREATED\tLAST USED\tSTATUS")
		for _, t := range toks {
			status, used := "active", "never"
			if t.Revoked {
				status = "revoked"
			}
			if !t.LastUsed.IsZero() {
				used = t.LastUsed.Format(time.RFC3339)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.Name, t.CreatedAt.Format(time.RFC3339), used, status)
		}
		return tw.Flush()
	case "revoke":
		if len(args) != 2 {
			return errors.New("usage: token revoke <name>")
		}
		if err := st.RevokeEnrollToken(ctx, args[1]); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("no token named %q", args[1])
			}
			return err
		}
		fmt.Fprintf(stdout, "token %q revoked (agents already enrolled keep working)\n", args[1])
	default:
		return fmt.Errorf("unknown token command %q", args[0])
	}
	return nil
}

func userCmd(cfg *config.Config, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) != 2 || args[0] != "set-password" {
		return errors.New("usage: user set-password <user>   (password on stdin)")
	}
	user := strings.TrimSpace(args[1])
	if user == "" {
		return errors.New("empty user name")
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return fmt.Errorf("read password from stdin: %w", err)
	}
	pw := strings.TrimRight(line, "\r\n")
	if len(pw) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return err
	}
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	hash, err := store.HashPassword(pw)
	if err != nil {
		return err
	}
	ctx := context.Background()
	switch err := st.SetUserPassword(ctx, user, hash); {
	case err == nil:
		fmt.Fprintf(stdout, "password for %q updated\n", user)
	case errors.Is(err, store.ErrNotFound):
		if err := st.CreateUser(ctx, user, hash); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "user %q created\n", user)
	default:
		return err
	}
	return nil
}
