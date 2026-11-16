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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"panoptes/internal/model"
	"panoptes/internal/server/api"
	"panoptes/internal/server/config"
	"panoptes/internal/server/core"
	"panoptes/internal/server/feeds"
	"panoptes/internal/server/llm"
	"panoptes/internal/server/match"
	"panoptes/internal/server/notify"
	"panoptes/internal/server/pipeline"
	"panoptes/internal/server/rules"
	"panoptes/internal/server/store"
	"panoptes/internal/server/web"
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
	// Start runs background workers (LLM drafter) once the server context exists.
	Start []func(ctx context.Context)
}

// lateTrigger lets components built before the pipeline (web UI, LLM drafter)
// re-run it later. The pipeline pointer is set right after pipeline.New.
type lateTrigger struct {
	p   *pipeline.Pipeline
	log *slog.Logger
}

func (l *lateTrigger) TriggerAll() {
	if l == nil || l.p == nil {
		return
	}
	go func() {
		if err := l.p.TriggerAll(context.Background()); err != nil {
			l.log.Error("re-run pipeline", "err", err)
		}
	}()
}

// settingsRoutes reads Matrix routes edited in the web UI (setting "matrix.routes").
type settingsRoutes struct{ st store.Store }

func (s settingsRoutes) MatrixRoutes(ctx context.Context) ([]notify.Route, error) {
	raw, err := s.st.GetSetting(ctx, "matrix.routes")
	if errors.Is(err, store.ErrNotFound) || len(raw) == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var routes []notify.Route
	if err := json.Unmarshal(raw, &routes); err != nil {
		return nil, fmt.Errorf("setting matrix.routes: %w", err)
	}
	return routes, nil
}

// unknownGrace gives the LLM drafter time to produce a rule before a
// "conditions unknown" alert is sent; without an LLM there is nothing to wait for.
func unknownGrace(cfg *config.Config) time.Duration {
	if cfg.LLM.Provider == "" || cfg.LLM.Provider == "none" {
		return 0
	}
	return 2 * time.Hour
}

// wire is THE place where real implementations replace the no-op defaults.
func wire(cfg *config.Config, st store.Store, log *slog.Logger, trig *lateTrigger) components {
	comp := components{
		Evaluator: core.NoopEvaluator{},
		Notifier:  core.NoopNotifier{},
		Drafter:   core.NoopDrafter{},
	}

	// Rules: shipped YAML + DB rules (LLM drafts, user edits).
	fileRules, err := rules.LoadDir(cfg.RulesDir)
	if err != nil {
		log.Warn("loading rules dir", "dir", cfg.RulesDir, "err", err)
	}
	engine := rules.New(fileRules, st)
	for _, p := range engine.Problems() {
		log.Warn("invalid rule skipped", "rule", p.RuleID, "source", p.Source, "err", p.Err)
	}
	log.Info("rules loaded", "count", len(engine.Rules()))
	comp.Evaluator = engine

	// Matrix notifier (optional).
	if cfg.Matrix.Homeserver != "" {
		mcfg := notify.Config{
			Homeserver:   cfg.Matrix.Homeserver,
			AccessToken:  os.Getenv(cfg.Matrix.AccessTokenEnv),
			DefaultRooms: cfg.Matrix.DefaultRooms,
		}
		for _, r := range cfg.Matrix.Routes {
			mcfg.Routes = append(mcfg.Routes, notify.Route{Label: r.Label, Rooms: r.Rooms})
		}
		m, err := notify.NewMatrix(mcfg, settingsRoutes{st}, nil)
		if err != nil {
			log.Error("matrix notifier disabled", "err", err)
		} else {
			comp.Notifier = m
			log.Info("matrix notifier enabled", "homeserver", cfg.Matrix.Homeserver)
		}
	}
	// LLM rule drafter (optional): drafts rules for High/Critical/KEV findings without one.
	prov, err := llm.NewProvider(cfg.LLM)
	switch {
	case err != nil:
		log.Error("LLM drafter disabled", "err", err)
	case prov != nil:
		d := llm.NewDrafter(llm.Deps{
			Store: st, Provider: prov, Validator: rulesService{engine},
			FactCatalog: factCatalog(), DailyLimit: cfg.LLM.DailyLimit, Logger: log, Rules: engine.Rules,
			OnRuleAdded: func(ctx context.Context, r model.Rule) {
				if err := engine.Reload(ctx); err != nil {
					log.Warn("reload rules after LLM draft", "err", err)
				}
				log.Info("LLM drafted rule", "rule", r.ID)
				trig.TriggerAll()
			},
			Siblings: func(ctx context.Context, vulnID, source string) []model.Finding {
				all, _, err := st.ListFindings(ctx, store.FindingFilter{VulnID: vulnID, Limit: 1000})
				if err != nil {
					return nil
				}
				var out []model.Finding
				for _, f := range all {
					if llm.SourceOf(f) == source {
						out = append(out, f)
					}
				}
				return out
			},
		})
		comp.Drafter = d
		comp.Start = append(comp.Start, d.Start)
		log.Info("LLM drafter enabled", "provider", prov.Name(), "daily_limit", cfg.LLM.DailyLimit)
	}

	// Web UI on the same mux as the agent API.
	ui, err := web.New(web.Deps{
		Store: st, Rules: rulesService{engine}, Pipeline: trig, Config: cfg, Logger: log,
	})
	if err != nil {
		log.Error("web UI disabled", "err", err)
	} else {
		comp.Mount = append(comp.Mount, ui.Mount)
	}
	return comp
}

// factCatalog describes the fact catalog to the LLM (see docs/contracts.md §3).
func factCatalog() []llm.FactSpec {
	names := rules.CatalogFacts()
	sort.Strings(names)
	out := make([]llm.FactSpec, 0, len(names))
	for _, n := range names {
		t, _ := rules.FactTypeOf(n)
		out = append(out, llm.FactSpec{Name: n, Type: fmt.Sprint(t), Description: factDescriptions[n]})
	}
	return out
}

var factDescriptions = map[string]string{
	"os.libc":           "glibc or musl",
	"kernel.modules":    "names of loaded kernel modules (/proc/modules)",
	"kernel.sysctl":     "selected sysctl values, keys like user.max_user_namespaces",
	"services.active":   "running systemd service unit names without .service",
	"sockets.listening": "listening sockets: proto, addr, port, process",
	"sockets.ports":     "distinct listening ports",
	"sshd.config":       "effective sshd config from 'sshd -T', lowercase keys",
	"nginx.modules":     "nginx -V configure modules, e.g. http_v2_module",
	"nginx.directives":  "nginx -T: directive name -> all values",
	"nginx.http2":       "nginx accepts HTTP/2",
	"apache.modules":    "apachectl -M module names, e.g. proxy_module",
	"apache.http2":      "mod_http2 loaded and h2/h2c enabled in Protocols",
	"php.sapi":          "installed PHP SAPIs: cli, fpm, apache2handler",
	"php.ini":           "selected php.ini values (allow_url_include, disable_functions, ...)",
	"docker.containers": "running containers: name, image, image_id, ports, privileged",
}

// rulesService adapts the rule engine to the web UI (validation is a package func).
type rulesService struct{ *rules.Engine }

func (rulesService) Validate(r model.Rule) error { return rules.Validate(r) }

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

	trig := &lateTrigger{log: log}
	comp := wire(cfg, st, log, trig)
	grypeDB := match.NewGrype(cfg.GrypeDBDir(), log)
	defer grypeDB.Close()
	pipe := pipeline.New(st, grypeDB, comp.Evaluator, comp.Notifier, comp.Drafter,
		pipeline.Options{PublicURL: cfg.PublicURL, Logger: log, UnknownGrace: unknownGrace(cfg)})
	trig.p = pipe
	for _, start := range comp.Start {
		start(ctx)
	}
	pipe.StartNotifyLoop(ctx, 5*time.Minute)

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
