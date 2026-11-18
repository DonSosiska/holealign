// Command holealign-server is the Holealign central server.
//
//	holealign-server [-config file] [serve]
//	holealign-server [-config file] token create <name> [-max-hosts N] [-expires 72h] [-labels a,b] | token list | token revoke <name>
//	holealign-server [-config file] host list | host allow-reenroll <id|hostname> [-ttl 1h] | host delete <id|hostname>
//	holealign-server [-config file] user set-password <user>   (password on stdin)
//	holealign-server rules keygen|build|sign|verify|import|status   (signed rules feed, docs/rules-feed.md)
//	holealign-server -version
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
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/DonSosiska/holealign/internal/model"
	"github.com/DonSosiska/holealign/internal/server/api"
	"github.com/DonSosiska/holealign/internal/server/clientip"
	"github.com/DonSosiska/holealign/internal/server/config"
	"github.com/DonSosiska/holealign/internal/server/core"
	"github.com/DonSosiska/holealign/internal/server/feeds"
	"github.com/DonSosiska/holealign/internal/server/health"
	"github.com/DonSosiska/holealign/internal/server/llm"
	"github.com/DonSosiska/holealign/internal/server/localagent"
	"github.com/DonSosiska/holealign/internal/server/match"
	"github.com/DonSosiska/holealign/internal/server/notify"
	"github.com/DonSosiska/holealign/internal/server/pipeline"
	"github.com/DonSosiska/holealign/internal/server/rules"
	"github.com/DonSosiska/holealign/internal/server/rulesfeed"
	"github.com/DonSosiska/holealign/internal/server/store"
	"github.com/DonSosiska/holealign/internal/server/web"
)

// version is set at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

func main() {
	restrictUmask()
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("holealign-server", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to server.yaml (default $HOLEALIGN_CONFIG or /etc/holealign/server.yaml)")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Usage = func() {
		fmt.Fprint(stderr, `usage: holealign-server [-config file] [command]

commands:
  serve                       run the server (default)
  token create <name> [-max-hosts N] [-expires 72h] [-labels a,b]
                              create an enrollment token (printed once); labels are authoritative
  host list                   list enrolled hosts
  host allow-reenroll <host> [-ttl 1h]
                              allow ONE re-enrollment of a host without its old key (id or hostname),
                              valid for the TTL (default 1h, max 168h)
  host delete <host>          delete a host and its findings
  token list                  list enrollment tokens
  token revoke <name>         revoke an enrollment token
  user set-password <user>    set (or create) a web user; password is read from stdin
  rules keygen|build|sign|verify|import|status|candidates|draft
                              central rules feed tooling (see 'rules' for details)
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
		fmt.Fprintln(stdout, "holealign-server", version)
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
	if cmd == "rules" {
		// keygen/build/sign/verify must work without a server configuration or database
		return rulesCmd(*cfgPath, rest, stdout, stderr)
	}

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
	case "host":
		cerr = hostCmd(cfg, rest, stdout)
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
	// Engine is the rule engine (the rules feed installs its layer into it).
	Engine *rules.Engine
	// Feed is the signed rules feed (nil when rules.feed.enabled is false).
	Feed *rulesfeed.Feed
	// Mount lets other packages (web UI) register routes on the admin mux (or on the shared mux
	// in legacy single-port mode).
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
		defer recoverLog(l.log, "lateTrigger.TriggerAll")
		if err := l.p.TriggerAll(context.Background()); err != nil {
			l.log.Error("re-run pipeline", "err", err)
		}
	}()
}

// recoverLog is deferred at the top of background goroutines: a panic is logged with its stack
// instead of killing the server.
func recoverLog(log *slog.Logger, where string) {
	if r := recover(); r != nil {
		log.Error("panic recovered in background goroutine", "where", where, "panic", r, "stack", string(debug.Stack()))
	}
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
func wire(cfg *config.Config, st store.Store, log *slog.Logger, trig *lateTrigger, clientIP func(*http.Request) string) components {
	comp := components{
		Evaluator: core.NoopEvaluator{},
		Notifier:  core.NoopNotifier{},
		Drafter:   core.NoopDrafter{},
	}

	// Rules, lowest precedence first: built-in (embedded; rules_dir adds/overrides by ID) <
	// signed rules feed (internal/server/rulesfeed) < DB rules (LLM drafts, user edits).
	engine := rules.New(builtinRules(cfg, log), st)
	for _, p := range engine.Problems() {
		log.Warn("invalid rule skipped", "rule", p.RuleID, "source", p.Source, "err", p.Err)
	}
	log.Info("rules loaded", "count", len(engine.Rules()))
	comp.Evaluator = engine
	comp.Engine = engine
	if cfg.Rules.Feed.Enabled {
		keys, err := rulesfeed.ParsePublicKeys(cfg.Rules.Feed.TrustedKeys)
		if err != nil { // config validation already checked the keys
			log.Error("rules feed disabled", "err", err)
		} else {
			comp.Feed = rulesfeed.New(rulesfeed.Options{
				URL: cfg.Rules.Feed.URL, Interval: cfg.Rules.Feed.Interval, Keys: keys, Dir: cfg.RulesFeedDir(),
				KV: st, Engine: engine, ServerVersion: version, Log: log,
				OnUpdated: func(context.Context) { trig.TriggerAll() },
			})
			// activate the persisted bundle before the first pipeline run
			comp.Feed.LoadPersisted(context.Background())
			comp.Start = append(comp.Start, func(ctx context.Context) {
				go func() { defer recoverLog(log, "rules feed"); comp.Feed.Run(ctx) }()
			})
			log.Info("rules feed enabled", "url", cfg.Rules.Feed.URL, "interval", cfg.Rules.Feed.Interval, "installed_seq", comp.Feed.Seq())
		}
	}

	// Matrix notifier (optional).
	if cfg.Matrix.Homeserver != "" {
		mcfg := notify.Config{
			Homeserver:   cfg.Matrix.Homeserver,
			AccessToken:  os.Getenv(cfg.Matrix.AccessTokenEnv),
			DefaultRooms: cfg.Matrix.DefaultRooms,
			OpsRooms:     cfg.Alerts.OpsRooms,
			// delivery problems show up as a banner on the dashboard
			OnDeliveryProblem: health.NewProblemRecorder(st, log),
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

	// Web UI (admin listener, or the shared mux in legacy mode).
	ui, err := web.New(web.Deps{
		Store: st, Rules: rulesService{engine}, Pipeline: trig, Config: cfg, Logger: log, ClientIP: clientIP,
	})
	if err != nil {
		log.Error("web UI disabled", "err", err)
	} else {
		comp.Mount = append(comp.Mount, ui.Mount)
	}
	return comp
}

// factCatalog describes the fact catalog to the LLM (see docs/contracts.md §3). The agent.* facts
// describe the agent's own health, not whether a vulnerability is exploitable, so they are not offered.
func factCatalog() []llm.FactSpec {
	names := rules.CatalogFacts()
	sort.Strings(names)
	out := make([]llm.FactSpec, 0, len(names))
	for _, n := range names {
		if strings.HasPrefix(n, "agent.") {
			continue
		}
		t, _ := rules.FactTypeOf(n)
		out = append(out, llm.FactSpec{Name: n, Type: fmt.Sprint(t), Description: factDescriptions[n]})
	}
	return out
}

// factDescriptions: one entry per catalog fact (except agent.*), written from docs/contracts.md §3
// and the collectors in internal/agent/facts. A fact whose collector did not run is absent, which
// the rule engine treats as unknown.
var factDescriptions = map[string]string{
	"os.id":             "ID from /etc/os-release, lowercase, e.g. debian, ubuntu, alpine, rhel",
	"os.version_id":     "VERSION_ID from /etc/os-release as a string, e.g. 12 or 3.20.3",
	"os.libc":           "C library: exactly glibc or musl",
	"os.libc_version":   "libc version from 'ldd --version', e.g. 2.36; absent when it could not be read",
	"kernel.release":    "running kernel release from 'uname -r', e.g. 6.1.0-18-amd64",
	"kernel.modules":    "names of loaded kernel modules (first column of /proc/modules), e.g. nf_tables",
	"kernel.sysctl":     "map of sysctl key to its current value (string), only for this closed allowlist and only keys present on the kernel: kernel.unprivileged_userns_clone, user.max_user_namespaces, kernel.unprivileged_bpf_disabled, kernel.kptr_restrict, kernel.yama.ptrace_scope, kernel.dmesg_restrict, net.ipv4.ip_forward, net.ipv6.conf.all.disable_ipv6, fs.protected_symlinks, fs.protected_hardlinks, vm.unprivileged_userfaultfd, kernel.io_uring_disabled, kernel.apparmor_restrict_unprivileged_userns",
	"services.active":   "running services: systemd unit names without .service (e.g. php8.2-fpm, apache2, ssh); without systemd, daemon names from /proc (sshd gives ssh and sshd, apache2/httpd give both, php-fpm8.2 gives php-fpm); sorted, deduplicated",
	"services.source":   "where services.active came from: exactly systemd or proc; absent together with services.active",
	"sockets.listening": "listening sockets, each a map with proto (tcp, tcp6, udp or udp6), addr (bound IP address as text, e.g. 0.0.0.0, 127.0.0.1, ::), port (int) and process (owning process name, empty when unknown)",
	"sockets.ports":     "distinct listening port numbers (ints) over tcp and udp",
	"sshd.installed":    "true when the sshd binary exists; false means OpenSSH server is not installed and the other sshd.* facts are absent",
	"sshd.version":      "OpenSSH version string from 'sshd -V', e.g. 9.2p1 Debian-2+deb12u3",
	"sshd.config":       "effective sshd configuration from 'sshd -T': map of lowercase keyword to its first value as a string (e.g. permitrootlogin -> without-password, passwordauthentication -> yes); absent when sshd -T was not run",
	"nginx.installed":   "true when nginx is installed; false means the other nginx.* facts are absent",
	"nginx.version":     "nginx version from 'nginx -v', e.g. 1.22.1",
	"nginx.modules":     "names of --with-* configure flags from 'nginx -V' without the prefix, e.g. http_v2_module, http_ssl_module",
	"nginx.directives":  "from 'nginx -T': map of directive name to the list of all argument strings seen (arguments joined by one space, one entry per occurrence, secret-looking values masked as ***, values capped at 256 bytes)",
	"nginx.http2":       "true when 'http2 on' or a 'listen ... http2' flag is configured",
	"apache.installed":  "true when Apache httpd is installed; false means the other apache.* facts are absent",
	"apache.version":    "Apache version from 'apachectl -v' or 'httpd -v', e.g. 2.4.57",
	"apache.modules":    "loaded module names from 'apachectl -M', e.g. proxy_module, http2_module",
	"apache.http2":      "true when http2_module is loaded and a Protocols directive contains h2 or h2c",
	"php.installed":     "true when the php binary exists; false means the other php.* facts are absent",
	"php.version":       "PHP version from 'php -v', e.g. 8.2.7",
	"php.sapi":          "SAPIs installed on disk (not necessarily running), sorted; exact values: cli, php-fpm, apache2handler",
	"php.ini":           "map of php.ini setting to its value (string, empty when unset) from 'php -i' for exactly these keys: allow_url_include, allow_url_fopen, disable_functions, expose_php, open_basedir, cgi.fix_pathinfo; reflects the CLI configuration, which may differ from php-fpm or Apache",
	"openssl.version":   "OpenSSL version from 'openssl version', e.g. 3.0.13",
	"docker.installed":  "true when the Docker socket exists; false means the other docker.* facts are absent",
	"docker.version":    "Docker engine version from the Docker API",
	"docker.containers": "running containers (at most 500), each a map with name, image, image_id, ports (list of strings like 0.0.0.0:8080->80/tcp for published ports or 80/tcp), and privileged (bool; absent when inspect failed)",
	"runc.version":      "runc version from 'runc --version', e.g. 1.1.12",
	"sudo.version":      "sudo version from 'sudo -V', e.g. 1.9.13p3",
}

// rulesService adapts the rule engine to the web UI (validation is a package func).
type rulesService struct{ *rules.Engine }

func (rulesService) Validate(r model.Rule) error { return rules.Validate(r) }

// --- serve ------------------------------------------------------------------

func serve(cfg *config.Config) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)
	for _, w := range cfg.Warnings() {
		log.Warn("insecure configuration: " + w)
	}
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

	trusted, err := config.ParseCIDRs(cfg.TrustedProxies)
	if err != nil {
		return fmt.Errorf("trusted_proxies: %w", err)
	}
	clientIP := clientip.New(trusted)

	trig := &lateTrigger{log: log}
	comp := wire(cfg, st, log, trig, clientIP)
	grypeDB := match.NewGrype(cfg.GrypeDBDir(), log)
	defer grypeDB.Close()
	mon := health.New(st, comp.Notifier, health.Options{
		AgentSilentAfter: cfg.Alerts.AgentSilentAfter, FeedStaleAfter: cfg.Alerts.FeedStaleAfter,
		FeedBuilt: func() time.Time { return grypeDB.Status().Built },
		PublicURL: cfg.PublicURL, Logger: log,
		RulesFeedStaleAfter: rulesFeedStaleAfter(cfg),
	})
	pipe := pipeline.New(st, grypeDB, comp.Evaluator, comp.Notifier, comp.Drafter,
		pipeline.Options{PublicURL: cfg.PublicURL, Logger: log, UnknownGrace: unknownGrace(cfg),
			OnRun: mon.ReportRun, OnPoison: mon.ReportPoison, OnClean: mon.ReportClean,
			// skipped/failed targets and host limits reach the health loop as a pipeline_error alert
			OnProblem:          mon.ReportProblem,
			MaxFindingsPerHost: cfg.Limits.FindingsPerHost,
			MatchBudgetPerHour: time.Duration(cfg.Limits.MatchSecondsPerHostHour) * time.Second})
	trig.p = pipe
	for _, start := range comp.Start {
		func() {
			defer recoverLog(log, "component start hook")
			start(ctx)
		}()
	}
	pipe.StartNotifyLoop(ctx, 5*time.Minute)
	pruneDone := startRetention(ctx, st, cfg, log)
	monDone := mon.Start(ctx, time.Minute)

	apiMux := api.NewMux(api.Deps{Store: st, Evaluator: comp.Evaluator, Pipeline: pipe, Logger: log, ClientIP: clientIP,
		InventoryAttemptsPerMinute: cfg.Limits.InventoryAttemptsPerMinute,
		InventoryAttemptBurst:      cfg.Limits.InventoryAttemptBurst,
		InventoryConcurrentDecodes: cfg.Limits.InventoryConcurrentDecodes})
	servers, err := buildServers(cfg, log, apiMux, comp.Mount)
	if err != nil {
		stop()
		pipe.Shutdown()
		return err
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
	go func() { defer close(feedsDone); defer recoverLog(log, "feeds updater"); updater.Run(ctx) }()

	errCh := make(chan error, len(servers))
	var serving sync.WaitGroup
	for _, s := range servers {
		ln, err := net.Listen("tcp", s.srv.Addr)
		if err != nil {
			stop()
			<-feedsDone
			<-monDone
			pipe.Shutdown()
			return fmt.Errorf("listen %s (%s): %w", s.name, s.srv.Addr, err)
		}
		serving.Add(1)
		go func() {
			defer serving.Done()
			defer recoverLog(log, "http serve "+s.name)
			log.Info("holealign-server listening", "role", s.name, "addr", ln.Addr().String(), "tls", s.tls, "version", version, "data_dir", cfg.DataDir)
			var err error
			if s.tls {
				err = s.srv.ServeTLS(ln, "", "") // certificates are in srv.TLSConfig
			} else {
				err = s.srv.Serve(ln)
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("%s listener: %w", s.name, err)
			}
		}()
	}

	// Agentless mode: the built-in agent monitors this host through the API handler in memory.
	localDone := startLocalAgent(ctx, cfg, st, apiMux, log, grypeDB.Ready)

	var serveErr error
	select {
	case serveErr = <-errCh:
		stop()
	case <-ctx.Done():
		log.Info("shutting down")
	}
	shCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, s := range servers {
		if err := s.srv.Shutdown(shCtx); err != nil {
			log.Warn("http shutdown", "role", s.name, "err", err)
		}
	}
	serving.Wait()
	select {
	case <-localDone:
	case <-time.After(30 * time.Second):
		log.Warn("local agent did not stop in time")
	}
	<-feedsDone
	<-monDone
	<-pruneDone
	pipe.Shutdown()
	if serveErr != nil {
		return fmt.Errorf("listen: %w", serveErr)
	}
	return nil
}

// startLocalAgent starts the built-in local agent when local_agent.enabled is set. The returned
// channel is closed when it has stopped (immediately when disabled).
func startLocalAgent(ctx context.Context, cfg *config.Config, st store.Store, apiHandler http.Handler, log *slog.Logger, ready func() bool) <-chan struct{} {
	if !cfg.LocalAgent.Enabled {
		done := make(chan struct{})
		close(done)
		return done
	}
	return localagent.New(localagent.Options{
		Config: cfg.LocalAgent, DataDir: cfg.DataDir, Store: st, Handler: apiHandler, Version: version, Log: log, Ready: ready,
	}).Start(ctx)
}

// minAdminPassword is the minimum length of the initial admin password.
const minAdminPassword = 12

// adminPasswordFileEnv names a file holding the initial admin password (preferred over the
// environment variable: it does not show up in process environments or `docker inspect`).
const adminPasswordFileEnv = "HOLEALIGN_ADMIN_PASSWORD_FILE"

// ensureAdmin creates user "admin" from HOLEALIGN_ADMIN_PASSWORD_FILE or the configured env var
// when no users exist yet.
func ensureAdmin(ctx context.Context, cfg *config.Config, st store.Store, log *slog.Logger) error {
	n, err := st.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	pw := ""
	if f := os.Getenv(adminPasswordFileEnv); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("read %s: %w", adminPasswordFileEnv, err)
		}
		pw = strings.TrimRight(string(b), "\r\n")
	} else if cfg.Admin.InitialPasswordEnv != "" {
		pw = os.Getenv(cfg.Admin.InitialPasswordEnv)
	}
	if pw == "" {
		if cfg.Admin.InitialPasswordEnv != "" || os.Getenv(adminPasswordFileEnv) != "" {
			log.Warn("no web users exist; set the admin password (env var or "+adminPasswordFileEnv+") or run 'user set-password admin'", "env", cfg.Admin.InitialPasswordEnv)
		}
		return nil
	}
	if len(pw) < minAdminPassword {
		return fmt.Errorf("initial admin password must be at least %d characters", minAdminPassword)
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
		return errors.New("usage: token create <name> [-max-hosts N] [-expires 72h] [-labels a,b] | token list | token revoke <name>")
	}
	if err := prepareCLI(cfg); err != nil {
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
		return tokenCreate(ctx, st, args[1:], stdout, stderr)
	case "list":
		toks, err := st.ListEnrollTokens(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tCREATED\tLAST USED\tSTATUS\tHOSTS\tEXPIRES\tLABELS")
		for _, t := range toks {
			status, used, exp, hosts := "active", "never", "never", fmt.Sprint(t.Hosts)
			switch {
			case t.Revoked:
				status = "revoked"
			case !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt):
				status = "expired"
			case t.MaxHosts > 0 && t.Hosts >= t.MaxHosts:
				status = "exhausted"
			}
			if t.MaxHosts > 0 {
				hosts += "/" + fmt.Sprint(t.MaxHosts)
			}
			if !t.LastUsed.IsZero() {
				used = t.LastUsed.Format(time.RFC3339)
			}
			if !t.ExpiresAt.IsZero() {
				exp = t.ExpiresAt.Format(time.RFC3339)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", t.Name, t.CreatedAt.Format(time.RFC3339), used, status, hosts, exp, strings.Join(t.Labels, ","))
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
	if len(pw) < minAdminPassword {
		return fmt.Errorf("password must be at least %d characters", minAdminPassword)
	}
	if err := prepareCLI(cfg); err != nil {
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

// tokenNameRe restricts token names (they appear in logs, the CLI and the web UI).
var tokenNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// maxReenrollTTL caps `host allow-reenroll -ttl`.
const maxReenrollTTL = 7 * 24 * time.Hour

func tokenCreate(ctx context.Context, st store.Store, args []string, stdout, stderr io.Writer) error {
	const usage = "usage: token create <name> [-max-hosts N] [-expires 72h] [-labels prod,web]"
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	maxHosts := fs.Int("max-hosts", 0, "maximum number of hosts that may enroll with this token (0 = unlimited)")
	expires := fs.Duration("expires", 0, "token lifetime, e.g. 72h (0 = never expires)")
	labels := fs.String("labels", "", "comma-separated labels; authoritative for hosts enrolled with this token")
	name := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return errors.New(usage)
	}
	if name == "" && fs.NArg() == 1 {
		name = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return errors.New(usage)
	}
	if strings.TrimSpace(name) == "" {
		return errors.New(usage)
	}
	if !tokenNameRe.MatchString(name) {
		return fmt.Errorf("invalid token name %q (must match %s)", name, tokenNameRe)
	}
	if *maxHosts < 0 || *expires < 0 {
		return errors.New("-max-hosts and -expires must not be negative")
	}
	var ls []string
	for _, l := range strings.Split(*labels, ",") {
		if l = strings.TrimSpace(l); l != "" {
			ls = append(ls, l)
		}
	}
	if err := api.ValidateLabels(ls); err != nil {
		return err
	}
	o := store.EnrollTokenOpts{Name: name, MaxHosts: *maxHosts, Labels: ls}
	if *expires > 0 {
		o.ExpiresAt = time.Now().Add(*expires)
	}
	secret, hash, err := store.NewSecret("pt_")
	if err != nil {
		return err
	}
	o.Hash = hash
	if err := st.CreateEnrollTokenOpts(ctx, o); err != nil {
		if errors.Is(err, store.ErrExists) {
			return fmt.Errorf("a token named %q already exists", name)
		}
		return err
	}
	fmt.Fprintln(stderr, "Enrollment token created. It is shown only once:")
	fmt.Fprintln(stdout, secret)
	return nil
}

func hostCmd(cfg *config.Config, args []string, stdout io.Writer) error {
	const usage = "usage: host list | host allow-reenroll <id|hostname> [-ttl 1h] | host delete <id|hostname>"
	if len(args) == 0 {
		return errors.New(usage)
	}
	// host selector and flags (flags may follow the selector: allow-reenroll <host> -ttl 2h)
	ttl := time.Hour
	sel, rest := "", args[1:]
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		sel, rest = rest[0], rest[1:]
	}
	if args[0] == "allow-reenroll" {
		fs := flag.NewFlagSet("host allow-reenroll", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		fs.DurationVar(&ttl, "ttl", time.Hour, "how long the re-enrollment stays allowed")
		if err := fs.Parse(rest); err != nil {
			return errors.New(usage)
		}
		rest = fs.Args()
		if sel == "" && len(rest) > 0 {
			sel, rest = rest[0], rest[1:]
		}
		if ttl <= 0 || ttl > maxReenrollTTL {
			return fmt.Errorf("-ttl must be between 1s and %s", maxReenrollTTL)
		}
	}
	if len(rest) > 0 {
		return errors.New(usage)
	}
	if err := prepareCLI(cfg); err != nil {
		return err
	}
	st, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	hosts, err := st.ListHostsAdmin(ctx)
	if err != nil {
		return err
	}
	find := func() (store.HostAdmin, error) {
		if sel == "" {
			return store.HostAdmin{}, errors.New(usage)
		}
		var hit []store.HostAdmin
		for _, h := range hosts {
			if h.ID == sel {
				return h, nil
			}
			if h.Hostname == sel {
				hit = append(hit, h)
			}
		}
		switch len(hit) {
		case 0:
			return store.HostAdmin{}, fmt.Errorf("no host %q", sel)
		case 1:
			return hit[0], nil
		}
		return store.HostAdmin{}, fmt.Errorf("hostname %q is ambiguous (%d hosts); use the host id", sel, len(hit))
	}
	switch args[0] {
	case "list":
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tHOSTNAME\tLABELS\tLAST CHECK-IN\tTOKEN\tREENROLL")
		for _, h := range hosts {
			last := "never"
			if !h.LastCheckin.IsZero() {
				last = h.LastCheckin.Format(time.RFC3339)
			}
			re := "-"
			if h.ReenrollAllowed {
				re = "allowed until " + h.ReenrollUntil.Format(time.RFC3339)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", h.ID, h.Hostname, strings.Join(h.Labels, ","), last, h.TokenName, re)
		}
		return tw.Flush()
	case "allow-reenroll":
		h, err := find()
		if err != nil {
			return err
		}
		until := time.Now().Add(ttl)
		if err := st.SetReenrollAllowedUntil(ctx, h.ID, until); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "host %s (%s) may re-enroll once without its previous key until %s\n", h.ID, h.Hostname, until.Format(time.RFC3339))
	case "delete":
		h, err := find()
		if err != nil {
			return err
		}
		if err := st.DeleteHost(ctx, h.ID); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "host %s (%s) deleted\n", h.ID, h.Hostname)
	default:
		return errors.New(usage)
	}
	return nil
}
