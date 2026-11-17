// Package localagent is the server's built-in agent ("agentless mode"): the server monitors its
// own host without a separately installed panoptes-agent.
//
// It runs the normal agent runner in-process and lets it talk to the server's own agent API
// through an in-memory transport (HandlerTransport), so every server-side validation, limit and
// pipeline path is exercised exactly as for a remote agent. Host data comes either from the root
// collector over its unix socket or from collectors running in the server process itself.
//
// Importing this package links the agent's inventory scanner (Syft). Its SQLite driver is the one
// the server already links through Grype; the agent binary registers modernc.org/sqlite in
// cmd/panoptes-agent instead (a second registration would panic at start).
package localagent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"sort"
	"time"

	agentcfg "github.com/DonSosiska/panoptes/internal/agent/config"
	"github.com/DonSosiska/panoptes/internal/agent/hostdata"
	"github.com/DonSosiska/panoptes/internal/agent/runner"
	"github.com/DonSosiska/panoptes/internal/agent/transport"
	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/config"
	"github.com/DonSosiska/panoptes/internal/server/store"
)

const (
	// TokenName is recorded as the "enrollment token" of the local host.
	TokenName = "local-agent"
	// KVLocalHost holds the id of the local host (the web UI shows a badge for it).
	KVLocalHost = "local_host"
	// StateSubdir is the directory inside data_dir that holds credentials.json.
	StateSubdir = "local-agent"

	probeTimeout = 5 * time.Second
	minBackoff   = 5 * time.Second
	maxBackoff   = 5 * time.Minute
)

// ErrConflict is returned when a host with this machine's id already exists and the server
// has no claim on it (typically a standalone panoptes-agent was installed here first).
var ErrConflict = errors.New("a host with this machine's id already exists and is not the built-in local host")

// Options configure the local agent.
type Options struct {
	Config  config.LocalAgent
	DataDir string
	Store   store.Store
	// Handler is the agent API (the mux the agent listener serves).
	Handler http.Handler
	Version string
	Log     *slog.Logger

	// Source overrides the data source selection (tests).
	Source hostdata.Source
	// Hostname overrides os.Hostname (tests).
	Hostname string
	// MinBackoff/MaxBackoff override the restart backoff (tests).
	MinBackoff, MaxBackoff time.Duration
	// OnRun is called each time the runner is about to start (tests).
	OnRun func()
}

// Agent is the built-in local agent.
type Agent struct {
	o   Options
	log *slog.Logger
}

// New creates the agent. Nothing happens until Start.
func New(o Options) *Agent {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.MinBackoff <= 0 {
		o.MinBackoff = minBackoff
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = maxBackoff
	}
	return &Agent{o: o, log: o.Log.With("component", "local-agent")}
}

// StateDir is where the local agent keeps credentials.json.
func StateDir(dataDir string) string { return dataDir + "/" + StateSubdir }

// agentConfig derives the agent runner configuration from the server's local_agent section.
func (a *Agent) agentConfig() agentcfg.Config {
	c := agentcfg.Default()
	l := a.o.Config
	c.ServerURL = BaseURL
	c.StateDir = StateDir(a.o.DataDir)
	c.Labels = slices.Clone(l.Labels)
	c.CheckinInterval = l.CheckinInterval
	c.InventoryInterval = l.InventoryInterval
	c.ScanLanguagePackages = l.ScanLanguagePackages
	if len(l.ExcludePaths) > 0 {
		c.ExcludePaths = slices.Clone(l.ExcludePaths)
	}
	// The in-process scanner reads files of the whole host. It must never open the server's own
	// SQLite files: closing any file descriptor of a file drops the process's POSIX locks on it,
	// which corrupts a database that another connection of this process holds open (seen in the
	// e2e run as "database disk image is malformed"). Always exclude data_dir.
	c.ExcludePaths = append(c.ExcludePaths, dataDirExcludes(a.o.DataDir)...)
	c.DockerSocket = l.DockerSocket
	c.CollectorSocket = l.CollectorSocket
	return c
}

// dataDirExcludes returns data_dir as given and with symlinks resolved (absolute paths).
func dataDirExcludes(dir string) []string {
	if dir == "" {
		return nil
	}
	var out []string
	if abs, err := filepath.Abs(dir); err == nil {
		out = append(out, abs)
		if real, err := filepath.EvalSymlinks(abs); err == nil && real != abs {
			out = append(out, real)
		}
	}
	return out
}

// Start launches the supervisor goroutine. The returned channel is closed once it has stopped
// (ctx cancelled, or a fatal condition such as ErrConflict). Panics and errors never leave the
// goroutine: the agent restarts with backoff.
func (a *Agent) Start(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.supervise(ctx)
	}()
	return done
}

func (a *Agent) supervise(ctx context.Context) {
	backoff := a.o.MinBackoff
	for ctx.Err() == nil {
		started := time.Now()
		err := a.runGuarded(ctx)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, ErrConflict) {
			return // already logged with instructions; retrying cannot help
		}
		if time.Since(started) > 10*time.Minute {
			backoff = a.o.MinBackoff // it ran for a while: not a crash loop
		}
		a.log.Warn("local agent stopped; restarting", "err", err, "retry_in", backoff.String())
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, a.o.MaxBackoff)
	}
}

// runGuarded runs one provisioning + runner session and converts a panic into an error.
func (a *Agent) runGuarded(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			a.log.Error("panic recovered in local agent", "panic", r, "stack", string(debug.Stack()))
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return a.run(ctx)
}

func (a *Agent) run(ctx context.Context) error {
	cfg := a.agentConfig()
	src, kind := a.o.Source, "custom"
	if src == nil {
		src, kind = a.selectSource(ctx, cfg)
	}
	info, err := src.Info(ctx)
	if err != nil {
		return fmt.Errorf("host info from %s source: %w", kind, err)
	}
	if err := a.Provision(ctx, info.MachineID); err != nil {
		if errors.Is(err, ErrConflict) {
			a.log.Error("local agent NOT started: "+err.Error()+". "+
				"A standalone agent (or an earlier enrollment) already owns this machine. Either remove that host "+
				"(`panoptes-server host delete <hostname>`, and stop/uninstall panoptes-agent) and restart the server, "+
				"or set local_agent.enabled: false.", "machine_id", info.MachineID)
		}
		return err
	}
	if a.o.OnRun != nil {
		a.o.OnRun()
	}
	client := transport.NewWithHTTP(BaseURL, "", NewHTTPClient(a.o.Handler))
	r := runner.NewWithClient(cfg, a.o.Version, a.log, src, client)
	a.log.Info("local agent running", "source", kind, "checkin_interval", cfg.CheckinInterval.String(),
		"inventory_interval", cfg.InventoryInterval.String(), "labels", cfg.Labels)
	if err := r.Run(ctx); err != nil {
		return err
	}
	return nil
}

// selectSource implements local_agent.source.
func (a *Agent) selectSource(ctx context.Context, cfg agentcfg.Config) (hostdata.Source, string) {
	l := a.o.Config
	switch l.Source {
	case config.LocalSourceCollector:
		a.log.Info("local agent source: collector", "socket", l.CollectorSocket)
		return hostdata.NewClient(l.CollectorSocket), config.LocalSourceCollector
	case config.LocalSourceInProcess:
		return a.inProcess(cfg, "configured"), config.LocalSourceInProcess
	}
	// auto
	probe := hostdata.NewClient(l.CollectorSocket)
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	if _, err := probe.Info(pctx); err == nil {
		a.log.Info("local agent source: collector (auto: socket reachable)", "socket", l.CollectorSocket)
		return hostdata.NewClient(l.CollectorSocket), config.LocalSourceCollector
	} else {
		a.log.Info("collector socket not usable, falling back", "socket", l.CollectorSocket, "err", err)
	}
	return a.inProcess(cfg, "auto: no usable collector socket"), config.LocalSourceInProcess
}

func (a *Agent) inProcess(cfg agentcfg.Config, why string) hostdata.Source {
	a.log.Info("local agent source: inprocess (" + why + ")")
	if os.Geteuid() != 0 {
		a.log.Warn("local agent collects inside the server process without root privileges (euid != 0): "+
			"facts may be incomplete (e.g. sshd -T, nginx -T, docker.sock, other users' sockets) and the inventory "+
			"may miss unreadable files; use local_agent.source: collector with panoptes-collector.service for full coverage",
			"euid", os.Geteuid())
	}
	return hostdata.NewLocal(cfg, false)
}

// Provision creates (or reuses) the local host record without an enrollment token and stores
// the agent key in StateDir/credentials.json. A host with the same machine id that this server
// has no claim on yields ErrConflict.
func (a *Agent) Provision(ctx context.Context, machineID string) error {
	st := a.o.Store
	stateDir := StateDir(a.o.DataDir)
	labels := slices.Clone(a.o.Config.Labels)
	if labels == nil {
		labels = []string{}
	}

	// Existing host with this machine id?
	hosts, err := st.ListHosts(ctx)
	if err != nil {
		return fmt.Errorf("list hosts: %w", err)
	}
	var existing *model.Host
	for i := range hosts {
		if hosts[i].MachineID == machineID {
			existing = &hosts[i]
			break
		}
	}
	marked, _ := st.KVGet(ctx, KVLocalHost)

	prevHash := ""
	if creds, err := transport.LoadCredentials(stateDir); err == nil {
		h, herr := st.HostByAgentKey(ctx, store.HashSecret(creds.AgentKey))
		switch {
		case herr == nil && h.MachineID == machineID:
			// ours: nothing to do unless the configured labels changed
			if sameLabels(h.Labels, labels) {
				return a.finish(ctx, h.ID, creds.AgentKey, creds.AgentID != h.ID, stateDir)
			}
			prevHash = store.HashSecret(creds.AgentKey)
			a.log.Info("local_agent.labels changed; updating the local host", "labels", labels)
		case herr != nil && !errors.Is(herr, store.ErrNotFound):
			return fmt.Errorf("check credentials: %w", herr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		a.log.Warn("local agent credentials unreadable; provisioning again", "err", err)
	}

	if existing != nil && prevHash == "" {
		// Not authenticated by our credentials. Only a host this server provisioned itself (marker)
		// may be taken over again, e.g. after a crash between writing credentials and the DB update.
		if marked != existing.ID {
			return fmt.Errorf("%w (host %s %q)", ErrConflict, existing.ID, existing.Hostname)
		}
		if err := st.SetReenrollAllowedUntil(ctx, existing.ID, time.Now().Add(time.Minute)); err != nil {
			return fmt.Errorf("recover local host: %w", err)
		}
	}

	key, hash, err := store.NewSecret("pa_")
	if err != nil {
		return err
	}
	// Credentials first: if we crash after the enrollment below, the stored key still matches.
	if err := transport.SaveCredentials(stateDir, transport.Credentials{AgentID: "pending", AgentKey: key}); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}
	hostname := a.o.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	host, err := st.EnrollHost(ctx, store.EnrollParams{
		MachineID: machineID, Hostname: hostname, Labels: labels, AgentVersion: a.o.Version, KeyHash: hash,
		PreviousKeyHash: prevHash, TokenName: TokenName, TokenLabels: labels,
	})
	if errors.Is(err, store.ErrReenrollDenied) {
		return fmt.Errorf("%w", ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("provision local host: %w", err)
	}
	a.log.Info("local host provisioned", "host", host.ID, "hostname", host.Hostname, "labels", labels)
	return a.finish(ctx, host.ID, key, true, stateDir)
}

// finish records the host id in the credentials file (when needed) and marks the host as local.
func (a *Agent) finish(ctx context.Context, hostID, key string, rewrite bool, stateDir string) error {
	if rewrite {
		if err := transport.SaveCredentials(stateDir, transport.Credentials{AgentID: hostID, AgentKey: key}); err != nil {
			return fmt.Errorf("save credentials: %w", err)
		}
	}
	if err := a.o.Store.KVSet(ctx, KVLocalHost, hostID, time.Now()); err != nil {
		return fmt.Errorf("mark local host: %w", err)
	}
	return nil
}

func sameLabels(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(x, y)
}
