// Command panoptes-agent sends host facts and software inventory to a Panoptes server.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"panoptes/internal/agent/collector"
	"panoptes/internal/agent/config"
	"panoptes/internal/agent/facts"
	"panoptes/internal/agent/hostdata"
	"panoptes/internal/agent/inventory"
	"panoptes/internal/agent/runner"
	"panoptes/internal/agent/transport"
)

// version is set with -ldflags "-X main.version=...".
var version = "dev"

func main() { os.Exit(run()) }

func run() int {
	var (
		cfgPath    = flag.String("config", "", "path to agent.yaml (default $PANOPTES_AGENT_CONFIG or "+config.DefaultPath+")")
		once       = flag.Bool("once", false, "do one check-in and inventory upload, then exit")
		printInv   = flag.Bool("print-inventory", false, "scan and print the inventory payload as JSON, no server needed")
		printFacts = flag.Bool("print-facts", false, "collect and print facts as JSON, no server needed")
		printPin   = flag.Bool("print-server-pin", false, "connect to server_url and print the leaf certificate's SPKI SHA-256 (chain is validated normally; not trust-on-first-use)")
		mode       = flag.String("mode", "all", "all (one process, default), collector (root, no network: serves host data on a unix socket) or sender (unprivileged: talks to the server, gets data from the collector)")
		showVer    = flag.Bool("version", false, "print version and exit")
		logLevel   = flag.String("log-level", "info", "log level: debug, info, warn, error")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(version)
		return 0
	}

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "invalid -log-level %q\n", *logLevel)
		return 2
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(log)

	switch *mode {
	case modeAll, modeCollector, modeSender:
	default:
		fmt.Fprintf(os.Stderr, "invalid -mode %q (all, collector or sender)\n", *mode)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *printFacts {
		return printJSON(runner.NormalizeFacts(facts.Collect(ctx, nil)))
	}

	path := config.ResolvePath(*cfgPath)
	cfg, err := loadConfig(path, *printInv)
	if err != nil {
		log.Error("config", "path", path, "err", err)
		return 1
	}

	if *printInv {
		payload, err := inventory.Scan(ctx, cfg)
		if err != nil {
			log.Error("scan failed", "err", err)
			return 1
		}
		return printJSON(payload)
	}

	if *printPin {
		return printServerPin(ctx, cfg)
	}

	runner.CheckPermissions(cfg, log)

	if *mode == modeCollector {
		if *once {
			log.Error("-once is not supported with -mode collector")
			return 2
		}
		return runCollector(ctx, cfg, log)
	}

	log.Info("panoptes-agent starting", "version", version, "mode", *mode, "server", cfg.ServerURL)
	var src hostdata.Source // nil = in-process (mode all)
	if *mode == modeSender {
		src = hostdata.NewClient(cfg.CollectorSocket)
	}
	r, err := runner.New(cfg, version, log, src)
	if err != nil {
		log.Error("setup", "err", err)
		return 1
	}
	if *once {
		err = r.RunOnce(ctx)
	} else {
		err = r.Run(ctx)
	}
	if err != nil {
		log.Error("agent stopped", "err", err)
		return 1
	}
	log.Info("agent stopped")
	return 0
}

const (
	modeAll       = "all"
	modeCollector = "collector"
	modeSender    = "sender"
)

// runCollector is the root half of the privilege separation: it serves host data on a unix
// socket and never opens a network connection.
func runCollector(ctx context.Context, cfg config.Config, log *slog.Logger) int {
	var allowed []uint32
	if uid, _, err := collector.ResolveUser(cfg.CollectorUser); err != nil {
		log.Warn("collector_user not found: only root may use the socket", "user", cfg.CollectorUser, "err", err)
	} else {
		allowed = append(allowed, uid)
	}
	srv := &collector.Server{
		Backend:     hostdata.NewLocal(cfg, true),
		SocketPath:  cfg.CollectorSocket,
		AllowedUIDs: allowed,
		Group:       cfg.CollectorUser,
		Log:         log,
	}
	log.Info("panoptes-agent collector starting", "version", version, "socket", cfg.CollectorSocket)
	if err := srv.Serve(ctx); err != nil {
		log.Error("collector stopped", "err", err)
		return 1
	}
	log.Info("collector stopped")
	return 0
}

// printServerPin prints the SPKI SHA-256 of the server's leaf certificate. The chain is
// validated with the configured trust roots first, so this is a convenience for
// copying the value into server_cert_sha256, not trust-on-first-use.
func printServerPin(ctx context.Context, cfg config.Config) int {
	pin, err := transport.FetchServerPin(ctx, cfg.ServerURL, transport.TLSOptions{
		CAFile: cfg.CAFile, ClientCert: cfg.ClientCert, ClientKey: cfg.ClientKey,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "print-server-pin:", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "note: the certificate chain was validated normally before this pin was read;")
	fmt.Fprintln(os.Stderr, "      compare the value out of band before adding it to server_cert_sha256.")
	fmt.Println(pin)
	return 0
}

// loadConfig loads the file; for -print-inventory a missing file falls back to defaults
// (no server is needed to scan).
func loadConfig(path string, lenient bool) (config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil && lenient && errors.Is(err, os.ErrNotExist) {
		return config.Default(), nil
	}
	return cfg, err
}

func printJSON(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		return 1
	}
	return 0
}
