package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/DonSosiska/holealign/internal/server/api"
	"github.com/DonSosiska/holealign/internal/server/config"
)

// namedServer is one HTTP listener.
type namedServer struct {
	name string // "agent", "admin" or "shared"
	srv  *http.Server
	tls  bool
}

// buildServers builds the HTTP servers (not yet listening).
//
// Normal mode: the agent listener (cfg.Listen) serves only the agent API and /healthz — every other
// path is a 404, so monitored hosts cannot even reach the login page — and the admin listener
// (cfg.AdminListen) serves the web UI and /healthz, not the agent API.
//
// Legacy mode (admin_listen empty or equal to listen): one listener serves both.
func buildServers(cfg *config.Config, log *slog.Logger, apiMux *http.ServeMux, mounts []func(*http.ServeMux)) ([]namedServer, error) {
	agentTLS, err := tlsConfig(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("tls_cert/tls_key: %w", err)
	}
	if cfg.SharedListener() {
		log.Warn("admin_listen is empty or equal to listen: the admin web UI shares the agent API port and is reachable from every monitored host; set admin_listen to a separate address")
		if cfg.AdminTLSCert != "" {
			log.Warn("admin_tls_cert is ignored in single-port mode; tls_cert applies to the shared listener")
		}
		for _, m := range mounts {
			m(apiMux)
		}
		return []namedServer{newServer("shared", cfg.Listen, api.LogRequests(log, apiMux), agentTLS)}, nil
	}
	adminTLS, err := tlsConfig(cfg.AdminTLSCert, cfg.AdminTLSKey)
	if err != nil {
		return nil, fmt.Errorf("admin_tls_cert/admin_tls_key: %w", err)
	}
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok")
	})
	for _, m := range mounts {
		m(adminMux)
	}
	return []namedServer{
		newServer("agent", cfg.Listen, api.LogRequests(log, apiMux), agentTLS),
		newServer("admin", cfg.AdminListen, api.LogRequests(log, adminMux), adminTLS),
	}, nil
}

func newServer(name, addr string, h http.Handler, tc *tls.Config) namedServer {
	return namedServer{name: name, tls: tc != nil, srv: &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         tc,
		MaxHeaderBytes:    64 << 10,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute, // inventory uploads up to 64 MiB
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}}
}

// tlsConfig loads a certificate/key pair; both empty means plain HTTP (nil config).
func tlsConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}, nil
}
