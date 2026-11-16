// Package api implements the agent-facing HTTP API (contracts §1) on net/http.
package api

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"panoptes/internal/model"
	"panoptes/internal/server/core"
	"panoptes/internal/server/store"
)

const (
	// MaxInventoryBytes caps both the request body and its decompressed size.
	MaxInventoryBytes = 64 << 20
	maxSmallBody      = 8 << 20 // enroll / check-in bodies (facts can be large)
	maxTargets        = 1000
)

// Trigger schedules a pipeline run for a host; it must not block. Implemented by pipeline.Pipeline.
type Trigger interface {
	Trigger(hostID string)
}

// Deps are the collaborators of the API handlers.
type Deps struct {
	Store     store.Store
	Evaluator core.RuleEvaluator // source of FactRequests for check-in responses
	Pipeline  Trigger
	Logger    *slog.Logger
	Now       func() time.Time
}

type server struct {
	Deps
	log *slog.Logger
}

// NewMux returns a ServeMux with the agent API registered. Web UI routes can be mounted on the
// same mux by the caller.
func NewMux(d Deps) *http.ServeMux {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Evaluator == nil {
		d.Evaluator = core.NoopEvaluator{}
	}
	s := &server{Deps: d, log: d.Logger}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("POST /api/v1/enroll", s.handleEnroll)
	mux.Handle("POST /api/v1/checkin", s.auth(s.handleCheckin))
	mux.Handle("POST /api/v1/inventory", s.auth(s.handleInventory))
	return mux
}

// LogRequests is an optional middleware that logs one line per request.
func LogRequests(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		log.Info("http", "method", r.Method, "path", r.URL.Path, "status", rw.status, "dur", time.Since(start).Round(time.Millisecond))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(c int) { w.status = c; w.ResponseWriter.WriteHeader(c) }

// --- helpers ---------------------------------------------------------------

type ctxKey struct{}

func hostFrom(ctx context.Context) model.Host { h, _ := ctx.Value(ctxKey{}).(model.Host); return h }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// decodeBody reads a JSON body of at most max bytes. It writes the error response itself.
func decodeBody(w http.ResponseWriter, r *http.Request, max int64, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		}
		return false
	}
	return true
}

func (s *server) internal(w http.ResponseWriter, what string, err error) {
	s.log.Error(what, "err", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

// auth authenticates the Bearer agent key and stores the host in the request context.
func (s *server) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		h := r.Header.Get("Authorization")
		if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		key := strings.TrimSpace(h[len(prefix):])
		host, err := s.Store.HostByAgentKey(r.Context(), store.HashSecret(key))
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusUnauthorized, "invalid agent key")
			return
		}
		if err != nil {
			s.internal(w, "agent auth", err)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, host)))
	})
}

// --- handlers --------------------------------------------------------------

func (s *server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req model.EnrollRequest
	if !decodeBody(w, r, 1<<20, &req) {
		return
	}
	ok, err := s.Store.UseEnrollToken(r.Context(), store.HashSecret(req.Token))
	if err != nil {
		s.internal(w, "enroll token lookup", err)
		return
	}
	if req.Token == "" || !ok {
		writeErr(w, http.StatusUnauthorized, "invalid enrollment token")
		return
	}
	if strings.TrimSpace(req.MachineID) == "" {
		writeErr(w, http.StatusBadRequest, "machine_id is required")
		return
	}
	key, hash, err := store.NewSecret("pa_")
	if err != nil {
		s.internal(w, "generate key", err)
		return
	}
	host, err := s.Store.EnrollHost(r.Context(), store.EnrollParams{
		MachineID: req.MachineID, Hostname: req.Hostname, Labels: req.Labels, AgentVersion: req.AgentVersion, KeyHash: hash,
	})
	if err != nil {
		s.internal(w, "enroll host", err)
		return
	}
	s.log.Info("host enrolled", "host", host.ID, "hostname", host.Hostname)
	writeJSON(w, http.StatusOK, model.EnrollResponse{AgentID: host.ID, AgentKey: key})
}

func (s *server) handleCheckin(w http.ResponseWriter, r *http.Request) {
	host := hostFrom(r.Context())
	var req model.CheckinRequest
	if !decodeBody(w, r, maxSmallBody, &req) {
		return
	}
	res, err := s.Store.ApplyCheckin(r.Context(), host.ID, req, s.Now())
	if err != nil {
		s.internal(w, "apply checkin", err)
		return
	}
	// facts changed and there is an inventory to evaluate them against -> recompute verdicts
	if res.FactsChanged && res.Host.InventoryHash != "" && s.Pipeline != nil {
		s.Pipeline.Trigger(host.ID)
	}
	reqs := s.Evaluator.FactRequests()
	if reqs == nil {
		reqs = []model.FactRequest{}
	}
	writeJSON(w, http.StatusOK, model.CheckinResponse{
		FactRequests:  reqs,
		WantInventory: res.Host.InventoryHash == "" || res.Host.InventoryHash != req.InventoryHash,
		WantFullFacts: !req.FactsComplete && res.FirstCheckin,
	})
}

var errTooLarge = errors.New("decompressed body too large")

// capReader fails with errTooLarge once more than max bytes were read.
type capReader struct {
	r    io.Reader
	left int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left < 0 {
		return 0, errTooLarge
	}
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	if c.left < 0 {
		return n, errTooLarge
	}
	return n, err
}

func (s *server) handleInventory(w http.ResponseWriter, r *http.Request) {
	host := hostFrom(r.Context())
	body := io.Reader(http.MaxBytesReader(w, r.Body, MaxInventoryBytes)) // compressed size cap
	switch enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))); enc {
	case "gzip", "x-gzip":
		gz, err := gzip.NewReader(body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid gzip body")
			return
		}
		defer gz.Close()
		body = &capReader{r: gz, left: MaxInventoryBytes} // decompressed size cap
	case "", "identity":
		body = &capReader{r: body, left: MaxInventoryBytes}
	default:
		writeErr(w, http.StatusUnsupportedMediaType, "unsupported Content-Encoding")
		return
	}
	var p model.InventoryPayload
	if err := json.NewDecoder(body).Decode(&p); err != nil {
		var mbe *http.MaxBytesError
		switch {
		case errors.Is(err, errTooLarge), errors.As(err, &mbe):
			writeErr(w, http.StatusRequestEntityTooLarge, "inventory too large (max 64 MiB decompressed)")
		default:
			writeErr(w, http.StatusBadRequest, "invalid inventory: "+err.Error())
		}
		return
	}
	if err := validateInventory(&p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Store.ReplaceInventory(r.Context(), host.ID, p); err != nil {
		s.internal(w, "store inventory", err)
		return
	}
	s.log.Info("inventory stored", "host", host.ID, "targets", len(p.Targets), "hash", p.Hash)
	if s.Pipeline != nil {
		s.Pipeline.Trigger(host.ID)
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func validateInventory(p *model.InventoryPayload) error {
	if p.Hash == "" {
		return errors.New("hash is required")
	}
	if len(p.Targets) > maxTargets {
		return fmt.Errorf("too many targets (max %d)", maxTargets)
	}
	seen := map[string]bool{}
	for i, t := range p.Targets {
		if t.Kind != model.TargetHost && t.Kind != model.TargetContainerImage {
			return fmt.Errorf("target %d: unknown kind %q", i, t.Kind)
		}
		if t.Name == "" {
			return fmt.Errorf("target %d: name is required", i)
		}
		if len(t.SBOM) == 0 || string(t.SBOM) == "null" {
			return fmt.Errorf("target %d: sbom is required", i)
		}
		k := string(t.Kind) + "\x00" + t.Name
		if seen[k] {
			return fmt.Errorf("target %d: duplicate %s %q", i, t.Kind, t.Name)
		}
		seen[k] = true
	}
	return nil
}
