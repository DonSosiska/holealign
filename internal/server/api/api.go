// Package api implements the agent-facing HTTP API (contracts §1) on net/http.
package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"panoptes/internal/model"
	"panoptes/internal/server/core"
	"panoptes/internal/server/store"
)

const (
	// MaxInventoryBytes caps both the request body and its decompressed size.
	MaxInventoryBytes = 64 << 20
	maxSmallBody      = 8 << 20 // enroll / check-in bodies (facts can be large)
	maxTargets        = 1000
	// MaxComponents caps the CycloneDX components of one target SBOM.
	MaxComponents = 50000

	defaultInventoryInterval = 5 * time.Minute
	defaultCheckinInterval   = 20 * time.Second
	defaultBurst             = 3
	maxHostname              = 253
	maxLabels                = 32
)

var (
	machineIDRe = regexp.MustCompile(`^[0-9a-f]{32,64}$`)
	labelRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
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

	// Rate limits; zero selects the default, a negative value disables the limit.
	InventoryInterval time.Duration // per host: one token refilled per interval, default 5m
	InventoryBurst    int           // per host bucket size, default 3
	CheckinInterval   time.Duration // per host: one token refilled per interval, default 20s
	CheckinBurst      int           // per host bucket size, default 3
	EnrollPerMinute   int           // per client IP, default 10
	BadAuthPerMinute  int           // failed Bearer auth per client IP, default 30
	// ClientIP overrides how the client address is derived (e.g. from X-Forwarded-For behind a
	// trusted reverse proxy). Default: the TCP peer address.
	ClientIP func(*http.Request) string
}

type server struct {
	Deps
	log       *slog.Logger
	checkinLim   *tokenBucketLimiter
	inventoryLim *tokenBucketLimiter
	enrollLim *ipLimiter
	authLim   *ipLimiter
}

func orDefault[T int | time.Duration](v, def T) T {
	if v == 0 {
		return def
	}
	return v
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
	d.InventoryInterval = orDefault(d.InventoryInterval, defaultInventoryInterval)
	d.CheckinInterval = orDefault(d.CheckinInterval, defaultCheckinInterval)
	d.InventoryBurst = orDefault(d.InventoryBurst, defaultBurst)
	d.CheckinBurst = orDefault(d.CheckinBurst, defaultBurst)
	d.EnrollPerMinute = orDefault(d.EnrollPerMinute, 10)
	d.BadAuthPerMinute = orDefault(d.BadAuthPerMinute, 30)
	if d.ClientIP == nil {
		d.ClientIP = remoteIP
	}
	s := &server{Deps: d, log: d.Logger,
		checkinLim:   newTokenBucketLimiter(d.CheckinInterval, d.CheckinBurst),
		inventoryLim: newTokenBucketLimiter(d.InventoryInterval, d.InventoryBurst),
		enrollLim: newIPLimiter(d.EnrollPerMinute), authLim: newIPLimiter(d.BadAuthPerMinute)}
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

// authFailed answers a failed Bearer authentication; repeated failures from one IP get 429.
// Only failures consume the bucket, so valid agents behind a shared address are never throttled.
func (s *server) authFailed(w http.ResponseWriter, r *http.Request, msg string) {
	if !s.authLim.allow(s.ClientIP(r), s.Now()) {
		tooMany(w, time.Minute, "too many failed authentication attempts")
		return
	}
	writeErr(w, http.StatusUnauthorized, msg)
}

func bearer(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(h[len(prefix):]), true
}

// auth authenticates the Bearer agent key and stores the host in the request context.
func (s *server) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, ok := bearer(r)
		if !ok {
			s.authFailed(w, r, "missing bearer token")
			return
		}
		host, err := s.Store.HostByAgentKey(r.Context(), store.HashSecret(key))
		if errors.Is(err, store.ErrNotFound) {
			s.authFailed(w, r, "invalid agent key")
			return
		}
		if err != nil {
			s.internal(w, "agent auth", err)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, host)))
	})
}

// cleanText strips control and bidi-override characters and truncates to max runes.
func cleanText(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			continue
		}
		if n++; n > max {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ValidateLabels checks label count and syntax (also used by the CLI for token labels).
func ValidateLabels(ls []string) error { return validLabels(ls) }

func validLabels(ls []string) error {
	if len(ls) > maxLabels {
		return fmt.Errorf("too many labels (max %d)", maxLabels)
	}
	for _, l := range ls {
		if !labelRe.MatchString(l) {
			return fmt.Errorf("invalid label %q (must match %s)", l, labelRe)
		}
	}
	return nil
}

// --- handlers --------------------------------------------------------------

func (s *server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.enrollLim.allow(s.ClientIP(r), s.Now()) {
		tooMany(w, time.Minute, "too many enrollment requests")
		return
	}
	var req model.EnrollRequest
	if !decodeBody(w, r, 1<<20, &req) {
		return
	}
	// Validate everything that needs no database before touching it.
	if req.Token == "" {
		writeErr(w, http.StatusUnauthorized, "invalid enrollment token")
		return
	}
	if !machineIDRe.MatchString(req.MachineID) {
		writeErr(w, http.StatusBadRequest, "machine_id must match ^[0-9a-f]{32,64}$")
		return
	}
	if err := validLabels(req.Labels); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Hostname = cleanText(req.Hostname, maxHostname)
	req.AgentVersion = cleanText(req.AgentVersion, 64)

	tok, err := s.Store.UseEnrollTokenInfo(r.Context(), store.HashSecret(req.Token), s.Now())
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusUnauthorized, "invalid enrollment token")
		return
	}
	if err != nil {
		s.internal(w, "enroll token lookup", err)
		return
	}
	prevHash := ""
	if k, ok := bearer(r); ok && k != "" {
		prevHash = store.HashSecret(k)
	}
	key, hash, err := store.NewSecret("pa_")
	if err != nil {
		s.internal(w, "generate key", err)
		return
	}
	host, err := s.Store.EnrollHost(r.Context(), store.EnrollParams{
		MachineID: req.MachineID, Hostname: req.Hostname, Labels: req.Labels, AgentVersion: req.AgentVersion, KeyHash: hash,
		PreviousKeyHash: prevHash, TokenName: tok.Name, MaxHosts: tok.MaxHosts, TokenLabels: tok.Labels,
	})
	switch {
	case errors.Is(err, store.ErrReenrollDenied):
		s.log.Warn("re-enroll refused", "machine_id", req.MachineID, "token", tok.Name, "ip", s.ClientIP(r))
		writeErr(w, http.StatusConflict, "host exists; previous key required (admin: panoptes-server host allow-reenroll <host>)")
		return
	case errors.Is(err, store.ErrTokenExhausted):
		writeErr(w, http.StatusForbidden, "enrollment token exhausted (max_hosts reached)")
		return
	case err != nil:
		s.internal(w, "enroll host", err)
		return
	}
	s.log.Info("host enrolled", "host", host.ID, "hostname", host.Hostname, "token", tok.Name)
	writeJSON(w, http.StatusOK, model.EnrollResponse{AgentID: host.ID, AgentKey: key})
}

func (s *server) handleCheckin(w http.ResponseWriter, r *http.Request) {
	host := hostFrom(r.Context())
	if wait := s.checkinLim.take(host.ID, s.Now()); wait > 0 {
		tooMany(w, wait, "check-in rate limit: burst "+strconv.Itoa(s.CheckinBurst)+", one per "+s.CheckinInterval.String())
		return
	}
	var req model.CheckinRequest
	if !decodeBody(w, r, maxSmallBody, &req) {
		return
	}
	if err := validLabels(req.Labels); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Hostname = cleanText(req.Hostname, maxHostname)
	req.AgentVersion = cleanText(req.AgentVersion, 64)
	res, err := s.Store.ApplyCheckin(r.Context(), host.ID, req, s.Now())
	var le *store.LimitError
	if errors.As(err, &le) {
		writeErr(w, http.StatusRequestEntityTooLarge, le.Msg)
		return
	}
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
	if code, err := validateInventory(&p); err != nil {
		writeErr(w, code, err.Error())
		return
	}
	// An identical inventory is answered before the limiter and spends no token: nothing changes.
	if host.InventoryHash != "" && host.InventoryHash == p.Hash {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"}) // unchanged: no re-matching
		return
	}
	if wait := s.inventoryLim.take(host.ID, s.Now()); wait > 0 {
		tooMany(w, wait, "inventory rate limit: burst "+strconv.Itoa(s.InventoryBurst)+", one per "+s.InventoryInterval.String())
		return
	}
	if err := s.Store.ReplaceInventory(r.Context(), host.ID, p); err != nil {
		s.inventoryLim.refund(host.ID)
		s.internal(w, "store inventory", err)
		return
	}
	s.log.Info("inventory stored", "host", host.ID, "targets", len(p.Targets), "hash", p.Hash)
	if s.Pipeline != nil {
		s.Pipeline.Trigger(host.ID)
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

func validateInventory(p *model.InventoryPayload) (int, error) {
	bad := http.StatusBadRequest
	if p.Hash == "" {
		return bad, errors.New("hash is required")
	}
	if len(p.Targets) > maxTargets {
		return bad, fmt.Errorf("too many targets (max %d)", maxTargets)
	}
	seen := map[string]bool{}
	for i, t := range p.Targets {
		if t.Kind != model.TargetHost && t.Kind != model.TargetContainerImage {
			return bad, fmt.Errorf("target %d: unknown kind %q", i, t.Kind)
		}
		if t.Name == "" {
			return bad, fmt.Errorf("target %d: name is required", i)
		}
		if len(t.SBOM) == 0 || string(t.SBOM) == "null" {
			return bad, fmt.Errorf("target %d: sbom is required", i)
		}
		if _, err := countComponents(t.SBOM, MaxComponents); err != nil {
			if errors.Is(err, errTooManyComponents) {
				return http.StatusRequestEntityTooLarge, fmt.Errorf("target %d: more than %d components", i, MaxComponents)
			}
			return bad, fmt.Errorf("target %d: invalid sbom: %v", i, err)
		}
		k := string(t.Kind) + "\x00" + t.Name
		if seen[k] {
			return bad, fmt.Errorf("target %d: duplicate %s %q", i, t.Kind, t.Name)
		}
		seen[k] = true
	}
	return 0, nil
}

var errTooManyComponents = errors.New("too many components")

type cdxComp struct {
	Components []cdxComp `json:"components"`
}

// countComponents streams the CycloneDX document and counts (nested) components, stopping as soon
// as limit is exceeded, so no huge component slice is ever built.
func countComponents(sbom []byte, limit int) (int, error) {
	dec := json.NewDecoder(bytes.NewReader(sbom))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return 0, errors.New("sbom must be a JSON object")
	}
	total := 0
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return 0, err
		}
		if kt != "components" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return 0, err
			}
			continue
		}
		if t, err := dec.Token(); err != nil || t != json.Delim('[') {
			if err != nil {
				return 0, err
			}
			continue // null or non-array: nothing to count
		}
		for dec.More() {
			var c cdxComp
			if err := dec.Decode(&c); err != nil {
				return 0, err
			}
			total += 1 + nested(c)
			if total > limit {
				return total, errTooManyComponents
			}
		}
		if _, err := dec.Token(); err != nil {
			return 0, err
		}
	}
	return total, nil
}

func nested(c cdxComp) int {
	n := 0
	for _, k := range c.Components {
		n += 1 + nested(k)
	}
	return n
}
