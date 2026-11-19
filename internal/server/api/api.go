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
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/DonSosiska/holealign/internal/model"
	"github.com/DonSosiska/holealign/internal/server/core"
	"github.com/DonSosiska/holealign/internal/server/store"
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

	// Per-target field limits (a target violating them is skipped, not the whole inventory).
	maxTargetName       = 512
	maxImageID          = 128
	maxContainers       = 200
	maxContainerNameLen = 256

	// Slow-body bounds while holding decodeSem on POST /api/v1/inventory.
	defaultInventoryReadIdleTimeout = 15 * time.Second
	defaultInventoryMinReadRate     = 16 << 10 // 16 KiB/s
	defaultInventoryRateGrace       = 5 * time.Second

	// agentMaxFactRequests matches the agent's per-checkin file.match request cap.
	agentMaxFactRequests = 20
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
	EnrollPerMinute   int           // invalid enrollment attempts per client (IPv4 / IPv6 /64), default 10
	EnrollOKPerMinute int           // successful-token enrollments per client, default 600
	BadAuthPerMinute  int           // failed Bearer auth per client IP, default 30
	// InvalidInventoryPerMinute caps inventory uploads per host that fail validation, default 6.
	InvalidInventoryPerMinute int
	// InventoryAttemptsPerMinute / InventoryAttemptBurst: per-host bucket charged by every inventory
	// request before its body is read (defaults 10/min, burst 6; negative disables).
	InventoryAttemptsPerMinute int
	InventoryAttemptBurst      int
	// InventoryConcurrentDecodes bounds inventory bodies being decoded at once, server-wide (default 4).
	InventoryConcurrentDecodes int
	// Slow-body bounds for POST /api/v1/inventory while a decodeSem slot is held; zero selects the
	// default, negative disables.
	InventoryReadIdleTimeout time.Duration // max pause between body reads (default 15 s)
	InventoryMinReadRate     int64         // minimum bytes/sec after InventoryRateGrace (default 16 KiB/s)
	InventoryRateGrace       time.Duration // grace window before enforcing min rate (default 5 s)
	// ClientIP overrides how the client address is derived (e.g. from X-Forwarded-For behind a
	// trusted reverse proxy). Default: the TCP peer address.
	ClientIP func(*http.Request) string
}

type server struct {
	Deps
	log          *slog.Logger
	checkinLim   *tokenBucketLimiter
	inventoryLim *tokenBucketLimiter
	enrollLim    *ipLimiter // charged by invalid enrollment requests only
	enrollOK     *ipLimiter // generous cap for requests with a valid token
	authLim      *ipLimiter
	badInvLim    *tokenBucketLimiter // per host, charged by inventory uploads failing validation
	attemptLim   *tokenBucketLimiter // per host, charged by every inventory request before the body is read
	decodeSem    chan struct{}       // bounds concurrent inventory decodes server-wide
	invMu        sync.Mutex
	invInflight  map[string]struct{} // hosts with an inventory decode in progress
}

func orDefault[T int | time.Duration](v, def T) T {
	if v == 0 {
		return def
	}
	return v
}

// attemptInterval turns a per-minute rate into a bucket refill interval; negative disables.
func attemptInterval(perMinute int) time.Duration {
	if perMinute < 0 {
		return -1
	}
	return time.Minute / time.Duration(max(perMinute, 1))
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
	d.EnrollOKPerMinute = orDefault(d.EnrollOKPerMinute, 600)
	d.BadAuthPerMinute = orDefault(d.BadAuthPerMinute, 30)
	d.InvalidInventoryPerMinute = orDefault(d.InvalidInventoryPerMinute, 6)
	d.InventoryAttemptsPerMinute = orDefault(d.InventoryAttemptsPerMinute, 10)
	d.InventoryAttemptBurst = orDefault(d.InventoryAttemptBurst, 6)
	d.InventoryConcurrentDecodes = orDefault(d.InventoryConcurrentDecodes, 4)
	if d.InventoryReadIdleTimeout == 0 {
		d.InventoryReadIdleTimeout = defaultInventoryReadIdleTimeout
	}
	if d.InventoryMinReadRate == 0 {
		d.InventoryMinReadRate = defaultInventoryMinReadRate
	}
	if d.InventoryRateGrace == 0 {
		d.InventoryRateGrace = defaultInventoryRateGrace
	}
	if d.ClientIP == nil {
		d.ClientIP = remoteIP
	}
	s := &server{Deps: d, log: d.Logger,
		decodeSem: make(chan struct{}, max(d.InventoryConcurrentDecodes, 1)), invInflight: map[string]struct{}{},
		attemptLim:   newTokenBucketLimiter(attemptInterval(d.InventoryAttemptsPerMinute), max(d.InventoryAttemptBurst, 1)),
		checkinLim:   newTokenBucketLimiter(d.CheckinInterval, d.CheckinBurst),
		inventoryLim: newTokenBucketLimiter(d.InventoryInterval, d.InventoryBurst),
		enrollLim:    newIPLimiter(d.EnrollPerMinute), enrollOK: newIPLimiter(d.EnrollOKPerMinute), authLim: newIPLimiter(d.BadAuthPerMinute),
		badInvLim: newTokenBucketLimiter(time.Minute/time.Duration(max(d.InvalidInventoryPerMinute, 1)), max(d.InvalidInventoryPerMinute, 1))}
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
	if r.ContentLength > max { // declared size: refuse before reading anything
		writeErr(w, http.StatusRequestEntityTooLarge, "request body too large")
		return false
	}
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

// decodeBodyQuiet is decodeBody with a caller-supplied error reporter.
func decodeBodyQuiet(w http.ResponseWriter, r *http.Request, max int64, v any, fail func(code int, msg string)) bool {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			fail(http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			fail(http.StatusBadRequest, "invalid JSON: "+err.Error())
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
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			continue
		}
		if n++; n > max {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

var osIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// cleanOS bounds and cleans every agent-supplied OS field. id and version_id must also match a
// conservative charset; a field that does not is dropped (stored empty), the check-in is kept.
func cleanOS(o model.OSInfo) model.OSInfo {
	ident := func(v string) string {
		v = cleanText(v, 64)
		if !osIDRe.MatchString(v) {
			return ""
		}
		return v
	}
	return model.OSInfo{
		ID: ident(o.ID), VersionID: ident(o.VersionID),
		PrettyName: cleanText(o.PrettyName, 128), Kernel: cleanText(o.Kernel, 128), Arch: cleanText(o.Arch, 64),
	}
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

// enrollBad answers an invalid enrollment request. Only these consume the per-client budget, so
// agents with valid tokens (e.g. a whole fleet behind one NAT or IPv6 /64) are never throttled by it.
func (s *server) enrollBad(w http.ResponseWriter, r *http.Request, code int, msg string) {
	if !s.enrollLim.allow(s.ClientIP(r), s.Now()) {
		tooMany(w, time.Minute, "too many invalid enrollment requests")
		return
	}
	writeErr(w, code, msg)
}

func (s *server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req model.EnrollRequest
	if r.ContentLength > 1<<20 {
		s.enrollBad(w, r, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	if !decodeBodyQuiet(w, r, 1<<20, &req, func(code int, msg string) { s.enrollBad(w, r, code, msg) }) {
		return
	}
	// Validate everything that needs no database before touching it.
	if req.Token == "" {
		s.enrollBad(w, r, http.StatusUnauthorized, "invalid enrollment token")
		return
	}
	if !machineIDRe.MatchString(req.MachineID) {
		s.enrollBad(w, r, http.StatusBadRequest, "machine_id must match ^[0-9a-f]{32,64}$")
		return
	}
	if err := validLabels(req.Labels); err != nil {
		s.enrollBad(w, r, http.StatusBadRequest, err.Error())
		return
	}
	req.Hostname = cleanText(req.Hostname, maxHostname)
	req.AgentVersion = cleanText(req.AgentVersion, 64)

	tok, err := s.Store.UseEnrollTokenInfo(r.Context(), store.HashSecret(req.Token), s.Now())
	if errors.Is(err, store.ErrNotFound) {
		s.enrollBad(w, r, http.StatusUnauthorized, "invalid enrollment token")
		return
	}
	if err != nil {
		s.internal(w, "enroll token lookup", err)
		return
	}
	// Valid token: separate, generous per-client cap (bounds DB work from one client).
	if !s.enrollOK.allow(s.ClientIP(r), s.Now()) {
		tooMany(w, time.Minute, "too many enrollment requests")
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
		writeErr(w, http.StatusConflict, "host exists; previous key required (admin: holealign-server host allow-reenroll <host>)")
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
	req.OS = cleanOS(req.OS)
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
	reqs := s.factRequestsForHost(r.Context(), host.ID)
	writeJSON(w, http.StatusOK, model.CheckinResponse{
		FactRequests:  reqs,
		WantInventory: res.Host.InventoryHash == "" || res.Host.InventoryHash != req.InventoryHash,
		WantFullFacts: !req.FactsComplete && res.FirstCheckin,
	})
}

type hostFactRequester interface {
	FactRequestsFor(findings []model.Finding) []model.FactRequest
}

// factRequestsForHost returns the file.match requests to send to hostID. When the evaluator
// supports per-host matching, requests needed by this host's own open findings are placed first so
// they fit inside the agent's 20-request cap even as the global rule set grows past 20 rules.
func (s *server) factRequestsForHost(ctx context.Context, hostID string) []model.FactRequest {
	all := s.Evaluator.FactRequests()
	hfr, ok := s.Evaluator.(hostFactRequester)
	if !ok || len(all) == 0 {
		if all == nil {
			return []model.FactRequest{}
		}
		return all
	}
	findings, err := s.Store.HostFindings(ctx, hostID)
	if err != nil {
		s.log.Warn("load host findings for fact_requests", "host", hostID, "err", err)
		return all
	}
	hostReqs := hfr.FactRequestsFor(findings)
	if len(hostReqs) > agentMaxFactRequests {
		s.log.Warn("host needs more file.match requests than agent limit", "host", hostID, "needed", len(hostReqs), "limit", agentMaxFactRequests)
	}
	seen := make(map[string]bool, len(hostReqs))
	out := make([]model.FactRequest, 0, min(len(all), max(len(hostReqs), agentMaxFactRequests)))
	for _, fr := range hostReqs {
		if !seen[fr.Name] {
			seen[fr.Name] = true
			out = append(out, fr)
		}
	}
	for _, fr := range all {
		if len(out) >= agentMaxFactRequests {
			break
		}
		if !seen[fr.Name] {
			seen[fr.Name] = true
			out = append(out, fr)
		}
	}
	return out
}

var (
	errTooLarge = errors.New("decompressed body too large")
	errSlowBody = errors.New("inventory upload too slow")
)

// slowBodyReader guards an inventory body read against slow-body / trickle attacks that would
// otherwise pin a global decodeSem slot for the full HTTP ReadTimeout.
type slowBodyReader struct {
	r       io.Reader
	rc      *http.ResponseController
	now     func() time.Time
	start   time.Time
	idle    time.Duration
	grace   time.Duration
	minRate int64
	total   int64
}

func (s *slowBodyReader) Read(p []byte) (int, error) {
	if s.idle > 0 && s.rc != nil {
		_ = s.rc.SetReadDeadline(time.Now().Add(s.idle))
	}
	n, err := s.r.Read(p)
	s.total += int64(n)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return n, errSlowBody
		}
		return n, err
	}
	if s.minRate > 0 && s.grace >= 0 {
		elapsed := s.now().Sub(s.start)
		if elapsed >= s.grace && float64(s.total) < elapsed.Seconds()*float64(s.minRate) {
			return n, errSlowBody
		}
	}
	return n, nil
}

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

// invalidInventory answers a rejected inventory upload and charges the host's invalid-upload budget.
func (s *server) invalidInventory(w http.ResponseWriter, hostID string, code int, v any) {
	s.badInvLim.take(hostID, s.Now())
	writeJSON(w, code, v)
}

func (s *server) handleInventory(w http.ResponseWriter, r *http.Request) {
	host := hostFrom(r.Context())
	// Cheap pre-limiter: a host that keeps sending uploads failing validation is refused before
	// its body is read at all.
	if wait := s.badInvLim.peek(host.ID, s.Now()); wait > 0 {
		tooMany(w, wait, "too many invalid inventory uploads")
		return
	}
	// Cheap attempt bucket: every request is charged before anything is read or decoded, including
	// identical-hash re-uploads and over-limit ones.
	if wait := s.attemptLim.take(host.ID, s.Now()); wait > 0 {
		tooMany(w, wait, "inventory upload attempts too frequent")
		return
	}
	// One decode in flight per host, and a global bound on concurrent decodes.
	s.invMu.Lock()
	if _, busy := s.invInflight[host.ID]; busy {
		s.invMu.Unlock()
		tooMany(w, 5*time.Second, "an inventory upload from this host is already being processed")
		return
	}
	s.invInflight[host.ID] = struct{}{}
	s.invMu.Unlock()
	defer func() {
		s.invMu.Lock()
		delete(s.invInflight, host.ID)
		s.invMu.Unlock()
	}()
	select {
	case s.decodeSem <- struct{}{}:
		defer func() { <-s.decodeSem }()
	default:
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusServiceUnavailable, "server busy decoding inventories; retry later")
		return
	}
	if r.ContentLength > MaxInventoryBytes { // declared size, before reading anything
		s.invalidInventory(w, host.ID, http.StatusRequestEntityTooLarge, map[string]string{"error": "inventory too large (max 64 MiB)"})
		return
	}
	rc := http.NewResponseController(w)
	defer func() { _ = rc.SetReadDeadline(time.Time{}) }()
	rawBody := io.Reader(http.MaxBytesReader(w, r.Body, MaxInventoryBytes)) // compressed size cap
	if s.InventoryReadIdleTimeout > 0 || s.InventoryMinReadRate > 0 {
		rawBody = &slowBodyReader{
			r:       rawBody,
			rc:      rc,
			now:     s.Now,
			start:   s.Now(),
			idle:    s.InventoryReadIdleTimeout,
			grace:   s.InventoryRateGrace,
			minRate: s.InventoryMinReadRate,
		}
	}
	body := rawBody
	switch enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))); enc {
	case "gzip", "x-gzip":
		gz, err := gzip.NewReader(body)
		if err != nil {
			if errors.Is(err, errSlowBody) {
				s.invalidInventory(w, host.ID, http.StatusRequestTimeout, map[string]string{"error": "inventory upload too slow"})
				return
			}
			s.invalidInventory(w, host.ID, http.StatusBadRequest, map[string]string{"error": "invalid gzip body"})
			return
		}
		defer gz.Close()
		body = &capReader{r: gz, left: MaxInventoryBytes} // decompressed size cap
	case "", "identity":
		body = &capReader{r: body, left: MaxInventoryBytes}
	default:
		s.invalidInventory(w, host.ID, http.StatusUnsupportedMediaType, map[string]string{"error": "unsupported Content-Encoding"})
		return
	}
	var p model.InventoryPayload
	if err := json.NewDecoder(body).Decode(&p); err != nil {
		var mbe *http.MaxBytesError
		switch {
		case errors.Is(err, errSlowBody):
			s.invalidInventory(w, host.ID, http.StatusRequestTimeout, map[string]string{"error": "inventory upload too slow"})
		case errors.Is(err, errTooLarge), errors.As(err, &mbe):
			s.invalidInventory(w, host.ID, http.StatusRequestEntityTooLarge, map[string]string{"error": "inventory too large (max 64 MiB decompressed)"})
		default:
			s.invalidInventory(w, host.ID, http.StatusBadRequest, map[string]string{"error": "invalid inventory: " + err.Error()})
		}
		return
	}
	// An identical inventory is answered before validation and the inventory limiter and spends no
	// inventory token: nothing changes (the attempt bucket above was still charged).
	if host.InventoryHash != "" && host.InventoryHash == p.Hash {
		resp := map[string]any{"status": "accepted"} // unchanged: no re-matching
		if sk, err := s.Store.ListSkippedTargets(r.Context(), host.ID); err == nil && len(sk) > 0 {
			resp["skipped"] = sk
		}
		writeJSON(w, http.StatusAccepted, resp)
		return
	}
	valid, skipped, err := validateInventory(&p)
	if err != nil {
		s.invalidInventory(w, host.ID, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(valid) == 0 && len(skipped) > 0 && allFormat(skipped) {
		s.invalidInventory(w, host.ID, http.StatusUnsupportedMediaType, map[string]any{
			"error": "no target is a CycloneDX JSON document (bomFormat \"CycloneDX\")", "skipped": skipped})
		return
	}
	if wait := s.inventoryLim.take(host.ID, s.Now()); wait > 0 {
		tooMany(w, wait, "inventory rate limit: burst "+strconv.Itoa(s.InventoryBurst)+", one per "+s.InventoryInterval.String())
		return
	}
	sk := make([]store.SkippedTarget, len(skipped))
	for i, k := range skipped {
		sk[i] = k.SkippedTarget
	}
	p.Targets = valid
	if err := s.Store.ReplaceInventorySkipped(r.Context(), host.ID, p, sk); err != nil {
		s.inventoryLim.refund(host.ID)
		s.internal(w, "store inventory", err)
		return
	}
	s.log.Info("inventory stored", "host", host.ID, "targets", len(valid), "skipped", len(skipped), "hash", p.Hash)
	for _, k := range skipped {
		s.log.Warn("inventory target skipped", "host", host.ID, "target", k.Name, "reason", k.Reason)
	}
	if s.Pipeline != nil {
		s.Pipeline.Trigger(host.ID)
	}
	resp := map[string]any{"status": "accepted"}
	if len(sk) > 0 {
		resp["skipped"] = sk
	}
	writeJSON(w, http.StatusAccepted, resp)
}

// skippedTarget is a refused target; format marks "not a (valid) CycloneDX document".
type skippedTarget struct {
	store.SkippedTarget
	format bool
}

func allFormat(sk []skippedTarget) bool {
	for _, k := range sk {
		if !k.format {
			return false
		}
	}
	return true
}

// validateInventory validates the payload as a whole (400) and every target on its own: invalid or
// oversized targets are returned as skipped, the valid ones are kept, so one bad target (e.g. a
// huge container image) never blinds the whole host.
func validateInventory(p *model.InventoryPayload) (valid []model.InventoryTarget, skipped []skippedTarget, err error) {
	if p.Hash == "" {
		return nil, nil, errors.New("hash is required")
	}
	if len(p.Hash) > 256 {
		return nil, nil, errors.New("hash too long")
	}
	if len(p.Targets) > maxTargets {
		return nil, nil, fmt.Errorf("too many targets (max %d)", maxTargets)
	}
	seen := map[string]bool{}
	for i, t := range p.Targets {
		skip := func(format bool, reason string) {
			name := cleanText(t.Name, 64)
			if name == "" {
				name = fmt.Sprintf("(target %d)", i)
			}
			kind := model.TargetKind(cleanText(string(t.Kind), 32))
			if kind != model.TargetHost && kind != model.TargetContainerImage {
				kind = "invalid"
			}
			skipped = append(skipped, skippedTarget{SkippedTarget: store.SkippedTarget{Kind: kind, Name: name, Reason: reason}, format: format})
		}
		switch {
		case t.Kind != model.TargetHost && t.Kind != model.TargetContainerImage:
			skip(false, fmt.Sprintf("unknown kind %q", cleanText(string(t.Kind), 32)))
			continue
		case t.Name == "":
			skip(false, "name is required")
			continue
		case len(t.Name) > maxTargetName:
			skip(false, fmt.Sprintf("name longer than %d bytes", maxTargetName))
			continue
		case len(t.ImageID) > maxImageID:
			skip(false, fmt.Sprintf("image_id longer than %d bytes", maxImageID))
			continue
		case len(t.Containers) > maxContainers:
			skip(false, fmt.Sprintf("more than %d containers", maxContainers))
			continue
		case len(t.SBOM) == 0 || string(t.SBOM) == "null":
			skip(true, "sbom is required")
			continue
		}
		longName := false
		for _, c := range t.Containers {
			if len(c) > maxContainerNameLen {
				longName = true
			}
		}
		if longName {
			skip(false, fmt.Sprintf("container name longer than %d bytes", maxContainerNameLen))
			continue
		}
		k := string(t.Kind) + "\x00" + t.Name
		if seen[k] {
			skip(false, "duplicate target")
			continue
		}
		if _, err := countComponents(t.SBOM, MaxComponents); err != nil {
			switch {
			case errors.Is(err, errTooManyComponents):
				skip(false, fmt.Sprintf("more than %d components", MaxComponents))
			default:
				skip(true, "invalid sbom: "+err.Error())
			}
			continue
		}
		seen[k] = true
		valid = append(valid, t)
	}
	return valid, skipped, nil
}

var (
	errTooManyComponents = errors.New("too many components")
	errNotCycloneDX      = errors.New(`not a CycloneDX JSON document (top-level "bomFormat" must be exactly "CycloneDX")`)
)

// countComponents streams the whole document once and counts every object in an array under a
// key named exactly "components" (at any depth), stopping as soon as limit is exceeded, so no huge
// component slice is ever built. The document must be a JSON object with top-level
// "bomFormat": "CycloneDX" (exact, case-sensitive). Keys that equal "components" or "bomFormat"
// only case-insensitively are rejected: a lenient downstream decoder (Grype/Syft) could otherwise
// parse components that this counter never saw.
func countComponents(sbom []byte, limit int) (int, error) {
	type frame struct {
		obj       bool
		expectKey bool
		key       string
		comps     bool // array that is the value of a "components" key
	}
	dec := json.NewDecoder(bytes.NewReader(sbom))
	var stack []frame
	total, formats, badFormat, done := 0, 0, false, false
	for {
		t, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
		if done {
			return 0, errors.New("trailing data after the JSON document")
		}
		if len(stack) == 0 && t != json.Delim('{') {
			return 0, errors.New("sbom must be a JSON object")
		}
		var top *frame
		if n := len(stack); n > 0 {
			top = &stack[n-1]
		}
		if _, isDelim := t.(json.Delim); top != nil && top.obj && top.expectKey && !isDelim {
			k, _ := t.(string)
			for _, name := range []string{"components", "bomFormat"} {
				if k != name && strings.EqualFold(k, name) {
					return 0, fmt.Errorf("ambiguous key %q (only the exact spelling %q is accepted)", k, name)
				}
			}
			top.key, top.expectKey = k, false
			continue
		}
		switch d := t.(type) {
		case json.Delim:
			if d == '{' || d == '[' {
				if top != nil && !top.obj && top.comps && d == '{' {
					if total++; total > limit {
						return total, errTooManyComponents
					}
				}
				if len(stack) == 1 && top.key == "bomFormat" {
					badFormat = true
				}
				stack = append(stack, frame{obj: d == '{', expectKey: d == '{',
					comps: d == '[' && top != nil && top.obj && top.key == "components"})
				continue
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				done = true
			} else if p := &stack[len(stack)-1]; p.obj {
				p.expectKey = true
			}
		default:
			if top != nil && top.obj {
				if len(stack) == 1 && top.key == "bomFormat" {
					if v, ok := t.(string); ok && v == "CycloneDX" {
						formats++
					} else {
						badFormat = true
					}
				}
				top.expectKey = true
			}
		}
	}
	if !done {
		return 0, errors.New("incomplete JSON document")
	}
	if formats == 0 || badFormat {
		return total, errNotCycloneDX
	}
	return total, nil
}
