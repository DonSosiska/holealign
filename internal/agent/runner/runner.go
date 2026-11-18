// Package runner implements the agent main loop: enroll, check in, upload inventory.
package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/DonSosiska/holealign/internal/agent/config"
	"github.com/DonSosiska/holealign/internal/agent/hostdata"
	"github.com/DonSosiska/holealign/internal/agent/transport"
	"github.com/DonSosiska/holealign/internal/model"
)

// unauthorizedRetry is how long to wait after a 401 when no enroll token is available.
const unauthorizedRetry = time.Hour

// Bounds for the server-suggested check-in interval, and the cap of the
// scan-failure backoff.
const (
	minNextCheckin  = 60 * time.Second
	maxNextCheckin  = time.Hour
	maxScanBackoff  = 6 * time.Hour
	inventoryErrKey = "agent.inventory_error"
	collectorErrKey = "agent.collector_error"
)

// clampNextCheckin converts the server's NextCheckinSeconds into a delay within
// [60 s, 1 h]; 0 (or negative) selects def. Bounds are checked on the int
// before multiplying so huge values cannot overflow time.Duration.
func clampNextCheckin(secs int, def time.Duration) time.Duration {
	switch {
	case secs <= 0:
		return def
	case secs < int(minNextCheckin/time.Second):
		return minNextCheckin
	case secs > int(maxNextCheckin/time.Second):
		return maxNextCheckin
	}
	return time.Duration(secs) * time.Second
}

// scanBackoff is the retry delay after n consecutive scan failures: the check-in
// interval doubled per failure, capped at 6 h.
func scanBackoff(base time.Duration, n int) time.Duration {
	if base <= 0 {
		base = time.Minute
	}
	d := base
	for i := 0; i < n && d < maxScanBackoff; i++ {
		d *= 2
	}
	if d > maxScanBackoff {
		d = maxScanBackoff
	}
	return d
}

// Runner holds the agent state between check-ins.
type Runner struct {
	cfg     config.Config
	version string
	log     *slog.Logger
	client  *transport.Client

	// src provides facts, inventory, OS info and change detection: in-process (mode all)
	// or from the root collector over its unix socket (mode sender).
	src hostdata.Source

	creds        transport.Credentials
	lastFacts    model.Facts // last snapshot acknowledged by the server; nil = never sent
	wantFull     bool
	factRequests []model.FactRequest
	invHash      string
	sleep        func(context.Context, time.Duration) bool // test hook for -once waits
	pendingInv   *model.InventoryPayload                   // scanned but not yet accepted (rate limited)
	lastInvAt    time.Time

	lastWantInv time.Time // last time a server WantInventory request was honoured

	lastInfo         hostdata.HostInfo // last OS info the collector gave
	haveInfo         bool
	tokenForgetTried bool // forget_enroll_token was attempted (once per process)

	scanFailures int
	scanRetryAt  time.Time
	lastScanErr  string
}

// New creates a runner.
// src nil selects the in-process source.
func New(cfg config.Config, version string, log *slog.Logger, src hostdata.Source) (*Runner, error) {
	if src == nil {
		src = hostdata.NewLocal(cfg, false)
	}
	if log == nil {
		log = slog.Default()
	}
	client, err := transport.NewWithTLS(cfg.ServerURL, "", transport.TLSOptions{
		CAFile:     cfg.CAFile,
		PinsSHA256: cfg.ServerCertSHA256,
		ClientCert: cfg.ClientCert,
		ClientKey:  cfg.ClientKey,
	})
	if err != nil {
		return nil, err
	}
	return newWithClient(cfg, version, log, src, client), nil
}

// NewWithClient is New with a caller-supplied transport client (the server's in-process local
// agent talks to the API handler through an in-memory http.RoundTripper). TLS options in cfg
// are ignored.
func NewWithClient(cfg config.Config, version string, log *slog.Logger, src hostdata.Source, client *transport.Client) *Runner {
	if src == nil {
		src = hostdata.NewLocal(cfg, false)
	}
	if log == nil {
		log = slog.Default()
	}
	return newWithClient(cfg, version, log, src, client)
}

func newWithClient(cfg config.Config, version string, log *slog.Logger, src hostdata.Source, client *transport.Client) *Runner {
	client.AllowInsecureHTTP = cfg.AllowInsecureHTTP
	if cfg.AllowInsecureHTTP && strings.HasPrefix(cfg.ServerURL, "http://") {
		log.Warn("allow_insecure_http is set: traffic including the agent key is NOT encrypted")
	}
	if cfg.CAFile != "" || len(cfg.ServerCertSHA256) > 0 {
		log.Info("server identity checks enabled", "ca_file", cfg.CAFile != "", "pins", len(cfg.ServerCertSHA256), "mtls", cfg.ClientCert != "")
	}
	return &Runner{
		cfg:     cfg,
		version: version,
		log:     log,
		client:  client,
		src:     src,
	}
}

// Run loops until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) error {
	for {
		err := r.ensureEnrolled(ctx)
		if err == nil {
			break
		}
		wait := unauthorizedRetry
		var rl *transport.RateLimitedError
		switch {
		case errors.As(err, &rl):
			r.log.Info("rate limited by server, retrying", "retry_in", rl.RetryAfter.String())
			wait = rl.RetryAfter
		case !errors.Is(err, transport.ErrEnrollConflict):
			return err
		}
		if !sleepCtx(ctx, wait) {
			return nil
		}
	}
	for {
		delay := r.cycle(ctx, false)
		if ctx.Err() != nil {
			return nil
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}

// RunOnce enrolls if needed, performs one check-in and uploads the inventory, then returns.
//
// When the server answers 429 with a Retry-After of at most 60 s the call waits and
// retries once; a longer wait fails with a clear message.
func (r *Runner) RunOnce(ctx context.Context) error {
	err := r.runOnce(ctx)
	var rl *transport.RateLimitedError
	if errors.As(err, &rl) && rl.RetryAfter <= onceMaxWait {
		r.log.Info("rate limited by server, waiting before one retry", "retry_in", rl.RetryAfter.String())
		sleep := r.sleep
		if sleep == nil {
			sleep = sleepCtx
		}
		if !sleep(ctx, rl.RetryAfter) {
			return ctx.Err()
		}
		err = r.runOnce(ctx)
	}
	if errors.As(err, &rl) {
		return fmt.Errorf("rate limited by the server; retry in %s: %w", rl.RetryAfter.Round(time.Second), err)
	}
	return err
}

// onceMaxWait is the longest Retry-After that -once waits out.
const onceMaxWait = 60 * time.Second

func (r *Runner) runOnce(ctx context.Context) error {
	if r.creds.AgentKey == "" {
		if err := r.ensureEnrolled(ctx); err != nil {
			return err
		}
	}
	_, err := r.checkinAndUpload(ctx, true)
	return err
}

// cycle runs one iteration and returns the delay until the next one.
func (r *Runner) cycle(ctx context.Context, forceInventory bool) time.Duration {
	delay, err := r.checkinAndUpload(ctx, forceInventory)
	if err != nil {
		if ctx.Err() != nil {
			return 0
		}
		if errors.Is(err, transport.ErrEnrollConflict) {
			return unauthorizedRetry
		}
		var rl *transport.RateLimitedError
		if errors.As(err, &rl) {
			// not a failure: nothing backs off, a pending inventory is re-sent next cycle
			r.log.Info("rate limited by server, retrying", "retry_in", rl.RetryAfter.String())
			return max(delay, rl.RetryAfter)
		}
		if errors.Is(err, transport.ErrUnauthorized) {
			r.log.Error("unauthorized and cannot re-enroll; retrying later", "retry_in", unauthorizedRetry)
			return unauthorizedRetry
		}
		r.log.Error("cycle failed", "err", err)
	}
	return delay
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (r *Runner) ensureEnrolled(ctx context.Context) error {
	creds, err := transport.LoadCredentials(r.cfg.StateDir)
	if err == nil {
		r.creds = creds
		r.client.Key = creds.AgentKey
		r.log.Info("loaded credentials", "agent_id", creds.AgentID)
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		r.log.Warn("credentials unreadable, enrolling again", "err", err)
	}
	return r.enroll(ctx)
}

func (r *Runner) enroll(ctx context.Context) error {
	if r.cfg.EnrollToken == "" {
		return errors.New("not enrolled and no enroll_token configured")
	}
	host, _ := os.Hostname()
	info, err := r.src.Info(ctx)
	if err != nil {
		return fmt.Errorf("host info: %w", err)
	}
	if r.client.Key == "" {
		// keep proving identity with a previous key if the state dir still has one
		if old, err := transport.LoadCredentials(r.cfg.StateDir); err == nil {
			r.client.Key = old.AgentKey
		}
	}
	resp, err := r.client.Enroll(ctx, model.EnrollRequest{
		Token:        r.cfg.EnrollToken,
		Hostname:     host,
		MachineID:    info.MachineID,
		Labels:       r.cfg.Labels,
		AgentVersion: r.version,
	})
	if errors.Is(err, transport.ErrEnrollConflict) {
		r.log.Error("server refused enrollment: host already exists and the previous key is missing or invalid; "+
			"run `holealign-server host allow-reenroll <hostname>` on the server; retrying hourly", "hostname", host)
	}
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	r.creds = transport.Credentials{AgentID: resp.AgentID, AgentKey: resp.AgentKey}
	r.client.Key = resp.AgentKey
	if err := transport.SaveCredentials(r.cfg.StateDir, r.creds); err != nil {
		return fmt.Errorf("save credentials: %w", err)
	}
	// a rotated key means the server may have lost our state
	r.lastFacts = nil
	r.log.Info("enrolled", "agent_id", resp.AgentID)
	return nil
}

func (r *Runner) checkinAndUpload(ctx context.Context, forceInventory bool) (time.Duration, error) {
	// A collector that answers with an error must not stop the check-in (a malicious server
	// could otherwise silence the agent by sending requests that break the collector): the
	// check-in goes out with the facts still known plus agent.collector_error. An unreachable
	// collector socket still skips the cycle.
	collectorErr := ""
	rawFacts, err := r.src.Facts(ctx, r.factRequests)
	if err != nil && len(r.factRequests) > 0 && requestRejected(err) {
		r.log.Warn("collector rejected the stored fact requests; dropping them and retrying once", "err", err)
		r.factRequests = nil
		rawFacts, err = r.src.Facts(ctx, nil)
	}
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, hostdata.ErrUnavailable) {
			return r.interval(), fmt.Errorf("collect facts: %w", err)
		}
		r.log.Warn("collecting facts failed; checking in with the facts still known", "err", err)
		collectorErr = err.Error()
		rawFacts = nil
	}
	info, err := r.src.Info(ctx)
	switch {
	case err == nil:
		r.lastInfo, r.haveInfo = info, true
	case ctx.Err() != nil || errors.Is(err, hostdata.ErrUnavailable) || !r.haveInfo:
		return r.interval(), fmt.Errorf("host info: %w", err)
	default:
		r.log.Warn("host info failed; using the previous value", "err", err)
		if collectorErr == "" {
			collectorErr = err.Error()
		}
		info = r.lastInfo
	}
	cur := NormalizeFacts(rawFacts)
	if collectorErr != "" {
		if r.lastFacts != nil {
			cur = NormalizeFacts(r.lastFacts) // copy: keep what the server knows
		}
		delete(cur, collectorErrKey)
		msg := strings.ToValidUTF8(collectorErr, "")
		if len(msg) > 200 {
			msg = strings.ToValidUTF8(msg[:200], "")
		}
		cur[collectorErrKey] = msg
	}
	if r.lastScanErr != "" {
		cur[inventoryErrKey] = r.lastScanErr
	}
	host, _ := os.Hostname()

	build := func() model.CheckinRequest {
		req := model.CheckinRequest{
			Hostname:      host,
			Labels:        r.cfg.Labels,
			AgentVersion:  r.version,
			OS:            info.OS,
			InventoryHash: r.invHash,
		}
		if r.lastFacts == nil || r.wantFull {
			req.Facts, req.FactsComplete = cur, true
		} else {
			req.Facts, req.FactsComplete = DiffFacts(r.lastFacts, cur), false
		}
		return req
	}

	resp, err := r.client.Checkin(ctx, build())
	if errors.Is(err, transport.ErrUnauthorized) && r.cfg.EnrollToken != "" {
		r.log.Warn("checkin unauthorized, re-enrolling")
		if eerr := r.enroll(ctx); eerr != nil {
			return r.interval(), eerr
		}
		resp, err = r.client.Checkin(ctx, build())
	}
	if err != nil {
		return r.interval(), fmt.Errorf("checkin: %w", err)
	}
	r.lastFacts = cur
	r.wantFull = resp.WantFullFacts
	r.factRequests = r.acceptFactRequests(resp.FactRequests)
	r.forgetEnrollToken(ctx)
	r.log.Debug("checkin ok", "facts", len(cur), "want_inventory", resp.WantInventory, "fact_requests", len(resp.FactRequests))
	next := clampNextCheckin(resp.NextCheckinSeconds, r.interval())

	changed, cerr := r.src.Changed(ctx)
	if cerr != nil {
		r.log.Warn("change detection failed", "err", cerr)
	}
	due := r.lastInvAt.IsZero() || time.Since(r.lastInvAt) >= r.cfg.InventoryInterval
	if r.pendingInv != nil {
		return next, r.sendInventory(ctx, r.pendingInv, time.Now())
	}
	if !forceInventory && time.Now().Before(r.scanRetryAt) {
		return next, nil // backing off after repeated scan failures
	}
	wantInv := r.honorWantInventory(resp.WantInventory, time.Now())
	if forceInventory || wantInv || changed || due {
		reason := "interval"
		switch {
		case forceInventory:
			reason = "forced"
		case wantInv:
			reason = "server request"
		case changed:
			reason = "package change"
		}
		if err := r.uploadInventory(ctx, reason); err != nil {
			return next, err
		}
	}
	return next, nil
}

// wantInventoryMinGap limits how often a server request for an inventory is honoured,
// so a malicious server cannot force back-to-back full scans.
const wantInventoryMinGap = 10 * time.Minute

func (r *Runner) honorWantInventory(want bool, now time.Time) bool {
	if !want {
		return false
	}
	if !r.lastWantInv.IsZero() && now.Sub(r.lastWantInv) < wantInventoryMinGap {
		return false
	}
	r.lastWantInv = now
	return true
}

func (r *Runner) interval() time.Duration { return r.cfg.CheckinInterval }

func (r *Runner) uploadInventory(ctx context.Context, reason string) error {
	r.log.Info("scanning inventory", "reason", reason)
	start := time.Now()
	payload, err := r.src.Inventory(ctx)
	if err != nil {
		if ctx.Err() == nil {
			r.scanFailures++
			r.scanRetryAt = time.Now().Add(scanBackoff(r.cfg.CheckinInterval, r.scanFailures))
			msg := err.Error()
			if len(msg) > 200 {
				msg = msg[:200]
			}
			r.lastScanErr = strings.ToValidUTF8(msg, "")
		}
		return fmt.Errorf("inventory scan: %w", err)
	}
	r.scanFailures, r.scanRetryAt, r.lastScanErr = 0, time.Time{}, ""
	return r.sendInventory(ctx, &payload, start)
}

func (r *Runner) sendInventory(ctx context.Context, payload *model.InventoryPayload, start time.Time) error {
	if err := r.client.UploadInventory(ctx, *payload); err != nil {
		var rl *transport.RateLimitedError
		if errors.As(err, &rl) {
			r.pendingInv = payload // same payload (hash) is uploaded on the next cycle
		} else {
			r.pendingInv = nil
		}
		return fmt.Errorf("inventory upload: %w", err)
	}
	r.pendingInv = nil
	r.invHash = payload.Hash
	r.lastInvAt = time.Now()
	r.log.Info("inventory uploaded", "targets", len(payload.Targets), "hash", payload.Hash, "took", time.Since(start).Round(time.Millisecond))
	return nil
}

// Limits of the fact requests the sender passes on to the root collector. The server is not
// trusted: anything else is dropped before it is stored or sent.
const (
	maxFactRequests    = 20
	maxFactRequestName = 128
	maxFactRequestPath = 512
	maxFactRequestPat  = 512
	factRequestPrefix  = "file.match:"
)

func cleanText(s string) bool { return utf8.ValidString(s) && !strings.ContainsRune(s, 0) }

// sanitizeFactRequests keeps the well-formed file.match requests (at most 20, unique names)
// and returns them rebuilt with only the path and pattern parameters, plus how many were
// dropped. The request line to the collector is capped at hostdata.MaxRequestBytes, so the
// list is also shortened until it fits.
func sanitizeFactRequests(in []model.FactRequest) (out []model.FactRequest, dropped int) {
	seen := map[string]bool{}
	for _, q := range in {
		path, pat := q.Params["path"], q.Params["pattern"]
		ok := q.Collector == "file.match" &&
			strings.HasPrefix(q.Name, factRequestPrefix) && len(q.Name) > len(factRequestPrefix) &&
			len(q.Name) <= maxFactRequestName && cleanText(q.Name) && !seen[q.Name] &&
			strings.HasPrefix(path, "/") && len(path) <= maxFactRequestPath && cleanText(path) &&
			pat != "" && len(pat) <= maxFactRequestPat && cleanText(pat) &&
			len(out) < maxFactRequests
		if !ok {
			dropped++
			continue
		}
		seen[q.Name] = true
		out = append(out, model.FactRequest{Name: q.Name, Collector: q.Collector,
			Params: map[string]string{"path": path, "pattern": pat}})
	}
	for len(out) > 0 {
		line, err := json.Marshal(hostdata.Request{Op: hostdata.OpFacts, FactRequests: out})
		if err == nil && len(line)+1 <= hostdata.MaxRequestBytes {
			break
		}
		out = out[:len(out)-1]
		dropped++
	}
	return out, dropped
}

func (r *Runner) acceptFactRequests(in []model.FactRequest) []model.FactRequest {
	out, dropped := sanitizeFactRequests(in)
	if dropped > 0 {
		r.log.Warn("ignored malformed or excessive fact requests from the server", "dropped", dropped, "kept", len(out))
	}
	return out
}

// requestRejected reports whether the collector refused the request itself (too large or
// unparsable), so that retrying the same request cannot succeed.
func requestRejected(err error) bool {
	m := err.Error()
	return strings.Contains(m, "request too large") || strings.Contains(m, "bad request")
}

// forgetEnrollToken asks (once per process) for enroll_token to be removed from the config
// file after enrollment and a first successful check-in: the token is only needed to enroll.
// With a collector the root collector does it; in mode all the process itself when it is root.
// A host that lost its credentials must be enrolled again with a fresh token.
func (r *Runner) forgetEnrollToken(ctx context.Context) {
	if r.tokenForgetTried || r.cfg.EnrollToken == "" || r.creds.AgentKey == "" {
		return
	}
	r.tokenForgetTried = true
	f, ok := r.src.(hostdata.EnrollTokenForgetter)
	if !ok {
		return
	}
	if err := f.ForgetEnrollToken(ctx); err != nil {
		r.log.Warn("could not remove enroll_token from the config file; remove it manually", "err", err)
		return
	}
	r.cfg.EnrollToken = ""
	r.log.Info("enroll_token removed from the config file")
}

// CheckPermissions logs a warning for secret-bearing files readable beyond the expected modes.
func CheckPermissions(cfg config.Config, log *slog.Logger) {
	for _, w := range config.PermissionWarnings(cfg, transport.CredentialsPath(cfg.StateDir)) {
		log.Warn(w)
	}
}
