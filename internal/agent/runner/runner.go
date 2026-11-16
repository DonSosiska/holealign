// Package runner implements the agent main loop: enroll, check in, upload inventory.
package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"panoptes/internal/agent/config"
	"panoptes/internal/agent/facts"
	"panoptes/internal/agent/inventory"
	"panoptes/internal/agent/transport"
	"panoptes/internal/model"
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

	// injectable for tests
	collectFacts func(ctx context.Context, reqs []model.FactRequest) model.Facts
	scan         func(ctx context.Context, cfg config.Config) (model.InventoryPayload, error)
	detector     interface {
		Changed(ctx context.Context) bool
		Reset(ctx context.Context)
	}

	creds        transport.Credentials
	lastFacts    model.Facts // last snapshot acknowledged by the server; nil = never sent
	wantFull     bool
	factRequests []model.FactRequest
	invHash      string
	lastInvAt    time.Time

	lastWantInv time.Time // last time a server WantInventory request was honoured

	scanFailures int
	scanRetryAt  time.Time
	lastScanErr  string
}

// New creates a runner.
func New(cfg config.Config, version string, log *slog.Logger) *Runner {
	if log == nil {
		log = slog.Default()
	}
	client := transport.New(cfg.ServerURL, "")
	client.AllowInsecureHTTP = cfg.AllowInsecureHTTP
	if cfg.AllowInsecureHTTP && strings.HasPrefix(cfg.ServerURL, "http://") {
		log.Warn("allow_insecure_http is set: traffic including the agent key is NOT encrypted")
	}
	return &Runner{
		cfg:          cfg,
		version:      version,
		log:          log,
		client:       client,
		collectFacts: facts.Collect,
		scan:         inventory.Scan,
		detector:     inventory.NewChangeDetector(cfg),
	}
}

// Run loops until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) error {
	for {
		err := r.ensureEnrolled(ctx)
		if err == nil {
			break
		}
		if !errors.Is(err, transport.ErrEnrollConflict) {
			return err
		}
		if !sleepCtx(ctx, unauthorizedRetry) {
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
func (r *Runner) RunOnce(ctx context.Context) error {
	if err := r.ensureEnrolled(ctx); err != nil {
		return err
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
	if r.client.Key == "" {
		// keep proving identity with a previous key if the state dir still has one
		if old, err := transport.LoadCredentials(r.cfg.StateDir); err == nil {
			r.client.Key = old.AgentKey
		}
	}
	resp, err := r.client.Enroll(ctx, model.EnrollRequest{
		Token:        r.cfg.EnrollToken,
		Hostname:     host,
		MachineID:    MachineID(),
		Labels:       r.cfg.Labels,
		AgentVersion: r.version,
	})
	if errors.Is(err, transport.ErrEnrollConflict) {
		r.log.Error("server refused enrollment: host already exists and the previous key is missing or invalid; "+
			"run `panoptes-server host allow-reenroll <hostname>` on the server; retrying hourly", "hostname", host)
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
	cur := NormalizeFacts(r.collectFacts(ctx, r.factRequests))
	if r.lastScanErr != "" {
		cur[inventoryErrKey] = r.lastScanErr
	}
	host, _ := os.Hostname()

	build := func() model.CheckinRequest {
		req := model.CheckinRequest{
			Hostname:      host,
			Labels:        r.cfg.Labels,
			AgentVersion:  r.version,
			OS:            CollectOSInfo(),
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
	r.factRequests = resp.FactRequests
	r.log.Debug("checkin ok", "facts", len(cur), "want_inventory", resp.WantInventory, "fact_requests", len(resp.FactRequests))
	next := clampNextCheckin(resp.NextCheckinSeconds, r.interval())

	changed := r.detector.Changed(ctx)
	due := r.lastInvAt.IsZero() || time.Since(r.lastInvAt) >= r.cfg.InventoryInterval
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
	payload, err := r.scan(ctx, r.cfg)
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
	if err := r.client.UploadInventory(ctx, payload); err != nil {
		return fmt.Errorf("inventory upload: %w", err)
	}
	r.invHash = payload.Hash
	r.lastInvAt = time.Now()
	r.detector.Reset(ctx)
	r.log.Info("inventory uploaded", "targets", len(payload.Targets), "hash", payload.Hash, "took", time.Since(start).Round(time.Millisecond))
	return nil
}
