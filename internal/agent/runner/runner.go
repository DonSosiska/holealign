// Package runner implements the agent main loop: enroll, check in, upload inventory.
package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"panoptes/internal/agent/config"
	"panoptes/internal/agent/facts"
	"panoptes/internal/agent/inventory"
	"panoptes/internal/agent/transport"
	"panoptes/internal/model"
)

// unauthorizedRetry is how long to wait after a 401 when no enroll token is available.
const unauthorizedRetry = time.Hour

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
}

// New creates a runner.
func New(cfg config.Config, version string, log *slog.Logger) *Runner {
	if log == nil {
		log = slog.Default()
	}
	return &Runner{
		cfg:          cfg,
		version:      version,
		log:          log,
		client:       transport.New(cfg.ServerURL, ""),
		collectFacts: facts.Collect,
		scan:         inventory.Scan,
		detector:     inventory.NewChangeDetector(cfg),
	}
}

// Run loops until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) error {
	if err := r.ensureEnrolled(ctx); err != nil {
		return err
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
		if errors.Is(err, transport.ErrUnauthorized) {
			r.log.Error("unauthorized and cannot re-enroll; retrying later", "retry_in", unauthorizedRetry)
			return unauthorizedRetry
		}
		r.log.Error("cycle failed", "err", err)
	}
	return delay
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
	resp, err := r.client.Enroll(ctx, model.EnrollRequest{
		Token:        r.cfg.EnrollToken,
		Hostname:     host,
		MachineID:    MachineID(),
		Labels:       r.cfg.Labels,
		AgentVersion: r.version,
	})
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
	next := r.interval()
	if resp.NextCheckinSeconds > 0 {
		next = time.Duration(resp.NextCheckinSeconds) * time.Second
	}

	changed := r.detector.Changed(ctx)
	due := r.lastInvAt.IsZero() || time.Since(r.lastInvAt) >= r.cfg.InventoryInterval
	if forceInventory || resp.WantInventory || changed || due {
		reason := "interval"
		switch {
		case forceInventory:
			reason = "forced"
		case resp.WantInventory:
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

func (r *Runner) interval() time.Duration { return r.cfg.CheckinInterval }

func (r *Runner) uploadInventory(ctx context.Context, reason string) error {
	r.log.Info("scanning inventory", "reason", reason)
	start := time.Now()
	payload, err := r.scan(ctx, r.cfg)
	if err != nil {
		return fmt.Errorf("inventory scan: %w", err)
	}
	if err := r.client.UploadInventory(ctx, payload); err != nil {
		return fmt.Errorf("inventory upload: %w", err)
	}
	r.invHash = payload.Hash
	r.lastInvAt = time.Now()
	r.detector.Reset(ctx)
	r.log.Info("inventory uploaded", "targets", len(payload.Targets), "hash", payload.Hash, "took", time.Since(start).Round(time.Millisecond))
	return nil
}
