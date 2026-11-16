// Package pipeline implements contracts §5: match -> evaluate -> upsert -> resolve -> draft -> notify.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"panoptes/internal/model"
	"panoptes/internal/server/core"
	"panoptes/internal/server/store"
)

// Matcher finds vulnerabilities in one CycloneDX SBOM. Implemented by match.Grype; faked in tests.
// Returned findings need only the matcher-derived fields; the pipeline fills host/target/verdict.
type Matcher interface {
	Match(ctx context.Context, kind model.TargetKind, sbom []byte, osInfo model.OSInfo) ([]model.Finding, error)
}

// Options tune the pipeline.
type Options struct {
	PublicURL   string // base for Event.WebURL
	Logger      *slog.Logger
	Now         func() time.Time
	Concurrency int // hosts processed in parallel (default 2; matching is CPU/memory heavy)
}

// Pipeline recomputes findings for hosts. Trigger is non-blocking and coalesces per host.
type Pipeline struct {
	st       store.Store
	matcher  Matcher
	eval     core.RuleEvaluator
	notifier core.Notifier
	drafter  core.RuleDrafter
	opts     Options
	log      *slog.Logger

	baseCtx context.Context
	cancel  context.CancelFunc
	sem     chan struct{}
	wg      sync.WaitGroup

	mu    sync.Mutex
	state map[string]*hostState
}

type hostState struct{ running, dirty bool }

// New builds a pipeline. The three plug-point interfaces can be swapped for real implementations.
func New(st store.Store, m Matcher, ev core.RuleEvaluator, n core.Notifier, d core.RuleDrafter, opts Options) *Pipeline {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 2
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Pipeline{
		st: st, matcher: m, eval: ev, notifier: n, drafter: d, opts: opts, log: opts.Logger,
		baseCtx: ctx, cancel: cancel, sem: make(chan struct{}, opts.Concurrency),
		state: map[string]*hostState{},
	}
}

// Trigger schedules a recomputation for hostID and returns immediately. Triggers arriving while a
// run is in progress for the same host are coalesced into exactly one follow-up run.
func (p *Pipeline) Trigger(hostID string) {
	p.mu.Lock()
	s := p.state[hostID]
	if s == nil {
		s = &hostState{}
		p.state[hostID] = s
	}
	if s.running {
		s.dirty = true
		p.mu.Unlock()
		return
	}
	s.running = true
	p.mu.Unlock()

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			p.runLimited(hostID)
			p.mu.Lock()
			if s.dirty && p.baseCtx.Err() == nil {
				s.dirty = false
				p.mu.Unlock()
				continue
			}
			s.running, s.dirty = false, false
			delete(p.state, hostID)
			p.mu.Unlock()
			return
		}
	}()
}

func (p *Pipeline) runLimited(hostID string) {
	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	case <-p.baseCtx.Done():
		return
	}
	if err := p.Run(p.baseCtx, hostID); err != nil && !errors.Is(err, context.Canceled) {
		p.log.Error("pipeline run failed", "host", hostID, "err", err)
	}
}

// TriggerAll schedules every known host (after a vuln DB update or rule change).
func (p *Pipeline) TriggerAll(ctx context.Context) error {
	hosts, err := p.st.ListHosts(ctx)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		p.Trigger(h.ID)
	}
	return nil
}

// Wait blocks until all scheduled runs finished (tests, graceful shutdown).
func (p *Pipeline) Wait() { p.wg.Wait() }

// Shutdown cancels in-flight runs and waits for them.
func (p *Pipeline) Shutdown() {
	p.cancel()
	p.wg.Wait()
}

type fkey struct{ target, pkg, ver, vuln string }

func keyOf(f model.Finding) fkey { return fkey{f.Target, f.PackageName, f.PackageVer, f.VulnID} }

// Run recomputes the findings of one host synchronously. If matching fails for any target
// (e.g. no vuln DB yet) nothing is changed.
func (p *Pipeline) Run(ctx context.Context, hostID string) error {
	host, err := p.st.GetHost(ctx, hostID)
	if err != nil {
		return fmt.Errorf("get host: %w", err)
	}
	targets, err := p.st.ListTargets(ctx, hostID)
	if err != nil {
		return fmt.Errorf("list targets: %w", err)
	}
	prev, err := p.st.HostFindings(ctx, hostID)
	if err != nil {
		return fmt.Errorf("load findings: %w", err)
	}
	prevByKey := make(map[fkey]model.Finding, len(prev))
	for _, f := range prev {
		prevByKey[keyOf(f)] = f
	}

	// 1. match every target
	var found []model.Finding
	seen := map[fkey]bool{}
	for _, t := range targets {
		if len(t.SBOM) == 0 {
			continue
		}
		fs, err := p.matcher.Match(ctx, t.Kind, t.SBOM, host.OS)
		if err != nil {
			return fmt.Errorf("match %s %q: %w", t.Kind, t.Name, err)
		}
		for _, f := range fs {
			f.HostID, f.Target, f.TargetKind = hostID, t.Name, t.Kind
			if seen[keyOf(f)] {
				continue
			}
			seen[keyOf(f)] = true
			found = append(found, f)
		}
	}

	// 2. evaluate
	hc := core.HostContext{Host: host, Facts: host.Facts}
	rules := map[fkey]*model.Rule{}
	for i := range found {
		f := &found[i]
		ev := p.eval.Evaluate(ctx, hc, *f)
		f.Verdict, f.VerdictReason = ev.Verdict, ev.Reason
		if f.Verdict == "" {
			f.Verdict = model.VerdictConditionsUnknown
		}
		f.RuleID, f.RuleStatus = "", ""
		if ev.Rule != nil {
			f.RuleID, f.RuleStatus = ev.Rule.ID, ev.RuleStatus
			if f.RuleStatus == "" {
				f.RuleStatus = ev.Rule.Status
			}
			rules[keyOf(*f)] = ev.Rule
		}
	}

	// 3. upsert; vanished findings become resolved
	now := p.opts.Now()
	res, err := p.st.ApplyHostFindings(ctx, hostID, found, now)
	if err != nil {
		return fmt.Errorf("store findings: %w", err)
	}

	// 4. rule drafting for findings nobody has a rule for
	for _, f := range res.Current {
		if f.RuleID == "" && (f.KEV || strings.EqualFold(f.Severity, "High") || strings.EqualFold(f.Severity, "Critical")) {
			p.drafter.Enqueue(ctx, f)
		}
	}

	// 5. events
	events, err := p.buildEvents(ctx, host, prevByKey, res, rules)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	if err := p.notifier.Notify(ctx, events); err != nil {
		// Not recorded as sent: exploitable events are retried on the next run.
		return fmt.Errorf("notify: %w", err)
	}
	for _, e := range events {
		if err := p.st.RecordNotification(ctx, store.FindingKey(e.Finding), store.DedupKey(e.Finding, e.Kind), e.Kind, now); err != nil {
			return fmt.Errorf("record notification: %w", err)
		}
	}
	return nil
}

func (p *Pipeline) buildEvents(ctx context.Context, host model.Host, prev map[fkey]model.Finding, res store.ApplyResult, rules map[fkey]*model.Rule) ([]model.Event, error) {
	var events []model.Event
	add := func(kind model.EventKind, f model.Finding) error {
		sent, err := p.st.NotificationSent(ctx, store.DedupKey(f, kind))
		if err != nil {
			return err
		}
		if sent {
			return nil // never send the same key twice in a row
		}
		events = append(events, model.Event{
			Kind: kind, Finding: f, Host: host, Rule: rules[keyOf(f)],
			FixCmd: FixCmd(f), WebURL: WebURL(p.opts.PublicURL, f.ID),
		})
		return nil
	}
	resolvedKind := func(v model.Verdict) bool {
		return v == model.VerdictResolved || v == model.VerdictNotExploitable || v == model.VerdictNotAffected
	}
	maybeResolved := func(f model.Finding) error {
		notified, err := p.st.FindingNotified(ctx, store.FindingKey(f))
		if err != nil || !notified {
			return err
		}
		return add(model.EventResolved, f)
	}

	for _, f := range res.Current {
		old, had := prev[keyOf(f)]
		isNew := !had || old.Verdict == model.VerdictResolved
		switch {
		case f.Verdict == model.VerdictExploitable:
			// state based on the dedup table: new, changed to exploitable, or not yet delivered
			if err := add(model.EventExploitable, f); err != nil {
				return nil, err
			}
		case f.Verdict == model.VerdictConditionsUnknown && isNew && (f.KEV || strings.EqualFold(f.Severity, "Critical")):
			if err := add(model.EventUnknownCritical, f); err != nil {
				return nil, err
			}
		case resolvedKind(f.Verdict) && had && old.Verdict != f.Verdict:
			if err := maybeResolved(f); err != nil {
				return nil, err
			}
		}
	}
	for _, f := range res.Resolved {
		if err := maybeResolved(f); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].Kind < events[j].Kind })
	return events, nil
}

// WebURL links to a finding in the web UI.
func WebURL(publicURL string, id int64) string {
	return strings.TrimRight(publicURL, "/") + "/findings/" + strconv.FormatInt(id, 10)
}

// FixCmd derives a package-manager command that fixes the finding on its host; empty when unknown.
// Values are validated so a hostile package name cannot smuggle shell syntax into a notification.
func FixCmd(f model.Finding) string {
	if f.FixState == "not-fixed" || f.FixState == "wont-fix" {
		return ""
	}
	if f.TargetKind == model.TargetContainerImage {
		if safeRef(f.Target) {
			return "rebuild/pull image " + f.Target + " with fixed base"
		}
		return "rebuild/pull image with fixed base"
	}
	name := f.PackageName
	if !safeName(name) {
		return ""
	}
	fixed := ""
	for _, v := range f.FixedVersions {
		if safeVersion(v) {
			fixed = v
			break
		}
	}
	switch f.PackageType {
	case "deb":
		return "apt-get install --only-upgrade " + name
	case "rpm":
		return "dnf upgrade " + name
	case "apk":
		return "apk upgrade " + name
	case "python":
		if fixed == "" {
			return "pip install -U " + name
		}
		return "pip install -U '" + name + ">=" + fixed + "'"
	case "npm":
		if fixed == "" {
			return "npm install " + name + "@latest"
		}
		return "npm install " + name + "@" + fixed
	}
	return ""
}

func allowed(s string, extra string, first func(byte) bool) bool {
	if s == "" || len(s) > 256 || !first(s[0]) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte(extra, c) >= 0) {
			return false
		}
	}
	return true
}

func alnum(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' }

func safeName(s string) bool {
	return allowed(s, "+._-@/", func(c byte) bool { return alnum(c) || c == '@' })
}
func safeVersion(s string) bool { return allowed(s, "+._:~-", alnum) }
func safeRef(s string) bool     { return allowed(s, "._:/@-", alnum) }
