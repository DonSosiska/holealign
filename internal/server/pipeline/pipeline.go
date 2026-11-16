// Package pipeline implements contracts §5: match -> evaluate -> upsert -> resolve -> draft -> notify.
package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"panoptes/internal/model"
	"panoptes/internal/server/core"
	"panoptes/internal/server/notify"
	"panoptes/internal/server/store"
)

// DefaultRunTimeout bounds one pipeline run.
const DefaultRunTimeout = 10 * time.Minute

// Matcher finds vulnerabilities in one CycloneDX SBOM. Implemented by match.Grype; faked in tests.
// Returned findings need only the matcher-derived fields; the pipeline fills host/target/verdict.
type Matcher interface {
	Match(ctx context.Context, kind model.TargetKind, sbom []byte, osInfo model.OSInfo) ([]model.Finding, error)
}

// Options tune the pipeline.
type Options struct {
	PublicURL string // base for Event.WebURL
	Logger    *slog.Logger
	Now       func() time.Time
	// UnknownGrace delays unknown_critical events: they are emitted only once a finding has been
	// conditions_unknown for this long (giving a rule drafter time to produce a verdict).
	// 0 = immediate. Delayed events are emitted by RunNotifyPass / StartNotifyLoop.
	UnknownGrace time.Duration
	Concurrency  int           // hosts processed in parallel (default 2; matching is CPU/memory heavy)
	RunTimeout   time.Duration // per-run limit (default DefaultRunTimeout)

	// OnRun, if set, is told the outcome of every background run (err nil = success; a panic is
	// reported as an error; cancellation at shutdown is not reported). OnPoison is called when a
	// target's matching panicked and the target was flagged. Both must not block.
	OnRun    func(hostID string, err error)
	OnPoison func(hostID, target string)
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
	if opts.RunTimeout <= 0 {
		opts.RunTimeout = DefaultRunTimeout
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
		defer func() {
			if r := recover(); r != nil { // runLimited recovers; this guards the bookkeeping
				p.log.Error("trigger goroutine panicked", "host", hostID, "panic", r, "stack", string(debug.Stack()))
				p.mu.Lock()
				delete(p.state, hostID)
				p.mu.Unlock()
			}
		}()
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
	// A host has at most one goroutine (Trigger coalesces), so it holds at most one slot.
	ctx, cancel := context.WithTimeout(p.baseCtx, p.opts.RunTimeout)
	defer cancel()
	var runErr error
	defer func() {
		if r := recover(); r != nil {
			p.log.Error("pipeline run panicked; run marked failed", "host", hostID, "panic", r, "stack", string(debug.Stack()))
			runErr = fmt.Errorf("panic: %v", r)
		}
		if p.opts.OnRun != nil && !errors.Is(runErr, context.Canceled) {
			func() {
				defer p.recoverLog("OnRun")
				p.opts.OnRun(hostID, runErr)
			}()
		}
	}()
	if runErr = p.Run(ctx, hostID); runErr != nil && !errors.Is(runErr, context.Canceled) {
		p.log.Error("pipeline run failed", "host", hostID, "err", runErr)
	}
}

// poisonKey is the kv key flagging a target whose matching panicked.
func poisonKey(hostID string, t model.InventoryTarget) string {
	h := sha256.New()
	h.Write([]byte(t.Kind))
	h.Write([]byte{0})
	h.Write([]byte(t.Name))
	h.Write([]byte{0})
	h.Write(t.SBOM)
	return "poison." + hostID + "." + hex.EncodeToString(h.Sum(nil))[:16]
}

// matchSafe runs the matcher, converting a panic into panicked=true.
func (p *Pipeline) matchSafe(ctx context.Context, t model.InventoryTarget, osInfo model.OSInfo) (fs []model.Finding, err error, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			p.log.Error("matcher panicked", "target", t.Name, "panic", r, "stack", string(debug.Stack()))
			panicked = true
		}
	}()
	fs, err = p.matcher.Match(ctx, t.Kind, t.SBOM, osInfo)
	return
}

// deliver notifies and records every delivered event. With a *notify.DeliveryError only the
// events not listed in Failed are recorded and only those are retried by a later run.
func (p *Pipeline) deliver(ctx context.Context, events []model.Event, now time.Time) error {
	nerr := p.notifier.Notify(ctx, events)
	var failed map[int]bool
	if nerr != nil {
		var de *notify.DeliveryError
		if !errors.As(nerr, &de) {
			// Not recorded as sent: the events are retried on the next run.
			return fmt.Errorf("notify: %w", nerr)
		}
		failed = map[int]bool{}
		for _, i := range de.Failed {
			failed[i] = true
		}
		if len(failed) == 0 {
			p.log.Error("notification delivered with permanent errors; not retrying", "err", nerr)
		}
	}
	for i, e := range events {
		if failed[i] {
			continue
		}
		if err := p.st.RecordNotification(ctx, store.FindingKey(e.Finding), store.DedupKey(e.Finding, e.Kind), e.Kind, now); err != nil {
			return fmt.Errorf("record notification: %w", err)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("notify: %d of %d events not delivered: %w", len(failed), len(events), nerr)
	}
	return nil
}

// TriggerAll schedules every known host (after a vuln DB update or rule change).
func (p *Pipeline) TriggerAll(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			p.log.Error("TriggerAll panicked", "panic", r, "stack", string(debug.Stack()))
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	hosts, err := p.st.ListHosts(ctx)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		p.Trigger(h.ID)
	}
	return nil
}

func (p *Pipeline) recoverLog(what string) {
	if r := recover(); r != nil {
		p.log.Error("panic recovered", "where", what, "panic", r, "stack", string(debug.Stack()))
	}
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
	// carryOver keeps the previous findings of a skipped target, so skipping never "resolves" them.
	carryOver := func(target string) {
		for _, f := range prev {
			if f.Target == target && f.Verdict != model.VerdictResolved && !seen[keyOf(f)] {
				seen[keyOf(f)] = true
				found = append(found, f)
			}
		}
	}
	for _, t := range targets {
		if len(t.SBOM) == 0 {
			continue
		}
		pk := poisonKey(hostID, t)
		if v, err := p.st.KVGet(ctx, pk); err == nil && v != "" {
			p.log.Debug("skipping poisoned target", "host", hostID, "target", t.Name)
			carryOver(t.Name)
			continue
		}
		fs, err, panicked := p.matchSafe(ctx, t, host.OS)
		if panicked {
			if err := p.st.KVSet(ctx, pk, "panic", p.opts.Now()); err != nil {
				return fmt.Errorf("record poison flag: %w", err)
			}
			p.log.Error("target poisoned: matcher panicked; skipped until a new inventory arrives", "host", hostID, "kind", t.Kind, "target", t.Name)
			if p.opts.OnPoison != nil {
				p.opts.OnPoison(hostID, t.Name)
			}
			carryOver(t.Name)
			continue
		}
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
	events, err := p.buildEvents(ctx, now, host, prevByKey, res, rules)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	return p.deliver(ctx, events, now)
}

func (p *Pipeline) buildEvents(ctx context.Context, now time.Time, host model.Host, prev map[fkey]model.Finding, res store.ApplyResult, rules map[fkey]*model.Rule) ([]model.Event, error) {
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
		case f.Verdict == model.VerdictConditionsUnknown && isNew && unknownCritical(f) && p.graceElapsed(f, now):
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

func unknownCritical(f model.Finding) bool {
	return f.Verdict == model.VerdictConditionsUnknown && (f.KEV || strings.EqualFold(f.Severity, "Critical"))
}

func (p *Pipeline) graceElapsed(f model.Finding, now time.Time) bool {
	return p.opts.UnknownGrace <= 0 || now.Sub(f.FirstSeen) >= p.opts.UnknownGrace
}

// RunNotifyPass emits the delayed unknown_critical events without re-running the matcher: it
// reads stored findings that are still conditions_unknown (KEV or Critical), older than
// UnknownGrace, and not yet notified. Dedup rules are the same as in Run.
func (p *Pipeline) RunNotifyPass(ctx context.Context) error {
	now := p.opts.Now()
	hosts := map[string]model.Host{}
	var events []model.Event
	for off := 0; ; off += 1000 {
		fs, _, err := p.st.ListFindings(ctx, store.FindingFilter{Verdict: model.VerdictConditionsUnknown, Limit: 1000, Offset: off})
		if err != nil {
			return fmt.Errorf("list findings: %w", err)
		}
		for _, f := range fs {
			if !unknownCritical(f) || !p.graceElapsed(f, now) {
				continue
			}
			if sent, err := p.st.NotificationSent(ctx, store.DedupKey(f, model.EventUnknownCritical)); err != nil {
				return err
			} else if sent {
				continue
			}
			// a finding that was already alerted on (e.g. exploitable, then facts lost) is not "new"
			if notified, err := p.st.FindingNotified(ctx, store.FindingKey(f)); err != nil {
				return err
			} else if notified {
				continue
			}
			h, ok := hosts[f.HostID]
			if !ok {
				if h, err = p.st.GetHost(ctx, f.HostID); err != nil {
					continue
				}
				hosts[f.HostID] = h
			}
			events = append(events, model.Event{Kind: model.EventUnknownCritical, Finding: f, Host: h,
				FixCmd: FixCmd(f), WebURL: WebURL(p.opts.PublicURL, f.ID)})
		}
		if len(fs) < 1000 {
			break
		}
	}
	if len(events) == 0 {
		return nil
	}
	return p.deliver(ctx, events, now)
}

// StartNotifyLoop runs RunNotifyPass every interval in a goroutine until ctx is done.
func (p *Pipeline) StartNotifyLoop(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Minute
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-p.baseCtx.Done():
				return
			case <-t.C:
				p.safeNotifyPass(ctx)
			}
		}
	}()
}

func (p *Pipeline) safeNotifyPass(ctx context.Context) {
	defer p.recoverLog("notify loop")
	if err := p.RunNotifyPass(ctx); err != nil && ctx.Err() == nil {
		p.log.Error("notify pass failed", "err", err)
	}
}
