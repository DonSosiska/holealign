// Package pipeline implements contracts §5: match -> evaluate -> upsert -> resolve -> draft -> notify.
package pipeline

import (
	"container/list"
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

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/core"
	"github.com/DonSosiska/panoptes/internal/server/match"
	"github.com/DonSosiska/panoptes/internal/server/notify"
	"github.com/DonSosiska/panoptes/internal/server/store"
)

// DefaultRunTimeout bounds one pipeline run.
const DefaultRunTimeout = 10 * time.Minute

// DefaultTargetTimeout bounds the matching of one target; a slower target is isolated like a failure.
const DefaultTargetTimeout = 5 * time.Minute

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
	// OnClean is called (not blocking) when a run for hostID completed with no skipped, failed,
	// poisoned or limited target: every earlier problem of the host is resolved (clears the banner).
	OnClean func(hostID string)
	// OnProblem is called (not blocking) for every target that was skipped by the API (oversized,
	// invalid), failed or timed out in matching, and for host-level limits (findings cap, match
	// time budget); target is "" for the latter. Wire it to the health monitor.
	OnProblem func(hostID, target, reason string)

	// TargetTimeout bounds one target's matching (default DefaultTargetTimeout).
	TargetTimeout time.Duration
	// MaxFindingsPerHost caps the open findings stored per host (0 = unlimited); the lowest
	// severities are dropped first.
	MaxFindingsPerHost int
	// MatchBudgetPerHour is the cumulative matcher time one host may use per rolling hour
	// (0 = unlimited). A host over budget has its runs deferred.
	MatchBudgetPerHour time.Duration
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
	sem     *fifoSem
	wg      sync.WaitGroup

	mu       sync.Mutex
	waitDB   map[string]bool // hosts whose last run was postponed because the vuln DB was not loaded
	state    map[string]*hostState
	usage    map[string][]matchUse  // per host matcher time in the last hour
	deferred map[string]*time.Timer // hosts whose runs wait for their time budget
}

type matchUse struct {
	at  time.Time
	dur time.Duration
}

// fifoSem is a counting semaphore that grants slots strictly in arrival order. A host that has
// just finished a run and asks again queues behind the hosts already waiting, so two heavy hosts
// cannot monopolise the matcher slots.
type fifoSem struct {
	mu   sync.Mutex
	free int
	q    *list.List // of chan struct{}
}

func newFifoSem(n int) *fifoSem { return &fifoSem{free: n, q: list.New()} }

func (f *fifoSem) acquire(ctx context.Context) error {
	f.mu.Lock()
	if f.free > 0 && f.q.Len() == 0 {
		f.free--
		f.mu.Unlock()
		return nil
	}
	ch := make(chan struct{})
	el := f.q.PushBack(ch)
	f.mu.Unlock()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		f.mu.Lock()
		select {
		case <-ch: // granted concurrently: hand the slot on
			f.mu.Unlock()
			f.release()
		default:
			f.q.Remove(el)
			f.mu.Unlock()
		}
		return ctx.Err()
	}
}

func (f *fifoSem) release() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if el := f.q.Front(); el != nil {
		f.q.Remove(el)
		close(el.Value.(chan struct{}))
		return
	}
	f.free++
}

func (f *fifoSem) waiting() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.q.Len()
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
	if opts.TargetTimeout <= 0 {
		opts.TargetTimeout = DefaultTargetTimeout
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Pipeline{
		st: st, matcher: m, eval: ev, notifier: n, drafter: d, opts: opts, log: opts.Logger,
		baseCtx: ctx, cancel: cancel, sem: newFifoSem(opts.Concurrency),
		waitDB: map[string]bool{}, state: map[string]*hostState{}, usage: map[string][]matchUse{}, deferred: map[string]*time.Timer{},
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
			wait := p.runLimited(hostID)
			p.mu.Lock()
			if wait > 0 { // over the match-time budget: run again when budget frees up
				s.running, s.dirty = false, false
				delete(p.state, hostID)
				p.deferLocked(hostID, wait)
				p.mu.Unlock()
				return
			}
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

// deferLocked schedules a Trigger for hostID after wait (p.mu held). One timer per host.
func (p *Pipeline) deferLocked(hostID string, wait time.Duration) {
	if p.baseCtx.Err() != nil {
		return
	}
	if t := p.deferred[hostID]; t != nil {
		t.Stop()
	}
	p.deferred[hostID] = time.AfterFunc(wait, func() {
		p.mu.Lock()
		delete(p.deferred, hostID)
		p.mu.Unlock()
		if p.baseCtx.Err() == nil {
			p.Trigger(hostID)
		}
	})
}

// budgetWait returns how long a run of hostID must wait because its matcher time in the last hour
// exhausted the budget (0 = may run).
func (p *Pipeline) budgetWait(hostID string, now time.Time) time.Duration {
	b := p.opts.MatchBudgetPerHour
	if b <= 0 {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	use := p.usage[hostID][:0:0]
	var total time.Duration
	for _, u := range p.usage[hostID] {
		if now.Sub(u.at) < time.Hour {
			use = append(use, u)
			total += u.dur
		}
	}
	if len(use) == 0 {
		delete(p.usage, hostID)
	} else {
		p.usage[hostID] = use
	}
	if total < b {
		return 0
	}
	// wait until enough old usage expires to drop below the budget
	over := total - b
	for _, u := range use {
		over -= u.dur
		if over < 0 {
			return u.at.Add(time.Hour).Sub(now) + time.Second
		}
	}
	return time.Hour
}

func (p *Pipeline) addUsage(hostID string, d time.Duration, now time.Time) {
	if p.opts.MatchBudgetPerHour <= 0 || d <= 0 {
		return
	}
	p.mu.Lock()
	p.usage[hostID] = append(p.usage[hostID], matchUse{at: now, dur: d})
	p.mu.Unlock()
}

// WaitingForDB lists the hosts whose last run was postponed because no vulnerability DB was
// loaded yet. They are re-run by TriggerAll / DBReady.
func (p *Pipeline) WaitingForDB() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for id := range p.waitDB {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// DBReady re-runs every host whose run was postponed for lack of a vulnerability DB. Call it
// after the DB became available (TriggerAll covers it as well).
func (p *Pipeline) DBReady() {
	for _, id := range p.WaitingForDB() {
		p.Trigger(id)
	}
}

func (p *Pipeline) clean(hostID string) {
	if p.opts.OnClean == nil {
		return
	}
	defer p.recoverLog("OnClean")
	p.opts.OnClean(hostID)
}

func (p *Pipeline) problem(hostID, target, reason string) {
	if p.opts.OnProblem == nil {
		return
	}
	defer p.recoverLog("OnProblem")
	p.opts.OnProblem(hostID, target, reason)
}

// runLimited runs one pipeline pass for hostID under the matcher slot semaphore. It returns a
// positive duration when the run was deferred because the host used up its match-time budget.
func (p *Pipeline) runLimited(hostID string) (deferFor time.Duration) {
	if wait := p.budgetWait(hostID, p.opts.Now()); wait > 0 {
		p.log.Warn("host exceeded its matcher time budget; run deferred", "host", hostID,
			"budget", p.opts.MatchBudgetPerHour, "retry_in", wait.Round(time.Second))
		p.problem(hostID, "", fmt.Sprintf("matcher time budget %s/hour exceeded; runs deferred %s", p.opts.MatchBudgetPerHour, wait.Round(time.Second)))
		return wait
	}
	if err := p.sem.acquire(p.baseCtx); err != nil {
		return 0
	}
	defer p.sem.release()
	// A host has at most one goroutine (Trigger coalesces), so it holds at most one slot. A
	// follow-up run queues behind every host already waiting (FIFO), never straight back in.
	ctx, cancel := context.WithTimeout(p.baseCtx, p.opts.RunTimeout)
	defer cancel()
	var runErr error
	defer func() {
		if r := recover(); r != nil {
			p.log.Error("pipeline run panicked; run marked failed", "host", hostID, "panic", r, "stack", string(debug.Stack()))
			runErr = fmt.Errorf("panic: %v", r)
		}
		p.mu.Lock()
		if errors.Is(runErr, match.ErrNoDB) {
			p.waitDB[hostID] = true
		} else {
			delete(p.waitDB, hostID)
		}
		p.mu.Unlock()
		// A missing vulnerability DB is a transient, server-wide condition: not a failed run of
		// this host (no failure count, no alert). The host is re-run once the DB is loaded.
		if errors.Is(runErr, match.ErrNoDB) {
			p.log.Info("vulnerability DB not loaded yet; run postponed until it is", "host", hostID)
		} else if p.opts.OnRun != nil && !errors.Is(runErr, context.Canceled) {
			func() {
				defer p.recoverLog("OnRun")
				p.opts.OnRun(hostID, runErr)
			}()
		}
	}()
	if runErr = p.Run(ctx, hostID); runErr != nil && !errors.Is(runErr, context.Canceled) && !errors.Is(runErr, match.ErrNoDB) {
		p.log.Error("pipeline run failed", "host", hostID, "err", runErr)
	}
	return 0
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
	p.mu.Lock()
	for id, t := range p.deferred {
		t.Stop()
		delete(p.deferred, id)
	}
	p.mu.Unlock()
	p.wg.Wait()
}

type fkey struct{ target, pkg, ver, vuln string }

func keyOf(f model.Finding) fkey { return fkey{f.Target, f.PackageName, f.PackageVer, f.VulnID} }

// Run recomputes the findings of one host synchronously. A target whose matching fails, times out
// or was refused at upload keeps its previous findings and is reported (OnProblem) while the other
// targets are processed; if no target could be matched at all nothing is changed and the run fails.
// A missing vulnerability DB (match.ErrNoDB) is not a target problem: the run returns an error
// wrapping it, changes nothing and reports nothing; it is repeated once the DB is loaded.
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
	// Targets the API refused (oversized, invalid): keep their previous findings and report them.
	if skipped, err := p.st.ListSkippedTargets(ctx, hostID); err == nil {
		for _, k := range skipped {
			carryOver(k.Name)
			p.log.Warn("target skipped at upload; previous findings kept", "host", hostID, "target", k.Name, "reason", k.Reason)
			p.problem(hostID, k.Name, "skipped at upload: "+k.Reason)
		}
	}
	var failed []string // "target: error" of isolated failures
	unclean := false    // some target was skipped, failed, poisoned or limited
	if skipped, err := p.st.ListSkippedTargets(ctx, hostID); err == nil && len(skipped) > 0 {
		unclean = true
	}
	matched := 0
	for _, t := range targets {
		if len(t.SBOM) == 0 {
			continue
		}
		pk := poisonKey(hostID, t)
		if v, err := p.st.KVGet(ctx, pk); err == nil && v != "" {
			p.log.Debug("skipping poisoned target", "host", hostID, "target", t.Name)
			carryOver(t.Name)
			unclean = true
			continue
		}
		tctx, tcancel := context.WithTimeout(ctx, p.opts.TargetTimeout)
		t0 := time.Now()
		fs, err, panicked := p.matchSafe(tctx, t, host.OS)
		tcancel()
		p.addUsage(hostID, time.Since(t0), p.opts.Now())
		if panicked {
			if err := p.st.KVSet(ctx, pk, "panic", p.opts.Now()); err != nil {
				return fmt.Errorf("record poison flag: %w", err)
			}
			p.log.Error("target poisoned: matcher panicked; skipped until a new inventory arrives", "host", hostID, "kind", t.Kind, "target", t.Name)
			if p.opts.OnPoison != nil {
				p.opts.OnPoison(hostID, t.Name)
			}
			carryOver(t.Name)
			unclean = true
			continue
		}
		if err != nil {
			if errors.Is(err, match.ErrNoDB) {
				// Server-wide and transient: not this target's fault. Change nothing; the run is
				// repeated when the DB is loaded.
				return fmt.Errorf("match %s %q: %w", t.Kind, t.Name, err)
			}
			if ctx.Err() != nil { // the whole run was cancelled or timed out: nothing is isolated
				return fmt.Errorf("match %s %q: %w", t.Kind, t.Name, ctx.Err())
			}
			// A failing or too slow target must not blind the others: keep its previous
			// findings, record the error and go on.
			msg := fmt.Sprintf("%s %q: %v", t.Kind, t.Name, err)
			failed = append(failed, msg)
			p.log.Error("target matching failed; previous findings kept", "host", hostID, "target", t.Name, "err", err)
			p.problem(hostID, t.Name, "matching failed: "+err.Error())
			carryOver(t.Name)
			unclean = true
			continue
		}
		matched++
		for _, f := range fs {
			f.HostID, f.Target, f.TargetKind = hostID, t.Name, t.Kind
			if seen[keyOf(f)] {
				continue
			}
			seen[keyOf(f)] = true
			found = append(found, f)
		}
	}
	if len(failed) > 0 && matched == 0 {
		// Nothing could be matched at all (e.g. every matcher call failed): change nothing, report the run as failed.
		return fmt.Errorf("match %s", strings.Join(failed, "; "))
	}
	before := len(found)
	found = p.capFindings(hostID, found)
	if len(found) != before {
		unclean = true
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

	if !unclean {
		p.clean(hostID)
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

var sevRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "negligible": 1}

// capFindings keeps at most MaxFindingsPerHost findings, dropping the lowest severity first
// (KEV and higher CVSS survive longer).
func (p *Pipeline) capFindings(hostID string, found []model.Finding) []model.Finding {
	max := p.opts.MaxFindingsPerHost
	if max <= 0 || len(found) <= max {
		return found
	}
	sort.SliceStable(found, func(i, j int) bool {
		a, b := found[i], found[j]
		if a.KEV != b.KEV {
			return a.KEV
		}
		if ra, rb := sevRank[strings.ToLower(a.Severity)], sevRank[strings.ToLower(b.Severity)]; ra != rb {
			return ra > rb
		}
		return a.CVSS > b.CVSS
	})
	dropped := len(found) - max
	p.log.Warn("host exceeds the open findings cap; lowest-severity findings dropped", "host", hostID, "cap", max, "dropped", dropped)
	p.problem(hostID, "", fmt.Sprintf("findings cap %d exceeded: %d lowest-severity findings dropped", max, dropped))
	return found[:max]
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
