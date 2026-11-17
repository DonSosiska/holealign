package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/store"
)

// keyedMatcher answers per SBOM content: findings, an error, or a delay until ctx is done.
type keyedMatcher struct {
	mu    sync.Mutex
	res   map[string][]model.Finding
	err   map[string]error
	block map[string]bool
	calls map[string]int
	delay time.Duration
}

func newKeyed() *keyedMatcher {
	return &keyedMatcher{res: map[string][]model.Finding{}, err: map[string]error{}, block: map[string]bool{}, calls: map[string]int{}}
}

func (m *keyedMatcher) Match(ctx context.Context, _ model.TargetKind, sbom []byte, _ model.OSInfo) ([]model.Finding, error) {
	m.mu.Lock()
	k := string(sbom)
	m.calls[k]++
	f, err, blk, d := m.res[k], m.err[k], m.block[k], m.delay
	m.mu.Unlock()
	if blk {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if d > 0 {
		time.Sleep(d)
	}
	return append([]model.Finding(nil), f...), err
}

func inv(t *testing.T, e *env, targets ...model.InventoryTarget) {
	t.Helper()
	if err := e.st.ReplaceInventory(context.Background(), e.host.ID, model.InventoryPayload{Hash: fmt.Sprint(time.Now().UnixNano()), Targets: targets}); err != nil {
		t.Fatal(err)
	}
}

func tgt(name string) model.InventoryTarget {
	return model.InventoryTarget{Kind: model.TargetContainerImage, Name: name, SBOM: json.RawMessage(`"` + name + `"`)}
}

func open(t *testing.T, e *env) map[string]int {
	t.Helper()
	fs, err := e.st.HostFindings(context.Background(), e.host.ID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, f := range fs {
		if f.Verdict != model.VerdictResolved {
			out[f.Target]++
		}
	}
	return out
}

func TestFailingTargetIsIsolatedAndKeepsItsFindings(t *testing.T) {
	e := setup(t)
	km := newKeyed()
	km.res[`"a"`] = []model.Finding{vuln("CVE-A", "High", false)}
	km.res[`"b"`] = []model.Finding{vuln("CVE-B", "High", false)}
	var mu sync.Mutex
	var problems []string
	e.p = New(e.st, km, e.ev, e.n, e.d, Options{OnProblem: func(h, target, reason string) {
		mu.Lock()
		problems = append(problems, target+": "+reason)
		mu.Unlock()
	}})
	t.Cleanup(e.p.Shutdown)
	inv(t, e, tgt("a"), tgt("b"))
	if err := e.p.Run(context.Background(), e.host.ID); err != nil {
		t.Fatal(err)
	}
	if got := open(t, e); got["a"] != 1 || got["b"] != 1 {
		t.Fatalf("initial: %v", got)
	}
	// a now fails, b changes: b must be updated, a must keep its finding
	km.mu.Lock()
	km.err[`"a"`] = errors.New("grype exploded")
	km.res[`"b"`] = []model.Finding{vuln("CVE-B2", "High", false)}
	km.mu.Unlock()
	if err := e.p.Run(context.Background(), e.host.ID); err != nil {
		t.Fatalf("one bad target must not fail the run: %v", err)
	}
	got := open(t, e)
	if got["a"] != 1 || got["b"] != 1 {
		t.Fatalf("after failure: %v", got)
	}
	fs, _ := e.st.HostFindings(context.Background(), e.host.ID)
	for _, f := range fs {
		if f.Target == "b" && f.VulnID == "CVE-B" && f.Verdict != model.VerdictResolved {
			t.Fatal("b's old finding should be resolved")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(problems) != 1 || problems[0][:2] != "a:" {
		t.Fatalf("problems: %v", problems)
	}
}

func TestTargetTimeoutIsIsolated(t *testing.T) {
	e := setup(t)
	km := newKeyed()
	km.res[`"a"`] = []model.Finding{vuln("CVE-A", "High", false)}
	km.block[`"slow"`] = true
	e.p = New(e.st, km, e.ev, e.n, e.d, Options{TargetTimeout: 50 * time.Millisecond})
	t.Cleanup(e.p.Shutdown)
	inv(t, e, tgt("a"), tgt("slow"))
	start := time.Now()
	if err := e.p.Run(context.Background(), e.host.ID); err != nil {
		t.Fatalf("timeout of one target failed the run: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("target timeout not applied")
	}
	if got := open(t, e); got["a"] != 1 {
		t.Fatalf("%v", got)
	}
}

func TestAllTargetsFailingFailsRun(t *testing.T) {
	e := setup(t)
	km := newKeyed()
	km.err[`"a"`] = errors.New("no db")
	km.err[`"b"`] = errors.New("no db")
	e.p = New(e.st, km, e.ev, e.n, e.d, Options{})
	t.Cleanup(e.p.Shutdown)
	inv(t, e, tgt("a"), tgt("b"))
	if err := e.p.Run(context.Background(), e.host.ID); err == nil {
		t.Fatal("expected error when nothing could be matched")
	}
}

func TestSkippedTargetsKeepFindingsAndAreReported(t *testing.T) {
	e := setup(t)
	km := newKeyed()
	km.res[`"huge"`] = []model.Finding{vuln("CVE-H", "Critical", false)}
	km.res[`"ok"`] = []model.Finding{vuln("CVE-O", "High", false)}
	var mu sync.Mutex
	var problems []string
	e.p = New(e.st, km, e.ev, e.n, e.d, Options{OnProblem: func(_, target, reason string) {
		mu.Lock()
		problems = append(problems, target+"|"+reason)
		mu.Unlock()
	}})
	t.Cleanup(e.p.Shutdown)
	inv(t, e, tgt("huge"), tgt("ok"))
	if err := e.p.Run(context.Background(), e.host.ID); err != nil {
		t.Fatal(err)
	}
	// the next inventory marks "huge" as skipped (e.g. it grew beyond the component cap)
	err := e.st.ReplaceInventorySkipped(context.Background(), e.host.ID,
		model.InventoryPayload{Hash: "h2", Targets: []model.InventoryTarget{tgt("ok")}},
		[]store.SkippedTarget{{Kind: model.TargetContainerImage, Name: "huge", Reason: "more than 50000 components"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.p.Run(context.Background(), e.host.ID); err != nil {
		t.Fatal(err)
	}
	if got := open(t, e); got["huge"] != 1 || got["ok"] != 1 {
		t.Fatalf("skipped target lost its findings: %v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(problems) != 1 || problems[0] != "huge|skipped at upload: more than 50000 components" {
		t.Fatalf("problems: %v", problems)
	}
}

func TestFindingsPerHostCapDropsLowestSeverity(t *testing.T) {
	e := setup(t)
	var fs []model.Finding
	for i := 0; i < 5; i++ {
		fs = append(fs, vuln(fmt.Sprintf("CVE-LOW-%d", i), "Low", false))
	}
	fs = append(fs, vuln("CVE-CRIT", "Critical", false), vuln("CVE-HIGH", "High", false), vuln("CVE-KEV", "Low", true))
	e.m.set(fs...)
	var reasons []string
	e.p = New(e.st, e.m, e.ev, e.n, e.d, Options{MaxFindingsPerHost: 3, OnProblem: func(_, _, r string) { reasons = append(reasons, r) }})
	t.Cleanup(e.p.Shutdown)
	if err := e.p.Run(context.Background(), e.host.ID); err != nil {
		t.Fatal(err)
	}
	all, _ := e.st.HostFindings(context.Background(), e.host.ID)
	if len(all) != 3 {
		t.Fatalf("stored %d findings, want 3", len(all))
	}
	have := map[string]bool{}
	for _, f := range all {
		have[f.VulnID] = true
	}
	if !have["CVE-CRIT"] || !have["CVE-HIGH"] || !have["CVE-KEV"] {
		t.Fatalf("wrong findings kept: %v", have)
	}
	if len(reasons) != 1 {
		t.Fatalf("hook: %v", reasons)
	}
}

func TestFifoSemGrantsInArrivalOrder(t *testing.T) {
	s := newFifoSem(1)
	ctx := context.Background()
	if err := s.acquire(ctx); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var order []int
	var wg sync.WaitGroup
	for i := 1; i <= 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.acquire(ctx)
			mu.Lock()
			order = append(order, i)
			mu.Unlock()
			time.Sleep(5 * time.Millisecond)
			s.release()
		}()
		for s.waiting() < i { // enqueue strictly one after the other
			time.Sleep(time.Millisecond)
		}
	}
	s.release()
	wg.Wait()
	if fmt.Sprint(order) != "[1 2 3]" {
		t.Fatalf("order %v", order)
	}
	// cancellation while queued frees the queue slot
	if err := s.acquire(ctx); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan error)
	go func() { done <- s.acquire(cctx) }()
	for s.waiting() < 1 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancelled acquire succeeded")
	}
	if s.waiting() != 0 {
		t.Fatal("cancelled waiter left in queue")
	}
	s.release()
	if err := s.acquire(ctx); err != nil {
		t.Fatal(err)
	}
}

// A host re-triggering itself must queue behind a host that is already waiting.
func TestNoBackToBackReacquireWhenOthersWait(t *testing.T) {
	e := setup(t)
	_, hash2, _ := store.NewSecret("pa_")
	h2, err := e.st.EnrollHost(context.Background(), store.EnrollParams{MachineID: "m2", Hostname: "web2", KeyHash: hash2})
	if err != nil {
		t.Fatal(err)
	}
	_ = e.st.ReplaceInventory(context.Background(), h2.ID, model.InventoryPayload{Hash: "x", Targets: []model.InventoryTarget{tgt("two")}})
	inv(t, e, tgt("one"))

	var mu sync.Mutex
	var order []string
	km := newKeyed()
	km.delay = 30 * time.Millisecond
	rec := &orderMatcher{inner: km, rec: func(s string) { mu.Lock(); order = append(order, s); mu.Unlock() }}
	p := New(e.st, rec, e.ev, e.n, e.d, Options{Concurrency: 1})
	t.Cleanup(p.Shutdown)

	p.Trigger(e.host.ID) // runs first
	time.Sleep(10 * time.Millisecond)
	p.Trigger(h2.ID) // waits for the slot
	time.Sleep(5 * time.Millisecond)
	p.Trigger(e.host.ID) // dirty: wants to run again
	p.Wait()
	mu.Lock()
	defer mu.Unlock()
	if fmt.Sprint(order) != "[one two one]" {
		t.Fatalf("host one re-acquired back to back: %v", order)
	}
}

type orderMatcher struct {
	inner *keyedMatcher
	rec   func(string)
}

func (o *orderMatcher) Match(ctx context.Context, k model.TargetKind, sbom []byte, os model.OSInfo) ([]model.Finding, error) {
	o.rec(string(sbom[1 : len(sbom)-1]))
	return o.inner.Match(ctx, k, sbom, os)
}

func TestMatchTimeBudgetDefersRuns(t *testing.T) {
	e := setup(t)
	km := newKeyed()
	km.delay = 40 * time.Millisecond
	now := time.Now()
	var mu sync.Mutex
	var problems []string
	p := New(e.st, km, e.ev, e.n, e.d, Options{
		MatchBudgetPerHour: 50 * time.Millisecond,
		Now:                func() time.Time { mu.Lock(); defer mu.Unlock(); return now },
		OnProblem:          func(_, _, r string) { mu.Lock(); problems = append(problems, r); mu.Unlock() },
	})
	t.Cleanup(p.Shutdown)
	inv(t, e, tgt("a"), tgt("b")) // two targets -> 80ms > budget
	p.Trigger(e.host.ID)
	p.Wait()
	calls := func() int { km.mu.Lock(); defer km.mu.Unlock(); return km.calls[`"a"`] }
	if calls() != 1 {
		t.Fatalf("first run: %d", calls())
	}
	// over budget: the next trigger is deferred, not run
	p.Trigger(e.host.ID)
	p.Wait()
	if calls() != 1 {
		t.Fatalf("over-budget run executed: %d", calls())
	}
	mu.Lock()
	if len(problems) != 1 {
		t.Fatalf("hook: %v", problems)
	}
	mu.Unlock()
	if w := p.budgetWait(e.host.ID, now); w <= 0 || w > time.Hour+2*time.Second {
		t.Fatalf("wait %v", w)
	}
	// an hour later the budget is free again
	mu.Lock()
	now = now.Add(61 * time.Minute)
	mu.Unlock()
	if w := p.budgetWait(e.host.ID, now); w != 0 {
		t.Fatalf("budget not released: %v", w)
	}
	p.Trigger(e.host.ID)
	p.Wait()
	if calls() != 2 {
		t.Fatalf("run after budget window: %d", calls())
	}
}
