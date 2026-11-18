package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/DonSosiska/holealign/internal/model"
	"github.com/DonSosiska/holealign/internal/server/match"
	"github.com/DonSosiska/holealign/internal/server/store"
)

func TestOnRunAndOnPoisonHooks(t *testing.T) {
	e := setup(t)
	var mu sync.Mutex
	var runs []error
	var poisoned []string
	e.p.opts.OnRun = func(_ string, err error) { mu.Lock(); runs = append(runs, err); mu.Unlock() }
	e.p.opts.OnPoison = func(_, target string) { mu.Lock(); poisoned = append(poisoned, target); mu.Unlock() }

	e.m.err = errors.New("no vuln DB")
	e.p.Trigger(e.host.ID)
	e.p.Wait()
	e.m.err = nil
	e.p.Trigger(e.host.ID)
	e.p.Wait()

	mu.Lock()
	if len(runs) != 2 || runs[0] == nil || runs[1] != nil {
		t.Fatalf("OnRun outcomes: %v", runs)
	}
	mu.Unlock()

	e.p.matcher = &panicMatcher{}
	// a poisoned target is flagged once; the run itself succeeds
	e.p.Trigger(e.host.ID)
	e.p.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(poisoned) != 1 || poisoned[0] != "host" {
		t.Fatalf("OnPoison: %v", poisoned)
	}
}

func TestNoDBIsTransientAndRerunWhenReady(t *testing.T) {
	e := setup(t)
	var mu sync.Mutex
	var runs []error
	var problems, poisoned, cleans int
	e.p.opts.OnRun = func(_ string, err error) { mu.Lock(); runs = append(runs, err); mu.Unlock() }
	e.p.opts.OnProblem = func(_, _, _ string) { mu.Lock(); problems++; mu.Unlock() }
	e.p.opts.OnPoison = func(_, _ string) { mu.Lock(); poisoned++; mu.Unlock() }
	e.p.opts.OnClean = func(string) { mu.Lock(); cleans++; mu.Unlock() }

	e.m.err = match.ErrNoDB
	for i := 0; i < 5; i++ { // never counts towards the consecutive-failure counter
		e.p.Trigger(e.host.ID)
		e.p.Wait()
	}
	mu.Lock()
	if len(runs) != 0 || problems != 0 || poisoned != 0 || cleans != 0 {
		t.Fatalf("no-DB runs reported: runs=%v problems=%d poisoned=%d cleans=%d", runs, problems, poisoned, cleans)
	}
	mu.Unlock()
	if w := e.p.WaitingForDB(); len(w) != 1 || w[0] != e.host.ID {
		t.Fatalf("WaitingForDB = %v", w)
	}
	targets, _ := e.st.ListTargets(context.Background(), e.host.ID)
	for _, tg := range targets {
		if v, _ := e.st.KVGet(context.Background(), poisonKey(e.host.ID, tg)); v != "" {
			t.Fatal("target poisoned by a missing DB")
		}
	}

	// the DB becomes ready: TriggerAll (what the feeds updater does) re-runs the host
	e.ev.setVerdict("CVE-1", model.VerdictExploitable)
	e.m.set(vuln("CVE-1", "High", false))
	if err := e.p.TriggerAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.p.Wait()
	fs, _, _ := e.st.ListFindings(context.Background(), store.FindingFilter{})
	if len(fs) != 1 {
		t.Fatalf("findings not computed after the DB became ready: %+v", fs)
	}
	if w := e.p.WaitingForDB(); len(w) != 0 {
		t.Fatalf("still waiting: %v", w)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(runs) != 1 || runs[0] != nil || cleans != 1 || problems != 0 {
		t.Fatalf("runs=%v cleans=%d problems=%d", runs, cleans, problems)
	}
}

func TestDBReadyRerunsWaitingHosts(t *testing.T) {
	e := setup(t)
	e.m.err = match.ErrNoDB
	e.p.Trigger(e.host.ID)
	e.p.Wait()
	e.m.set(vuln("CVE-1", "High", false))
	e.p.DBReady()
	e.p.Wait()
	if fs, _, _ := e.st.ListFindings(context.Background(), store.FindingFilter{}); len(fs) != 1 {
		t.Fatalf("findings: %+v", fs)
	}
}

func TestRealErrorWordingAndCleanOnSuccess(t *testing.T) {
	e := setup(t)
	var mu sync.Mutex
	var reasons []string
	cleans := 0
	e.p.opts.OnProblem = func(_, _, r string) { mu.Lock(); reasons = append(reasons, r); mu.Unlock() }
	e.p.opts.OnClean = func(string) { mu.Lock(); cleans++; mu.Unlock() }

	e.m.err = errors.New("kaboom")
	_ = e.p.Run(context.Background(), e.host.ID)
	mu.Lock()
	if len(reasons) != 1 || reasons[0] != "matching failed: kaboom" || cleans != 0 {
		t.Fatalf("reasons=%v cleans=%d", reasons, cleans)
	}
	mu.Unlock()

	e.m.set()
	if err := e.p.Run(context.Background(), e.host.ID); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if cleans != 1 {
		t.Fatalf("cleans=%d", cleans)
	}
	mu.Unlock()

	// a panic is still reported as a poisoned (crashed) target and is not clean
	e.p.matcher = &panicMatcher{}
	poisoned := 0
	e.p.opts.OnPoison = func(_, _ string) { poisoned++ }
	_ = e.p.Run(context.Background(), e.host.ID)
	mu.Lock()
	defer mu.Unlock()
	if poisoned != 1 || cleans != 1 {
		t.Fatalf("poisoned=%d cleans=%d", poisoned, cleans)
	}
}

// lockedBuf is a log sink that is safe for the pipeline's goroutines.
type lockedBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestNoDBLogsInfoNotError(t *testing.T) {
	e := setup(t)
	var buf lockedBuf
	e.p.log = slog.New(slog.NewTextHandler(&buf, nil))
	e.m.err = fmt.Errorf("grype: %w", match.ErrNoDB)
	e.p.Trigger(e.host.ID)
	e.p.Wait()
	out := buf.String()
	if strings.Contains(out, "level=ERROR") {
		t.Fatalf("no-DB run logged an ERROR:\n%s", out)
	}
	if !strings.Contains(out, "level=INFO") || !strings.Contains(out, "vulnerability DB not loaded yet") {
		t.Fatalf("missing postponed INFO line:\n%s", out)
	}
}

func TestRealRunErrorStillLoggedAsError(t *testing.T) {
	e := setup(t)
	var buf lockedBuf
	e.p.log = slog.New(slog.NewTextHandler(&buf, nil))
	e.m.err = errors.New("kaboom")
	e.p.Trigger(e.host.ID)
	e.p.Wait()
	out := buf.String()
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "pipeline run failed") {
		t.Fatalf("real failure not logged as ERROR:\n%s", out)
	}
}
