package pipeline

import (
	"errors"
	"sync"
	"testing"
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
