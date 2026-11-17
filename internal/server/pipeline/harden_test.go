package pipeline

import (
	"context"
	"errors"
	"testing"

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/notify"
	"github.com/DonSosiska/panoptes/internal/server/store"
)

type panicMatcher struct{ calls int }

func (m *panicMatcher) Match(context.Context, model.TargetKind, []byte, model.OSInfo) ([]model.Finding, error) {
	m.calls++
	panic("grype exploded")
}

func TestMatcherPanicPoisonsTargetAndDoesNotCrash(t *testing.T) {
	e := setup(t)
	pm := &panicMatcher{}
	e.p = New(e.st, pm, e.ev, e.n, e.d, Options{})
	t.Cleanup(e.p.Shutdown)
	ctx := context.Background()

	e.p.Trigger(e.host.ID) // goroutine path
	e.p.Wait()
	if pm.calls != 1 {
		t.Fatalf("calls=%d", pm.calls)
	}
	if err := e.p.Run(ctx, e.host.ID); err != nil { // poisoned target is skipped, no second panic
		t.Fatal(err)
	}
	if pm.calls != 1 {
		t.Fatalf("poisoned target matched again: %d", pm.calls)
	}
	// a new inventory clears the flag
	if err := e.st.ReplaceInventory(ctx, e.host.ID, model.InventoryPayload{Hash: "y", Targets: []model.InventoryTarget{
		{Kind: model.TargetHost, Name: "host", SBOM: []byte(`{}`)}}}); err != nil {
		t.Fatal(err)
	}
	_ = e.p.Run(ctx, e.host.ID)
	if pm.calls != 2 {
		t.Fatalf("flag not cleared by new inventory: %d", pm.calls)
	}
}

type partialNotifier struct {
	failIdx map[int]bool
	err     error
}

func (n *partialNotifier) Notify(_ context.Context, ev []model.Event) error {
	var de notify.DeliveryError
	for i := range ev {
		if n.failIdx[i] {
			de.Failed = append(de.Failed, i)
		}
	}
	if len(de.Failed) == 0 && n.err == nil {
		return nil
	}
	de.Err = errors.New("some failed")
	return &de
}

func TestPipelineRecordsOnlyDeliveredEvents(t *testing.T) {
	e := setup(t)
	e.ev.setVerdict("CVE-1", model.VerdictExploitable)
	e.ev.setVerdict("CVE-2", model.VerdictExploitable)
	e.m.set(vuln("CVE-1", "High", false), vuln("CVE-2", "High", false))
	e.p = New(e.st, e.m, e.ev, &partialNotifier{failIdx: map[int]bool{1: true}}, e.d, Options{})
	t.Cleanup(e.p.Shutdown)
	ctx := context.Background()
	if err := e.p.Run(ctx, e.host.ID); err == nil {
		t.Fatal("expected error for the undelivered event")
	}
	fs, _ := e.st.HostFindings(ctx, e.host.ID)
	sent := 0
	for _, f := range fs {
		ok, _ := e.st.NotificationSent(ctx, store.DedupKey(f, model.EventExploitable))
		if ok {
			sent++
		}
	}
	if sent != 1 {
		t.Fatalf("recorded %d events, want exactly the delivered one", sent)
	}
	// retry: only the failed event is offered again
	e.p = New(e.st, e.m, e.ev, e.n, e.d, Options{})
	t.Cleanup(e.p.Shutdown)
	if err := e.p.Run(ctx, e.host.ID); err != nil {
		t.Fatal(err)
	}
	if got := e.n.take(); len(got) != 1 {
		t.Fatalf("retried %d events, want 1", len(got))
	}
}
