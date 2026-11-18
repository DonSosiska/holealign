package pipeline

import (
	"context"
	"testing"

	"github.com/DonSosiska/holealign/internal/model"
)

// Regression: the cap used to run before evaluation, ranking an exploitable low-severity finding
// below unknown high ones; the dropped finding was then resolved and a resolved all-clear sent.
func TestFindingsCapNeverResolvesDroppedFindings(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.ev.setVerdict("CVE-EXPL", model.VerdictExploitable)
	e.m.set(vuln("CVE-EXPL", "Low", false), vuln("CVE-H1", "High", false), vuln("CVE-H2", "High", false), vuln("CVE-H3", "Critical", false))
	notified := false
	for _, ev := range e.run(t) {
		notified = notified || (ev.Kind == model.EventExploitable && ev.Finding.VulnID == "CVE-EXPL")
	}
	if !notified {
		t.Fatal("setup: exploitable event expected")
	}

	e.p = New(e.st, e.m, e.ev, e.n, e.d, Options{MaxFindingsPerHost: 2})
	t.Cleanup(e.p.Shutdown)
	for _, ev := range e.run(t) {
		if ev.Kind == model.EventResolved {
			t.Fatalf("resolved event for a finding dropped by the cap: %s", ev.Finding.VulnID)
		}
	}
	all, _ := e.st.HostFindings(ctx, e.host.ID)
	by := map[string]model.Finding{}
	for _, f := range all {
		by[f.VulnID] = f
	}
	if f := by["CVE-EXPL"]; f.Verdict != model.VerdictExploitable {
		t.Fatalf("exploitable finding lost: %+v", f)
	}
	for id, f := range by {
		if f.Verdict == model.VerdictResolved {
			t.Fatalf("%s was resolved by the cap", id)
		}
	}
	// previously stored findings that the cap drops are kept unchanged, not resolved
	if len(by) != 4 {
		t.Fatalf("stored %d findings, want the 4 previous ones kept", len(by))
	}

	// a never-stored finding that falls below the cap is not stored at all
	e2 := setup(t)
	e2.ev.setVerdict("CVE-EXPL", model.VerdictExploitable)
	e2.m.set(vuln("CVE-EXPL", "Low", false), vuln("CVE-H1", "High", false), vuln("CVE-H2", "Critical", false))
	e2.p = New(e2.st, e2.m, e2.ev, e2.n, e2.d, Options{MaxFindingsPerHost: 2})
	t.Cleanup(e2.p.Shutdown)
	e2.run(t)
	all, _ = e2.st.HostFindings(ctx, e2.host.ID)
	if len(all) != 2 {
		t.Fatalf("stored %d, want 2", len(all))
	}
	for _, f := range all {
		if f.VulnID == "CVE-H1" {
			t.Fatal("lower-ranked finding kept although the cap is full")
		}
	}
}
