package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"panoptes/internal/model"
	"panoptes/internal/server/core"
	"panoptes/internal/server/store"
)

type fakeMatcher struct {
	mu       sync.Mutex
	findings []model.Finding
	err      error
	calls    int
}

func (m *fakeMatcher) set(f ...model.Finding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.findings, m.err = f, nil
}

func (m *fakeMatcher) Match(context.Context, model.TargetKind, []byte, model.OSInfo) ([]model.Finding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return append([]model.Finding(nil), m.findings...), m.err
}

type fakeEval struct {
	mu       sync.Mutex
	verdicts map[string]model.Verdict // vuln id -> verdict
	rule     *model.Rule
}

func (e *fakeEval) Evaluate(_ context.Context, _ core.HostContext, f model.Finding) core.Evaluation {
	e.mu.Lock()
	defer e.mu.Unlock()
	v, ok := e.verdicts[f.VulnID]
	if !ok {
		return core.Evaluation{Verdict: model.VerdictConditionsUnknown, Reason: "no rule"}
	}
	return core.Evaluation{Verdict: v, Reason: "because", Rule: e.rule, RuleStatus: model.RuleReviewed}
}
func (e *fakeEval) FactRequests() []model.FactRequest { return nil }
func (e *fakeEval) setVerdict(id string, v model.Verdict) {
	e.mu.Lock()
	e.verdicts[id] = v
	e.mu.Unlock()
}

type recNotifier struct {
	mu     sync.Mutex
	events []model.Event
	fail   bool
}

func (n *recNotifier) Notify(_ context.Context, ev []model.Event) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.fail {
		return errors.New("boom")
	}
	n.events = append(n.events, ev...)
	return nil
}
func (n *recNotifier) take() []model.Event {
	n.mu.Lock()
	defer n.mu.Unlock()
	e := n.events
	n.events = nil
	return e
}

type recDrafter struct {
	mu  sync.Mutex
	ids []string
}

func (d *recDrafter) Enqueue(_ context.Context, f model.Finding) {
	d.mu.Lock()
	d.ids = append(d.ids, f.VulnID)
	d.mu.Unlock()
}

type env struct {
	st   *store.SQLite
	m    *fakeMatcher
	ev   *fakeEval
	n    *recNotifier
	d    *recDrafter
	p    *Pipeline
	host model.Host
}

func setup(t *testing.T) *env {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	_, hash, _ := store.NewSecret("pa_")
	h, err := st.EnrollHost(context.Background(), store.EnrollParams{MachineID: "m1", Hostname: "web1", Labels: []string{"prod"}, KeyHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceInventory(context.Background(), h.ID, model.InventoryPayload{Hash: "x", Targets: []model.InventoryTarget{
		{Kind: model.TargetHost, Name: "host", SBOM: json.RawMessage(`{}`)},
	}}); err != nil {
		t.Fatal(err)
	}
	e := &env{st: st, m: &fakeMatcher{}, ev: &fakeEval{verdicts: map[string]model.Verdict{}, rule: &model.Rule{ID: "R1", Status: model.RuleReviewed}},
		n: &recNotifier{}, d: &recDrafter{}, host: h}
	e.p = New(st, e.m, e.ev, e.n, e.d, Options{PublicURL: "https://pan.example.com/"})
	t.Cleanup(e.p.Shutdown)
	return e
}

func vuln(id, sev string, kev bool) model.Finding {
	return model.Finding{PackageName: "openssh-server", PackageVer: "1:9.2", PackageType: "deb", VulnID: id, Severity: sev, KEV: kev,
		FixedVersions: []string{"1:9.2p1-2+deb12u3"}, FixState: "fixed"}
}

func (e *env) run(t *testing.T) []model.Event {
	t.Helper()
	if err := e.p.Run(context.Background(), e.host.ID); err != nil {
		t.Fatal(err)
	}
	return e.n.take()
}

func TestExploitableEventOnceThenResolved(t *testing.T) {
	e := setup(t)
	e.ev.setVerdict("CVE-1", model.VerdictExploitable)
	e.m.set(vuln("CVE-1", "High", false))

	ev := e.run(t)
	if len(ev) != 1 || ev[0].Kind != model.EventExploitable {
		t.Fatalf("want one exploitable event, got %+v", ev)
	}
	got := ev[0]
	if got.Finding.ID == 0 || got.Finding.HostID != e.host.ID || got.Finding.Target != "host" || got.Finding.Verdict != model.VerdictExploitable {
		t.Fatalf("finding: %+v", got.Finding)
	}
	if got.Host.Hostname != "web1" || got.Rule == nil || got.Rule.ID != "R1" || got.Finding.RuleID != "R1" {
		t.Fatalf("host/rule: %+v", got)
	}
	if got.WebURL != "https://pan.example.com/findings/"+itoa(got.Finding.ID) {
		t.Fatalf("web url %q", got.WebURL)
	}
	if got.FixCmd != "apt-get install --only-upgrade openssh-server" {
		t.Fatalf("fix cmd %q", got.FixCmd)
	}

	if ev := e.run(t); len(ev) != 0 {
		t.Fatalf("same again must be silent, got %+v", ev)
	}

	// package upgraded: finding disappears -> resolved event, then silence
	e.m.set()
	ev = e.run(t)
	if len(ev) != 1 || ev[0].Kind != model.EventResolved || ev[0].Finding.Verdict != model.VerdictResolved {
		t.Fatalf("want resolved, got %+v", ev)
	}
	if ev := e.run(t); len(ev) != 0 {
		t.Fatalf("resolved twice: %+v", ev)
	}

	// it comes back and is exploitable again: a fresh event
	e.m.set(vuln("CVE-1", "High", false))
	ev = e.run(t)
	if len(ev) != 1 || ev[0].Kind != model.EventExploitable {
		t.Fatalf("re-exploitable: %+v", ev)
	}
}

func itoa(i int64) string { return WebURL("", i)[len("/findings/"):] }

func TestVerdictChangesToAndFromExploitable(t *testing.T) {
	e := setup(t)
	e.ev.setVerdict("CVE-1", model.VerdictNotExploitable)
	e.m.set(vuln("CVE-1", "High", false))
	if ev := e.run(t); len(ev) != 0 {
		t.Fatalf("not exploitable must be silent: %+v", ev)
	}
	e.ev.setVerdict("CVE-1", model.VerdictExploitable) // facts changed
	ev := e.run(t)
	if len(ev) != 1 || ev[0].Kind != model.EventExploitable {
		t.Fatalf("changed to exploitable: %+v", ev)
	}
	e.ev.setVerdict("CVE-1", model.VerdictNotExploitable) // mitigated
	ev = e.run(t)
	if len(ev) != 1 || ev[0].Kind != model.EventResolved {
		t.Fatalf("mitigated: %+v", ev)
	}
	if ev := e.run(t); len(ev) != 0 {
		t.Fatalf("repeat: %+v", ev)
	}
}

func TestUnknownCriticalOnlyForKEVOrCritical(t *testing.T) {
	e := setup(t)
	e.m.set(vuln("CVE-LOW", "Medium", false), vuln("CVE-HIGH", "High", false), vuln("CVE-CRIT", "Critical", false), vuln("CVE-KEV", "Medium", true))
	ev := e.run(t)
	kinds := map[string]model.EventKind{}
	for _, x := range ev {
		kinds[x.Finding.VulnID] = x.Kind
	}
	if len(ev) != 2 || kinds["CVE-CRIT"] != model.EventUnknownCritical || kinds["CVE-KEV"] != model.EventUnknownCritical {
		t.Fatalf("got %+v", kinds)
	}
	if ev := e.run(t); len(ev) != 0 {
		t.Fatalf("unknown_critical re-sent: %+v", ev)
	}
	// reason-only change (verdict stays unknown) must not re-send
	e.ev.mu.Lock()
	e.ev.mu.Unlock()
	if ev := e.run(t); len(ev) != 0 {
		t.Fatalf("%+v", ev)
	}
	// drafter got High/Critical/KEV findings without rule, not the Medium non-KEV one
	got := map[string]bool{}
	for _, id := range e.d.ids {
		got[id] = true
	}
	if got["CVE-LOW"] || !got["CVE-HIGH"] || !got["CVE-CRIT"] || !got["CVE-KEV"] {
		t.Fatalf("drafter: %v", e.d.ids)
	}
	// an unknown_critical finding that is later found not exploitable -> resolved
	e.ev.setVerdict("CVE-CRIT", model.VerdictNotExploitable)
	ev = e.run(t)
	if len(ev) != 1 || ev[0].Kind != model.EventResolved || ev[0].Finding.VulnID != "CVE-CRIT" {
		t.Fatalf("%+v", ev)
	}
}

func TestDraftingSkippedWhenRuleExists(t *testing.T) {
	e := setup(t)
	e.ev.setVerdict("CVE-1", model.VerdictNotExploitable)
	e.m.set(vuln("CVE-1", "Critical", true))
	e.run(t)
	if len(e.d.ids) != 0 {
		t.Fatalf("drafter called for ruled finding: %v", e.d.ids)
	}
}

func TestMatcherErrorKeepsFindings(t *testing.T) {
	e := setup(t)
	e.ev.setVerdict("CVE-1", model.VerdictExploitable)
	e.m.set(vuln("CVE-1", "High", false))
	e.run(t)

	e.m.mu.Lock()
	e.m.err = errors.New("no db")
	e.m.mu.Unlock()
	if err := e.p.Run(context.Background(), e.host.ID); err == nil {
		t.Fatal("expected error")
	}
	fs, _, _ := e.st.ListFindings(context.Background(), store.FindingFilter{})
	if len(fs) != 1 || fs[0].Verdict != model.VerdictExploitable {
		t.Fatalf("findings must survive matcher failure: %+v", fs)
	}
	if ev := e.n.take(); len(ev) != 0 {
		t.Fatal("no events on failure")
	}
}

func TestNotifierFailureRetriesExploitable(t *testing.T) {
	e := setup(t)
	e.ev.setVerdict("CVE-1", model.VerdictExploitable)
	e.m.set(vuln("CVE-1", "High", false))
	e.n.fail = true
	if err := e.p.Run(context.Background(), e.host.ID); err == nil {
		t.Fatal("expected notify error")
	}
	e.n.fail = false
	if ev := e.run(t); len(ev) != 1 || ev[0].Kind != model.EventExploitable {
		t.Fatalf("retry: %+v", ev)
	}
}

func TestTriggerCoalescesPerHost(t *testing.T) {
	e := setup(t)
	e.m.set(vuln("CVE-1", "Low", false))
	for i := 0; i < 50; i++ {
		e.p.Trigger(e.host.ID)
	}
	e.p.Wait()
	e.m.mu.Lock()
	calls := e.m.calls
	e.m.mu.Unlock()
	if calls < 1 || calls > 3 {
		t.Fatalf("expected coalescing, matcher called %d times", calls)
	}
	fs, _, _ := e.st.ListFindings(context.Background(), store.FindingFilter{})
	if len(fs) != 1 {
		t.Fatalf("findings: %d", len(fs))
	}
}

func TestFixCmd(t *testing.T) {
	cases := []struct {
		f    model.Finding
		want string
	}{
		{model.Finding{PackageType: "deb", PackageName: "openssl"}, "apt-get install --only-upgrade openssl"},
		{model.Finding{PackageType: "rpm", PackageName: "openssl"}, "dnf upgrade openssl"},
		{model.Finding{PackageType: "apk", PackageName: "busybox"}, "apk upgrade busybox"},
		{model.Finding{PackageType: "python", PackageName: "django", FixedVersions: []string{"4.2.1"}}, "pip install -U 'django>=4.2.1'"},
		{model.Finding{PackageType: "npm", PackageName: "lodash", FixedVersions: []string{"4.17.21"}}, "npm install lodash@4.17.21"},
		{model.Finding{PackageType: "deb", PackageName: "openssl", TargetKind: model.TargetContainerImage, Target: "nginx:1.25"}, "rebuild/pull image nginx:1.25 with fixed base"},
		{model.Finding{PackageType: "go-module", PackageName: "golang.org/x/net"}, ""},
		{model.Finding{PackageType: "deb", PackageName: "x; rm -rf /"}, ""},
		{model.Finding{PackageType: "deb", PackageName: "openssl", FixState: "not-fixed"}, ""},
		{model.Finding{PackageType: "python", PackageName: "django", FixedVersions: []string{"1'; id #"}}, "pip install -U django"},
	}
	for _, c := range cases {
		if got := FixCmd(c.f); got != c.want {
			t.Errorf("%+v: got %q want %q", c.f, got, c.want)
		}
	}
}

var _ = time.Second
