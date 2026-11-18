package notify

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/DonSosiska/holealign/internal/model"
)

func pkgEvent(vuln, host, pkg, ver string, fixed ...string) model.Event {
	ev := testEvent(model.EventExploitable, vuln, host)
	ev.Finding.PackageName = pkg
	ev.Finding.PackageVer = ver
	ev.Finding.FixedVersions = fixed
	return ev
}

func opensshEvents(host string) []model.Event {
	const vuln = "CVE-2024-6387"
	return []model.Event{
		pkgEvent(vuln, host, "openssh-client", "1:8.9p1-3", "1:8.9p1-3+deb12u1"),
		pkgEvent(vuln, host, "openssh-server", "1:8.9p1-3", "1:8.9p1-3+deb12u1"),
		pkgEvent(vuln, host, "openssh-sftp-server", "1:8.9p1-3"),
	}
}

func TestOpensshGroupedIntoOneMessage(t *testing.T) {
	hs := newFakeHS(t, nil)
	m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org"}}, nil)
	if err := m.Notify(context.Background(), opensshEvents("web01")); err != nil {
		t.Fatal(err)
	}
	reqs := hs.requests()
	if len(reqs) != 1 {
		t.Fatalf("messages = %d, want 1", len(reqs))
	}
	body := reqs[0].body.Body
	if n := strings.Count(body, "EXPLOITABLE:"); n != 1 {
		t.Errorf("header count = %d, want 1:\n%s", n, body)
	}
	for _, want := range []string{
		"Packages: openssh-client 1:8.9p1-3 → fixed in 1:8.9p1-3+deb12u1",
		"openssh-server 1:8.9p1-3 → fixed in 1:8.9p1-3+deb12u1",
		"openssh-sftp-server 1:8.9p1-3 → no fix yet",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
	if strings.Count(body, "openssh-client") != 1 {
		t.Errorf("package listed more than once:\n%s", body)
	}
}

func TestDifferentHostsSeparateMessages(t *testing.T) {
	hs := newFakeHS(t, nil)
	m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org"}}, nil)
	events := append(opensshEvents("web01"), opensshEvents("web02")...)
	if err := m.Notify(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	reqs := hs.requests()
	if len(reqs) != 2 {
		t.Fatalf("messages = %d, want 2", len(reqs))
	}
	if !strings.Contains(reqs[0].body.Body, "on web01") || !strings.Contains(reqs[1].body.Body, "on web02") {
		t.Errorf("messages not per host:\n%q\n%q", reqs[0].body.Body, reqs[1].body.Body)
	}
}

func TestDifferentTargetsSeparateMessages(t *testing.T) {
	hs := newFakeHS(t, nil)
	m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org"}}, nil)
	host := pkgEvent("CVE-1", "web01", "nginx", "1.24")
	image := pkgEvent("CVE-1", "web01", "nginx", "1.24")
	image.Finding.Target = "nginx:1.25"
	image.Finding.TargetKind = model.TargetContainerImage
	if err := m.Notify(context.Background(), []model.Event{host, image}); err != nil {
		t.Fatal(err)
	}
	if n := len(hs.requests()); n != 2 {
		t.Fatalf("messages = %d, want 2", n)
	}
}

func TestResolvedGrouped(t *testing.T) {
	hs := newFakeHS(t, nil)
	m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org"}}, nil)
	var events []model.Event
	for _, p := range []string{"nginx", "nginx-common"} {
		ev := pkgEvent("CVE-2024-9", "web01", p, "1.24.0")
		ev.Kind = model.EventResolved
		ev.Finding.Verdict = model.VerdictNotAffected
		events = append(events, ev)
	}
	if err := m.Notify(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	reqs := hs.requests()
	if len(reqs) != 1 {
		t.Fatalf("messages = %d, want 1", len(reqs))
	}
	if reqs[0].body.MsgType != "m.notice" {
		t.Errorf("msgtype = %q, want m.notice", reqs[0].body.MsgType)
	}
	want := "✅ RESOLVED: CVE-2024-9 on web01\nnginx 1.24.0: now not_affected; nginx-common 1.24.0: now not_affected"
	if reqs[0].body.Body != want {
		t.Errorf("body = %q\nwant %q", reqs[0].body.Body, want)
	}
}

func TestBurstCountsGroupsNotEvents(t *testing.T) {
	// 15 groups of 2 events each: 30 events, but at the threshold, so no summary.
	hs := newFakeHS(t, nil)
	m := newTestMatrix(t, hs, Config{Default: []string{"!r:example.org"}}, nil)
	var events []model.Event
	for i := range burstThreshold {
		vuln := fmt.Sprintf("CVE-%d", i)
		events = append(events, pkgEvent(vuln, "web01", "a", "1"), pkgEvent(vuln, "web01", "b", "1"))
	}
	if err := m.Notify(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	if n := len(hs.requests()); n != burstThreshold {
		t.Errorf("messages = %d, want %d", n, burstThreshold)
	}

	// 16 groups of 2 events: above the threshold, so burst mode applies.
	hs2 := newFakeHS(t, nil)
	m2 := newTestMatrix(t, hs2, Config{Default: []string{"!r:example.org"}}, nil)
	events = nil
	for i := range burstThreshold + 1 {
		vuln := fmt.Sprintf("CVE-%d", i)
		events = append(events, pkgEvent(vuln, "web01", "a", "1"), pkgEvent(vuln, "web01", "b", "1"))
	}
	if err := m2.Notify(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	reqs := hs2.requests()
	if len(reqs) != burstKeep+1 {
		t.Fatalf("messages = %d, want %d", len(reqs), burstKeep+1)
	}
	if !strings.Contains(reqs[burstKeep].body.Body, "…and 6 more findings") {
		t.Errorf("summary = %q", reqs[burstKeep].body.Body)
	}
}

func TestRenderGroupMergesFields(t *testing.T) {
	const reason = "TLS termination enabled"
	a := pkgEvent("CVE-1", "web01", "openssl", "3.0.1", "3.0.7")
	a.Finding.Severity = "Medium"
	a.Finding.CVSS = 5.0
	a.Finding.EPSS = 0.010
	a.Finding.VerdictReason = reason
	a.FixCmd = "apt-get install --only-upgrade openssl"
	a.WebURL = "https://holealign.example/findings/1"
	a.Rule = &model.Rule{Title: "Heartbeat", Fix: model.Fix{Mitigation: "disable heartbeat"}}

	b := pkgEvent("CVE-1", "web01", "<script>libssl</script>", "3.0.1", "3.0.8")
	b.Finding.Severity = "High"
	b.Finding.CVSS = 8.1
	b.Finding.EPSS = 0.032
	b.Finding.KEV = true
	b.Finding.VerdictReason = reason
	b.Finding.RuleStatus = model.RuleDraft
	b.FixCmd = "apt-get install --only-upgrade libssl3"
	b.WebURL = "https://holealign.example/findings/2"
	b.Rule = &model.Rule{Title: "Heartbeat", Fix: model.Fix{Mitigation: "disable heartbeat"}}

	plain, h := renderGroup([]model.Event{a, b})

	for _, want := range []string{
		"Severity High · CVSS 8.1 · EPSS 3.2% · 🚨 KEV",
		"Why: " + reason,
		"Rule: Heartbeat",
		"Fix: apt-get install --only-upgrade openssl",
		"Fix: apt-get install --only-upgrade libssl3",
		"Mitigation: disable heartbeat",
		"Details: https://holealign.example/findings/1",
		"⚠️ unreviewed LLM draft — review the rule in the web UI before acting",
	} {
		if !hasLine(plain, want) {
			t.Errorf("plain missing line %q:\n%s", want, plain)
		}
	}
	for _, once := range []string{"Why:", "Rule:", "Mitigation:", "Details:"} {
		if n := strings.Count(plain, once); n != 1 {
			t.Errorf("%q appears %d times, want 1:\n%s", once, n, plain)
		}
	}
	if strings.Contains(h, "<script>") {
		t.Errorf("package name not escaped in HTML:\n%s", h)
	}
	if !strings.Contains(h, "&lt;script&gt;libssl&lt;/script&gt;") {
		t.Errorf("escaped package missing from HTML:\n%s", h)
	}
	if strings.Contains(h, "holealign.example/findings/2") {
		t.Errorf("link must be the first event's WebURL only:\n%s", h)
	}
}
