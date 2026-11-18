package rules

import (
	"testing"

	"github.com/DonSosiska/panoptes/internal/model"
)

// Drafts whose result only varies over a literal that no real host reports are true (or false) on
// every real host and must not count as grounded.
func TestGroundingRejectsUnrealisticLiterals(t *testing.T) {
	for _, c := range []struct {
		expr  string
		facts []string
	}{
		{`facts["os.id"] != "zzz-never"`, []string{"os.id"}},
		{`!("zzz-never" in facts["services.active"])`, []string{"services.active"}},
		{`facts["os.libc"] != "nolibc"`, []string{"os.libc"}},
		{`facts["os.libc"] == "nolibc"`, []string{"os.libc"}},
		{`facts["os.id"] in ["zzz", "qqq"]`, []string{"os.id"}},
		{`!has_module(facts["kernel.modules"], "zzz_never")`, []string{"kernel.modules"}},
		{`facts["sshd.config"][?"permitrootlogin"].orValue("no") != "zzz-never"`, []string{"sshd.config"}},
		{`!facts["nginx.modules"].exists(m, m == "zzz_never")`, []string{"nginx.modules"}},
		{`facts["php.version"] != "zzz-never"`, []string{"php.version"}},
	} {
		if depOf(t, groundRule(c.expr, c.facts...)) {
			t.Errorf("%q judged fact-dependent", c.expr)
		}
	}
}

func TestGroundingKeepsLegitimateDrafts(t *testing.T) {
	for _, c := range []struct {
		expr  string
		facts []string
	}{
		{`"php-fpm" in facts["php.sapi"] && facts["php.ini"][?"allow_url_include"].orValue("0") == "1"`, []string{"php.sapi", "php.ini"}},
		{`facts["sshd.config"]["logingracetime"] != "0"`, []string{"sshd.config"}},
		{`facts["os.id"] == "debian"`, []string{"os.id"}},
		{`facts["os.id"] in ["debian", "ubuntu"] && facts["os.libc"] == "glibc"`, []string{"os.id", "os.libc"}},
		{`facts["os.libc"] == "musl"`, []string{"os.libc"}},
		{`facts["os.id"].startsWith("deb")`, []string{"os.id"}},
		{`"nf_tables" in facts["kernel.modules"]`, []string{"kernel.modules"}},
		{`"sshd" in facts["services.active"] || "ssh" in facts["services.active"]`, []string{"services.active"}},
		{`has_module(facts["nginx.modules"], "http_v2_module")`, []string{"nginx.modules"}},
		{`facts["nginx.version"] == "1.25.3"`, []string{"nginx.version"}},
		{`version_lt(facts["sudo.version"], "1.9.17")`, []string{"sudo.version"}},
		{`facts["sockets.ports"].exists(p, p == 8443)`, []string{"sockets.ports"}},
		{`facts["nginx.http2"] && "http_v2_module" in facts["nginx.modules"]`, []string{"nginx.http2", "nginx.modules"}},
		{`"foo-agent" in facts["services.active"]`, []string{"services.active"}}, // named after the package (selector foo)
	} {
		if !depOf(t, groundRule(c.expr, c.facts...)) {
			t.Errorf("%q judged fact-independent", c.expr)
		}
	}
}

// End to end: the audit bypasses must not produce an exploitable verdict from a draft.
func TestDraftBypassesAreConditionsUnknown(t *testing.T) {
	for _, c := range []struct {
		expr  string
		facts []string
		have  map[string]any
	}{
		{`facts["os.id"] != "zzz-never"`, []string{"os.id"}, map[string]any{"os.id": "debian"}},
		{`!("zzz-never" in facts["services.active"])`, []string{"services.active"}, map[string]any{"services.active": []any{"cron"}}},
		{`facts["os.libc"] != "nolibc"`, []string{"os.libc"}, map[string]any{"os.libc": "glibc"}},
	} {
		e := draftEngine(model.Rule{ID: "a", Status: model.RuleDraft, Facts: c.facts, ExploitableIf: c.expr})
		for _, sev := range []string{"Low", "High", "Critical"} {
			want(t, evalSev(t, e, true, sev, c.have), model.VerdictConditionsUnknown, "does not depend on host facts")
		}
	}
	e := draftEngine(model.Rule{ID: "a", Status: model.RuleDraft, Facts: []string{"os.libc"}, ExploitableIf: `facts["os.libc"] == "glibc"`})
	want(t, evalKEV(t, e, true, map[string]any{"os.libc": "glibc"}), model.VerdictExploitable, "LLM draft (unreviewed)")
}
