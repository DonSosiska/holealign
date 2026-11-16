package rules

import (
	"context"
	"strings"
	"testing"

	"panoptes/internal/model"
	"panoptes/internal/server/core"
)

func draftEngine(r model.Rule) *Engine {
	r.Vulns = []string{"CVE-2030-1"}
	r.Packages = []model.PackageSelector{{Name: "foo"}}
	r.Explanation = "because reasons"
	r.Title = "t"
	r.Source = "llm:test"
	e := New([]model.Rule{r}, nil)
	if p := e.Problems(); len(p) > 0 {
		panic(p[0].String())
	}
	return e
}

func evalSev(t *testing.T, e *Engine, kev bool, sev string, facts map[string]any) core.Evaluation {
	t.Helper()
	hc := core.HostContext{Host: model.Host{Hostname: "h"}, Facts: jsonFacts(t, facts)}
	return e.Evaluate(context.Background(), hc, model.Finding{VulnID: "CVE-2030-1", PackageName: "foo", KEV: kev, Severity: sev})
}

func evalKEV(t *testing.T, e *Engine, kev bool, facts map[string]any) core.Evaluation {
	return evalSev(t, e, kev, "High", facts)
}

func TestDraftGuard(t *testing.T) {
	// ungrounded: always unknown
	e := draftEngine(model.Rule{ID: "a", Status: model.RuleDraft, ExploitableIf: "true"})
	ev := evalKEV(t, e, false, nil)
	want(t, ev, model.VerdictConditionsUnknown, "LLM draft suggests exploitable: because reasons")
	if ev.Rule == nil || ev.RuleStatus != model.RuleDraft {
		t.Errorf("rule info lost: %+v", ev)
	}
	e = draftEngine(model.Rule{ID: "a", Status: model.RuleDraft, ExploitableIf: "false"})
	want(t, evalKEV(t, e, false, nil), model.VerdictConditionsUnknown, "LLM draft suggests affected_not_exploitable")
	// .installed only
	e = draftEngine(model.Rule{ID: "a", Status: model.RuleDraft, Facts: []string{"nginx.installed"}, ExploitableIf: `facts["nginx.installed"] == true`})
	want(t, evalKEV(t, e, false, map[string]any{"nginx.installed": true}), model.VerdictConditionsUnknown, "LLM draft suggests")
	// declared-but-unused real fact does not ground
	e = draftEngine(model.Rule{ID: "a", Status: model.RuleDraft, Facts: []string{"services.active"}, ExploitableIf: `true`})
	want(t, evalKEV(t, e, false, map[string]any{"services.active": []any{"sshd"}}), model.VerdictConditionsUnknown, "LLM draft suggests")
	// fact mentioned only inside a string literal does not ground
	e = draftEngine(model.Rule{ID: "a", Status: model.RuleDraft, Facts: []string{"services.active"}, ExploitableIf: `"facts[\"services.active\"]" == "x" || true`})
	want(t, evalKEV(t, e, false, map[string]any{"services.active": []any{"sshd"}}), model.VerdictConditionsUnknown, "LLM draft suggests")
	// grounded exploitable allowed, with draft warning
	g := model.Rule{ID: "a", Status: model.RuleDraft, Facts: []string{"services.active"}, ExploitableIf: `"sshd" in facts["services.active"]`}
	e = draftEngine(g)
	ev = evalKEV(t, e, true, map[string]any{"services.active": []any{"sshd"}})
	want(t, ev, model.VerdictExploitable, "LLM draft (unreviewed)")
	// grounded not exploitable: ok normally, unknown on KEV / Critical
	g.ExploitableIf = `"nope" in facts["services.active"]`
	e = draftEngine(g)
	f := map[string]any{"services.active": []any{"sshd"}}
	want(t, evalKEV(t, e, false, f), model.VerdictNotExploitable, "LLM draft (unreviewed)")
	want(t, evalKEV(t, e, true, f), model.VerdictConditionsUnknown, "KEV/Critical need review")
	want(t, evalSev(t, e, false, "CRITICAL", f), model.VerdictConditionsUnknown, "KEV/Critical need review")
	// reviewed: unaffected
	e = draftEngine(model.Rule{ID: "a", Status: model.RuleReviewed, ExploitableIf: "true"})
	want(t, evalKEV(t, e, false, nil), model.VerdictExploitable)
	e = draftEngine(model.Rule{ID: "a", Status: model.RuleReviewed, ExploitableIf: "false"})
	want(t, evalKEV(t, e, true, nil), model.VerdictNotExploitable)
}

func TestDraftCannotOverrideReviewed(t *testing.T) {
	files := loadShipped(t)
	var rev model.Rule
	for _, r := range files {
		if r.ID == "CVE-2024-6387" {
			rev = r
		}
	}
	d := rev
	d.ID = "CVE-2024-6387-llm"
	d.Status = model.RuleDraft
	d.Source = "llm:x"
	d.ExploitableIf = "false"
	db := &fakeDB{rules: []model.Rule{d}}
	e := New(files, db)
	hf := map[string]any{"os.libc": "glibc", "sshd.config": map[string]any{"logingracetime": "120"}}
	ev := eval(t, e, "CVE-2024-6387", "openssh-server", "deb", hf)
	want(t, ev, model.VerdictExploitable)
	if ev.RuleStatus != model.RuleReviewed || ev.Rule.ID != "CVE-2024-6387" {
		t.Fatalf("draft won: %+v", ev.Rule)
	}
	// same ID draft
	d.ID = "CVE-2024-6387"
	db.rules = []model.Rule{d}
	_ = e.Reload(context.Background())
	want(t, eval(t, e, "CVE-2024-6387", "openssh-server", "deb", hf), model.VerdictExploitable)
}

func TestValidateFileMatchPolicy(t *testing.T) {
	mk := func(path, pat string) model.Rule {
		r := validRule()
		r.Facts = nil
		r.ExploitableIf = "true"
		r.Status = model.RuleDraft
		r.FactRequests = []model.FactRequest{{Name: "file.match:test-1.a", Collector: "file.match", Params: map[string]string{"path": path, "pattern": pat}}}
		return r
	}
	if err := Validate(mk("/etc/nginx/conf.d/*.conf", `^\s*ssl_protocols`)); err != nil {
		t.Fatalf("good request rejected: %v", err)
	}
	if err := Validate(mk("/opt/*/conf/*.conf", `Listen`)); err != nil {
		t.Fatalf("opt root rejected: %v", err)
	}
	bad := []struct{ path, pat string }{
		{"/etc/shadow", ".*"},
		{"/etc/shadow", "root"},
		{"/etc/sh*", "root"},
		{"/etc/*", "root"},
		{"/etc/ssh/ssh_host_*", "x"},
		{"/etc/ssh/ssh_host_rsa*", "x"},
		{"/etc/ssl/private/*.conf", "x"},
		{"/etc/../root/.ssh/id_rsa", "x"},
		{"/etc/nginx/../shadow", "x"},
		{"etc/nginx/a.conf", "x"},
		{"/root/a.conf", "x"},
		{"/etc/app/server.key", "x"},
		{"/etc/app/Credentials.conf", "x"},
		{"/etc/app/db.env", "x"},
		{"/etc/NetworkManager/system-connections/x", "x"},
		{"/etc/panoptes/agent.yaml", "x"},
		{"/opt/panoptes/conf/a.conf", "x"},
		{"/etc/a/[.][.]/shadow", "x"},
		{"/etc/a.conf", ""},
		{"/etc/a.conf", "^"},
		{"/etc/a.conf", "(?s).*"},
		{"/etc/a.conf", "foo|"},
		{"/etc/a.conf", ".+"},
		{"/etc/a.conf", strings.Repeat("a", 257)},
	}
	for _, c := range bad {
		if err := Validate(mk(c.path, c.pat)); err == nil {
			t.Errorf("accepted path=%q pattern=%q", c.path, c.pat)
		}
	}
	// names
	r := mk("/etc/a.conf", "foo")
	r.FactRequests[0].Name = "file.match:other.a"
	if err := Validate(r); err == nil || !strings.Contains(err.Error(), "namespaced") {
		t.Errorf("name not namespaced: %v", err)
	}
	r.FactRequests[0].Name = "file.match:test-1." + strings.Repeat("a", 70)
	if err := Validate(r); err == nil {
		t.Error("long name accepted")
	}
	r.FactRequests[0].Name = "file.match:test-1.A"
	if err := Validate(r); err == nil {
		t.Error("uppercase name accepted")
	}
	// max 5
	r = mk("/etc/a.conf", "foo")
	r.FactRequests = nil
	for i := 0; i < 6; i++ {
		r.FactRequests = append(r.FactRequests, model.FactRequest{Name: "file.match:test-1.r" + string(rune('a'+i)), Collector: "file.match", Params: map[string]string{"path": "/etc/a.conf", "pattern": "foo"}})
	}
	if err := Validate(r); err == nil || !strings.Contains(err.Error(), "at most 5") {
		t.Errorf("6 requests: %v", err)
	}
	if err := FileMatchPathAllowed("/etc/ssh/sshd_config"); err != nil {
		t.Errorf("sshd_config rejected: %v", err)
	}
}

func TestValidateIDAndOptionalIndexAndAST(t *testing.T) {
	r := validRule()
	r.ID = "bad id!"
	if err := Validate(r); err == nil || !strings.Contains(err.Error(), "id") {
		t.Errorf("bad id accepted: %v", err)
	}
	r = validRule()
	r.Facts = []string{"sshd.config"}
	r.ExploitableIf = `facts["sshd.config"].?["a"].orValue("1") == "1"`
	if err := Validate(r); err == nil || !strings.Contains(err.Error(), `m[?"key"]`) {
		t.Errorf(".?[ accepted: %v", err)
	}
	// ".?[" inside a string literal is fine
	r.ExploitableIf = `facts["sshd.config"][?"a"].orValue(".?[") == ".?["`
	if err := Validate(r); err != nil {
		t.Errorf("string literal rejected: %v", err)
	}
	// a fact name inside a string literal is not a reference
	r = validRule()
	r.ExploitableIf = `facts["os.id"] == "facts[\"os.libc\"]"`
	if err := Validate(r); err != nil {
		t.Errorf("literal treated as reference: %v", err)
	}
	// undeclared fact via AST
	r.ExploitableIf = `facts["os.id"] == "x" && facts["os.libc"] == "glibc"`
	if err := Validate(r); err == nil || !strings.Contains(err.Error(), "not listed in facts") {
		t.Errorf("undeclared fact accepted: %v", err)
	}
	// bare/dynamic facts access
	r.ExploitableIf = `facts["os." + "libc"] == "glibc"`
	if err := Validate(r); err == nil {
		t.Error("dynamic facts index accepted")
	}
}
