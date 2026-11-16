package rules

import (
	"context"
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

func evalKEV(t *testing.T, e *Engine, kev bool, facts map[string]any) core.Evaluation {
	t.Helper()
	hc := core.HostContext{Host: model.Host{Hostname: "h"}, Facts: jsonFacts(t, facts)}
	return e.Evaluate(context.Background(), hc, model.Finding{VulnID: "CVE-2030-1", PackageName: "foo", KEV: kev})
}

func TestUngroundedDraftGuard(t *testing.T) {
	// ungrounded true -> unknown
	e := draftEngine(model.Rule{ID: "a", Status: model.RuleDraft, ExploitableIf: "true"})
	ev := evalKEV(t, e, false, nil)
	want(t, ev, model.VerdictConditionsUnknown, "LLM draft (unreviewed, no host evidence): likely exploitable", "because reasons")
	if ev.Rule == nil || ev.RuleStatus != model.RuleDraft {
		t.Errorf("rule info lost: %+v", ev)
	}
	// ungrounded false -> not exploitable, prefixed
	e = draftEngine(model.Rule{ID: "a", Status: model.RuleDraft, ExploitableIf: "false"})
	want(t, evalKEV(t, e, false, nil), model.VerdictNotExploitable, "LLM draft (unreviewed): ")
	// ... but KEV -> unknown
	want(t, evalKEV(t, e, true, nil), model.VerdictConditionsUnknown, "KEV")
	// only <x>.installed counts as ungrounded
	e = draftEngine(model.Rule{ID: "a", Status: model.RuleDraft, Facts: []string{"nginx.installed"}, ExploitableIf: `facts["nginx.installed"] == true`})
	want(t, evalKEV(t, e, false, map[string]any{"nginx.installed": true}), model.VerdictConditionsUnknown, "no host evidence")
	// real fact: unaffected
	e = draftEngine(model.Rule{ID: "a", Status: model.RuleDraft, Facts: []string{"services.active"}, ExploitableIf: `"sshd" in facts["services.active"]`})
	want(t, evalKEV(t, e, false, map[string]any{"services.active": []any{"sshd"}}), model.VerdictExploitable)
	// reviewed: unaffected
	e = draftEngine(model.Rule{ID: "a", Status: model.RuleReviewed, ExploitableIf: "true"})
	want(t, evalKEV(t, e, false, nil), model.VerdictExploitable)
	e = draftEngine(model.Rule{ID: "a", Status: model.RuleReviewed, ExploitableIf: "false"})
	want(t, evalKEV(t, e, true, nil), model.VerdictNotExploitable)
}
