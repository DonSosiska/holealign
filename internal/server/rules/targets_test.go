package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/core"
)

func evalKind(t *testing.T, e *Engine, kind model.TargetKind, facts map[string]any) core.Evaluation {
	t.Helper()
	hc := core.HostContext{Host: model.Host{Hostname: "h"}, Facts: jsonFacts(t, facts)}
	return e.Evaluate(context.Background(), hc, model.Finding{
		VulnID: "CVE-2030-1", PackageName: "foo", PackageType: "deb", PackageVer: "1.0",
		Target: "t", TargetKind: kind,
	})
}

func targetRule(r model.Rule) *Engine {
	r.ID = "t1"
	r.Vulns = []string{"CVE-2030-1"}
	r.Packages = []model.PackageSelector{{Name: "foo"}}
	r.Title, r.Explanation, r.Source, r.Status = "t", "e", "builtin", model.RuleReviewed
	e := New([]model.Rule{r}, nil)
	if p := e.Problems(); len(p) > 0 {
		panic(p[0].String())
	}
	return e
}

func TestTargetsDefaultHostOnly(t *testing.T) {
	e := targetRule(model.Rule{Facts: []string{"os.libc"}, ExploitableIf: `facts["os.libc"] == "glibc"`})
	f := map[string]any{"os.libc": "musl"}
	want(t, evalKind(t, e, model.TargetHost, f), model.VerdictNotExploitable)
	want(t, evalKind(t, e, "", f), model.VerdictNotExploitable)
	ev := evalKind(t, e, model.TargetContainerImage, f)
	want(t, ev, model.VerdictConditionsUnknown, "host facts", "container image")
	ev = evalKind(t, e, model.TargetContainerImage, map[string]any{"os.libc": "glibc"})
	want(t, ev, model.VerdictConditionsUnknown, "container image")
}

func TestTargetsFactFreeRuleAppliesToImages(t *testing.T) {
	e := targetRule(model.Rule{ExploitableIf: `pkg.name == "foo"`})
	want(t, evalKind(t, e, model.TargetContainerImage, nil), model.VerdictExploitable)
}

func TestTargetsHostVarCounts(t *testing.T) {
	e := targetRule(model.Rule{ExploitableIf: `host.arch == "amd64"`})
	want(t, evalKind(t, e, model.TargetContainerImage, nil), model.VerdictConditionsUnknown, "host facts")
	e = targetRule(model.Rule{ExploitableIf: `true`, NotAffectedIf: `host.os_id == "alpine"`})
	want(t, evalKind(t, e, model.TargetContainerImage, nil), model.VerdictConditionsUnknown, "host facts")
}

func TestTargetsListedImageStillNeverUsesHostFacts(t *testing.T) {
	e := targetRule(model.Rule{Targets: []string{"host", "container_image"}, Facts: []string{"os.libc"},
		ExploitableIf: `facts["os.libc"] == "glibc"`})
	want(t, evalKind(t, e, model.TargetContainerImage, map[string]any{"os.libc": "glibc"}), model.VerdictConditionsUnknown)
	want(t, evalKind(t, e, model.TargetHost, map[string]any{"os.libc": "glibc"}), model.VerdictExploitable)
	// host-only fact-free rule restricted to images only is still evaluated (it reads no facts)
	e = targetRule(model.Rule{Targets: []string{"container_image"}, ExploitableIf: `true`})
	want(t, evalKind(t, e, model.TargetHost, nil), model.VerdictExploitable)
}

func TestTargetsValidation(t *testing.T) {
	base := model.Rule{ID: "x", Vulns: []string{"CVE-1"}, Title: "t", Explanation: "e", Status: model.RuleReviewed, Source: "builtin",
		Packages: []model.PackageSelector{{Name: "foo"}}, ExploitableIf: "true"}
	for _, ts := range [][]string{nil, {"host"}, {"container_image"}, {"host", "container_image"}} {
		r := base
		r.Targets = ts
		if err := Validate(r); err != nil {
			t.Errorf("targets %v: %v", ts, err)
		}
	}
	for _, ts := range [][]string{{"vm"}, {"host", "host"}, {""}} {
		r := base
		r.Targets = ts
		err := Validate(r)
		if err == nil || !strings.Contains(err.Error(), "targets[") {
			t.Errorf("targets %v: want validation error, got %v", ts, err)
		}
	}
}

func TestTargetsParseYAML(t *testing.T) {
	r, err := ParseRule([]byte("id: a\nvulns: [CVE-1]\ntargets: [host, container_image]\n"))
	if err != nil || len(r.Targets) != 2 {
		t.Fatalf("%v %+v", err, r.Targets)
	}
}
