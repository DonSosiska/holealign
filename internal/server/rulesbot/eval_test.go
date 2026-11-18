package rulesbot

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/DonSosiska/holealign/internal/model"
	"github.com/DonSosiska/holealign/internal/server/llm"
	"github.com/DonSosiska/holealign/internal/server/rules"
)

func TestParseVariants(t *testing.T) {
	vs, err := ParseVariants("claude-sonnet-5-5@medium, claude-haiku-5-5, claude-haiku-5-5@high", "low")
	if err != nil {
		t.Fatal(err)
	}
	want := []Variant{{"claude-sonnet-5-5", "medium"}, {"claude-haiku-5-5", "low"}, {"claude-haiku-5-5", "high"}}
	if len(vs) != 3 || vs[0] != want[0] || vs[1] != want[1] || vs[2] != want[2] {
		t.Fatalf("got %v", vs)
	}
	if vs[2].String() != "claude-haiku-5-5@high" {
		t.Fatal(vs[2].String())
	}
	for _, bad := range []string{"", "m@bogus", "@high", "a,a", "a@low,a@low"} {
		if _, err := ParseVariants(bad, "medium"); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	if vs, _ := ParseVariants("m", ""); vs[0].Effort != "medium" {
		t.Fatal("default effort")
	}
}

func TestCandidateFromRule(t *testing.T) {
	r := model.Rule{ID: "x", Vulns: []string{"GHSA-aaaa", "CVE-2099-1", "CVE-2099-2"},
		Packages: []model.PackageSelector{{Name: "openssh-server", Type: "rpm"}, {Name: "nginx*", Type: "deb"}, {Name: "nginx-extras", Type: "deb"}}}
	c, err := CandidateFromRule(r)
	if err != nil {
		t.Fatal(err)
	}
	if c.Vuln != "CVE-2099-1" || strings.Join(c.Aliases, ",") != "GHSA-aaaa,CVE-2099-2" || c.Package != "nginx" ||
		c.Type != "deb" || c.Ecosystem != "Debian:12" || strings.Join(c.BinaryPackages, ",") != "nginx,nginx-extras" {
		t.Fatalf("%+v", c)
	}
	r.Packages = []model.PackageSelector{{Source: "openssh", Type: "deb"}}
	if c, _ = CandidateFromRule(r); c.Package != "openssh" || len(c.BinaryPackages) != 0 {
		t.Fatalf("source selector: %+v", c)
	}
	r.Vulns = []string{"GHSA-x"}
	if c, _ = CandidateFromRule(r); c.Vuln != "GHSA-x" {
		t.Fatalf("first id when no CVE: %+v", c)
	}
	if _, err := CandidateFromRule(model.Rule{Packages: r.Packages}); err == nil {
		t.Fatal("no vulns must fail")
	}
	if _, err := CandidateFromRule(model.Rule{Vulns: []string{"CVE-1"}, Packages: []model.PackageSelector{{Name: "x", Type: "rpm"}}}); err == nil {
		t.Fatal("rpm only must fail")
	}
}

// refRule is a reviewed reference rule: exploitable while PermitRootLogin is not "no".
func refRule(id, title, expr string) model.Rule {
	return model.Rule{ID: id, Vulns: []string{"CVE-2099-0100"}, Title: title,
		Packages: []model.PackageSelector{{Source: "openssh", Type: "deb"}}, Facts: []string{"sshd.config"},
		ExploitableIf: expr, Explanation: "x", Fix: model.Fix{Upgrade: "Upgrade."}, Status: model.RuleReviewed, Source: "user"}
}

func refCases() []rules.TestCase {
	f := func(pkg, typ string) rules.TestFinding {
		return rules.TestFinding{Vuln: "CVE-2099-0100", Package: pkg, Source: "openssh", Type: typ}
	}
	return []rules.TestCase{
		{Name: "root login on", Finding: f("openssh-server", "deb"), Facts: map[string]any{"sshd.config": map[string]any{"permitrootlogin": "yes"}}, Want: model.VerdictExploitable},
		{Name: "root login off", Finding: f("openssh-server", "deb"), Facts: map[string]any{"sshd.config": map[string]any{"permitrootlogin": "no"}}, Want: model.VerdictNotExploitable},
		{Name: "no facts", Finding: f("openssh-server", "deb"), Want: model.VerdictConditionsUnknown},
		{Name: "rpm case is skipped", Finding: f("openssh-server", "rpm"), Want: model.VerdictExploitable},
	}
}

func TestScoreDraft(t *testing.T) {
	ref := refRule("CVE-2099-0100-openssh", "ref", goodExpr)
	same := refRule("CVE-2099-0100-openssh", "draft", goodExpr)
	s := ScoreDraft(same, ref, refCases(), "openssh")
	if s.Compared != 3 || s.Matched != 3 || s.Skipped != 1 || s.Unsafe != 0 || s.MissedExploitable != 0 || s.Agreement != 1 {
		t.Fatalf("identical rule: %+v", s)
	}
	// A draft that only fires for "prohibit-password": the reference's exploitable case becomes
	// not exploitable, the dangerous direction.
	wrong := refRule("CVE-2099-0100-openssh", "draft", `facts["sshd.config"][?"permitrootlogin"].orValue("yes") == "prohibit-password"`)
	s = ScoreDraft(wrong, ref, refCases(), "openssh")
	if s.Compared != 3 || s.Matched != 2 || s.Unsafe != 1 || s.MissedExploitable != 1 || s.Skipped != 1 {
		t.Fatalf("wrong rule: %+v", s)
	}
	if s.Agreement < 0.66 || s.Agreement > 0.67 {
		t.Fatalf("agreement %v", s.Agreement)
	}
	// Cases that already carry a different source never match the drafted source selector.
	cs := refCases()
	for i := range cs {
		cs[i].Finding.Source = "other"
	}
	if s = ScoreDraft(same, ref, cs, "openssh"); s.Compared != 0 || s.Skipped != 4 || s.Agreement != 0 {
		t.Fatalf("different source: %+v", s)
	}
	// conditions_unknown wanted, draft says not exploitable: unsafe too, but not a missed exploitable.
	never := refRule("CVE-2099-0100-openssh", "draft", "false")
	never.Facts = nil
	cs = []rules.TestCase{{Name: "unknown", Finding: rules.TestFinding{Vuln: "CVE-2099-0100", Package: "openssh-server", Source: "openssh", Type: "deb"}, Want: model.VerdictConditionsUnknown}}
	if s = ScoreDraft(never, ref, cs, "openssh"); s.Unsafe != 1 || s.MissedExploitable != 0 {
		t.Fatalf("unknown wanted: %+v", s)
	}
}

// evalProv answers per call from a script and records the system prompts it was given.
type evalProv struct {
	mu      sync.Mutex
	reply   string
	systems []string
	err     error
}

func (p *evalProv) Name() string { return "fake:m" }
func (p *evalProv) Complete(_ context.Context, system, _ string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.systems = append(p.systems, system)
	if p.err != nil {
		return "", p.err
	}
	return p.reply, nil
}

const wrongExpr = `facts["sshd.config"][?"permitrootlogin"].orValue("yes") == "prohibit-password"`

const wrongTests = `[
 {"name": "pw only", "finding": {"vuln": "CVE-2099-0100", "package": "openssh-server", "type": "deb"}, "facts": {"sshd.config": {"permitrootlogin": "prohibit-password"}}, "want": "exploitable"},
 {"name": "off", "finding": {"package": "openssh-server"}, "facts": {"sshd.config": {"permitrootlogin": "no"}}, "want": "affected_not_exploitable"},
 {"name": "no facts", "finding": {"package": "openssh-server"}, "want": "conditions_unknown"}]`

func evalFixture() ([]model.Rule, map[string][]rules.TestCase) {
	rs := []model.Rule{
		refRule("AAA-ref", "UNIQUE-REFERENCE-TITLE", goodExpr),
		refRule("BBB-other", "other rule one", goodExpr),
		refRule("CCC-other", "other rule two", goodExpr),
		refRule("DDD-other", "other rule three", goodExpr),
		refRule("EEE-draft", "not reviewed", goodExpr),
	}
	for i := 1; i < len(rs); i++ { // distinct vulns and packages: only the reference rule matches the reference cases
		rs[i].Vulns = []string{"CVE-2098-000" + string(rune('0'+i))}
		rs[i].Packages = []model.PackageSelector{{Source: "other" + string(rune('0'+i)), Type: "deb"}}
	}
	rs[4].Status = model.RuleDraft
	tests := map[string][]rules.TestCase{}
	for _, id := range []string{"AAA-ref", "BBB-other", "CCC-other", "DDD-other", "EEE-draft"} {
		tests[id] = refCases()
	}
	return rs, tests
}

func TestDefaultEvalIDs(t *testing.T) {
	rs, tests := evalFixture()
	delete(tests, "CCC-other")
	got := strings.Join(DefaultEvalIDs(rs, tests), ",")
	if got != "AAA-ref,BBB-other,DDD-other" {
		t.Fatal(got)
	}
}

func TestRunEvalScoresAndExcludesReference(t *testing.T) {
	rs, tests := evalFixture()
	good := &evalProv{reply: reply(goodExpr, goodTests)}
	bad := &evalProv{reply: reply(wrongExpr, wrongTests)}
	provs := map[string]*evalProv{"good@medium": good, "bad@high": bad}
	rep, err := RunEval(context.Background(), EvalOptions{
		Rules: rs, Tests: tests, IDs: []string{"AAA-ref"},
		Variants: []Variant{{"good", "medium"}, {"bad", "high"}}, Runs: 2, MaxAttempts: 2, Concurrency: 3,
		NewProvider: func(v Variant) (llm.Provider, error) { return provs[v.String()], nil },
		Advisory:    fakeAdv{},
		Catalog:     []llm.FactSpec{{Name: "sshd.config", Type: "map<string,string>", Description: "sshd -T"}},
	})
	// Fakes report no usage, which must not matter: they answered.
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 4 {
		t.Fatalf("results: %d", len(rep.Results))
	}
	for _, r := range rep.Results {
		if !r.Success || r.Attempts != 1 || r.Score == nil {
			t.Fatalf("%+v", r)
		}
		switch r.Variant {
		case "good@medium":
			if r.Score.Agreement != 1 || r.Score.Unsafe != 0 {
				t.Errorf("good: %+v", r.Score)
			}
		case "bad@high":
			if r.Score.Unsafe != 1 || r.Score.MissedExploitable != 1 {
				t.Errorf("bad: %+v", r.Score)
			}
		}
	}
	// No leakage: the reference rule is not among the examples, the other reviewed ones are.
	for _, p := range []*evalProv{good, bad} {
		for _, sys := range p.systems {
			if strings.Contains(sys, "UNIQUE-REFERENCE-TITLE") {
				t.Fatal("the reference rule leaked into the prompt")
			}
			if !strings.Contains(sys, "other rule one") {
				t.Fatal("other reviewed rules must still be examples")
			}
		}
	}

	md := rep.Markdown()
	for _, s := range []string{"## good@medium", "## bad@high", "## Variants compared", "| AAA-ref | 2/2 | 100% | 0 |", "| AAA-ref | 2/2 | 67% | 2 |", "| good@medium | 2 | 100% | 100% | 100% | 0 |", "| bad@high | 2 | 100% | 67% | 67% | 2 | 2 |"} {
		if !strings.Contains(md, s) {
			t.Errorf("markdown lacks %q:\n%s", s, md)
		}
	}
	b, err := json.Marshal(rep)
	if err != nil || !strings.Contains(string(b), `"rule_id":"AAA-ref"`) || !strings.Contains(string(b), `"agreement"`) {
		t.Fatalf("json: %v %s", err, b)
	}
}

func TestRunEvalFailuresAreResults(t *testing.T) {
	rs, tests := evalFixture()
	invalid := &evalProv{reply: `{"rule": {}, "tests": []}`}
	rep, err := RunEval(context.Background(), EvalOptions{
		Rules: rs, Tests: tests, IDs: []string{"AAA-ref"}, Variants: []Variant{{"v", "low"}}, Runs: 1, MaxAttempts: 2,
		NewProvider: func(Variant) (llm.Provider, error) { return invalid, nil }, Advisory: fakeAdv{},
	})
	if err != nil {
		t.Fatalf("a failed draft is a result, not an error: %v", err)
	}
	r := rep.Results[0]
	if r.Success || r.Attempts != 2 || r.Error == "" || r.Score != nil {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(rep.Markdown(), "| AAA-ref | 0/1 | n/a | 0 | 2.0 |") {
		t.Fatalf("markdown:\n%s", rep.Markdown())
	}

	refused := &evalProv{err: llm.ErrRefused}
	rep, err = RunEval(context.Background(), EvalOptions{
		Rules: rs, Tests: tests, IDs: []string{"AAA-ref"}, Variants: []Variant{{"v", "low"}}, Runs: 1,
		NewProvider: func(Variant) (llm.Provider, error) { return refused, nil }, Advisory: fakeAdv{},
	})
	if err != nil || !rep.Results[0].Refused {
		t.Fatalf("refusal: %v %+v", err, rep.Results)
	}

	down := &evalProv{err: errors.New("connection refused")}
	rep, err = RunEval(context.Background(), EvalOptions{
		Rules: rs, Tests: tests, IDs: []string{"AAA-ref"}, Variants: []Variant{{"v", "low"}}, Runs: 1,
		NewProvider: func(Variant) (llm.Provider, error) { return down, nil }, Advisory: fakeAdv{},
	})
	if !errors.Is(err, ErrNoCalls) || rep == nil || len(rep.Results) != 1 {
		t.Fatalf("no call possible: %v %v", err, rep)
	}
}

func TestRunEvalInputErrors(t *testing.T) {
	rs, tests := evalFixture()
	np := func(Variant) (llm.Provider, error) { return &evalProv{}, nil }
	if _, err := RunEval(context.Background(), EvalOptions{Rules: rs, Tests: tests, IDs: []string{"nope"}, Variants: []Variant{{"v", "low"}}, NewProvider: np}); err == nil {
		t.Fatal("unknown id")
	}
	if _, err := RunEval(context.Background(), EvalOptions{Rules: rs, Tests: tests, NewProvider: np}); err == nil {
		t.Fatal("no variants")
	}
	if _, err := RunEval(context.Background(), EvalOptions{Rules: rs, Tests: map[string][]rules.TestCase{}, Variants: []Variant{{"v", "low"}}, NewProvider: np}); err == nil {
		t.Fatal("no reference rules with tests")
	}
}

func TestReportCosts(t *testing.T) {
	u := llm.Usage{Model: "claude-haiku-5-5", InputTokens: 1_000_000, OutputTokens: 1_000_000}
	usd, ok := llm.EstimateUSD(u)
	rep := &Report{RuleIDs: []string{"r"}, Variants: []Variant{{"claude-haiku-5-5", "low"}, {"unpriced", "low"}}, Runs: 1, MaxAttempts: 2,
		Results: []RunResult{
			{RuleID: "r", Variant: "claude-haiku-5-5@low", Run: 1, Success: true, Attempts: 1, Calls: 1, Usage: u, EstUSD: usd, EstKnown: ok, Score: &Score{Compared: 2, Matched: 1, Agreement: 0.5}},
			{RuleID: "r", Variant: "unpriced@low", Run: 1, Success: true, Attempts: 1, Calls: 1, Usage: llm.Usage{Model: "unpriced", InputTokens: 10}, Score: &Score{Compared: 1, Matched: 1, Agreement: 1}},
		}}
	md := rep.Markdown()
	if !strings.Contains(md, "$0.6000") || !strings.Contains(md, "n/a") {
		t.Fatalf("costs:\n%s", md)
	}
}

func TestScoreDraftFillsSourceForNameSelectedReference(t *testing.T) {
	ref := refRule("CVE-2099-0100-openssh", "ref", goodExpr)
	ref.Packages = []model.PackageSelector{{Name: "openssh-server", Type: "deb"}}
	drafted := refRule("CVE-2099-0100-openssh", "draft", goodExpr)
	cs := refCases()
	for i := range cs {
		cs[i].Finding.Source = ""
	}
	if s := ScoreDraft(drafted, ref, cs, "openssh"); s.Compared != 3 || s.Matched != 3 || s.Skipped != 1 {
		t.Fatalf("%+v", s)
	}
}
