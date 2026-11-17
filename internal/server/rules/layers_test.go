package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DonSosiska/panoptes/internal/model"
	shipped "github.com/DonSosiska/panoptes/rules"
)

const shippedTests = "../../../rules-tests"

func loadShippedTests(t *testing.T) []RuleTests {
	t.Helper()
	ents, err := os.ReadDir(shippedTests)
	if err != nil {
		t.Fatal(err)
	}
	var out []RuleTests
	for _, e := range ents {
		if filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(shippedTests, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		cases, err := ParseTests(data)
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		out = append(out, RuleTests{RuleID: strings.TrimSuffix(e.Name(), ".yaml"), Cases: cases})
	}
	return out
}

// Every shipped rule has a test file in rules-tests/ and all cases pass with the real engine.
func TestShippedRuleTests(t *testing.T) {
	rs := loadShipped(t)
	tests := loadShippedTests(t)
	have := map[string]bool{}
	for _, rt := range tests {
		have[rt.RuleID] = true
	}
	for _, r := range rs {
		if !have[r.ID] {
			t.Errorf("rule %s has no tests/%s.yaml in rules-tests/", r.ID, r.ID)
		}
	}
	for _, f := range RunTests(rs, tests) {
		t.Error(f)
	}
}

func TestRunTestsReportsFailures(t *testing.T) {
	rs := loadShipped(t)
	bad := []RuleTests{
		{RuleID: "CVE-2024-6387", Cases: []TestCase{
			{Name: "wrong verdict", Want: model.VerdictNotExploitable,
				Finding: TestFinding{Vuln: "CVE-2024-6387", Package: "openssh-server", Type: "deb"},
				Facts:   map[string]any{"os.libc": "glibc", "sshd.config": map[string]any{}}},
			{Name: "other rule matches", Want: model.VerdictExploitable,
				Finding: TestFinding{Vuln: "CVE-2023-44487", Package: "nginx", Type: "deb"}},
		}},
		{RuleID: "no-such-rule", Cases: []TestCase{{Name: "x", Want: model.VerdictExploitable}}},
	}
	fails := RunTests(rs, bad)
	if len(fails) != 3 {
		t.Fatalf("want 3 failures, got %v", fails)
	}
}

func TestParseTestsStrict(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown key": "- {name: a, want: exploitable, finding: {vuln: V, package: p}, bogus: 1}\n",
		"bad verdict": "- {name: a, want: maybe, finding: {vuln: V, package: p}}\n",
		"no name":     "- {want: exploitable, finding: {vuln: V, package: p}}\n",
		"no finding":  "- {name: a, want: exploitable}\n",
		"empty":       "",
	} {
		if _, err := ParseTests([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The embedded rules are exactly the files in rules/.
func TestEmbeddedRulesMatchDir(t *testing.T) {
	emb, err := LoadFS(shipped.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	dir := loadShipped(t)
	if len(emb) != len(dir) {
		t.Fatalf("embedded %d, dir %d", len(emb), len(dir))
	}
	for i := range emb {
		if emb[i].ID != dir[i].ID {
			t.Errorf("embedded %s vs dir %s", emb[i].ID, dir[i].ID)
		}
	}
}

func layerRule(id, expr string, st model.RuleStatus) model.Rule {
	r := validRule()
	r.ID, r.Status, r.ExploitableIf = id, st, expr
	r.Facts = []string{"os.id"}
	return r
}

func TestLayerPrecedenceAndSources(t *testing.T) {
	builtin := layerRule("R-1", `facts["os.id"] == "builtin"`, model.RuleReviewed)
	feedRule := layerRule("R-1", `facts["os.id"] == "feed"`, model.RuleReviewed)
	feedOnly := layerRule("R-2", `true`, model.RuleReviewed)
	feedOnly.Vulns = []string{"CVE-2000-0002"}
	db := &fakeDB{}
	e := New([]model.Rule{builtin}, db)
	vuln := validRule().Vulns[0]

	if got := e.Sources()["R-1"]; got != "builtin" {
		t.Fatalf("source = %q", got)
	}
	want(t, eval(t, e, vuln, "pkg", "deb", map[string]any{"os.id": "builtin"}), model.VerdictExploitable)

	// feed replaces the built-in rule with the same ID
	e.SetFeed(5, []model.Rule{feedRule, feedOnly})
	if err := e.Reload(t.Context()); err != nil {
		t.Fatal(err)
	}
	want(t, eval(t, e, vuln, "pkg", "deb", map[string]any{"os.id": "builtin"}), model.VerdictNotExploitable)
	want(t, eval(t, e, vuln, "pkg", "deb", map[string]any{"os.id": "feed"}), model.VerdictExploitable)
	if got := e.Sources(); got["R-1"] != "feed:5" || got["R-2"] != "feed:5" {
		t.Fatalf("sources = %v", got)
	}

	// a DB draft never overrides a reviewed feed rule
	draft := layerRule("R-1", `facts["os.id"] == "draft"`, model.RuleDraft)
	db.rules = []model.Rule{draft}
	_ = e.Reload(t.Context())
	want(t, eval(t, e, vuln, "pkg", "deb", map[string]any{"os.id": "feed"}), model.VerdictExploitable)
	if p := e.Problems(); len(p) != 1 || !strings.Contains(p[0].Err.Error(), "cannot override") {
		t.Fatalf("problems: %v", p)
	}
	if e.Sources()["R-1"] != "feed:5" {
		t.Fatalf("sources = %v", e.Sources())
	}

	// a DB user rule (reviewed) overrides the feed rule
	user := layerRule("R-1", `facts["os.id"] == "user"`, model.RuleReviewed)
	user.Source = "user"
	db.rules = []model.Rule{user}
	_ = e.Reload(t.Context())
	want(t, eval(t, e, vuln, "pkg", "deb", map[string]any{"os.id": "user"}), model.VerdictExploitable)
	want(t, eval(t, e, vuln, "pkg", "deb", map[string]any{"os.id": "feed"}), model.VerdictNotExploitable)
	if got := e.Sources(); got["R-1"] != "db" || got["R-2"] != "feed:5" {
		t.Fatalf("sources = %v", got)
	}

	// a feed rule with a different ID beats the built-in rule for the same CVE/package
	db.rules = nil
	other := layerRule("A-feed", `true`, model.RuleReviewed)
	e.SetFeed(6, []model.Rule{other})
	_ = e.Reload(t.Context())
	ev := eval(t, e, vuln, "pkg", "deb", map[string]any{"os.id": "builtin"})
	want(t, ev, model.VerdictExploitable)
	if ev.Rule.ID != "A-feed" {
		t.Fatalf("rule = %s", ev.Rule.ID)
	}

	// removing the feed layer restores the built-in rules
	e.SetFeed(0, nil)
	_ = e.Reload(t.Context())
	want(t, eval(t, e, vuln, "pkg", "deb", map[string]any{"os.id": "builtin"}), model.VerdictExploitable)
	if got := e.Sources()["R-1"]; got != "builtin" {
		t.Fatalf("source = %q", got)
	}
}
