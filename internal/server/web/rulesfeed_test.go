package web

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DonSosiska/panoptes/internal/model"
)

// Sources makes fakeRules a RuleSourcer, like the real engine.
func (f *fakeRules) Sources() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sources
}

func TestRuleSourceBadges(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	mk := func(id, status string) model.Rule {
		return model.Rule{ID: id, Vulns: []string{"CVE-2030-1"}, Title: "t " + id, Packages: []model.PackageSelector{{Name: "foo"}},
			Facts: []string{"os.id"}, ExploitableIf: "true", Explanation: "x", Status: model.RuleStatus(status), Source: "builtin"}
	}
	e.rules.mu.Lock()
	e.rules.rules = []model.Rule{mk("R-BUILTIN", "reviewed"), mk("R-FEED", "reviewed"), mk("R-LOCAL", "reviewed")}
	e.rules.sources = map[string]string{"R-BUILTIN": "builtin", "R-FEED": "feed:12", "R-LOCAL": "db"}
	e.rules.mu.Unlock()

	list := e.do("GET", "/rules", nil, c).Body.String()
	for _, want := range []string{">built-in<", ">feed #12<", ">local<"} {
		if !strings.Contains(list, want) {
			t.Errorf("rules list misses badge %q", want)
		}
	}
	page := e.do("GET", "/rules/R-FEED", nil, c).Body.String()
	if !strings.Contains(page, "feed #12") || !strings.Contains(page, "read-only") || !strings.Contains(page, "local override") {
		t.Errorf("feed rule page: source/read-only note missing")
	}
	if p := e.do("GET", "/rules/R-LOCAL", nil, c).Body.String(); strings.Contains(p, "read-only") || !strings.Contains(p, ">local<") {
		t.Error("local rule page wrong")
	}
	if p := e.do("GET", "/rules/R-BUILTIN", nil, c).Body.String(); !strings.Contains(p, ">built-in<") {
		t.Error("built-in badge missing on the rule page")
	}
}

func TestDashboardRulesFeedBlock(t *testing.T) {
	e := newEnv(t, true)
	c := e.session("admin")
	if b := e.do("GET", "/", nil, c).Body.String(); strings.Contains(b, "Rules feed") {
		t.Fatal("rules feed block shown while disabled")
	}
	e.srv.cfg.Rules.Feed.Enabled = true
	ctx := context.Background()
	now := time.Now()
	for k, v := range map[string]string{
		"rulesfeed.seq": "42", "rulesfeed.updated_at": "2026-01-01T00:00:00Z",
		"rulesfeed.checked_at": "2026-01-02T00:00:00Z", "rulesfeed.last_error": "bundle 43: signature key is not trusted",
		"health.rules_feed_stale": "rules feed last checked 8d ago",
	} {
		if err := e.st.KVSet(ctx, k, v, now); err != nil {
			t.Fatal(err)
		}
	}
	b := e.do("GET", "/", nil, c).Body.String()
	for _, want := range []string{"Rules feed", "#42", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", "not trusted", "Rules feed stale:", "last checked 8d ago"} {
		if !strings.Contains(b, want) {
			t.Errorf("dashboard misses %q", want)
		}
	}
}
