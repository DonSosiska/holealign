package rulesbot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/llm"
	"github.com/DonSosiska/panoptes/internal/server/rules"
	"github.com/DonSosiska/panoptes/internal/server/rulesfeed"
)

const (
	repoRules = "../../../rules"
	repoTests = "../../../rules-tests"
)

type fakeProv struct {
	replies []string
	prompts []string
	err     error
}

func (p *fakeProv) Name() string { return "fake:test-model" }
func (p *fakeProv) Complete(_ context.Context, _, user string) (string, error) {
	p.prompts = append(p.prompts, user)
	if p.err != nil {
		return "", p.err
	}
	i := len(p.prompts) - 1
	if i >= len(p.replies) {
		i = len(p.replies) - 1
	}
	return p.replies[i], nil
}

type fakeAdv struct{}

func (fakeAdv) Get(context.Context, string, []string) (string, error) {
	return "Summary: root login issue\nReferences:\n- https://example.org/advisory/1\n", nil
}

func cand() Candidate {
	return Candidate{Vuln: "CVE-2099-0100", Aliases: []string{"DEBIAN-CVE-2099-0100"}, Package: "openssh", BinaryPackages: []string{"openssh-server"},
		Type: "deb", Ecosystem: "Debian:12", Severity: "High", CVSS: 8.1, EPSS: 0.2, KEV: true, Published: "2099-01-01T00:00:00Z"}
}

const goodExpr = `facts["sshd.config"][?"permitrootlogin"].orValue("yes") != "no"`

func reply(expr, tests string) string {
	return `{"rule": {"id": "x", "vulns": ["bogus"], "title": "OpenSSH root login issue", "packages": [{"name": "*"}],
	  "facts": ["sshd.config"], "exploitable_if": ` + jsonStr(expr) + `, "explanation": "Needs root login enabled.",
	  "fix": {"upgrade": "Upgrade openssh."}, "status": "reviewed", "source": "x",
	  "references": ["https://example.org/advisory/1", "https://evil.example/made-up"]},
	 "tests": ` + tests + `}`
}

func jsonStr(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

const goodTests = `[
 {"name": "root login on", "finding": {"vuln": "CVE-2099-0100", "package": "openssh-server", "type": "deb"}, "facts": {"sshd.config": {"permitrootlogin": "yes"}}, "want": "exploitable"},
 {"name": "root login off", "finding": {"package": "openssh-server"}, "facts": {"sshd.config": {"permitrootlogin": "no"}}, "want": "affected_not_exploitable"},
 {"name": "no sshd facts", "finding": {"package": "openssh-server"}, "want": "conditions_unknown"}]`

func existing(t *testing.T) ([]model.Rule, map[string][]rules.TestCase) {
	t.Helper()
	rs, ts, err := LoadExisting(repoRules, repoTests)
	if err != nil || len(rs) == 0 || len(ts) == 0 {
		t.Fatalf("load: %v %d %d", err, len(rs), len(ts))
	}
	return rs, ts
}

func opts(t *testing.T, p llm.Provider) DraftOptions {
	rs, ts := existing(t)
	return DraftOptions{Candidate: cand(), Provider: p, Rules: rs, Tests: ts, Advisory: fakeAdv{},
		Catalog: []llm.FactSpec{{Name: "sshd.config", Type: "map<string,string>", Description: "sshd -T"}}}
}

func TestDraftHappyPath(t *testing.T) {
	p := &fakeProv{replies: []string{reply(goodExpr, goodTests)}}
	res, err := Draft(context.Background(), opts(t, p))
	if err != nil {
		t.Fatal(err)
	}
	r := res.Rule
	if r.ID != "CVE-2099-0100-openssh" || r.Status != model.RuleDraft || r.Source != "llm:test-model" ||
		strings.Join(r.Vulns, ",") != "CVE-2099-0100,DEBIAN-CVE-2099-0100" ||
		len(r.Packages) != 1 || r.Packages[0] != (model.PackageSelector{Name: "openssh-server", Type: "deb"}) {
		t.Fatalf("forced fields: %+v", r)
	}
	if len(r.References) != 1 || r.References[0] != "https://example.org/advisory/1" {
		t.Fatalf("references must come from the advisory: %v", r.References)
	}
	if len(p.prompts) != 1 || !strings.Contains(p.prompts[0], "<untrusted_advisory>") {
		t.Fatal("prompt shape")
	}
	dir := t.TempDir()
	rp, tp, err := WriteFiles(res, filepath.Join(dir, "rules"), filepath.Join(dir, "tests"))
	if err != nil {
		t.Fatal(err)
	}
	y, _ := os.ReadFile(rp)
	for _, s := range []string{"# vuln: CVE-2099-0100", "KEV: true", "https://osv.dev/vulnerability/CVE-2099-0100", "status: draft"} {
		if !strings.Contains(string(y), s) {
			t.Errorf("rule file lacks %q:\n%s", s, y)
		}
	}
	for _, s := range []string{"## Rule for CVE-2099-0100", "| CISA KEV | yes |", "### Test cases", "root login on", "set `status: reviewed` after checking",
		"The conditions match the advisory", "No `file.match` request reads a sensitive path", "https://example.org/advisory/1"} {
		if !strings.Contains(res.PRBody, s) {
			t.Errorf("PR body lacks %q:\n%s", s, res.PRBody)
		}
	}
	if _, _, err := WriteFiles(res, filepath.Join(dir, "rules"), filepath.Join(dir, "tests")); !errors.Is(err, ErrIDExists) {
		t.Fatalf("second write: %v", err)
	}

	// Placed in a repo with the existing rules (after a human sets status: reviewed), the bundle builds.
	repo := t.TempDir()
	copyDir(t, repoRules, filepath.Join(repo, "rules"))
	copyDir(t, repoTests, filepath.Join(repo, "tests"))
	rb, _ := os.ReadFile(rp)
	tb, _ := os.ReadFile(tp)
	rb = []byte(strings.Replace(string(rb), "status: draft", "status: reviewed", 1))
	_ = os.WriteFile(filepath.Join(repo, "rules", r.ID+".yaml"), rb, 0o644)
	_ = os.WriteFile(filepath.Join(repo, "tests", r.ID+".yaml"), tb, 0o644)
	if _, _, err := rulesfeed.Build(rulesfeed.BuildOptions{RulesDir: filepath.Join(repo, "rules"), TestsDir: filepath.Join(repo, "tests"),
		Seq: 1, CreatedAt: time.Unix(0, 0)}); err != nil {
		t.Fatalf("Build: %v", err)
	}
}

func copyDir(t *testing.T, from, to string) {
	t.Helper()
	if err := os.MkdirAll(to, 0o755); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(from)
	for _, e := range ents {
		if e.Name() == "embed.go" {
			continue
		}
		b, _ := os.ReadFile(filepath.Join(from, e.Name()))
		if err := os.WriteFile(filepath.Join(to, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDraftRetriesWithErrors(t *testing.T) {
	bad := reply(`facts["no.such.fact"] == "x"`, goodTests)
	p := &fakeProv{replies: []string{bad, reply(goodExpr, goodTests)}}
	res, err := Draft(context.Background(), opts(t, p))
	if err != nil || res == nil {
		t.Fatal(err)
	}
	if len(p.prompts) != 2 || !strings.Contains(p.prompts[1], "rejected by the validator") || !strings.Contains(p.prompts[1], "no.such.fact") {
		t.Fatalf("retry prompt: %d prompts", len(p.prompts))
	}
	// the retry message is capped
	if len(p.prompts[1]) > len(p.prompts[0])+maxProblemBytes+400 {
		t.Fatal("retry error not capped")
	}
}

func TestDraftFailingTestsAndCoverage(t *testing.T) {
	wrongWant := strings.Replace(goodTests, `"want": "exploitable"`, `"want": "affected_not_exploitable"`, 1)
	for name, tests := range map[string]string{
		"failing test":    wrongWant,
		"no exploitable":  `[{"name":"a","finding":{"package":"openssh-server"},"facts":{"sshd.config":{"permitrootlogin":"no"}},"want":"affected_not_exploitable"}]`,
		"unknown fact":    `[{"name":"a","finding":{"package":"openssh-server"},"facts":{"made.up":1},"want":"exploitable"}]`,
		"foreign package": `[{"name":"a","finding":{"package":"bash"},"want":"exploitable"}]`,
	} {
		p := &fakeProv{replies: []string{reply(goodExpr, tests)}}
		_, err := Draft(context.Background(), opts(t, p))
		var de *DraftError
		if !errors.As(err, &de) || len(p.prompts) != 2 {
			t.Errorf("%s: err=%v prompts=%d", name, err, len(p.prompts))
		}
	}
}

func TestDraftConstFalseNeedsNoExploitableCase(t *testing.T) {
	tests := `[{"name":"never","finding":{"package":"openssh-server"},"want":"affected_not_exploitable"}]`
	r := strings.Replace(reply("false", tests), `"facts": ["sshd.config"]`, `"facts": []`, 1)
	if _, err := Draft(context.Background(), opts(t, &fakeProv{replies: []string{r}})); err != nil {
		t.Fatal(err)
	}
}

func TestDraftIDCollisionAndRefusal(t *testing.T) {
	p := &fakeProv{replies: []string{reply(goodExpr, goodTests)}}
	o := opts(t, p)
	o.Rules = append(o.Rules, model.Rule{ID: "CVE-2099-0100-openssh"})
	if _, err := Draft(context.Background(), o); !errors.Is(err, ErrIDExists) || len(p.prompts) != 0 {
		t.Fatalf("collision: %v, calls %d", err, len(p.prompts))
	}
	p = &fakeProv{err: llm.ErrRefused}
	var de *DraftError
	if _, err := Draft(context.Background(), opts(t, p)); !errors.As(err, &de) {
		t.Fatalf("refusal: %v", err)
	}
	p = &fakeProv{err: errors.New("network down")}
	if _, err := Draft(context.Background(), opts(t, p)); err == nil || errors.As(err, &de) {
		t.Fatalf("provider error must not be a DraftError: %v", err)
	}
}
