package rulesbot

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/llm"
	"github.com/DonSosiska/panoptes/internal/server/rules"
	"github.com/DonSosiska/panoptes/internal/server/rulesfeed"
)

const (
	completeTimeout = 120 * time.Second
	maxProblemBytes = 2048
)

// ErrIDExists means a rule with the generated ID already exists.
var ErrIDExists = errors.New("a rule with this ID already exists")

// DraftError means the model could not produce a valid rule with passing tests (or refused). Nothing is written.
type DraftError struct{ Msg string }

func (e *DraftError) Error() string { return e.Msg }

// DraftOptions configure Draft.
type DraftOptions struct {
	Candidate   Candidate
	Provider    llm.Provider
	Rules       []model.Rule                // existing rules (few-shot examples, ID collision, test engine)
	Tests       map[string][]rules.TestCase // existing tests by rule ID (few-shot examples)
	Catalog     []llm.FactSpec
	Advisory    llm.AdvisorySource
	MaxAttempts int // default 2
	Logger      *slog.Logger
}

// DraftResult is a drafted rule, its tests, their YAML files and the pull request body.
type DraftResult struct {
	Rule      model.Rule
	Cases     []rules.TestCase
	RuleYAML  []byte
	TestsYAML []byte
	PRBody    string
}

// RuleID is the ID of the rule drafted for a candidate: "<VULN>-<source package>", sanitised.
func RuleID(c Candidate) string { return llm.RuleID(c.Vuln, c.Package) }

// Draft asks the model for a rule and tests for the candidate and checks them: rules.Validate,
// the rulesfeed coverage rules and rules.RunTests. A failure is retried with the error messages
// appended (up to MaxAttempts attempts in all).
func Draft(ctx context.Context, o DraftOptions) (*DraftResult, error) {
	log := o.Logger
	if log == nil {
		log = slog.Default()
	}
	if o.Provider == nil {
		return nil, errors.New("no LLM provider configured")
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 2
	}
	c := o.Candidate
	if c.Vuln == "" || c.Package == "" || c.Type == "" {
		return nil, errors.New("candidate needs vuln, package and type")
	}
	if len(c.BinaryPackages) == 0 {
		c.BinaryPackages = []string{c.Package}
	}
	id := RuleID(c)
	for _, r := range o.Rules {
		if r.ID == id {
			return nil, fmt.Errorf("%w: %s", ErrIDExists, id)
		}
	}
	in := llm.RepoInput{Vuln: c.Vuln, Aliases: c.Aliases, Package: c.Package, Binaries: c.BinaryPackages, Type: c.Type,
		Ecosystem: c.Ecosystem, Severity: c.Severity, CVSS: c.CVSS, EPSS: c.EPSS, KEV: c.KEV, RuleID: id}

	advisory := ""
	if o.Advisory != nil {
		a, err := o.Advisory.Get(ctx, c.Vuln, c.Aliases)
		if err != nil {
			log.Warn("advisory unavailable, drafting from the candidate data", "err", err)
		} else {
			advisory = a
		}
	}
	system, user := llm.BuildRepoPrompts(in, o.Catalog, pickExamples(o.Rules, o.Tests), advisory)

	var lastErr error
	for attempt := 1; attempt <= o.MaxAttempts; attempt++ {
		prompt := user
		if lastErr != nil {
			prompt = llm.BuildRepoRetry(user, capErr(lastErr))
		}
		cctx, cancel := context.WithTimeout(ctx, completeTimeout)
		reply, err := o.Provider.Complete(cctx, system, prompt)
		cancel()
		if err != nil {
			if errors.Is(err, llm.ErrRefused) {
				return nil, &DraftError{Msg: "the model refused to draft this rule"}
			}
			return nil, fmt.Errorf("LLM call failed: %w", err)
		}
		res, err := check(reply, in, o, advisory)
		if err == nil {
			return res, nil
		}
		log.Info("draft rejected", "attempt", attempt, "err", err)
		lastErr = err
	}
	return nil, &DraftError{Msg: fmt.Sprintf("no valid rule after %d attempt(s): %v", o.MaxAttempts, capErr(lastErr))}
}

func capErr(err error) error {
	s := err.Error()
	if len(s) > maxProblemBytes {
		s = strings.ToValidUTF8(s[:maxProblemBytes], "")
	}
	return errors.New(s)
}

func check(reply string, in llm.RepoInput, o DraftOptions, advisory string) (*DraftResult, error) {
	rule, cases, err := llm.ParseRepoReply(reply, in, o.Provider.Name())
	if err != nil {
		return nil, err
	}
	// References must come from the advisory text.
	var refs []string
	for _, u := range rule.References {
		if strings.Contains(advisory, u) {
			refs = append(refs, u)
		}
	}
	rule.References = refs
	if err := rules.Validate(rule); err != nil {
		return nil, err
	}
	if err := verify(rule, cases, o.Rules); err != nil {
		return nil, err
	}
	res := &DraftResult{Rule: rule, Cases: cases}
	if res.RuleYAML, err = marshalRule(rule, o.Candidate, advisory); err != nil {
		return nil, err
	}
	if res.TestsYAML, err = marshalTests(cases); err != nil {
		return nil, err
	}
	// What gets written must be what was tested: parse the YAML back and run everything again.
	pr, err := rules.ParseRule(res.RuleYAML)
	if err != nil {
		return nil, fmt.Errorf("internal: written rule does not parse: %w", err)
	}
	pc, err := rules.ParseTests(res.TestsYAML)
	if err != nil {
		return nil, fmt.Errorf("internal: written tests do not parse: %w", err)
	}
	if err := rules.Validate(pr); err != nil {
		return nil, err
	}
	if err := verify(pr, pc, o.Rules); err != nil {
		return nil, err
	}
	res.PRBody = prBody(o.Candidate, rule, cases, o.Provider.Name())
	return res, nil
}

// verify applies the repository's acceptance checks to one rule and its tests.
// The rule is evaluated as a copy with status reviewed: drafts never lower verdicts at runtime, so
// the tests must exercise the rule logic itself.
func verify(rule model.Rule, cases []rules.TestCase, existing []model.Rule) error {
	rule.Status = model.RuleReviewed
	rt := []rules.RuleTests{{RuleID: rule.ID, Cases: cases}}
	var problems []string
	problems = append(problems, rulesfeed.CoverageProblems([]model.Rule{rule}, rt)...)
	all := append(append([]model.Rule{}, existing...), rule)
	for _, f := range rules.RunTests(all, rt) {
		if f.RuleID == rule.ID {
			problems = append(problems, "test failed: "+f.String())
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n"))
	}
	return nil
}

// pickExamples chooses up to three existing rules that have tests, in ID order.
func pickExamples(rs []model.Rule, tests map[string][]rules.TestCase) []llm.RepoExample {
	sorted := append([]model.Rule{}, rs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	var out []llm.RepoExample
	for _, r := range sorted {
		if r.Status == model.RuleReviewed && len(tests[r.ID]) > 0 && len(out) < 3 {
			out = append(out, llm.RepoExample{Rule: r, Tests: tests[r.ID]})
		}
	}
	return out
}

// LoadExisting reads the rules directory and, for each rule, its test file from the tests directory.
func LoadExisting(rulesDir, testsDir string) ([]model.Rule, map[string][]rules.TestCase, error) {
	var rs []model.Rule
	if rulesDir != "" {
		var err error
		rs, err = rules.LoadDir(rulesDir)
		if err != nil {
			return nil, nil, err
		}
	}
	tests := map[string][]rules.TestCase{}
	if testsDir != "" {
		for _, r := range rs {
			data, err := os.ReadFile(filepath.Join(testsDir, r.ID+".yaml"))
			if err != nil {
				continue
			}
			if cs, err := rules.ParseTests(data); err == nil {
				tests[r.ID] = cs
			}
		}
	}
	return rs, tests, nil
}

// WriteFiles writes <outRules>/<id>.yaml and <outTests>/<id>.yaml, refusing to overwrite; when
// the second file cannot be written the first is removed again.
func WriteFiles(res *DraftResult, outRules, outTests string) (rulePath, testsPath string, err error) {
	id := res.Rule.ID
	rulePath = filepath.Join(outRules, id+".yaml")
	testsPath = filepath.Join(outTests, id+".yaml")
	for _, d := range []string{outRules, outTests} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return "", "", err
		}
	}
	if err := writeNew(rulePath, res.RuleYAML); err != nil {
		return "", "", err
	}
	if err := writeNew(testsPath, res.TestsYAML); err != nil {
		os.Remove(rulePath)
		return "", "", err
	}
	return rulePath, testsPath, nil
}

func writeNew(p string, data []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %s", ErrIDExists, p)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(p)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(p)
		return err
	}
	return nil
}

func osvURL(vuln string) string { return "https://osv.dev/vulnerability/" + vuln }

func marshalRule(r model.Rule, c Candidate, advisory string) ([]byte, error) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# %s: %s\n", r.ID, "drafted by panoptes-server rules draft; set status: reviewed after checking")
	fmt.Fprintf(&b, "# vuln: %s   package: %s (%s, %s)\n", c.Vuln, c.Package, c.Type, c.Ecosystem)
	fmt.Fprintf(&b, "# severity: %s (CVSS %.1f)   EPSS: %.4f   KEV: %v\n", c.Severity, c.CVSS, c.EPSS, c.KEV)
	fmt.Fprintf(&b, "# advisory: %s\n", osvURL(c.Vuln))
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return b.Bytes(), enc.Close()
}

type outFinding struct {
	Vuln     string `yaml:"vuln"`
	Package  string `yaml:"package"`
	Type     string `yaml:"type"`
	Severity string `yaml:"severity,omitempty"`
	KEV      bool   `yaml:"kev,omitempty"`
}

type outHost struct {
	OSID      string `yaml:"os_id,omitempty"`
	OSVersion string `yaml:"os_version_id,omitempty"`
	Arch      string `yaml:"arch,omitempty"`
}

type outTest struct {
	Name    string         `yaml:"name"`
	Finding outFinding     `yaml:"finding,flow"`
	Facts   map[string]any `yaml:"facts,omitempty"`
	Host    *outHost       `yaml:"host,omitempty,flow"`
	Want    model.Verdict  `yaml:"want"`
}

func marshalTests(cs []rules.TestCase) ([]byte, error) {
	out := make([]outTest, 0, len(cs))
	for _, c := range cs {
		t := outTest{Name: c.Name, Facts: c.Facts, Want: c.Want,
			Finding: outFinding{Vuln: c.Finding.Vuln, Package: c.Finding.Package, Type: c.Finding.Type, Severity: c.Finding.Severity, KEV: c.Finding.KEV}}
		if h := (outHost{OSID: c.Host.OSID, OSVersion: c.Host.OSVersion, Arch: c.Host.Arch}); h != (outHost{}) {
			t.Host = &h
		}
		out = append(out, t)
	}
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(out); err != nil {
		return nil, err
	}
	return b.Bytes(), enc.Close()
}
