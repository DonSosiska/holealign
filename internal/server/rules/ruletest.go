package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/core"
)

// TestCase is one case of a rule test file (tests/<rule-id>.yaml, a YAML list of cases).
type TestCase struct {
	Name    string         `yaml:"name"`
	Finding TestFinding    `yaml:"finding"`
	Facts   map[string]any `yaml:"facts"`
	Host    TestHost       `yaml:"host"`
	Want    model.Verdict  `yaml:"want"`
}

// TestFinding is the finding a case evaluates.
type TestFinding struct {
	Vuln     string `yaml:"vuln"`
	Package  string `yaml:"package"`
	Source   string `yaml:"source"` // source package; default: none (the finding has no upstream qualifier)
	Type     string `yaml:"type"`
	Version  string `yaml:"version"`
	Severity string `yaml:"severity"`
	KEV      bool   `yaml:"kev"`
	// TargetKind is "host" (default) or "container_image".
	TargetKind string `yaml:"target_kind"`
}

// TestHost is the host context of a case.
type TestHost struct {
	OSID      string   `yaml:"os_id"`
	OSVersion string   `yaml:"os_version_id"`
	Arch      string   `yaml:"arch"`
	Labels    []string `yaml:"labels"`
}

// RuleTests are the cases for one rule.
type RuleTests struct {
	RuleID string
	Cases  []TestCase
}

// TestFailure describes one failing case (or a problem with the test set itself).
type TestFailure struct {
	RuleID string
	Case   string
	Reason string
}

func (f TestFailure) String() string {
	if f.Case == "" {
		return fmt.Sprintf("%s: %s", f.RuleID, f.Reason)
	}
	return fmt.Sprintf("%s: case %q: %s", f.RuleID, f.Case, f.Reason)
}

var validWant = map[model.Verdict]bool{
	model.VerdictExploitable: true, model.VerdictNotExploitable: true,
	model.VerdictConditionsUnknown: true, model.VerdictNotAffected: true,
}

// ParseTests decodes one test file strictly (unknown keys are errors).
func ParseTests(data []byte) ([]TestCase, error) {
	var cases []TestCase
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cases); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("empty test file")
		}
		return nil, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, errors.New("only one YAML document is allowed")
	}
	if len(cases) == 0 {
		return nil, errors.New("no test cases")
	}
	for i, c := range cases {
		if strings.TrimSpace(c.Name) == "" {
			return nil, fmt.Errorf("case %d: name is required", i+1)
		}
		if !validWant[c.Want] {
			return nil, fmt.Errorf("case %q: want %q is not a verdict (exploitable, affected_not_exploitable, conditions_unknown, not_affected)", c.Name, c.Want)
		}
		if c.Finding.Vuln == "" || c.Finding.Package == "" {
			return nil, fmt.Errorf("case %q: finding.vuln and finding.package are required", c.Name)
		}
	}
	return cases, nil
}

// RunTests evaluates every case with a real Engine built from rules only (no DB, no feed) and
// returns the failures. A case passes when the rule under test (RuleID) is the one that matched
// and the verdict equals want. Tests for a rule that is not in rules fail.
func RunTests(rules []model.Rule, tests []RuleTests) []TestFailure {
	e := New(rules, nil)
	var fails []TestFailure
	byID := map[string]bool{}
	for _, r := range rules {
		byID[r.ID] = true
	}
	for _, p := range e.Problems() {
		fails = append(fails, TestFailure{RuleID: p.RuleID, Reason: "rule does not compile: " + p.Err.Error()})
	}
	for _, rt := range tests {
		if !byID[rt.RuleID] {
			fails = append(fails, TestFailure{RuleID: rt.RuleID, Reason: "tests refer to a rule that is not in the set"})
			continue
		}
		for _, c := range rt.Cases {
			if reason := runCase(e, rt.RuleID, c); reason != "" {
				fails = append(fails, TestFailure{RuleID: rt.RuleID, Case: c.Name, Reason: reason})
			}
		}
	}
	sort.SliceStable(fails, func(i, j int) bool { return fails[i].RuleID < fails[j].RuleID })
	return fails
}

func runCase(e *Engine, ruleID string, c TestCase) string {
	ev, err := EvalCase(e, c)
	if err != nil {
		return err.Error()
	}
	if ev.Rule == nil || ev.Rule.ID != ruleID {
		got := "no rule"
		if ev.Rule != nil {
			got = "rule " + ev.Rule.ID
		}
		return fmt.Sprintf("the finding is matched by %s, not by %s", got, ruleID)
	}
	if ev.Verdict != c.Want {
		return fmt.Sprintf("verdict %s (%s), want %s", ev.Verdict, ev.Reason, c.Want)
	}
	return ""
}

// EvalCase evaluates the finding of a test case on its host context exactly as RunTests does and
// returns the evaluation (ev.Rule is nil when no rule matched). An error means the case itself
// cannot be evaluated (facts that are not JSON-compatible).
func EvalCase(e *Engine, c TestCase) (core.Evaluation, error) {
	// Facts arrive from agents as JSON: round-trip so numbers are float64 like on the wire.
	b, err := json.Marshal(c.Facts)
	if err != nil {
		return core.Evaluation{}, errors.New("facts are not JSON-compatible: " + err.Error())
	}
	facts := model.Facts{}
	if err := json.Unmarshal(b, &facts); err != nil {
		return core.Evaluation{}, errors.New("facts: " + err.Error())
	}
	if facts == nil {
		facts = model.Facts{}
	}
	hc := core.HostContext{
		Host: model.Host{Hostname: "test-host", Labels: c.Host.Labels,
			OS: model.OSInfo{ID: c.Host.OSID, VersionID: c.Host.OSVersion, Arch: c.Host.Arch}},
		Facts: facts,
	}
	f := model.Finding{VulnID: c.Finding.Vuln, PackageName: c.Finding.Package, PackageType: c.Finding.Type,
		PackageVer: c.Finding.Version, Severity: c.Finding.Severity, KEV: c.Finding.KEV,
		Target: "host", TargetKind: model.TargetHost}
	if c.Finding.TargetKind != "" {
		f.TargetKind = model.TargetKind(c.Finding.TargetKind)
		if f.TargetKind == model.TargetContainerImage {
			f.Target = "image:latest"
		}
	}
	if c.Finding.Source != "" {
		q := url.Values{}
		q.Set("upstream", c.Finding.Source)
		f.PURL = "pkg:" + purlType(c.Finding.Type) + "/test/" + url.PathEscape(c.Finding.Package) + "?" + q.Encode()
	}
	return e.Evaluate(context.Background(), hc, f), nil
}

func purlType(t string) string {
	if t == "" {
		return "generic"
	}
	return t
}
