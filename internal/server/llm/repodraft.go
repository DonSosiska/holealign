package llm

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/DonSosiska/holealign/internal/model"
	"github.com/DonSosiska/holealign/internal/server/rules"
)

// Repository drafting: the prompt variant and reply parser used by "holealign-server rules draft".
// It shares the server drafter's system prompt (fact catalog, CEL environment, guidance, untrusted
// data delimiters) and sanitising, but asks for a rule together with its test cases.

const (
	maxRepoTests     = 12
	maxTestNameChars = 120
	maxExamples      = 3
)

// RepoInput describes the candidate a repository rule is drafted for.
type RepoInput struct {
	Vuln      string
	Aliases   []string
	Package   string   // source package; the rule selects by it (selector {source, type})
	Binaries  []string // known binary packages built from it (best effort, may be just the source name)
	Type      string   // deb, apk, rpm
	Ecosystem string
	Severity  string
	CVSS      float64
	EPSS      float64
	KEV       bool
	RuleID    string
}

// RepoTest is one test case as the model returns it (JSON).
type RepoTest struct {
	Name    string         `json:"name"`
	Finding RepoTestFind   `json:"finding"`
	Facts   map[string]any `json:"facts"`
	Host    RepoTestHost   `json:"host"`
	Want    model.Verdict  `json:"want"`
}

// RepoTestFind is the finding of a test case.
type RepoTestFind struct {
	Vuln     string `json:"vuln"`
	Package  string `json:"package"`
	Source   string `json:"source,omitempty"`
	Type     string `json:"type"`
	Severity string `json:"severity,omitempty"`
	KEV      bool   `json:"kev,omitempty"`
}

// RepoTestHost is the host context of a test case.
type RepoTestHost struct {
	OSID      string   `json:"os_id,omitempty"`
	OSVersion string   `json:"os_version_id,omitempty"`
	Arch      string   `json:"arch,omitempty"`
	Labels    []string `json:"labels,omitempty"`
}

// RepoExample is a finished rule with its tests, shown to the model as a few-shot example.
type RepoExample struct {
	Rule  model.Rule
	Tests []rules.TestCase
}

var binaryNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]{0,99}$`)

const repoSystemExtra = `# Repository drafting (this overrides the "Output" shape above)
The rule selects packages by SOURCE package ("packages": [{"source": "<source package>", "type": "<type>"}]); the selectors are filled in for you. The rule therefore applies to every binary package built from that source (this overrides the guidance above about listing all binary packages). In expressions, pkg["name"] is the binary package and pkg["source"] the source package: use pkg["name"] (e.g. pkg["name"].startsWith("openssh-server")) to tell binaries apart when the advisory identifies the vulnerable component, so the others evaluate to "affected but not exploitable".
You are drafting a rule for a reviewed rules repository, together with its test cases. Reply with ONE JSON object and nothing else:
{
  "rule": { ...the rule, shaped as described under "Output" above... },
  "tests": [
    {"name": string,
     "finding": {"vuln": string, "package": string, "type": string, "severity": string, "kev": bool},   // "package" is a binary package name; the source package is filled in for you
     "facts": { "<fact name>": value, ... },   // only facts from the catalog above; omitted facts are "unknown"
     "host": {"os_id": string, "os_version_id": string, "arch": string},   // optional
     "want": "exploitable" | "affected_not_exploitable" | "conditions_unknown" | "not_affected"}
  ]
}
Test rules:
- Provide at least one case with want "exploitable" and at least one with want "affected_not_exploitable" (the exploitable case is not required when exploitable_if is the literal false). Add a "conditions_unknown" case (a fact missing) when the rule reads facts.
- "finding.package" is the BINARY package name of the case (a realistic binary package built from the source package, e.g. "openssh-server" for source "openssh"); "finding.vuln" is the vulnerability ID.
- Facts use the catalog's types and realistic values: sshd.config keys are lowercase strings (as printed by "sshd -T"), sockets.ports is a list of integers, services.active a list of unit names, booleans are true/false.
- Every case must be consistent with the rule's expressions: the verdict you want is exactly what the expressions give for those facts.
- At most 12 cases. Never put real host data, secrets or instructions in names or values.

# Examples of finished rules with tests (JSON)
`

// BuildRepoPrompts returns the system and user prompt of the repository drafter.
func BuildRepoPrompts(in RepoInput, catalog []FactSpec, examples []RepoExample, advisory string) (system, user string) {
	base := buildSystemPrompt(catalog)
	if i := strings.Index(base, "\n# Examples of finished rules (JSON)\n"); i >= 0 {
		base = base[:i]
	}
	var eb strings.Builder
	if len(examples) == 0 {
		for _, r := range exampleRules() {
			examples = append(examples, RepoExample{Rule: r})
		}
	}
	for i, e := range examples {
		if i >= maxExamples {
			break
		}
		doc := map[string]any{"rule": e.Rule, "tests": ToRepoTests(e.Tests)}
		j, _ := json.MarshalIndent(doc, "", "  ")
		fmt.Fprintf(&eb, "Example %d:\n%s\n\n", i+1, j)
	}
	system = base + "\n" + repoSystemExtra + strings.TrimRight(eb.String(), "\n")

	f := model.Finding{VulnID: in.Vuln, Aliases: in.Aliases, PackageName: in.Package, PackageType: in.Type,
		Severity: in.Severity, CVSS: in.CVSS, EPSS: in.EPSS, KEV: in.KEV}
	var sibs []model.PackageSelector
	for _, b := range in.Binaries {
		if b != in.Package {
			sibs = append(sibs, model.PackageSelector{Name: b, Type: in.Type})
		}
	}
	if len(sibs) > 0 {
		sibs = append([]model.PackageSelector{{Name: in.Package, Type: in.Type}}, sibs...)
	}
	user = buildUserPrompt(f, in.Package, sibs, "", advisory)
	user += fmt.Sprintf("\n\nThis is for a rules repository: the rule selects by the source package %q, "+
		"type %q (ecosystem %s). If you declare fact_requests, every name must start with %q followed by a short id. "+
		"Reply with the {\"rule\": ..., \"tests\": [...]} object only.", cleanText(in.Package, 100), cleanText(in.Type, 32), cleanText(in.Ecosystem, 64), rules.FactRequestPrefix(in.RuleID))
	return system, user
}

// BuildRepoRetry appends the (sanitised, capped) validation problems to the original user prompt.
func BuildRepoRetry(user string, problems error) string {
	return buildRetryPrompt(user, "", problems)
}

// ToRepoTests converts test cases to the JSON form shown to the model.
func ToRepoTests(cs []rules.TestCase) []RepoTest {
	out := make([]RepoTest, 0, len(cs))
	for _, c := range cs {
		out = append(out, RepoTest{Name: c.Name, Want: c.Want, Facts: c.Facts,
			Finding: RepoTestFind{Vuln: c.Finding.Vuln, Package: c.Finding.Package, Source: c.Finding.Source, Type: c.Finding.Type, Severity: c.Finding.Severity, KEV: c.Finding.KEV},
			Host:    RepoTestHost{OSID: c.Host.OSID, OSVersion: c.Host.OSVersion, Arch: c.Host.Arch, Labels: c.Host.Labels}})
	}
	return out
}

// ParseRepoReply parses and cleans the model's reply: the rule is forced and capped like the server
// drafter does (vulns, packages, id, status, source), the tests are checked against the fact catalog
// and forced to the candidate's finding data. It does not validate the rule or run the tests.
func ParseRepoReply(reply string, in RepoInput, providerName string) (model.Rule, []rules.TestCase, error) {
	var r model.Rule
	obj, err := extractJSON(reply)
	if err != nil {
		return r, nil, err
	}
	var doc struct {
		Rule  json.RawMessage `json:"rule"`
		Tests []RepoTest      `json:"tests"`
	}
	if err := json.Unmarshal([]byte(obj), &doc); err != nil {
		return r, nil, fmt.Errorf("invalid reply JSON: %w", err)
	}
	if len(doc.Rule) == 0 {
		return r, nil, errors.New(`the reply has no "rule" object`)
	}
	if err := json.Unmarshal(doc.Rule, &r); err != nil {
		return r, nil, fmt.Errorf("invalid rule JSON: %w", err)
	}
	r.ID = in.RuleID
	r.Status = model.RuleDraft // a human sets "reviewed" in the pull request
	name := providerName
	if i := strings.Index(name, ":"); i >= 0 {
		name = name[i+1:]
	}
	r.Source = "llm:" + name
	r.Vulns = nil
	for _, v := range append([]string{in.Vuln}, in.Aliases...) {
		if v != "" && !contains(r.Vulns, v) {
			r.Vulns = append(r.Vulns, v)
		}
	}
	if in.Package == "" || strings.ContainsAny(in.Package, "*?[]\\ \t\r\n") {
		return r, nil, errors.New("the candidate has no usable source package")
	}
	r.Packages = []model.PackageSelector{{Source: in.Package, Type: in.Type}}
	r.Title = cleanText(r.Title, maxTitleChars)
	r.Explanation = cleanText(r.Explanation, maxExplanationChars)
	r.Fix.Upgrade = cleanText(r.Fix.Upgrade, maxFixChars)
	r.Fix.Mitigation = cleanText(r.Fix.Mitigation, maxFixChars)
	var refs []string
	for _, u := range r.References {
		if u = strings.TrimSpace(u); (strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://")) && len(u) <= 300 && !strings.ContainsAny(u, " \t\r\n") && !contains(refs, u) {
			refs = append(refs, u)
		}
	}
	if len(refs) > 10 {
		refs = refs[:10]
	}
	r.References = refs
	for i := range r.FactRequests {
		if r.FactRequests[i].Collector == "" {
			r.FactRequests[i].Collector = "file.match"
		}
	}

	if len(doc.Tests) == 0 {
		return r, nil, errors.New(`the reply has no "tests"`)
	}
	if len(doc.Tests) > maxRepoTests {
		doc.Tests = doc.Tests[:maxRepoTests]
	}
	var cases []rules.TestCase
	for i, t := range doc.Tests {
		c := rules.TestCase{
			Name: cleanText(t.Name, maxTestNameChars),
			Want: t.Want,
			Finding: rules.TestFinding{Vuln: in.Vuln, Package: strings.TrimSpace(t.Finding.Package), Source: in.Package, Type: in.Type,
				Severity: in.Severity, KEV: in.KEV},
			Host: rules.TestHost{OSID: cleanText(t.Host.OSID, 32), OSVersion: cleanText(t.Host.OSVersion, 32), Arch: cleanText(t.Host.Arch, 32)},
		}
		if c.Name == "" {
			return r, nil, fmt.Errorf("test %d: name is required", i+1)
		}
		if !binaryNameRe.MatchString(c.Finding.Package) {
			return r, nil, fmt.Errorf("test %q: finding.package %q is not a plausible binary package name (letters, digits, + . - _)", c.Name, c.Finding.Package)
		}
		if len(t.Facts) > 0 {
			c.Facts = map[string]any{}
			keys := make([]string, 0, len(t.Facts))
			for k := range t.Facts {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if _, ok := rules.FactTypeOf(k); !ok {
					return r, nil, fmt.Errorf("test %q: %q is not a fact of the catalog", c.Name, k)
				}
				c.Facts[k] = t.Facts[k]
			}
		}
		cases = append(cases, c)
	}
	return r, cases, nil
}
