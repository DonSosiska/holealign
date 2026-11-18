package rulesbot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DonSosiska/holealign/internal/model"
	"github.com/DonSosiska/holealign/internal/server/rules"
)

// Everything the model or the feed wrote is shown as code (inline code span or fenced block) so
// that Markdown links, images, autolinks, @mentions, HTML and emphasis stay inert. The only links
// in the body are the advisory links built here from validated IDs.

// mdCell renders s as an inline code span that is safe inside a Markdown table cell.
func mdCell(s string, max int) string {
	s = strings.NewReplacer("\n", " ", "\r", " ", "`", "'", "|", "\\|").Replace(s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max]) + "..."
	}
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return "`` " + s + " ``"
}

// mdBlock renders s as a fenced code block whose fence is longer than any backtick run in s.
func mdBlock(s string, max int) string {
	if r := []rune(s); len(r) > max {
		s = string(r[:max]) + "..."
	}
	s = strings.ReplaceAll(s, "\r", "")
	run, longest := 0, 0
	for _, c := range s {
		if c == '`' {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	n := longest + 1
	if n < 3 {
		n = 3
	}
	f := strings.Repeat("`", n)
	return f + "\n" + strings.TrimRight(s, "\n") + "\n" + f + "\n\n"
}

// advisoryLinks builds the fixed links for a candidate from IDs that match the strict patterns.
func advisoryLinks(c Candidate) string {
	var l []string
	if cveOnlyR.MatchString(c.Vuln) {
		l = append(l, "["+c.Vuln+" on OSV]("+osvURL(c.Vuln)+")",
			"[NVD](https://nvd.nist.gov/vuln/detail/"+c.Vuln+")",
			"[CISA KEV search](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext="+c.Vuln+")")
	}
	for _, a := range c.Aliases {
		if ghsaR.MatchString(a) {
			l = append(l, "[GitHub advisory "+a+"](https://github.com/advisories/"+a+")")
		}
	}
	if len(l) == 0 {
		return "-"
	}
	return strings.Join(l, ", ")
}

// ruleScope shows the vulns and packages of the rule exactly as the rule file has them.
func ruleScope(r model.Rule) string {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	_ = enc.Encode(struct {
		Vulns    []string                `yaml:"vulns"`
		Packages []model.PackageSelector `yaml:"packages"`
	}{r.Vulns, r.Packages})
	return b.String()
}

func prBody(c Candidate, r model.Rule, cases []rules.TestCase, providerName string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Rule for %s (%s)\n\n", mdCell(c.Vuln, 40), mdCell(c.Package, 80))
	b.WriteString("| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Vulnerability | %s |\n", mdCell(c.Vuln, 40))
	fmt.Fprintf(&b, "| Advisories | %s |\n", advisoryLinks(c))
	fmt.Fprintf(&b, "| Package | %s (%s) |\n", mdCell(strings.Join(packageNames(r), ", "), 200), mdCell(c.Type, 16))
	fmt.Fprintf(&b, "| Ecosystem | %s |\n", mdCell(c.Ecosystem, 64))
	fmt.Fprintf(&b, "| Severity | %s |\n", mdCell(c.Severity, 32))
	fmt.Fprintf(&b, "| CVSS | %.1f |\n", c.CVSS)
	fmt.Fprintf(&b, "| EPSS | %.4f |\n", c.EPSS)
	fmt.Fprintf(&b, "| CISA KEV | %v |\n", yesNo(c.KEV))
	fmt.Fprintf(&b, "| Rule ID | %s |\n\n", mdCell(r.ID, 130))

	b.WriteString("### Rule scope\n\nThe rule applies to every vulnerability ID and package selector below, exactly as written in the rule file. Check that each ID is the same vulnerability as the one above.\n\n")
	b.WriteString(mdBlock(ruleScope(r), 4000))

	b.WriteString("### What the rule says\n\nThe text below was written by the model and is shown verbatim as code.\n\nTitle:\n\n")
	b.WriteString(mdBlock(r.Title, 300))
	b.WriteString("Explanation:\n\n")
	b.WriteString(mdBlock(r.Explanation, 700))
	b.WriteString("Exploitable when:\n\n" + mdBlock(r.ExploitableIf, 4000))
	if r.NotAffectedIf != "" {
		b.WriteString("Not affected when:\n\n" + mdBlock(r.NotAffectedIf, 4000))
	}
	if len(r.Facts) > 0 {
		fmt.Fprintf(&b, "Facts read: %s\n\n", mdCell(strings.Join(r.Facts, ", "), 400))
	} else {
		b.WriteString("Facts read: none\n\n")
	}
	for _, fr := range r.FactRequests {
		fmt.Fprintf(&b, "- fact request %s: path %s, pattern %s\n", mdCell(fr.Name, 100), mdCell(fr.Params["path"], 200), mdCell(fr.Params["pattern"], 300))
	}
	if len(r.FactRequests) > 0 {
		b.WriteString("\n")
	}
	if r.Fix.Upgrade != "" {
		b.WriteString("Upgrade:\n\n" + mdBlock(r.Fix.Upgrade, 300))
	}
	if r.Fix.Mitigation != "" {
		b.WriteString("Mitigation:\n\n" + mdBlock(r.Fix.Mitigation, 300))
	}

	b.WriteString("### Test cases\n\n| Case | Package | Facts | Expected verdict |\n|---|---|---|---|\n")
	for _, tc := range cases {
		facts := "-"
		if len(tc.Facts) > 0 {
			j, _ := json.Marshal(tc.Facts)
			facts = mdCell(string(j), 160)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", mdCell(tc.Name, 120), mdCell(tc.Finding.Package, 80), facts, mdCell(fmt.Sprint(tc.Want), 40))
	}

	b.WriteString("\n### References\n\nThe first link is built by the bot; the others come from the advisory text and are shown as plain text, not links.\n\n")
	fmt.Fprintf(&b, "- %s\n", osvURL(c.Vuln))
	for _, u := range r.References {
		fmt.Fprintf(&b, "- %s\n", mdCell(u, 300))
	}

	b.WriteString("\n### Review\n\n")
	fmt.Fprintf(&b, "This rule was drafted by an LLM (%s) from the advisory and is committed with `status: draft`. Check it as carefully as hand-written code, then **set `status: reviewed` after checking** (CI validates the bundle only then); that commit is the review.\n\n", mdCell(strings.TrimPrefix(providerName, "anthropic:"), 80))
	b.WriteString("- [ ] The conditions match the advisory\n")
	b.WriteString("- [ ] Every ID and package selector under \"Rule scope\" is the same vulnerability and package as above\n")
	b.WriteString("- [ ] The facts exist and are collected by the agent\n")
	b.WriteString("- [ ] No `file.match` request reads a sensitive path\n")
	b.WriteString("- [ ] The tests cover both outcomes (exploitable and not exploitable)\n")
	return b.String()
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func packageNames(r model.Rule) []string {
	var out []string
	for _, p := range r.Packages {
		if p.Source != "" {
			out = append(out, "source:"+p.Source)
			continue
		}
		out = append(out, p.Name)
	}
	return out
}
