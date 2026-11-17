package rulesbot

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/rules"
)

// mdCell makes model- or feed-supplied text safe inside a Markdown table cell.
func mdCell(s string, max int) string {
	s = strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ", "`", "'", "<", "&lt;", ">", "&gt;").Replace(s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max]) + "..."
	}
	return s
}

func prBody(c Candidate, r model.Rule, cases []rules.TestCase, providerName string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Rule for %s (%s)\n\n", mdCell(c.Vuln, 40), mdCell(c.Package, 80))
	b.WriteString("| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Vulnerability | [%s](%s) |\n", mdCell(c.Vuln, 40), osvURL(c.Vuln))
	fmt.Fprintf(&b, "| Package | %s (%s) |\n", mdCell(strings.Join(packageNames(r), ", "), 200), mdCell(c.Type, 16))
	fmt.Fprintf(&b, "| Ecosystem | %s |\n", mdCell(c.Ecosystem, 64))
	fmt.Fprintf(&b, "| Severity | %s |\n", mdCell(c.Severity, 32))
	fmt.Fprintf(&b, "| CVSS | %.1f |\n", c.CVSS)
	fmt.Fprintf(&b, "| EPSS | %.4f |\n", c.EPSS)
	fmt.Fprintf(&b, "| CISA KEV | %v |\n", yesNo(c.KEV))
	fmt.Fprintf(&b, "| Rule ID | %s |\n\n", mdCell(r.ID, 130))

	b.WriteString("### What the rule says\n\n")
	fmt.Fprintf(&b, "**%s**\n\n", mdCell(r.Title, 300))
	fmt.Fprintf(&b, "%s\n\n", mdCell(r.Explanation, 700))
	b.WriteString("Exploitable when:\n\n```\n" + fence(r.ExploitableIf) + "\n```\n\n")
	if r.NotAffectedIf != "" {
		b.WriteString("Not affected when:\n\n```\n" + fence(r.NotAffectedIf) + "\n```\n\n")
	}
	if len(r.Facts) > 0 {
		fmt.Fprintf(&b, "Facts read: %s\n\n", mdCell(strings.Join(r.Facts, ", "), 400))
	} else {
		b.WriteString("Facts read: none\n\n")
	}
	for _, fr := range r.FactRequests {
		fmt.Fprintf(&b, "- fact request `%s`: path `%s`, pattern `%s`\n", mdCell(fr.Name, 100), mdCell(fr.Params["path"], 200), mdCell(fr.Params["pattern"], 300))
	}
	if len(r.FactRequests) > 0 {
		b.WriteString("\n")
	}
	if r.Fix.Upgrade != "" {
		fmt.Fprintf(&b, "Upgrade: %s\n\n", mdCell(r.Fix.Upgrade, 300))
	}
	if r.Fix.Mitigation != "" {
		fmt.Fprintf(&b, "Mitigation: %s\n\n", mdCell(r.Fix.Mitigation, 300))
	}

	b.WriteString("### Test cases\n\n| Case | Package | Facts | Expected verdict |\n|---|---|---|---|\n")
	for _, tc := range cases {
		facts := "-"
		if len(tc.Facts) > 0 {
			j, _ := json.Marshal(tc.Facts)
			facts = mdCell(string(j), 160)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", mdCell(tc.Name, 120), mdCell(tc.Finding.Package, 80), facts, tc.Want)
	}

	b.WriteString("\n### References\n\n")
	fmt.Fprintf(&b, "- %s\n", osvURL(c.Vuln))
	for _, u := range r.References {
		fmt.Fprintf(&b, "- %s\n", mdCell(u, 300))
	}

	b.WriteString("\n### Review\n\n")
	fmt.Fprintf(&b, "This rule was drafted by an LLM (%s) from the advisory and is committed with `status: draft`. Check it as carefully as hand-written code, then **set `status: reviewed` after checking** (CI validates the bundle only then); that commit is the review.\n\n", mdCell(strings.TrimPrefix(providerName, "anthropic:"), 80))
	b.WriteString("- [ ] The conditions match the advisory\n")
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

func fence(s string) string { return strings.ReplaceAll(s, "```", "'''") }

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
