package rules

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"panoptes/internal/model"
)

const (
	maxPackageSelectors = 50
	maxRuleJSONBytes    = 32 << 10
)

var ruleIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ValidationError aggregates every problem found in one rule.
type ValidationError struct {
	RuleID   string
	Problems []string
}

func (e *ValidationError) Error() string {
	id := e.RuleID
	if id == "" {
		id = "<no id>"
	}
	return fmt.Sprintf("rule %s: %d problem(s): %s", id, len(e.Problems), strings.Join(e.Problems, "; "))
}

// declaredFacts returns rule.Facts plus the names of its fact_requests, deduped, in order.
func declaredFacts(r model.Rule) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range r.Facts {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, fr := range r.FactRequests {
		if !seen[fr.Name] {
			seen[fr.Name] = true
			out = append(out, fr.Name)
		}
	}
	return out
}

// Validate checks a rule for structural and semantic problems and returns a
// *ValidationError listing all of them, or nil.
func Validate(r model.Rule) error {
	var p []string
	add := func(format string, a ...any) { p = append(p, fmt.Sprintf(format, a...)) }

	if strings.TrimSpace(r.ID) == "" {
		add("id is required")
	} else if !ruleIDRe.MatchString(r.ID) {
		add("id %q is invalid (want %s)", r.ID, ruleIDRe)
	}
	if strings.TrimSpace(r.Title) == "" {
		add("title is required")
	}
	if strings.TrimSpace(r.Explanation) == "" {
		add("explanation is required")
	}
	switch r.Status {
	case model.RuleReviewed, model.RuleDraft, model.RuleRejected:
	case "":
		add("status is required (reviewed, draft or rejected)")
	default:
		add("status %q is invalid (want reviewed, draft or rejected)", r.Status)
	}
	if strings.TrimSpace(r.Source) == "" {
		add("source is required (builtin, user or llm:<model>)")
	}

	if len(r.Vulns) == 0 {
		add("at least one entry in vulns is required")
	}
	for i, v := range r.Vulns {
		if strings.TrimSpace(v) == "" {
			add("vulns[%d] is empty", i)
		}
	}

	if len(r.Packages) == 0 {
		add("at least one package selector is required")
	}
	if len(r.Packages) > maxPackageSelectors {
		add("at most %d package selectors per rule (got %d)", maxPackageSelectors, len(r.Packages))
	}
	if b, err := json.Marshal(r); err != nil || len(b) > maxRuleJSONBytes {
		add("rule is larger than %d bytes as JSON", maxRuleJSONBytes)
	}
	for i, s := range r.Packages {
		if s.Name == "" {
			add("packages[%d]: name is required", i)
			continue
		}
		if _, err := path.Match(s.Name, "x"); err != nil {
			add("packages[%d]: invalid glob %q: %v", i, s.Name, err)
		}
	}

	// fact_requests
	reqs := map[string]bool{}
	if len(r.FactRequests) > maxFactRequests {
		add("at most %d fact_requests per rule (got %d)", maxFactRequests, len(r.FactRequests))
	}
	for i, fr := range r.FactRequests {
		if fr.Collector != "file.match" {
			add("fact_requests[%d] (%s): collector must be \"file.match\", got %q", i, fr.Name, fr.Collector)
		}
		if fr.Params["path"] == "" {
			add("fact_requests[%d] (%s): params.path is required", i, fr.Name)
		}
		if fr.Params["pattern"] == "" {
			add("fact_requests[%d] (%s): params.pattern is required", i, fr.Name)
		}
		for _, m := range checkRequest(r.ID, factReq{Name: fr.Name, Path: fr.Params["path"], Pattern: fr.Params["pattern"]}) {
			add("fact_requests[%d] (%s): %s", i, fr.Name, m)
		}
		if reqs[fr.Name] {
			add("fact_requests[%d]: duplicate name %q", i, fr.Name)
		}
		reqs[fr.Name] = true
	}

	// facts
	declared := map[string]bool{}
	for _, n := range r.Facts {
		declared[n] = true
		if strings.HasPrefix(n, FileMatchPrefix) {
			if !reqs[n] {
				add("fact %q is not declared in fact_requests", n)
			}
			continue
		}
		if _, ok := factCatalog[n]; !ok {
			add("unknown fact %q (not in the fact catalog)", n)
		}
	}
	for n := range reqs {
		declared[n] = true
	}

	// expressions
	var refLists [][]factRef
	if strings.TrimSpace(r.ExploitableIf) == "" {
		add("exploitable_if is required")
	} else if _, refs, err := compileBool(r.ExploitableIf); err != nil {
		add("exploitable_if: %v", singleLine(err))
	} else {
		refLists = append(refLists, refs)
	}
	if strings.TrimSpace(r.NotAffectedIf) != "" {
		if _, refs, err := compileBool(r.NotAffectedIf); err != nil {
			add("not_affected_if: %v", singleLine(err))
		} else {
			refLists = append(refLists, refs)
		}
	}
	for _, ref := range mergeRefs(refLists...) {
		if !declared[ref.Name] {
			if _, known := FactTypeOf(ref.Name); known {
				add("expression reads fact %q which is not listed in facts", ref.Name)
			} else {
				add("expression reads unknown fact %q", ref.Name)
			}
		}
	}

	if len(p) == 0 {
		return nil
	}
	return &ValidationError{RuleID: r.ID, Problems: p}
}

func singleLine(err error) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(err.Error(), "\n", " ")), " ")
}
