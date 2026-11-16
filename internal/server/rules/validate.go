package rules

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"panoptes/internal/model"
)

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

// factRefRe finds literal facts["name"] references, optionally followed by one
// map key access (facts["m"]["k"] or facts["m"].?["k"]).
var factRefRe = regexp.MustCompile(`facts\["([^"]+)"\](?:\.\?\["([^"]+)"\]|\[\??"([^"]+)"\])?`)

type factRef struct{ Name, Key string }

func expressionFactRefs(exprs ...string) []factRef {
	var out []factRef
	seen := map[factRef]bool{}
	for _, e := range exprs {
		for _, m := range factRefRe.FindAllStringSubmatch(e, -1) {
			r := factRef{Name: m[1], Key: m[2] + m[3]}
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	return out
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
	for i, fr := range r.FactRequests {
		switch {
		case !strings.HasPrefix(fr.Name, FileMatchPrefix) || len(fr.Name) == len(FileMatchPrefix):
			add("fact_requests[%d]: name %q must be %s<id>", i, fr.Name, FileMatchPrefix)
		case fr.Collector != "file.match":
			add("fact_requests[%d] (%s): collector must be \"file.match\", got %q", i, fr.Name, fr.Collector)
		}
		if fr.Params["path"] == "" {
			add("fact_requests[%d] (%s): params.path is required", i, fr.Name)
		}
		pat := fr.Params["pattern"]
		if pat == "" {
			add("fact_requests[%d] (%s): params.pattern is required", i, fr.Name)
		} else if len(pat) > 512 {
			add("fact_requests[%d] (%s): params.pattern longer than 512 chars", i, fr.Name)
		} else if _, err := regexp.Compile(pat); err != nil {
			add("fact_requests[%d] (%s): params.pattern is not valid RE2: %v", i, fr.Name, err)
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
	if strings.TrimSpace(r.ExploitableIf) == "" {
		add("exploitable_if is required")
	} else if _, err := compileBool(r.ExploitableIf); err != nil {
		add("exploitable_if: %v", singleLine(err))
	}
	if strings.TrimSpace(r.NotAffectedIf) != "" {
		if _, err := compileBool(r.NotAffectedIf); err != nil {
			add("not_affected_if: %v", singleLine(err))
		}
	}
	for _, ref := range expressionFactRefs(r.ExploitableIf, r.NotAffectedIf) {
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
