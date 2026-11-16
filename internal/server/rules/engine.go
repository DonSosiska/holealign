package rules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"cel.dev/cel-go/cel"

	"panoptes/internal/model"
	"panoptes/internal/server/core"
)

// DefaultEvalTimeout is the per-expression evaluation timeout.
const DefaultEvalTimeout = 50 * time.Millisecond

const maxValueLen = 120

// RuleProblem describes a rule that was skipped because it is invalid.
type RuleProblem struct {
	RuleID string
	Source string // "file" or "db"
	Err    error
}

func (p RuleProblem) String() string { return fmt.Sprintf("%s rule %s: %v", p.Source, p.RuleID, p.Err) }

// Option configures an Engine.
type Option func(*Engine)

// WithEvalTimeout overrides the per-evaluation timeout (default 50 ms).
func WithEvalTimeout(d time.Duration) Option { return func(e *Engine) { e.timeout = d } }

type compiled struct {
	rule     model.Rule
	exploit  cel.Program
	notAff   cel.Program
	fromDB   bool
	declared []string // facts that must be present
	refs     []factRef
	redact   bool // rule reads file.match facts: never echo values in errors
}

type snapshot struct {
	all      []model.Rule // merged, sorted by ID (includes rejected)
	active   []*compiled  // applicable rules, sorted by ID
	requests []model.FactRequest
	problems []RuleProblem
}

// Engine evaluates rules. It implements core.RuleEvaluator and is safe for
// concurrent use.
type Engine struct {
	fileRules []model.Rule
	db        DBSource
	timeout   time.Duration
	snap      atomic.Pointer[snapshot]
}

var _ core.RuleEvaluator = (*Engine)(nil)

// New builds an Engine from file rules and an optional DB source (may be nil).
// DB rules are loaded immediately; a failing DB read is reported in Problems.
func New(fileRules []model.Rule, db DBSource, opts ...Option) *Engine {
	e := &Engine{fileRules: append([]model.Rule(nil), fileRules...), db: db, timeout: DefaultEvalTimeout}
	for _, o := range opts {
		o(e)
	}
	_ = e.Reload(context.Background())
	return e
}

// Reload re-reads DB rules and recompiles everything. Invalid rules are skipped
// and listed by Problems. If the DB cannot be read the previous DB rules are
// not retained: the error is returned and file rules alone are active.
func (e *Engine) Reload(ctx context.Context) error {
	var dbRules []model.Rule
	var dbErr error
	if e.db != nil {
		dbRules, dbErr = e.db.ListRules(ctx)
	}
	s := &snapshot{}
	if dbErr != nil {
		s.problems = append(s.problems, RuleProblem{Source: "db", Err: fmt.Errorf("list rules: %w", dbErr)})
	}

	build := func(r model.Rule, fromDB bool) (*compiled, error) {
		if err := Validate(r); err != nil {
			return nil, err
		}
		c := &compiled{rule: r, fromDB: fromDB, declared: declaredFacts(r), redact: len(r.FactRequests) > 0}
		var err error
		var r1, r2 []factRef
		if c.exploit, r1, err = compileBool(r.ExploitableIf); err != nil {
			return nil, err
		}
		if r.NotAffectedIf != "" {
			if c.notAff, r2, err = compileBool(r.NotAffectedIf); err != nil {
				return nil, err
			}
		}
		c.refs = mergeRefs(r1, r2)
		return c, nil
	}

	byID := map[string]*compiled{}
	src := func(db bool) string {
		if db {
			return "db"
		}
		return "file"
	}
	for _, grp := range []struct {
		rules []model.Rule
		db    bool
	}{{e.fileRules, false}, {dbRules, true}} {
		for _, r := range grp.rules {
			c, err := build(r, grp.db)
			if err != nil {
				s.problems = append(s.problems, RuleProblem{RuleID: r.ID, Source: src(grp.db), Err: err})
				continue
			}
			if old := byID[r.ID]; grp.db && old != nil && !old.fromDB && r.Status == model.RuleDraft {
				s.problems = append(s.problems, RuleProblem{RuleID: r.ID, Source: "db",
					Err: errors.New("draft rule cannot override a file rule with the same id; file rule kept")})
				continue
			}
			byID[r.ID] = c // DB processed last: overrides file (except drafts, see above)
		}
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	reqSeen := map[string]bool{}
	for _, id := range ids {
		c := byID[id]
		s.all = append(s.all, c.rule)
		if c.rule.Status == model.RuleRejected {
			continue
		}
		s.active = append(s.active, c)
		if c.rule.Status != model.RuleReviewed {
			continue // only reviewed rules may request host data
		}
		for _, fr := range c.rule.FactRequests {
			if !reqSeen[fr.Name] {
				reqSeen[fr.Name] = true
				s.requests = append(s.requests, fr)
			}
		}
	}
	sort.Slice(s.requests, func(i, j int) bool { return s.requests[i].Name < s.requests[j].Name })
	e.snap.Store(s)
	return dbErr
}

// Problems lists the rules skipped by the last Reload.
func (e *Engine) Problems() []RuleProblem {
	return append([]RuleProblem(nil), e.snap.Load().problems...)
}

// Rules returns all known rules (file and DB merged, including rejected), sorted by ID.
func (e *Engine) Rules() []model.Rule {
	return append([]model.Rule(nil), e.snap.Load().all...)
}

// Lookup returns the rules covering vulnID (any status), sorted by ID.
func (e *Engine) Lookup(vulnID string) []model.Rule {
	var out []model.Rule
	for _, r := range e.snap.Load().all {
		for _, v := range r.Vulns {
			if v == vulnID {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// FactRequests returns the union of the fact requests of reviewed rules only, deduped by name.
func (e *Engine) FactRequests() []model.FactRequest {
	return append([]model.FactRequest(nil), e.snap.Load().requests...)
}

func selectorMatches(sels []model.PackageSelector, name, typ string) bool {
	for _, s := range sels {
		if s.Type != "" && s.Type != typ {
			continue
		}
		if ok, err := path.Match(s.Name, name); err == nil && ok {
			return true
		}
	}
	return false
}

func statusRank(s model.RuleStatus) int {
	if s == model.RuleReviewed {
		return 2
	}
	return 1
}

// better orders candidates: reviewed over draft, then DB over file, then lowest ID.
func better(a, b *compiled) bool {
	if ra, rb := statusRank(a.rule.Status), statusRank(b.rule.Status); ra != rb {
		return ra > rb
	}
	if a.fromDB != b.fromDB {
		return a.fromDB
	}
	return a.rule.ID < b.rule.ID
}

func (e *Engine) find(f model.Finding) *compiled {
	ids := append([]string{f.VulnID}, f.Aliases...)
	var best *compiled
	for _, c := range e.snap.Load().active { // sorted by ID
		hit := false
		for _, v := range c.rule.Vulns {
			for _, id := range ids {
				if id == v {
					hit = true
				}
			}
		}
		if !hit || !selectorMatches(c.rule.Packages, f.PackageName, f.PackageType) {
			continue
		}
		if best == nil || better(c, best) {
			best = c
		}
	}
	return best
}

// grounded reports whether the expressions of c actually reference at least
// one host fact that is not "<x>.installed" (installed-ness is already implied
// by the package being present).
func (c *compiled) grounded() bool {
	for _, r := range c.refs {
		if !strings.HasSuffix(r.Name, ".installed") {
			return true
		}
	}
	return false
}

func firstChars(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

// Evaluate implements core.RuleEvaluator (verdict algorithm of contracts section 4).
func (e *Engine) Evaluate(ctx context.Context, hc core.HostContext, f model.Finding) core.Evaluation {
	c := e.find(f)
	if c == nil {
		return core.Evaluation{Verdict: model.VerdictConditionsUnknown, Reason: "no rule"}
	}
	ev := e.evaluate(ctx, c, hc, f)
	if c.rule.Status != model.RuleDraft {
		return ev
	}
	if ev.Verdict != model.VerdictExploitable && ev.Verdict != model.VerdictNotExploitable {
		return ev
	}
	expl := firstChars(c.rule.Explanation, 200)
	if !c.grounded() {
		suggested := string(ev.Verdict)
		ev.Verdict = model.VerdictConditionsUnknown
		ev.Reason = "LLM draft suggests " + suggested + ": " + expl
		return ev
	}
	if ev.Verdict == model.VerdictNotExploitable && (f.KEV || strings.EqualFold(strings.TrimSpace(f.Severity), "critical")) {
		ev.Verdict = model.VerdictConditionsUnknown
		ev.Reason = "LLM draft suggests not exploitable (unreviewed; KEV/Critical need review): " + expl
		return ev
	}
	ev.Reason = "LLM draft (unreviewed): " + ev.Reason
	return ev
}

func (e *Engine) evaluate(ctx context.Context, c *compiled, hc core.HostContext, f model.Finding) core.Evaluation {
	rule := c.rule
	ev := core.Evaluation{Rule: &rule, RuleStatus: rule.Status}

	facts := hc.Facts
	if facts == nil {
		facts = hc.Host.Facts
	}
	var missing []string
	act := map[string]any{}
	for _, n := range c.declared {
		v, ok := facts[n]
		if !ok || v == nil {
			missing = append(missing, n)
			continue
		}
		act[n] = normalize(v)
	}
	if len(missing) > 0 {
		ev.Verdict = model.VerdictConditionsUnknown
		ev.Reason = "missing facts: " + strings.Join(missing, ", ")
		return ev
	}

	vars := map[string]any{"facts": act, "pkg": pkgVars(f), "host": hostVars(hc.Host)}
	ectx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	if c.notAff != nil {
		b, err := evalBool(ectx, c.notAff, vars)
		if err != nil {
			ev.Verdict = model.VerdictConditionsUnknown
			ev.Reason = "not_affected_if error: " + errText(c, err)
			return ev
		}
		if b {
			ev.Verdict = model.VerdictNotExploitable
			ev.Reason = "not_affected_if matched: " + describe(c, act)
			return ev
		}
	}
	b, err := evalBool(ectx, c.exploit, vars)
	if err != nil {
		ev.Verdict = model.VerdictConditionsUnknown
		ev.Reason = "exploitable_if error: " + errText(c, err)
		return ev
	}
	if b {
		ev.Verdict = model.VerdictExploitable
	} else {
		ev.Verdict = model.VerdictNotExploitable
	}
	ev.Reason = describe(c, act)
	return ev
}

func errText(c *compiled, err error) string {
	if c.redact {
		return "evaluation failed (details withheld: rule reads file.match facts)"
	}
	return singleLine(err)
}

func evalBool(ctx context.Context, p cel.Program, vars map[string]any) (bool, error) {
	out, _, err := p.ContextEval(ctx, vars)
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expression returned %T, not bool", out.Value())
	}
	return b, nil
}

func pkgVars(f model.Finding) map[string]any {
	fixed := make([]any, len(f.FixedVersions))
	for i, v := range f.FixedVersions {
		fixed[i] = v
	}
	return map[string]any{
		"name": f.PackageName, "version": f.PackageVer, "type": f.PackageType, "purl": f.PURL,
		"fixed_versions": fixed, "target": f.Target, "target_kind": string(f.TargetKind),
	}
}

func hostVars(h model.Host) map[string]any {
	labels := make([]any, len(h.Labels))
	for i, l := range h.Labels {
		labels[i] = l
	}
	return map[string]any{
		"hostname": h.Hostname, "labels": labels, "os_id": h.OS.ID,
		"os_version_id": h.OS.VersionID, "kernel": h.OS.Kernel, "arch": h.OS.Arch,
	}
}

// describe lists the facts the expressions read with their values, e.g.
// "os.libc=glibc, sshd.config.logingracetime=120".
func describe(c *compiled, facts map[string]any) string {
	var parts []string
	seen := map[string]bool{}
	add := func(label string, v any, ok bool) {
		if seen[label] {
			return
		}
		seen[label] = true
		if !ok {
			parts = append(parts, label+"=<unset>")
			return
		}
		if strings.HasPrefix(label, FileMatchPrefix) {
			n := 0
			if l, isList := v.([]any); isList {
				n = len(l)
			}
			parts = append(parts, fmt.Sprintf("%s=%d matching lines", label, n))
			return
		}
		parts = append(parts, label+"="+shorten(formatValue(v)))
	}
	for _, r := range c.refs {
		v, ok := facts[r.Name]
		if !ok {
			continue
		}
		if r.Key == "" || strings.HasPrefix(r.Name, FileMatchPrefix) {
			add(r.Name, v, true)
			continue
		}
		if m, isMap := v.(map[string]any); isMap {
			kv, kok := m[r.Key]
			add(r.Name+"."+r.Key, kv, kok)
		} else {
			add(r.Name, v, true)
		}
	}
	if len(parts) == 0 { // constant or non-literal expression: show declared facts
		for _, n := range c.declared {
			if v, ok := facts[n]; ok {
				add(n, v, true)
			}
		}
	}
	if len(parts) == 0 {
		return "no host facts involved"
	}
	return strings.Join(parts, ", ")
}

func formatValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

func shorten(s string) string {
	r := []rune(s)
	if len(r) <= maxValueLen {
		return s
	}
	return string(r[:maxValueLen-3]) + "..."
}
