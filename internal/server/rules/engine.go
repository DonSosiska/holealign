package rules

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"cel.dev/cel-go/cel"
	celast "cel.dev/cel-go/common/ast"

	"github.com/DonSosiska/panoptes/internal/model"
	"github.com/DonSosiska/panoptes/internal/server/core"
)

// DefaultEvalTimeout is the per-expression evaluation timeout.
const DefaultEvalTimeout = 50 * time.Millisecond

const maxValueLen = 120

// RuleProblem describes a rule that was skipped because it is invalid.
type RuleProblem struct {
	RuleID string
	Source string // "file", "feed" or "db"
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
	layer    int      // layerBuiltin < layerFeed < layerDB
	declared []string // facts that must be present
	refs     []factRef
	redact   bool // rule reads file.match facts: never echo values in errors
	// readsHost reports that the rule reads host facts: facts/fact_requests, any facts[...]
	// reference or any host.* variable. Such a rule cannot be judged for container images.
	readsHost bool
	// factDep reports (drafts only) that exploitable_if's result actually
	// varies with host facts; computed once at compile time.
	factDep bool
}

// Rule layers, lowest precedence first (docs/contracts.md section 4).
const (
	layerBuiltin = iota // shipped rules (embedded, optionally overridden from rules_dir)
	layerFeed           // signed central rules feed
	layerDB             // LLM drafts and user edits stored in the database
)

type snapshot struct {
	all      []model.Rule      // merged, sorted by ID (includes rejected)
	sources  map[string]string // rule ID -> "builtin", "feed:<seq>" or "db"
	active   []*compiled       // applicable rules, sorted by ID
	requests []model.FactRequest
	problems []RuleProblem
}

// Engine evaluates rules. It implements core.RuleEvaluator and is safe for
// concurrent use.
type Engine struct {
	fileRules []model.Rule
	feed      atomic.Pointer[feedLayer]
	db        DBSource
	timeout   time.Duration
	snap      atomic.Pointer[snapshot]
}

var _ core.RuleEvaluator = (*Engine)(nil)

type feedLayer struct {
	seq   uint64
	rules []model.Rule
}

// SetFeed installs the rules of the signed rules feed (bundle sequence seq) as the layer
// between the built-in rules and the DB rules: built-in < feed < DB. A feed rule replaces a
// built-in rule with the same ID; a DB rule (reviewed or user-written) replaces a feed rule with
// the same ID, and a reviewed rule for the same CVE/package always beats a lower layer. Call
// Reload afterwards to recompile. nil rules remove the layer.
func (e *Engine) SetFeed(seq uint64, rs []model.Rule) {
	if rs == nil {
		e.feed.Store(nil)
		return
	}
	e.feed.Store(&feedLayer{seq: seq, rules: append([]model.Rule(nil), rs...)})
}

// Sources maps each rule ID known to the engine to the layer it comes from: "builtin",
// "feed:<seq>" or "db".
func (e *Engine) Sources() map[string]string {
	src := e.snap.Load().sources
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

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

	build := func(r model.Rule, layer int) (*compiled, error) {
		if err := Validate(r); err != nil {
			return nil, err
		}
		c := &compiled{rule: r, layer: layer, declared: declaredFacts(r), redact: len(r.FactRequests) > 0}
		var err error
		var r1, r2 []factRef
		var root celast.Expr
		if c.exploit, r1, root, err = compileBoolAST(r.ExploitableIf); err != nil {
			return nil, err
		}
		var root2 celast.Expr
		if r.NotAffectedIf != "" {
			if c.notAff, r2, root2, err = compileBoolAST(r.NotAffectedIf); err != nil {
				return nil, err
			}
		}
		c.refs = mergeRefs(r1, r2)
		c.readsHost = len(c.declared) > 0 || len(c.refs) > 0 || usesHostVar(root) || usesHostVar(root2)
		if r.Status == model.RuleDraft {
			c.factDep = factDependent(c.exploit, root, r1, r)
		}
		return c, nil
	}

	byID := map[string]*compiled{}
	srcName := []string{"file", "feed", "db"}
	fl := e.feed.Load()
	var feedRules []model.Rule
	if fl != nil {
		feedRules = fl.rules
	}
	for layer, rs := range [][]model.Rule{e.fileRules, feedRules, dbRules} {
		for _, r := range rs {
			c, err := build(r, layer)
			if err != nil {
				s.problems = append(s.problems, RuleProblem{RuleID: r.ID, Source: srcName[layer], Err: err})
				continue
			}
			if old := byID[r.ID]; layer == layerDB && old != nil && old.layer < layerDB && r.Status == model.RuleDraft {
				s.problems = append(s.problems, RuleProblem{RuleID: r.ID, Source: "db",
					Err: errors.New("draft rule cannot override a file rule with the same id; file rule kept")})
				continue
			}
			byID[r.ID] = c // higher layers are processed later and override (except drafts, see above)
		}
	}
	s.sources = make(map[string]string, len(byID))
	for id, c := range byID {
		switch c.layer {
		case layerDB:
			s.sources[id] = "db"
		case layerFeed:
			s.sources[id] = fmt.Sprintf("feed:%d", fl.seq)
		default:
			s.sources[id] = "builtin"
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

// Rules returns all known rules (built-in, feed and DB merged, including rejected), sorted by ID.
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

func statusRank(s model.RuleStatus) int {
	if s == model.RuleReviewed {
		return 2
	}
	return 1
}

// better orders candidates: reviewed over draft, then DB over feed over built-in, then lowest ID.
func better(a, b *compiled) bool {
	if ra, rb := statusRank(a.rule.Status), statusRank(b.rule.Status); ra != rb {
		return ra > rb
	}
	if a.layer != b.layer {
		return a.layer > b.layer
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
		if !hit || !SelectorMatches(c.rule.Packages, f.PackageName, SourceOf(f.PURL, f.PackageName), f.PackageType) {
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
	// Drafts are unreviewed LLM output: they may raise a finding to
	// "exploitable" (when grounded in host facts) but never lower a verdict.
	switch ev.Verdict {
	case model.VerdictExploitable:
		if !c.grounded() || !c.factDep {
			ev.Verdict = model.VerdictConditionsUnknown
			ev.Reason = "LLM draft: condition does not depend on host facts"
			return ev
		}
		ev.Reason = "LLM draft (unreviewed): " + ev.Reason
	case model.VerdictNotExploitable:
		ev.Verdict = model.VerdictConditionsUnknown
		ev.Reason = "LLM draft suggests not exploitable (unreviewed): " + firstChars(c.rule.Explanation, 200)
	}
	return ev
}

func (e *Engine) evaluate(ctx context.Context, c *compiled, hc core.HostContext, f model.Finding) core.Evaluation {
	rule := c.rule
	ev := core.Evaluation{Rule: &rule, RuleStatus: rule.Status}

	facts := hc.Facts
	if facts == nil {
		facts = hc.Host.Facts
	}
	if c.readsHost && !targetApplies(rule.Targets, f.TargetKind) {
		ev.Verdict = model.VerdictConditionsUnknown
		ev.Reason = "rule evaluates host facts; not applicable to " + kindLabel(f.TargetKind) + " targets"
		return ev
	}
	if c.readsHost && f.TargetKind == model.TargetContainerImage {
		// even a rule that lists container_image cannot judge an image on the host's facts
		ev.Verdict = model.VerdictConditionsUnknown
		ev.Reason = "rule evaluates host facts; not applicable to container image targets"
		return ev
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

// targetApplies reports whether a rule with the given targets list (default: host only) covers
// findings of the given target kind. An empty kind counts as host.
func targetApplies(targets []string, k model.TargetKind) bool {
	if k == "" {
		k = model.TargetHost
	}
	if len(targets) == 0 {
		return k == model.TargetHost
	}
	for _, t := range targets {
		if t == string(k) {
			return true
		}
	}
	return false
}

func kindLabel(k model.TargetKind) string {
	if k == model.TargetContainerImage {
		return "container image"
	}
	if k == "" {
		return string(model.TargetHost)
	}
	return string(k)
}

// usesHostVar reports whether the expression references the "host" variable.
func usesHostVar(root celast.Expr) bool {
	found := false
	var rec func(e celast.Expr)
	rec = func(e celast.Expr) {
		if e == nil || found {
			return
		}
		switch e.Kind() {
		case celast.IdentKind:
			if e.AsIdent() == "host" {
				found = true
			}
		case celast.SelectKind:
			rec(e.AsSelect().Operand())
		case celast.CallKind:
			c := e.AsCall()
			rec(c.Target())
			for _, a := range c.Args() {
				rec(a)
			}
		case celast.ComprehensionKind:
			c := e.AsComprehension()
			for _, x := range []celast.Expr{c.IterRange(), c.AccuInit(), c.LoopCondition(), c.LoopStep(), c.Result()} {
				rec(x)
			}
		case celast.ListKind:
			for _, x := range e.AsList().Elements() {
				rec(x)
			}
		case celast.MapKind:
			for _, en := range e.AsMap().Entries() {
				m := en.AsMapEntry()
				rec(m.Key())
				rec(m.Value())
			}
		case celast.StructKind:
			for _, en := range e.AsStruct().Fields() {
				rec(en.AsStructField().Value())
			}
		}
	}
	rec(root)
	return found
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
		"name": f.PackageName, "source": SourceOf(f.PURL, f.PackageName), "version": f.PackageVer, "type": f.PackageType, "purl": f.PURL,
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
