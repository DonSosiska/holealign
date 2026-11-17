package rules

import (
	"context"
	"path"
	"sort"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	celast "cel.dev/cel-go/common/ast"

	"panoptes/internal/model"
)

// Semantic grounding (docs/contracts.md section 4): a draft may only produce
// "exploitable" if its exploitable_if actually depends on host facts. This is
// decided once, at compile time, by evaluating the expression against
// synthetic activations in which every referenced fact is varied.

const (
	groundMaxEvals   = 256
	groundMaxVariant = 6
	groundCandCap    = 10
	groundTimeout    = 2 * time.Second
	hintAncestors    = 4
	hintCap          = 8
)

// missingValue marks a fact that is absent from the activation.
type missingValue struct{}

type hints struct {
	strs []string
	ints []int64
}

func (h *hints) addStr(s string) {
	if len(s) > 128 {
		return
	}
	for _, x := range h.strs {
		if x == s {
			return
		}
	}
	if len(h.strs) < hintCap {
		h.strs = append(h.strs, s)
	}
}

func (h *hints) addInt(n int64) {
	for _, x := range h.ints {
		if x == n {
			return
		}
	}
	if len(h.ints) < hintCap {
		h.ints = append(h.ints, n)
	}
}

func (h *hints) addLit(e celast.Expr) {
	if e == nil {
		return
	}
	switch e.Kind() {
	case celast.LiteralKind:
		switch v := e.AsLiteral().Value().(type) {
		case string:
			h.addStr(v)
		case int64:
			h.addInt(v)
		case uint64:
			h.addInt(int64(v))
		}
	case celast.ListKind:
		for _, x := range e.AsList().Elements() {
			h.addLit(x)
		}
	}
}

func (h *hints) addDeep(e celast.Expr) {
	if e == nil {
		return
	}
	switch e.Kind() {
	case celast.LiteralKind, celast.ListKind:
		h.addLit(e)
		if e.Kind() == celast.ListKind {
			for _, x := range e.AsList().Elements() {
				h.addDeep(x)
			}
		}
	case celast.CallKind:
		c := e.AsCall()
		h.addDeep(c.Target())
		for _, a := range c.Args() {
			h.addDeep(a)
		}
	case celast.SelectKind:
		h.addDeep(e.AsSelect().Operand())
	case celast.ComprehensionKind:
		c := e.AsComprehension()
		for _, x := range []celast.Expr{c.IterRange(), c.AccuInit(), c.LoopCondition(), c.LoopStep(), c.Result()} {
			h.addDeep(x)
		}
	}
}

// collectHints returns, per referenced fact name, the literals that occur in
// the nearest enclosing calls / comprehensions of its references.
func collectHints(root celast.Expr) map[string]*hints {
	out := map[string]*hints{}
	get := func(n string) *hints {
		if out[n] == nil {
			out[n] = &hints{}
		}
		return out[n]
	}
	var rec func(e celast.Expr, anc []celast.Expr)
	rec = func(e celast.Expr, anc []celast.Expr) {
		if e == nil {
			return
		}
		name, isRef := "", false
		if e.Kind() == celast.SelectKind && isFactsIdent(e.AsSelect().Operand()) {
			name, isRef = e.AsSelect().FieldName(), true
		} else if n, ok := factIndex(e); ok {
			name, isRef = n, true
		} else if isIndexCall(e) {
			if n, ok := factIndex(e.AsCall().Args()[0]); ok {
				if _, ok := stringLit(e.AsCall().Args()[1]); ok {
					name, isRef = n, true
				}
			}
		}
		if isRef {
			h := get(name)
			for i, k := 0, len(anc)-1; k >= 0 && i < hintAncestors; i, k = i+1, k-1 {
				a := anc[k]
				switch a.Kind() {
				case celast.CallKind:
					c := a.AsCall()
					h.addLit(c.Target())
					for _, x := range c.Args() {
						h.addLit(x)
					}
				case celast.ComprehensionKind:
					h.addDeep(a)
				}
			}
			return
		}
		next := append(anc[:len(anc):len(anc)], e)
		switch e.Kind() {
		case celast.SelectKind:
			rec(e.AsSelect().Operand(), next)
		case celast.CallKind:
			c := e.AsCall()
			rec(c.Target(), next)
			for _, a := range c.Args() {
				rec(a, next)
			}
		case celast.ComprehensionKind:
			c := e.AsComprehension()
			for _, x := range []celast.Expr{c.IterRange(), c.AccuInit(), c.LoopCondition(), c.LoopStep(), c.Result()} {
				rec(x, next)
			}
		case celast.ListKind:
			for _, x := range e.AsList().Elements() {
				rec(x, next)
			}
		case celast.MapKind:
			for _, en := range e.AsMap().Entries() {
				m := en.AsMapEntry()
				rec(m.Key(), next)
				rec(m.Value(), next)
			}
		case celast.StructKind:
			for _, en := range e.AsStruct().Fields() {
				rec(en.AsStructField().Value(), next)
			}
		}
	}
	rec(root, nil)
	return out
}

func strList(v ...string) []any {
	out := make([]any, len(v))
	for i, s := range v {
		out[i] = s
	}
	return out
}

func intList(v ...int64) []any {
	out := make([]any, len(v))
	for i, n := range v {
		out[i] = n
	}
	return out
}

func capCands(c []any) []any {
	if len(c) > groundCandCap {
		return c[:groundCandCap]
	}
	return c
}

// candidates returns type-appropriate values for fact name, "typical" first and
// "missing" last. keys are the literal map keys referenced for that fact.
func candidates(name string, keys []string, h *hints) []any {
	if h == nil {
		h = &hints{}
	}
	strs := append([]string{"x", ""}, h.strs...)
	ints := append([]int64{1, 0}, h.ints...)
	for _, n := range h.ints {
		ints = append(ints, n+1, n-1)
	}
	var c []any
	t, _ := FactTypeOf(name)
	switch t {
	case TString:
		for _, s := range strs {
			c = append(c, s)
		}
	case TBool:
		c = []any{true, false}
	case TStringList:
		c = append(c, strList(), strList(h.strs...))
		for _, s := range strs {
			c = append(c, strList(s))
		}
	case TIntList:
		c = append(c, intList(), intList(h.ints...))
		for _, n := range ints {
			c = append(c, intList(n))
		}
	case TStringMap:
		c = append(c, map[string]any{})
		for _, s := range strs {
			m := map[string]any{}
			for _, k := range keys {
				m[k] = s
			}
			c = append(c, m)
		}
		for _, k := range keys { // only the first-referenced key set; others absent
			c = append(c, map[string]any{k: "x"})
			break
		}
	case TMapOfList:
		c = append(c, map[string]any{})
		variants := [][]any{strList(), strList("x"), strList(h.strs...)}
		for _, s := range h.strs {
			variants = append(variants, strList(s))
		}
		for _, v := range variants {
			m := map[string]any{}
			for _, k := range keys {
				m[k] = v
			}
			c = append(c, m)
		}
	case TObjectList:
		c = append(c, []any{}, []any{map[string]any{}})
		for _, n := range ints {
			for _, s := range strs[:2] {
				c = append(c, []any{map[string]any{"port": n, "address": s, "name": s, "image": s, "process": s, "proto": s, "protocol": s, "state": s}})
			}
		}
	default:
		return []any{missingValue{}}
	}
	return append(capCands(c), missingValue{})
}

// groundVariants builds the constant pkg values the analysis runs with, one per
// package selector of the rule (first few), so that conditions such as
// pkg["name"].startsWith("openssh-server") can be satisfied.
func groundVariants(r model.Rule, lits []string) []map[string]any {
	type pv struct{ name, typ string }
	var vs []pv
	seen := map[pv]bool{}
	add := func(v pv) {
		if !seen[v] && len(vs) < groundMaxVariant {
			seen[v] = true
			vs = append(vs, v)
		}
	}
	// string literals of the expression that a selector glob matches are the
	// most likely real package names (selector "openssh*" + "openssh-server")
	for _, s := range r.Packages {
		for _, l := range lits {
			if ok, _ := path.Match(s.Name, l); ok {
				t := s.Type
				if t == "" {
					t = "deb"
				}
				add(pv{l, t})
			}
		}
	}
	for _, s := range r.Packages {
		n := strings.NewReplacer(`\`, "", "*", "", "?", "x").Replace(s.Name)
		t := s.Type
		if t == "" {
			t = "deb"
		}
		add(pv{n, t})
	}
	add(pv{"pkg", "deb"})
	out := make([]map[string]any, len(vs))
	for i, v := range vs {
		out[i] = pkgVars(model.Finding{
			VulnID: "CVE-0000-0000", PackageName: v.name, PackageVer: "1.0.0", PackageType: v.typ,
			PURL: "pkg:" + v.typ + "/" + v.name + "@1.0.0", FixedVersions: []string{"99.0.0"},
			Target: "x", TargetKind: model.TargetKind("host"),
		})
	}
	return out
}

// factDependent reports whether the expression's boolean result changes with
// the values of the host facts it references (pkg and host held constant).
// An expression that is constant, only errors, or whose result never varies
// is fact-independent.
func factDependent(prog cel.Program, root celast.Expr, refs []factRef, r model.Rule) bool {
	if prog == nil || len(refs) == 0 {
		return false
	}
	names := []string{}
	keys := map[string][]string{}
	for _, rf := range refs {
		if _, ok := keys[rf.Name]; !ok {
			names = append(names, rf.Name)
			keys[rf.Name] = nil
		}
		if rf.Key != "" {
			keys[rf.Name] = append(keys[rf.Name], rf.Key)
		}
	}
	sort.Strings(names)
	hs := collectHints(root)
	cands := make([][]any, len(names))
	for i, n := range names {
		cands[i] = candidates(n, keys[n], hs[n])
	}

	ctx, cancel := context.WithTimeout(context.Background(), groundTimeout)
	defer cancel()
	host := hostVars(model.Host{Hostname: "h", OS: model.OSInfo{ID: "debian", VersionID: "12", Kernel: "6.1.0", Arch: "amd64"}})
	var all hints
	all.addDeep(root)
	variants := groundVariants(r, all.strs)
	budget := groundMaxEvals / len(variants)
	var sawTrue, sawFalse bool
	for _, pkg := range variants {
		evals := 0
		try := func(idx []int) bool { // returns true when decided
			if evals >= budget {
				return true
			}
			evals++
			facts := map[string]any{}
			for i, n := range names {
				if v := cands[i][idx[i]]; v != (missingValue{}) {
					facts[n] = normalize(v)
				}
			}
			b, err := evalBool(ctx, prog, map[string]any{"facts": facts, "pkg": pkg, "host": host})
			if err == nil {
				if b {
					sawTrue = true
				} else {
					sawFalse = true
				}
			}
			return sawTrue && sawFalse
		}
		idx := make([]int, len(names))
		if try(idx) {
			if sawTrue && sawFalse {
				return true
			}
			continue
		}
		// one fact at a time
		for i := range names {
			for j := 1; j < len(cands[i]); j++ {
				idx2 := append([]int(nil), idx...)
				idx2[i] = j
				if try(idx2) {
					break
				}
			}
			if sawTrue && sawFalse {
				return true
			}
		}
		// pseudo-random combinations (deterministic)
		state := uint64(0x9E3779B97F4A7C15)
		for evals < budget && ctx.Err() == nil {
			cur := make([]int, len(names))
			for i := range cur {
				state = state*6364136223846793005 + 1442695040888963407
				cur[i] = int((state >> 33) % uint64(len(cands[i])))
			}
			if try(cur) && sawTrue && sawFalse {
				return true
			}
		}
	}
	return sawTrue && sawFalse
}
