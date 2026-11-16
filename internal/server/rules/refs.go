package rules

import (
	"errors"

	celast "cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
)

type factRef struct{ Name, Key string }

func isFactsIdent(e celast.Expr) bool {
	return e != nil && e.Kind() == celast.IdentKind && e.AsIdent() == "facts"
}

func stringLit(e celast.Expr) (string, bool) {
	if e == nil || e.Kind() != celast.LiteralKind {
		return "", false
	}
	s, ok := e.AsLiteral().Value().(string)
	return s, ok
}

func isIndexCall(e celast.Expr) bool {
	if e == nil || e.Kind() != celast.CallKind {
		return false
	}
	c := e.AsCall()
	return (c.FunctionName() == operators.Index || c.FunctionName() == operators.OptIndex) && len(c.Args()) == 2
}

// factIndex recognises facts["name"] / facts[?"name"].
func factIndex(e celast.Expr) (string, bool) {
	if !isIndexCall(e) {
		return "", false
	}
	a := e.AsCall().Args()
	if !isFactsIdent(a[0]) {
		return "", false
	}
	return stringLit(a[1])
}

var errDynamicFacts = errors.New(`facts must be accessed with a string literal, e.g. facts["os.id"]`)

// astFactRefs walks a checked CEL AST and returns the facts it references
// (facts["lit"], facts[?"lit"], facts.name), with the literal map key of an
// immediately following index when present. String literals and comments
// never produce references.
func astFactRefs(root celast.Expr) ([]factRef, error) {
	var out []factRef
	seen := map[factRef]bool{}
	add := func(r factRef) {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	bad := false
	var rec func(e celast.Expr)
	rec = func(e celast.Expr) {
		if e == nil {
			return
		}
		switch e.Kind() {
		case celast.IdentKind:
			if isFactsIdent(e) {
				bad = true
			}
		case celast.SelectKind:
			s := e.AsSelect()
			if isFactsIdent(s.Operand()) {
				add(factRef{Name: s.FieldName()})
				return
			}
			rec(s.Operand())
		case celast.CallKind:
			c := e.AsCall()
			if n, ok := factIndex(e); ok {
				add(factRef{Name: n})
				return
			}
			if isIndexCall(e) {
				a := c.Args()
				if isFactsIdent(a[0]) {
					bad = true
					return
				}
				if n, ok := factIndex(a[0]); ok {
					if k, ok := stringLit(a[1]); ok {
						add(factRef{Name: n, Key: k})
						return
					}
				}
			}
			if t := c.Target(); t != nil {
				rec(t)
			}
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
	if bad {
		return nil, errDynamicFacts
	}
	return out, nil
}

func mergeRefs(lists ...[]factRef) []factRef {
	var out []factRef
	seen := map[factRef]bool{}
	for _, l := range lists {
		for _, r := range l {
			if !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	return out
}
