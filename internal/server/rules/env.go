package rules

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
)

const (
	costLimit = 10000
	// interruptFrequency is how many comprehension iterations pass between context checks.
	interruptFrequency = 100
)

var (
	envOnce sync.Once
	envInst *cel.Env
	envErr  error
)

// celEnv returns the shared (thread-safe) CEL environment of docs/contracts.md section 4.
func celEnv() (*cel.Env, error) {
	envOnce.Do(func() {
		strMap := cel.MapType(cel.StringType, cel.DynType)
		envInst, envErr = cel.NewEnv(
			cel.OptionalTypes(),
			cel.Variable("facts", strMap),
			cel.Variable("pkg", strMap),
			cel.Variable("host", strMap),
			cel.Function("version_lt",
				cel.Overload("version_lt_string_string",
					[]*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
					cel.BinaryBinding(func(a, b ref.Val) ref.Val {
						return types.Bool(versionCompare(a.Value().(string), b.Value().(string)) < 0)
					}))),
			cel.Function("version_ge",
				cel.Overload("version_ge_string_string",
					[]*cel.Type{cel.StringType, cel.StringType}, cel.BoolType,
					cel.BinaryBinding(func(a, b ref.Val) ref.Val {
						return types.Bool(versionCompare(a.Value().(string), b.Value().(string)) >= 0)
					}))),
			cel.Function("has_module",
				cel.Overload("has_module_list_string",
					[]*cel.Type{cel.ListType(cel.DynType), cel.StringType}, cel.BoolType,
					cel.BinaryBinding(func(l, n ref.Val) ref.Val {
						c, ok := l.(traits.Container)
						if !ok {
							return types.NewErr("has_module: first argument is not a list")
						}
						return c.Contains(n)
					}))),
		)
	})
	return envInst, envErr
}

// hasDotOptIndex reports whether src contains the legacy spelling ".?[" outside
// string literals and comments.
func hasDotOptIndex(src string) bool {
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '"' || c == '\'':
			raw := i > 0 && (src[i-1] == 'r' || src[i-1] == 'R')
			q := string(c)
			triple := i+2 < len(src) && src[i+1] == c && src[i+2] == c
			if triple {
				q = strings.Repeat(q, 3)
				i += 3
			} else {
				i++
			}
			for i < len(src) {
				if !raw && src[i] == '\\' {
					i += 2
					continue
				}
				if strings.HasPrefix(src[i:], q) {
					i += len(q) - 1
					break
				}
				if !triple && src[i] == '\n' {
					break
				}
				i++
			}
		case strings.HasPrefix(src[i:], ".?["):
			return true
		}
	}
	return false
}

// compileBool compiles an expression, checks that it yields bool and returns
// the program together with the facts it references (from the checked AST).
func compileBool(src string) (cel.Program, []factRef, error) {
	env, err := celEnv()
	if err != nil {
		return nil, nil, fmt.Errorf("cel environment: %w", err)
	}
	if hasDotOptIndex(src) {
		return nil, nil, errors.New(`the ".?[" optional-index syntax is not supported; use m[?"key"]`)
	}
	ast, iss := env.Compile(src)
	if iss != nil && iss.Err() != nil {
		return nil, nil, iss.Err()
	}
	if t := ast.OutputType(); !t.IsExactType(cel.BoolType) {
		return nil, nil, fmt.Errorf("expression must return bool, got %s", t)
	}
	refs, err := astFactRefs(ast.NativeRep().Expr())
	if err != nil {
		return nil, nil, err
	}
	p, err := env.Program(ast,
		cel.CostLimit(costLimit),
		cel.InterruptCheckFrequency(interruptFrequency),
	)
	return p, refs, err
}

// normalize converts JSON-decoded values into forms that behave naturally in CEL:
// whole-number float64 become int64, collections are converted recursively.
func normalize(v any) any {
	switch x := v.(type) {
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1<<53 {
			return int64(x)
		}
		return x
	case int:
		return int64(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalize(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = normalize(e)
		}
		return out
	default:
		return v
	}
}
