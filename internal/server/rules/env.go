package rules

import (
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

// rewriteOptionalIndex translates the optional-index spelling used in
// docs/contracts.md and the shipped rules, m.?["k"], into the syntax cel-go
// actually accepts, m[?"k"].
func rewriteOptionalIndex(src string) string {
	return strings.ReplaceAll(src, ".?[", "[?")
}

// compileBool compiles an expression and checks that it yields bool.
func compileBool(src string) (cel.Program, error) {
	env, err := celEnv()
	if err != nil {
		return nil, fmt.Errorf("cel environment: %w", err)
	}
	ast, iss := env.Compile(rewriteOptionalIndex(src))
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	if t := ast.OutputType(); !t.IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("expression must return bool, got %s", t)
	}
	return env.Program(ast,
		cel.CostLimit(costLimit),
		cel.InterruptCheckFrequency(interruptFrequency),
	)
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
