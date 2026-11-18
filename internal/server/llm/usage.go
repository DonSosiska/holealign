package llm

import (
	"context"
	"strings"
)

// Usage is the token usage of one successful provider call.
type Usage struct {
	Model            string
	InputTokens      int64
	OutputTokens     int64
	CacheReadTokens  int64
	CacheWriteTokens int64
}

type usageSinkKey struct{}

// WithUsageSink returns a context whose provider calls report their Usage to f. f may be called
// from several goroutines when the context is shared; it must be safe for that.
func WithUsageSink(ctx context.Context, f func(Usage)) context.Context {
	return context.WithValue(ctx, usageSinkKey{}, f)
}

// reportUsage is called by the providers after every successful response.
func reportUsage(ctx context.Context, u Usage) {
	if f, ok := ctx.Value(usageSinkKey{}).(func(Usage)); ok && f != nil {
		f(u)
	}
}

// price is USD per million tokens. Cache writes cost 1.25x the input price.
type price struct{ in, out, read float64 }

// prices are list prices as of 2026-11, for estimation only: they are not read from the API and
// the bill is authoritative.
var prices = map[string]price{
	"claude-sonnet-5-5": {2, 10, 0.10},
	"claude-opus-5-5":   {4, 20, 0.20},
	"claude-haiku-5-5":  {0.10, 0.50, 0.01},
	"claude-sonnet-5":   {2, 10, 0.20},
}

// EstimateUSD estimates the cost of u from the price table. ok is false for an unknown model.
// A dated model ID ("claude-haiku-5-5-20261101") uses the price of the longest listed name it extends.
func EstimateUSD(u Usage) (usd float64, ok bool) {
	p, found := prices[u.Model]
	if !found {
		best := ""
		for name, pp := range prices {
			if strings.HasPrefix(u.Model, name+"-") && len(name) > len(best) {
				best, p, found = name, pp, true
			}
		}
	}
	if !found {
		return 0, false
	}
	usd = (float64(u.InputTokens)*p.in + float64(u.OutputTokens)*p.out +
		float64(u.CacheReadTokens)*p.read + float64(u.CacheWriteTokens)*p.in*1.25) / 1e6
	return usd, true
}

// Add returns the sum of u and o (u's model wins unless empty).
func (u Usage) Add(o Usage) Usage {
	if u.Model == "" {
		u.Model = o.Model
	}
	u.InputTokens += o.InputTokens
	u.OutputTokens += o.OutputTokens
	u.CacheReadTokens += o.CacheReadTokens
	u.CacheWriteTokens += o.CacheWriteTokens
	return u
}
