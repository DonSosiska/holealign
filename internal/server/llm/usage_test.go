package llm

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DonSosiska/panoptes/internal/server/config"
)

func TestEstimateUSD(t *testing.T) {
	// Sonnet 5.5: 1M in at 2, 1M out at 10, 1M cache read at 0.10, 1M cache write at 1.25x2.
	u := Usage{Model: "claude-sonnet-5-5", InputTokens: 1e6, OutputTokens: 1e6, CacheReadTokens: 1e6, CacheWriteTokens: 1e6}
	got, ok := EstimateUSD(u)
	if !ok || math.Abs(got-(2+10+0.10+2.5)) > 1e-9 {
		t.Fatalf("sonnet: %v %v", got, ok)
	}
	if got, ok = EstimateUSD(Usage{Model: "claude-haiku-5-5", InputTokens: 1e6, OutputTokens: 1e6}); !ok || math.Abs(got-0.6) > 1e-9 {
		t.Fatalf("haiku: %v %v", got, ok)
	}
	if got, ok = EstimateUSD(Usage{Model: "claude-opus-5-5", CacheReadTokens: 1e6}); !ok || math.Abs(got-0.2) > 1e-9 {
		t.Fatalf("opus: %v %v", got, ok)
	}
	if got, ok = EstimateUSD(Usage{Model: "claude-sonnet-5", CacheReadTokens: 1e6}); !ok || math.Abs(got-0.2) > 1e-9 {
		t.Fatalf("sonnet-5: %v %v", got, ok)
	}
	if got, ok = EstimateUSD(Usage{Model: "claude-haiku-5-5-20261101", InputTokens: 1e6}); !ok || math.Abs(got-0.1) > 1e-9 {
		t.Fatalf("dated: %v %v", got, ok)
	}
	if _, ok = EstimateUSD(Usage{Model: "llama", InputTokens: 5}); ok {
		t.Fatal("unknown model must not be priced")
	}
}

func TestUsageSink(t *testing.T) {
	reportUsage(context.Background(), Usage{Model: "m"}) // no sink: no-op
	var got []Usage
	ctx := WithUsageSink(context.Background(), func(u Usage) { got = append(got, u) })
	reportUsage(ctx, Usage{Model: "a", InputTokens: 1})
	reportUsage(ctx, Usage{Model: "a", InputTokens: 2})
	if len(got) != 2 || got[1].InputTokens != 2 {
		t.Fatalf("%v", got)
	}
	if s := got[0].Add(got[1]); s.InputTokens != 3 || s.Model != "a" {
		t.Fatalf("%v", s)
	}
}

func usageServer(t *testing.T, body *map[string]any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_1", "type": "message", "role": "assistant", "model": "x",
			"content":     []map[string]any{{"type": "text", "text": "{}"}},
			"stop_reason": "end_turn", "stop_sequence": nil,
			"usage": map[string]any{"input_tokens": 11, "output_tokens": 22, "cache_read_input_tokens": 33, "cache_creation_input_tokens": 44},
		})
	}))
}

func TestAnthropicCachingEffortAndUsage(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "k")
	for _, model := range []string{"claude-sonnet-5-5", "claude-haiku-5-5"} { // beta and non-beta path
		var body map[string]any
		srv := usageServer(t, &body)
		p, _ := NewProvider(config.LLM{Provider: "anthropic", Model: model, BaseURL: srv.URL, Effort: "high"})
		var got []Usage
		ctx := WithUsageSink(context.Background(), func(u Usage) { got = append(got, u) })
		if _, err := p.Complete(ctx, "SYSTEM", "user"); err != nil {
			t.Fatal(err)
		}
		srv.Close()
		sys, _ := body["system"].([]any)
		if len(sys) != 1 {
			t.Fatalf("%s: system %v", model, body["system"])
		}
		blk := sys[0].(map[string]any)
		cc, _ := blk["cache_control"].(map[string]any)
		if blk["text"] != "SYSTEM" || cc["type"] != "ephemeral" {
			t.Fatalf("%s: system block %v", model, blk)
		}
		if _, hasTTL := cc["ttl"]; hasTTL {
			t.Fatalf("%s: default TTL expected: %v", model, cc)
		}
		if oc, _ := body["output_config"].(map[string]any); oc["effort"] != "high" {
			t.Fatalf("%s: output_config %v", model, body["output_config"])
		}
		if len(got) != 1 || got[0] != (Usage{Model: model, InputTokens: 11, OutputTokens: 22, CacheReadTokens: 33, CacheWriteTokens: 44}) {
			t.Fatalf("%s: usage %+v", model, got)
		}
	}
	// Empty effort means medium.
	var body map[string]any
	srv := usageServer(t, &body)
	defer srv.Close()
	p, _ := NewProvider(config.LLM{Provider: "anthropic", Model: "claude-haiku-5-5", BaseURL: srv.URL})
	if _, err := p.Complete(context.Background(), "s", "u"); err != nil {
		t.Fatal(err)
	}
	if oc, _ := body["output_config"].(map[string]any); oc["effort"] != "medium" {
		t.Fatalf("default effort: %v", body["output_config"])
	}
}

func TestOpenAIUsageAndNoCacheControl(t *testing.T) {
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":9}}`))
	}))
	defer srv.Close()
	p, _ := NewProvider(config.LLM{Provider: "openai-compatible", Model: "llama", BaseURL: srv.URL})
	var got []Usage
	ctx := WithUsageSink(context.Background(), func(u Usage) { got = append(got, u) })
	if _, err := p.Complete(ctx, "s", "u"); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != (Usage{Model: "llama", InputTokens: 7, OutputTokens: 9}) {
		t.Fatalf("%+v", got)
	}
	if string(raw) == "" || json.Valid(raw) == false || strings.Contains(string(raw), "cache_control") {
		t.Fatalf("request %s", raw)
	}
}

func TestSystemPromptIsStable(t *testing.T) {
	cat := []FactSpec{{Name: "a", Type: "string", Description: "d"}, {Name: "b", Type: "int", Description: "e"}}
	first := buildSystemPrompt(cat)
	for i := 0; i < 20; i++ {
		if buildSystemPrompt(cat) != first {
			t.Fatal("the system prompt must be byte-identical across calls (prompt cache prefix)")
		}
	}
	in := RepoInput{Vuln: "CVE-1", Package: "p", Type: "deb", RuleID: "CVE-1-p"}
	s1, _ := BuildRepoPrompts(in, cat, nil, "advisory one")
	in.Vuln, in.Package, in.RuleID = "CVE-2", "q", "CVE-2-q"
	s2, _ := BuildRepoPrompts(in, cat, nil, "advisory two")
	if s1 != s2 {
		t.Fatal("per-candidate data must stay out of the repository system prompt")
	}
}
