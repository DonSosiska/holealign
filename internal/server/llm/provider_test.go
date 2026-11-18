package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DonSosiska/holealign/internal/server/config"
)

type captured struct {
	mu   sync.Mutex
	path string
	hdr  http.Header
	body map[string]any
}

func anthropicServer(t *testing.T, c *captured, stop string, text string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.path, c.hdr = r.URL.Path, r.Header.Clone()
		c.body = map[string]any{}
		_ = json.Unmarshal(raw, &c.body)
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"id": "msg_1", "type": "message", "role": "assistant", "model": "x",
			"content":     []map[string]any{{"type": "text", "text": text[:len(text)/2]}, {"type": "text", "text": text[len(text)/2:]}},
			"stop_reason": stop, "stop_sequence": nil,
			"usage": map[string]any{"input_tokens": 1, "output_tokens": 1},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestAnthropicSonnetBetaFallback(t *testing.T) {
	var c captured
	srv := anthropicServer(t, &c, "end_turn", `{"ok":true}`)
	defer srv.Close()
	p, _ := NewProvider(config.LLM{Provider: "anthropic", Model: "claude-sonnet-5-5", BaseURL: srv.URL, APIKeyEnv: "NOPE_UNSET"})
	t.Setenv("ANTHROPIC_API_KEY", "k")
	p, _ = NewProvider(config.LLM{Provider: "anthropic", Model: "claude-sonnet-5-5", BaseURL: srv.URL, APIKeyEnv: "NOPE_UNSET"})
	out, err := p.Complete(context.Background(), "sys", "usr")
	if err != nil || out != `{"ok":true}` {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if p.Name() != "anthropic:claude-sonnet-5-5" {
		t.Fatal(p.Name())
	}
	if !strings.Contains(c.path, "messages") {
		t.Fatalf("path %s", c.path)
	}
	if !strings.Contains(c.hdr.Get("anthropic-beta"), "server-side-fallback-2026-07-01") {
		t.Fatalf("beta header %q", c.hdr.Get("anthropic-beta"))
	}
	checkCommonBody(t, c.body)
	if c.body["fallbacks"] == nil {
		t.Fatalf("fallbacks missing: %v", c.body)
	}
}

func TestAnthropicHaikuPlain(t *testing.T) {
	var c captured
	srv := anthropicServer(t, &c, "end_turn", "hello world")
	defer srv.Close()
	t.Setenv("ANTHROPIC_API_KEY", "k")
	p, _ := NewProvider(config.LLM{Provider: "anthropic", Model: "claude-haiku-5-5", BaseURL: srv.URL})
	out, err := p.Complete(context.Background(), "sys", "usr")
	if err != nil || out != "hello world" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if strings.Contains(c.hdr.Get("anthropic-beta"), "server-side-fallback") || c.body["fallbacks"] != nil {
		t.Fatalf("unexpected fallback: %v %v", c.hdr, c.body)
	}
	checkCommonBody(t, c.body)
}

func checkCommonBody(t *testing.T, b map[string]any) {
	t.Helper()
	if b["model"] == "" || b["max_tokens"].(float64) != 16000 {
		t.Fatalf("model/max_tokens: %v", b)
	}
	for _, k := range []string{"thinking", "temperature", "top_p", "top_k", "tools", "tool_choice"} {
		if _, ok := b[k]; ok {
			t.Fatalf("must not send %s: %v", k, b)
		}
	}
	oc, _ := b["output_config"].(map[string]any)
	if oc["effort"] != "medium" {
		t.Fatalf("output_config: %v", b["output_config"])
	}
}

func TestAnthropicRefusal(t *testing.T) {
	for _, model := range []string{"claude-sonnet-5-5", "claude-haiku-5-5"} {
		var c captured
		srv := anthropicServer(t, &c, "refusal", "")
		t.Setenv("ANTHROPIC_API_KEY", "k")
		p, _ := NewProvider(config.LLM{Provider: "anthropic", Model: model, BaseURL: srv.URL})
		_, err := p.Complete(context.Background(), "s", "u")
		srv.Close()
		if !errors.Is(err, ErrRefused) {
			t.Fatalf("%s: err=%v", model, err)
		}
	}
}

func TestAnthropicAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"invalid_request_error","message":"bad"}}`))
	}))
	defer srv.Close()
	t.Setenv("ANTHROPIC_API_KEY", "k")
	p, _ := NewProvider(config.LLM{Provider: "anthropic", Model: "claude-haiku-5-5", BaseURL: srv.URL})
	_, err := p.Complete(context.Background(), "s", "u")
	if err == nil || errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "400") {
		t.Fatal(err)
	}
}

func TestNewProviderNone(t *testing.T) {
	p, err := NewProvider(config.LLM{Provider: "none"})
	if p != nil || err != nil {
		t.Fatal(p, err)
	}
	if _, err := NewProvider(config.LLM{Provider: "bogus"}); err == nil {
		t.Fatal("want error")
	}
}

func TestOpenAICompatible(t *testing.T) {
	var gotAuth, gotPath string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"a\":1}"},"finish_reason":"stop"}]}`))
	}))
	defer srv.Close()

	t.Setenv("MY_KEY", "sekret")
	p, err := NewProvider(config.LLM{Provider: "openai-compatible", Model: "llama", BaseURL: srv.URL + "/v1/", APIKeyEnv: "MY_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Complete(context.Background(), "sys", "usr")
	if err != nil || out != `{"a":1}` {
		t.Fatalf("%q %v", out, err)
	}
	if gotAuth != "Bearer sekret" || gotPath != "/v1/chat/completions" {
		t.Fatalf("auth=%q path=%q", gotAuth, gotPath)
	}
	rf := body["response_format"].(map[string]any)
	msgs := body["messages"].([]any)
	if body["model"] != "llama" || rf["type"] != "json_object" || len(msgs) != 2 {
		t.Fatalf("%v", body)
	}

	p, _ = NewProvider(config.LLM{Provider: "openai-compatible", Model: "llama", BaseURL: srv.URL + "/v1", APIKeyEnv: "UNSET_KEY_VAR"})
	if _, err := p.Complete(context.Background(), "s", "u"); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "" {
		t.Fatalf("auth header should be absent, got %q", gotAuth)
	}
}

func TestAnthropicClientsShared(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "shared-test")
	a := newAnthropic(config.LLM{Provider: "anthropic", Model: "claude-sonnet-5-5", BaseURL: "http://127.0.0.1:1"})
	b := newAnthropic(config.LLM{Provider: "anthropic", Model: "claude-haiku-5-5", BaseURL: "http://127.0.0.1:1", Effort: "high"})
	if a.client != b.client {
		t.Fatal("providers with the same credentials must share one client (one token cache)")
	}
	t.Setenv("ANTHROPIC_API_KEY", "other")
	c := newAnthropic(config.LLM{Provider: "anthropic", Model: "claude-haiku-5-5", BaseURL: "http://127.0.0.1:1"})
	if c.client == a.client {
		t.Fatal("different credentials must not share a client")
	}
}
