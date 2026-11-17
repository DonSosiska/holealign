package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/DonSosiska/panoptes/internal/server/config"
)

type openAIProvider struct {
	baseURL string
	model   string
	key     string
	hc      *http.Client
}

func newOpenAI(cfg config.LLM) (*openAIProvider, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("llm: openai-compatible provider needs llm.base_url")
	}
	p := &openAIProvider{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		model:   cfg.Model,
		hc:      &http.Client{Timeout: 120 * time.Second},
	}
	if cfg.APIKeyEnv != "" {
		p.key = os.Getenv(cfg.APIKeyEnv)
	}
	return p, nil
}

func (p *openAIProvider) Name() string { return "openai-compatible:" + p.model }

func (p *openAIProvider) Complete(ctx context.Context, system, user string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"model": p.model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"response_format": map[string]string{"type": "json_object"},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.key != "" {
		req.Header.Set("Authorization", "Bearer "+p.key)
	}
	resp, err := p.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("llm: openai-compatible: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("llm: openai-compatible: status %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
				Refusal string `json:"refusal"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("llm: openai-compatible: bad response: %w", err)
	}
	if len(out.Choices) == 0 {
		return "", errors.New("llm: openai-compatible: no choices")
	}
	c := out.Choices[0]
	if c.Message.Refusal != "" || c.FinishReason == "content_filter" {
		return "", ErrRefused
	}
	return c.Message.Content, nil
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}
