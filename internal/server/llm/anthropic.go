package llm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"

	"github.com/DonSosiska/panoptes/internal/server/config"
)

type anthropicProvider struct {
	client anthropic.Client
	model  string
	effort string // low|medium|high|xhigh|max
}

func newAnthropic(cfg config.LLM) *anthropicProvider {
	var opts []option.RequestOption
	if cfg.APIKeyEnv != "" {
		if k := os.Getenv(cfg.APIKeyEnv); k != "" {
			opts = append(opts, option.WithAPIKey(k))
		}
	}
	if cfg.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(cfg.BaseURL))
	}
	effort := cfg.Effort
	if effort == "" {
		effort = "medium"
	}
	return &anthropicProvider{client: anthropic.NewClient(opts...), model: cfg.Model, effort: effort}
}

func (p *anthropicProvider) Name() string { return "anthropic:" + p.model }

// usesFallback reports whether the model is called via the beta endpoint with server-side
// fallback, so a refusal (cyber classifier) is re-served by another model in the same call.
func usesFallback(model string) bool {
	return model == "claude-sonnet-5-5" || model == "claude-opus-5-5"
}

func (p *anthropicProvider) Complete(ctx context.Context, system, user string) (string, error) {
	var (
		stop string
		text strings.Builder
		err  error
	)
	if usesFallback(p.model) {
		var msg *anthropic.BetaMessage
		msg, err = p.client.Beta.Messages.New(ctx, anthropic.BetaMessageNewParams{
			Model:     p.model,
			MaxTokens: 16000,
			// The system prompt is the cached prefix: it must stay byte-identical across calls.
			System: []anthropic.BetaTextBlockParam{{Text: system, CacheControl: anthropic.NewBetaCacheControlEphemeralParam()}},
			Messages: []anthropic.BetaMessageParam{
				anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(user)),
			},
			OutputConfig: anthropic.BetaOutputConfigParam{Effort: anthropic.BetaOutputConfigEffort(p.effort)},
			Betas:        []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01},
			Fallbacks:    anthropic.BetaFallbacksParamOfDefault(),
		})
		if err == nil {
			stop = string(msg.StopReason)
			reportUsage(ctx, Usage{Model: p.model, InputTokens: msg.Usage.InputTokens, OutputTokens: msg.Usage.OutputTokens,
				CacheReadTokens: msg.Usage.CacheReadInputTokens, CacheWriteTokens: msg.Usage.CacheCreationInputTokens})
			for _, b := range msg.Content {
				if b.Type == "text" {
					text.WriteString(b.Text)
				}
			}
		}
	} else {
		var msg *anthropic.Message
		msg, err = p.client.Messages.New(ctx, anthropic.MessageNewParams{
			Model:     p.model,
			MaxTokens: 16000,
			System:    []anthropic.TextBlockParam{{Text: system, CacheControl: anthropic.NewCacheControlEphemeralParam()}},
			Messages: []anthropic.MessageParam{
				anthropic.NewUserMessage(anthropic.NewTextBlock(user)),
			},
			OutputConfig: anthropic.OutputConfigParam{Effort: anthropic.OutputConfigEffort(p.effort)},
		})
		if err == nil {
			stop = string(msg.StopReason)
			reportUsage(ctx, Usage{Model: p.model, InputTokens: msg.Usage.InputTokens, OutputTokens: msg.Usage.OutputTokens,
				CacheReadTokens: msg.Usage.CacheReadInputTokens, CacheWriteTokens: msg.Usage.CacheCreationInputTokens})
			for _, b := range msg.Content {
				if b.Type == "text" {
					text.WriteString(b.Text)
				}
			}
		}
	}
	if err != nil {
		var apierr *anthropic.Error
		if errors.As(err, &apierr) {
			retry := apierr.StatusCode == 429 || apierr.StatusCode >= 500
			return "", fmt.Errorf("llm: anthropic API status %d (retryable=%v): %w", apierr.StatusCode, retry, err)
		}
		return "", fmt.Errorf("llm: anthropic: %w", err)
	}
	if stop == string(anthropic.StopReasonRefusal) {
		return "", ErrRefused
	}
	return text.String(), nil
}
