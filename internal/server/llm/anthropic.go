package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"

	"github.com/DonSosiska/holealign/internal/server/config"
)

type anthropicProvider struct {
	client *anthropic.Client
	model  string
	effort string // low|medium|high|xhigh|max
}

func newAnthropic(cfg config.LLM) *anthropicProvider {
	effort := cfg.Effort
	if effort == "" {
		effort = "medium"
	}
	return &anthropicProvider{client: sharedClient(cfg), model: cfg.Model, effort: effort}
}

// Providers built in one process (for example one per model in "rules eval") share one client per
// credential source, so they share one credential cache. With workload identity federation every
// client exchanges the identity token on its own, and an identity token with a jti can be exchanged
// only once: separate clients reading the same token file fail with jti_reused (401).
var (
	clientsMu sync.Mutex
	clients   = map[string]*anthropic.Client{}
)

// sdkCredentialEnv are the environment variables the SDK reads for credentials.
var sdkCredentialEnv = []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE", "ANTHROPIC_BASE_URL",
	"ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID", "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_WORKSPACE_ID",
	"ANTHROPIC_IDENTITY_TOKEN_FILE", "ANTHROPIC_IDENTITY_TOKEN"}

func sharedClient(cfg config.LLM) *anthropic.Client {
	var opts []option.RequestOption
	// The key covers every credential source the SDK may use (hashed, never stored in clear).
	h := sha256.New()
	if cfg.APIKeyEnv != "" {
		if k := os.Getenv(cfg.APIKeyEnv); k != "" {
			opts = append(opts, option.WithAPIKey(k))
			h.Write([]byte("key\x00" + k + "\x00"))
		}
	}
	if cfg.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(cfg.BaseURL))
	}
	h.Write([]byte("url\x00" + cfg.BaseURL + "\x00"))
	for _, v := range sdkCredentialEnv {
		h.Write([]byte(v + "\x00" + os.Getenv(v) + "\x00"))
	}
	key := hex.EncodeToString(h.Sum(nil))
	clientsMu.Lock()
	defer clientsMu.Unlock()
	if c, ok := clients[key]; ok {
		return c
	}
	c := anthropic.NewClient(opts...)
	clients[key] = &c
	return &c
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
