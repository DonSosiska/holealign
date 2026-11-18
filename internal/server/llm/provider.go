// Package llm drafts detection rules for findings that have none, using an LLM.
package llm

import (
	"context"
	"errors"
	"fmt"

	"github.com/DonSosiska/holealign/internal/server/config"
)

// Provider is a single-turn text completion backend.
type Provider interface {
	Complete(ctx context.Context, system, user string) (text string, err error)
	Name() string // e.g. "anthropic:claude-sonnet-5-5"
}

// ErrRefused is returned when the model refused to answer.
var ErrRefused = errors.New("llm: model refused")

// NewProvider builds the provider selected in the config. Provider "none" (or empty) returns (nil, nil).
func NewProvider(cfg config.LLM) (Provider, error) {
	switch cfg.Provider {
	case "", "none":
		return nil, nil
	case "anthropic":
		return newAnthropic(cfg), nil
	case "openai-compatible":
		return newOpenAI(cfg)
	}
	return nil, fmt.Errorf("llm: unknown provider %q", cfg.Provider)
}
