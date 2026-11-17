// Package core defines the plug points between server components so they can be
// built independently. The pipeline (internal/server/match + api) depends only on
// these interfaces; implementations live in rules/, notify/, llm/ and are wired in
// cmd/panoptes-server.
package core

import (
	"context"

	"github.com/DonSosiska/panoptes/internal/model"
)

// HostContext is everything a rule may look at for one host.
type HostContext struct {
	Host  model.Host
	Facts model.Facts
}

// Evaluation is the outcome of applying rules to one finding.
type Evaluation struct {
	Verdict    model.Verdict
	Reason     string
	Rule       *model.Rule // nil when no rule matched
	RuleStatus model.RuleStatus
}

// RuleEvaluator decides the verdict for a finding. Implemented by internal/server/rules.
type RuleEvaluator interface {
	Evaluate(ctx context.Context, hc HostContext, f model.Finding) Evaluation
	// FactRequests returns the parametrised facts all active rules need; sent to agents on check-in.
	FactRequests() []model.FactRequest
}

// Notifier delivers events. Implemented by internal/server/notify.
type Notifier interface {
	Notify(ctx context.Context, events []model.Event) error
}

// RuleDrafter is told about findings that have no rule yet. Implemented by internal/server/llm.
// Enqueue must not block; drafting happens in the background.
type RuleDrafter interface {
	Enqueue(ctx context.Context, f model.Finding)
}

// --- no-op defaults so the pipeline runs before the real components exist ---

type NoopEvaluator struct{}

func (NoopEvaluator) Evaluate(context.Context, HostContext, model.Finding) Evaluation {
	return Evaluation{Verdict: model.VerdictConditionsUnknown, Reason: "no rule engine configured"}
}
func (NoopEvaluator) FactRequests() []model.FactRequest { return nil }

type NoopNotifier struct{}

func (NoopNotifier) Notify(context.Context, []model.Event) error { return nil }

type NoopDrafter struct{}

func (NoopDrafter) Enqueue(context.Context, model.Finding) {}
