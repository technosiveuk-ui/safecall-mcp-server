package policy

import (
	"context"
	"fmt"

	"github.com/technosiveuk-ui/safecall-mcp-server/core"
)

// Evaluator matches tool calls to policies and produces enforcement decisions.
// It implements strict-defaults logic and the fail-closed posture.
type Evaluator struct {
	provider       Provider
	strictDefaults bool
	defaultAction  core.Action
}

// EvaluatorOption configures an Evaluator.
type EvaluatorOption func(*Evaluator)

// WithStrictDefaults enables strict-defaults mode: tools without explicit
// policies are subject to the default action (BLOCK unless overridden).
func WithStrictDefaults() EvaluatorOption {
	return func(e *Evaluator) {
		e.strictDefaults = true
	}
}

// WithDefaultAction sets the default action for unmapped tools when
// strict defaults is enabled.
func WithDefaultAction(action core.Action) EvaluatorOption {
	return func(e *Evaluator) {
		e.defaultAction = action
	}
}

// NewEvaluator creates a policy evaluator.
func NewEvaluator(provider Provider, opts ...EvaluatorOption) *Evaluator {
	e := &Evaluator{
		provider:      provider,
		defaultAction: core.ActionBlock, // fail-closed default
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Evaluate determines the enforcement decision for a tool call.
// If findings are non-empty and the policy is ALLOW, it escalates to REDACT.
func (e *Evaluator) Evaluate(ctx context.Context, toolName string, findings []core.Finding) (*core.Decision, error) {
	// If no provider is configured, use strict defaults or allow.
	if e.provider == nil {
		if e.strictDefaults {
			return &core.Decision{
				Action: e.defaultAction,
				Reason: fmt.Sprintf("no policy provider configured; strict defaults applied (%s)", e.defaultAction),
			}, nil
		}
		return e.decisionForFindings(core.ActionAllow, findings, "no policy provider configured"), nil
	}

	pol, err := e.provider.PolicyFor(ctx, toolName)
	if err != nil {
		// NFR3: fail-closed on provider errors.
		return &core.Decision{
			Action: core.ActionBlock,
			Reason: fmt.Sprintf("policy provider error: %v", err),
		}, nil
	}

	if pol == nil {
		// No explicit policy for this tool.
		if e.strictDefaults {
			return &core.Decision{
				Action:   e.defaultAction,
				Reason:   fmt.Sprintf("no policy for tool %q; strict defaults applied (%s)", toolName, e.defaultAction),
				Findings: findings,
			}, nil
		}
		// Without strict defaults, allow but attach findings.
		return e.decisionForFindings(core.ActionAllow, findings, "no policy; permissive mode"), nil
	}

	return &core.Decision{
		Action:       pol.Action,
		Reason:       fmt.Sprintf("policy matched for tool %q", toolName),
		Findings:     findings,
		RedactFields: pol.RedactFields,
	}, nil
}

// decisionForFindings builds a decision, escalating ALLOW → REDACT if findings exist.
func (e *Evaluator) decisionForFindings(action core.Action, findings []core.Finding, reason string) *core.Decision {
	if action == core.ActionAllow && len(findings) > 0 {
		return &core.Decision{
			Action:   core.ActionRedact,
			Reason:   reason + "; escalated to REDACT due to findings",
			Findings: findings,
		}
	}
	return &core.Decision{
		Action:   action,
		Reason:   reason,
		Findings: findings,
	}
}
