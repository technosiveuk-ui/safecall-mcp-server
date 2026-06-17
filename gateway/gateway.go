// Package gateway is the hot-path orchestrator for SafeCall. It chains
// inspection → policy evaluation → execution → audit emission.
//
// CRITICAL: This package must have ZERO imports of github.com/cloudwego/eino.
// The ALLOW/BLOCK/REDACT paths execute as pure Go logic here. Only the
// INTERRUPT path is handed off to adapter/eino via the InterruptError
// domain type.
package gateway

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/technosiveuk-ui/safecall-mcp-server/audit"
	"github.com/technosiveuk-ui/safecall-mcp-server/core"
	"github.com/technosiveuk-ui/safecall-mcp-server/inspection"
	"github.com/technosiveuk-ui/safecall-mcp-server/policy"
)

// ExecFunc is the signature of the underlying tool function.
type ExecFunc func(ctx context.Context, args map[string]any) (string, error)

// Gateway orchestrates the security enforcement pipeline:
//
//	inspect → evaluate → (allow|block|redact|interrupt) → audit
//
// It is safe for concurrent use.
type Gateway struct {
	evaluator        *policy.Evaluator
	inspectors       *inspection.Registry
	emitter          audit.Emitter
	inspectResponses bool   // opt-in outbound response DLP inspection (GAP-002 / FR3)
	seq              int64  // monotonic counter for per-call request IDs (atomic)
}

// New creates a Gateway with the given components.
func New(evaluator *policy.Evaluator, inspectors *inspection.Registry, emitter audit.Emitter) *Gateway {
	if emitter == nil {
		emitter = audit.NopEmitter{}
	}
	return &Gateway{
		evaluator:  evaluator,
		inspectors: inspectors,
		emitter:    emitter,
	}
}

// WithResponseInspection enables outbound response DLP inspection (GAP-002 /
// PRD FR3). When enabled, tool responses are scanned for sensitive data after
// execution and masked if findings are present or inspection errors. It is
// opt-in so the default ALLOW/REDACT hot path is unchanged (NFR2 <20µs).
func (g *Gateway) WithResponseInspection() *Gateway {
	g.inspectResponses = true
	return g
}

// inspectAndMaskResponse implements GAP-002 (PRD FR3 outbound response
// inspection). When enabled, the gateway scans the tool's response string by
// reusing the argument Inspector pipeline (the response is wrapped in a single
// pseudo-field named "response").
//
// This is a deliberate STUB:
//   - On any finding — or on an inspection error — the ENTIRE response is
//     masked with RedactedPlaceholder (fail-closed on leakage: never return
//     uninspected data).
//   - TODO: substring-level masking (replace only the matched span),
//     policy-driven control (inspect only when the tool's policy requests it),
//     and a dedicated response Inspector for structured payloads. Whole-response
//     masking is intentionally coarse for the stub.
func (g *Gateway) inspectAndMaskResponse(ctx context.Context, result string) (string, []core.Finding) {
	if !g.inspectResponses || g.inspectors == nil {
		return result, nil
	}
	respFindings, err := g.inspectors.Inspect(ctx, map[string]any{"response": result})
	if err != nil {
		// Fail-closed on leakage: cannot vouch for the response, so mask it.
		return core.RedactedPlaceholder, nil
	}
	if len(respFindings) > 0 {
		return core.RedactedPlaceholder, respFindings
	}
	return result, nil
}

// Process runs the full enforcement pipeline for a single tool call.
//
// Pipeline:
//  1. Pre-inspect arguments for sensitive data
//  2. Evaluate policy (with findings)
//  3. Act on the decision:
//     - ALLOW:     execute with original args
//     - BLOCK:     return BlockedError
//     - REDACT:    mask findings in args, then execute
//     - INTERRUPT: return InterruptError (for ACL translation)
//  4. Post-inspect response
//  5. Emit audit event
func (g *Gateway) Process(ctx context.Context, toolName string, args map[string]any, exec ExecFunc) (string, error) {
	start := time.Now()
	requestID := g.newRequestID()

	// 1. Pre-inspect arguments.
	var findings []core.Finding
	if g.inspectors != nil {
		var err error
		findings, err = g.inspectors.Inspect(ctx, args)
		if err != nil {
			// Fail-closed: inspection error → BLOCK.
			reason := fmt.Sprintf("inspection error: %v", err)
			g.emitAudit(ctx, toolName, core.ActionBlock, reason, findings, requestID, start, nil)
			return "", &core.BlockedError{
				ToolName: toolName,
				Reason:   reason,
			}
		}
	}

	// 2. Evaluate policy.
	decision, err := g.evaluator.Evaluate(ctx, toolName, findings)
	if err != nil {
		// Fail-closed: evaluator error → BLOCK.
		reason := fmt.Sprintf("policy evaluation error: %v", err)
		g.emitAudit(ctx, toolName, core.ActionBlock, reason, findings, requestID, start, nil)
		return "", &core.BlockedError{
			ToolName: toolName,
			Reason:   reason,
		}
	}

	// 3. Act on the decision.
	switch decision.Action {
	case core.ActionBlock:
		g.emitAudit(ctx, toolName, core.ActionBlock, decision.Reason, findings, requestID, start, nil)
		return "", &core.BlockedError{
			ToolName: toolName,
			Reason:   decision.Reason,
		}

	case core.ActionInterrupt:
		checkpointID := fmt.Sprintf("cp_%s_%d", toolName, time.Now().UnixNano())
		g.emitAuditWithCheckpoint(ctx, toolName, core.ActionInterrupt, decision.Reason, findings, requestID, start, checkpointID, nil)
		return "", &core.InterruptError{
			CheckpointID: checkpointID,
			ToolName:     toolName,
			Reason:       decision.Reason,
		}

	case core.ActionRedact:
		// Mask sensitive values in args before execution: first the inspector
		// findings (DLP), then any fields the matched policy explicitly declares.
		redactArgs(args, findings)
		findings = redactPolicyFields(args, decision.RedactFields, findings)
		result, execErr := exec(ctx, args)
		if execErr == nil {
			var respFindings []core.Finding
			result, respFindings = g.inspectAndMaskResponse(ctx, result)
			findings = append(findings, respFindings...)
		}
		g.emitAudit(ctx, toolName, core.ActionRedact, decision.Reason, findings, requestID, start, execErr)
		return result, execErr

	case core.ActionAllow:
		result, execErr := exec(ctx, args)
		if execErr == nil {
			var respFindings []core.Finding
			result, respFindings = g.inspectAndMaskResponse(ctx, result)
			findings = append(findings, respFindings...)
		}
		g.emitAudit(ctx, toolName, core.ActionAllow, decision.Reason, findings, requestID, start, execErr)
		return result, execErr

	default:
		// Unknown action → fail-closed.
		reason := fmt.Sprintf("unknown action %v; fail-closed", decision.Action)
		g.emitAudit(ctx, toolName, core.ActionBlock, reason, findings, requestID, start, nil)
		return "", &core.BlockedError{
			ToolName: toolName,
			Reason:   reason,
		}
	}
}

// redactArgs replaces sensitive values in the argument map with the
// redacted placeholder.
func redactArgs(args map[string]any, findings []core.Finding) {
	for _, f := range findings {
		redactField(args, f.FieldName, core.RedactedPlaceholder)
	}
}

// redactPolicyFields redacts fields the matched policy explicitly declares
// (RedactFields) that were not already caught and redacted by inspection
// findings. A Finding is appended for each policy-redacted field so the audit
// trail records the policy-driven redaction with a fingerprint. Fields absent
// from the arguments are skipped (nothing to redact).
func redactPolicyFields(args map[string]any, paths []string, findings []core.Finding) []core.Finding {
	if len(paths) == 0 {
		return findings
	}
	already := make(map[string]bool, len(findings))
	for _, f := range findings {
		already[f.FieldName] = true
	}
	for _, path := range paths {
		if already[path] {
			continue // inspection already flagged and redacted this field
		}
		orig, ok := lookupField(args, path)
		if !ok {
			continue // field absent in args — nothing to redact
		}
		redactField(args, path, core.RedactedPlaceholder)
		findings = append(findings, core.NewFinding(path, "POLICY/REDACT_FIELD", fmt.Sprintf("%v", orig)))
	}
	return findings
}

// lookupField returns the value at a dot-separated path, or (nil, false) if the
// path does not exist.
func lookupField(m map[string]any, path string) (any, bool) {
	parts := splitFieldPath(path)
	current := m
	for i, part := range parts {
		if i == len(parts)-1 {
			v, ok := current[part]
			return v, ok
		}
		nested, ok := current[part].(map[string]any)
		if !ok {
			return nil, false
		}
		current = nested
	}
	return nil, false
}

// redactField sets a nested field (dot-separated path) to the given value.
func redactField(m map[string]any, fieldPath string, value string) {
	parts := splitFieldPath(fieldPath)
	current := m
	for i, part := range parts {
		if i == len(parts)-1 {
			// Leaf: replace value.
			current[part] = value
			return
		}
		// Traverse into nested map.
		if nested, ok := current[part].(map[string]any); ok {
			current = nested
		} else {
			return // path doesn't exist, nothing to redact
		}
	}
}

// splitFieldPath splits a dot-separated field path, e.g. "user.ssn" → ["user", "ssn"].
func splitFieldPath(path string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(path); i++ {
		if path[i] == '.' {
			if i > start {
				parts = append(parts, path[start:i])
			}
			start = i + 1
		}
	}
	if start < len(path) {
		parts = append(parts, path[start:])
	}
	return parts
}

func (g *Gateway) emitAudit(ctx context.Context, toolName string, action core.Action, reason string, findings []core.Finding, requestID string, start time.Time, execErr error) {
	g.emitAuditWithCheckpoint(ctx, toolName, action, reason, findings, requestID, start, "", execErr)
}

func (g *Gateway) emitAuditWithCheckpoint(ctx context.Context, toolName string, action core.Action, reason string, findings []core.Finding, requestID string, start time.Time, checkpointID string, execErr error) {
	event := audit.AuditEvent{
		Timestamp:    time.Now(),
		ToolName:     toolName,
		Action:       action,
		Reason:       reason,
		Findings:     findings,
		RequestID:    requestID,
		CheckpointID: checkpointID,
		Duration:     time.Since(start),
	}
	if execErr != nil {
		event.Error = execErr.Error()
	}
	// Audit emission errors are not fatal — log them but don't break the call.
	_ = g.emitter.Emit(ctx, event)
}

// newRequestID returns a process-unique, monotonic identifier for correlating
// the audit events of a single Process call.
func (g *Gateway) newRequestID() string {
	return fmt.Sprintf("req_%d", atomic.AddInt64(&g.seq, 1))
}
