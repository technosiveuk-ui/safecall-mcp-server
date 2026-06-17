package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/technosiveuk-ui/safecall-mcp-server/core"
)

func TestStaticProvider_MatchesPolicy(t *testing.T) {
	provider := NewStaticProvider(map[string]*Policy{
		"query_db": {Action: core.ActionRedact, RedactFields: []string{"ssn"}},
	})

	pol, err := provider.PolicyFor(context.Background(), "query_db")
	if err != nil {
		t.Fatal(err)
	}
	if pol == nil {
		t.Fatal("expected policy, got nil")
	}
	if pol.Action != core.ActionRedact {
		t.Errorf("expected REDACT, got %v", pol.Action)
	}
}

func TestStaticProvider_NoMatch(t *testing.T) {
	provider := NewStaticProvider(map[string]*Policy{})
	pol, err := provider.PolicyFor(context.Background(), "unknown_tool")
	if err != nil {
		t.Fatal(err)
	}
	if pol != nil {
		t.Errorf("expected nil policy for unknown tool, got %+v", pol)
	}
}

func TestEvaluator_StrictDefaults_Block(t *testing.T) {
	provider := NewStaticProvider(map[string]*Policy{})
	eval := NewEvaluator(provider, WithStrictDefaults())

	decision, err := eval.Evaluate(context.Background(), "unknown_tool", nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != core.ActionBlock {
		t.Errorf("expected BLOCK for unmapped tool with strict defaults, got %v", decision.Action)
	}
}

func TestEvaluator_StrictDefaults_CustomAction(t *testing.T) {
	provider := NewStaticProvider(map[string]*Policy{})
	eval := NewEvaluator(provider,
		WithStrictDefaults(),
		WithDefaultAction(core.ActionRedact),
	)

	decision, err := eval.Evaluate(context.Background(), "unknown_tool", nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != core.ActionRedact {
		t.Errorf("expected REDACT for custom strict default, got %v", decision.Action)
	}
}

func TestEvaluator_ExplicitPolicy(t *testing.T) {
	provider := NewStaticProvider(map[string]*Policy{
		"delete_db": {Action: core.ActionInterrupt},
	})
	eval := NewEvaluator(provider, WithStrictDefaults())

	decision, err := eval.Evaluate(context.Background(), "delete_db", nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != core.ActionInterrupt {
		t.Errorf("expected INTERRUPT, got %v", decision.Action)
	}
}

func TestEvaluator_FailClosed_NilProvider(t *testing.T) {
	eval := NewEvaluator(nil, WithStrictDefaults())
	decision, err := eval.Evaluate(context.Background(), "any_tool", nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != core.ActionBlock {
		t.Errorf("expected BLOCK when no provider, got %v", decision.Action)
	}
}

func TestEvaluator_EscalatesToRedact(t *testing.T) {
	provider := NewStaticProvider(map[string]*Policy{})
	eval := NewEvaluator(provider) // no strict defaults — permissive mode

	findings := []core.Finding{{FieldName: "ssn", Category: "PII/SSN"}}
	decision, err := eval.Evaluate(context.Background(), "query_db", findings)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != core.ActionRedact {
		t.Errorf("expected REDACT escalation due to findings, got %v", decision.Action)
	}
}

func TestYamlProvider_BadPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.yaml")
	content := []byte("tools:\n  test:\n    action: ALLOW\n")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := NewYamlProvider(path)
	if err == nil {
		t.Fatal("expected error for 0644 permissions")
	}
}

func TestYamlProvider_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.yaml")
	content := []byte(`tools:
  query_db:
    action: REDACT
    redact_fields:
      - ssn
  send_message:
    action: ALLOW
`)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}

	provider, err := NewYamlProvider(path)
	if err != nil {
		t.Fatal(err)
	}

	pol, err := provider.PolicyFor(context.Background(), "query_db")
	if err != nil {
		t.Fatal(err)
	}
	if pol == nil {
		t.Fatal("expected policy for query_db")
	}
	if pol.Action != core.ActionRedact {
		t.Errorf("expected REDACT, got %v", pol.Action)
	}
	if len(pol.RedactFields) != 1 || pol.RedactFields[0] != "ssn" {
		t.Errorf("expected redact_fields [ssn], got %v", pol.RedactFields)
	}
}

// TestEvaluator_ExplicitAllow_AttachesFindingsButDoesNotEscalate documents
// the CURRENT, PRD-compliant behaviour around GAP-003: an explicitly-ALLOWed
// tool that carries sensitive findings is ALLOWED through, with the findings
// attached to the decision (so they appear in the audit trail) but NOT
// auto-escalated to REDACT. The PRD does not require escalation on an explicit
// ALLOW; it is tracked only as a future consistency consideration
// (UAT_PLAN.md §5.5, GAP-003).
//
// If product later decides an explicit ALLOW + finding should escalate to
// REDACT (for parity with the no-policy path in TestEvaluator_EscalatesToRedact),
// flip the assertion below to ActionRedact and route the explicit-match branch
// in policy/evaluator.go through decisionForFindings.
func TestEvaluator_ExplicitAllow_AttachesFindingsButDoesNotEscalate(t *testing.T) {
	provider := NewStaticProvider(map[string]*Policy{
		"send_message": {Action: core.ActionAllow},
	})
	eval := NewEvaluator(provider)

	findings := []core.Finding{{FieldName: "api_key", Category: "SECRET/API_KEY"}}
	decision, err := eval.Evaluate(context.Background(), "send_message", findings)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != core.ActionAllow {
		t.Errorf("expected explicit ALLOW to hold (current behaviour), got %v", decision.Action)
	}
	if len(decision.Findings) == 0 {
		t.Error("expected the sensitive finding to be attached to the decision for audit")
	}
}
