package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/technosiveuk-ui/safecall-mcp-server/audit"
	"github.com/technosiveuk-ui/safecall-mcp-server/core"
	"github.com/technosiveuk-ui/safecall-mcp-server/inspection"
	"github.com/technosiveuk-ui/safecall-mcp-server/policy"
)

func newTestGateway(provider policy.Provider, strictDefaults bool, inspectors ...inspection.Inspector) (*Gateway, *bytes.Buffer) {
	var opts []policy.EvaluatorOption
	if strictDefaults {
		opts = append(opts, policy.WithStrictDefaults())
	}
	eval := policy.NewEvaluator(provider, opts...)

	var reg *inspection.Registry
	if len(inspectors) > 0 {
		reg = inspection.NewRegistry(inspectors...)
	}

	var buf bytes.Buffer
	emitter := audit.NewWriterEmitter(&buf)

	gw := New(eval, reg, emitter)
	return gw, &buf
}

func TestProcess_AllowPath(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"hello": {Action: core.ActionAllow},
	})
	gw, auditBuf := newTestGateway(provider, false)

	called := false
	fn := func(_ context.Context, args map[string]any) (string, error) {
		called = true
		return "world", nil
	}

	result, err := gw.Process(context.Background(), "hello", map[string]any{"name": "test"}, fn)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("expected function to be called")
	}
	if result != "world" {
		t.Errorf("expected 'world', got %q", result)
	}

	// Verify audit was emitted.
	var event audit.AuditEvent
	if err := json.NewDecoder(auditBuf).Decode(&event); err != nil {
		t.Fatalf("no audit event emitted: %v", err)
	}
	if event.Action != core.ActionAllow {
		t.Errorf("expected ALLOW audit, got %v", event.Action)
	}
}

func TestProcess_BlockPath(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"danger": {Action: core.ActionBlock},
	})
	gw, _ := newTestGateway(provider, false)

	called := false
	fn := func(_ context.Context, _ map[string]any) (string, error) {
		called = true
		return "", nil
	}

	_, err := gw.Process(context.Background(), "danger", map[string]any{}, fn)
	if err == nil {
		t.Fatal("expected error for BLOCK")
	}
	if called {
		t.Error("function should not have been called for BLOCK")
	}

	var blocked *core.BlockedError
	if !errors.As(err, &blocked) {
		t.Errorf("expected BlockedError, got %T: %v", err, err)
	}
}

func TestProcess_RedactPath(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"query_db": {Action: core.ActionRedact},
	})
	gw, _ := newTestGateway(provider, false, inspection.NewRegexInspector())

	var receivedArgs map[string]any
	fn := func(_ context.Context, args map[string]any) (string, error) {
		receivedArgs = args
		return "ok", nil
	}

	args := map[string]any{"ssn": "123-45-6789", "name": "John"}
	result, err := gw.Process(context.Background(), "query_db", args, fn)
	if err != nil {
		t.Fatal(err)
	}
	if result != "ok" {
		t.Errorf("expected 'ok', got %q", result)
	}
	if receivedArgs["ssn"] != core.RedactedPlaceholder {
		t.Errorf("expected SSN to be redacted, got %q", receivedArgs["ssn"])
	}
	if receivedArgs["name"] != "John" {
		t.Errorf("expected 'name' to be unchanged, got %q", receivedArgs["name"])
	}
}

func TestProcess_StrictDefaults_Block(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{})
	gw, _ := newTestGateway(provider, true)

	called := false
	fn := func(_ context.Context, _ map[string]any) (string, error) {
		called = true
		return "", nil
	}

	_, err := gw.Process(context.Background(), "unregistered_tool", map[string]any{}, fn)
	if err == nil {
		t.Fatal("expected BLOCK for unregistered tool with strict defaults")
	}
	if called {
		t.Error("function should not have been called")
	}
}

func TestProcess_InterruptPath(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"delete_db": {Action: core.ActionInterrupt},
	})
	gw, _ := newTestGateway(provider, false)

	fn := func(_ context.Context, _ map[string]any) (string, error) {
		t.Error("function should not be called for INTERRUPT")
		return "", nil
	}

	_, err := gw.Process(context.Background(), "delete_db", map[string]any{}, fn)
	if err == nil {
		t.Fatal("expected InterruptError")
	}

	var ie *core.InterruptError
	if !errors.As(err, &ie) {
		t.Errorf("expected InterruptError, got %T: %v", err, err)
	}
	if ie.ToolName != "delete_db" {
		t.Errorf("expected tool 'delete_db', got %q", ie.ToolName)
	}
}

func TestFuncInvoker(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"greet": {Action: core.ActionAllow},
	})
	gw, _ := newTestGateway(provider, false)

	original := func(_ context.Context, args map[string]any) (string, error) {
		return "hello " + args["name"].(string), nil
	}

	wrapped := FuncInvoker("greet", gw, original)
	result, err := wrapped(context.Background(), map[string]any{"name": "world"})
	if err != nil {
		t.Fatal(err)
	}
	if result != "hello world" {
		t.Errorf("expected 'hello world', got %q", result)
	}
}

func TestRedactField_Nested(t *testing.T) {
	args := map[string]any{
		"user": map[string]any{
			"ssn": "123-45-6789",
		},
	}
	redactField(args, "user.ssn", core.RedactedPlaceholder)

	user := args["user"].(map[string]any)
	if user["ssn"] != core.RedactedPlaceholder {
		t.Errorf("expected nested field to be redacted, got %q", user["ssn"])
	}
}

// BenchmarkAllowPath verifies NFR2: ALLOW path overhead must be < 20µs.
func BenchmarkAllowPath(b *testing.B) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"fast_tool": {Action: core.ActionAllow},
	})
	eval := policy.NewEvaluator(provider)
	gw := New(eval, nil, audit.NopEmitter{})

	fn := func(_ context.Context, _ map[string]any) (string, error) {
		return "ok", nil
	}
	args := map[string]any{"key": "value"}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = gw.Process(ctx, "fast_tool", args, fn)
	}
}

// TestProcess_ResponseInspection_RedactsSensitiveResponse covers GAP-002
// (PRD FR3 outbound response inspection), opt-in via WithResponseInspection.
func TestProcess_ResponseInspection_RedactsSensitiveResponse(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"lookup": {Action: core.ActionAllow},
	})
	gw, auditBuf := newTestGateway(provider, false, inspection.NewRegexInspector())
	gw.WithResponseInspection() // opt-in (GAP-002)

	fn := func(_ context.Context, _ map[string]any) (string, error) {
		return "Customer record: SSN 123-45-6789", nil
	}

	result, err := gw.Process(context.Background(), "lookup", map[string]any{}, fn)
	if err != nil {
		t.Fatal(err)
	}
	if result != core.RedactedPlaceholder {
		t.Errorf("GAP-002: expected response containing SSN to be masked, got %q", result)
	}

	// The response finding must be recorded in the audit event.
	var event audit.AuditEvent
	if err := json.NewDecoder(auditBuf).Decode(&event); err != nil {
		t.Fatalf("no audit event emitted: %v", err)
	}
	if len(event.Findings) == 0 {
		t.Error("expected response finding recorded in audit event")
	}
}

// TestAudit_NeverLeaksSecrets is the regression test for the SafeCall core
// security invariant: a secret detected in the arguments MUST NOT appear in the
// serialized audit output, under any Emitter. The raw plaintext is replaced by
// a non-reversible Fingerprint for correlation. We assert against the raw
// emitted bytes (not just decoded fields) so a forgotten field tag can never
// silently re-introduce the leak.
func TestAudit_NeverLeaksSecrets(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"query_db": {Action: core.ActionRedact},
	})
	gw, auditBuf := newTestGateway(provider, false, inspection.NewRegexInspector())

	const secret = "123-45-6789" // realistic SSN
	fn := func(_ context.Context, _ map[string]any) (string, error) {
		return "ok", nil
	}

	_, err := gw.Process(context.Background(), "query_db",
		map[string]any{"ssn": secret, "name": "John"}, fn)
	if err != nil {
		t.Fatal(err)
	}

	raw := auditBuf.String()

	// 1. The plaintext secret must never be present in the serialized audit.
	if strings.Contains(raw, secret) {
		t.Fatalf("SECURITY: plaintext secret %q leaked into audit output:\n%s", secret, raw)
	}

	// 2. The original_value field must not be serialized at all.
	if strings.Contains(raw, "original_value") {
		t.Fatalf("SECURITY: original_value must never be serialized; got:\n%s", raw)
	}

	// 3. Decoded event must carry a non-empty fingerprint (correlation) and no
	//    original value.
	var event audit.AuditEvent
	if err := json.NewDecoder(strings.NewReader(raw)).Decode(&event); err != nil {
		t.Fatalf("failed to decode audit event: %v", err)
	}
	if len(event.Findings) == 0 {
		t.Fatal("expected at least one finding in audit event")
	}
	for _, f := range event.Findings {
		if f.OriginalValue != "" {
			t.Errorf("finding %q: original_value must be empty in audit, got %q", f.FieldName, f.OriginalValue)
		}
		if f.Fingerprint == "" {
			t.Errorf("finding %q: expected non-empty fingerprint for correlation", f.FieldName)
		}
	}
}

// TestAudit_RecordsForensicContext verifies the audit event carries the
// forensic detail required for security operations: a non-empty Reason (why the
// decision was made), a non-empty RequestID (correlation), and the execution
// Error when the underlying tool fails.
func TestAudit_RecordsForensicContext(t *testing.T) {
	// BLOCK path: reason + request id must be recorded.
	blockProvider := policy.NewStaticProvider(map[string]*policy.Policy{
		"denied": {Action: core.ActionBlock},
	})
	gw, auditBuf := newTestGateway(blockProvider, false)
	_, err := gw.Process(context.Background(), "denied", map[string]any{}, func(context.Context, map[string]any) (string, error) {
		t.Error("exec should not run on BLOCK")
		return "", nil
	})
	if err == nil {
		t.Fatal("expected BLOCK error")
	}
	var blockEvent audit.AuditEvent
	if err := json.NewDecoder(auditBuf).Decode(&blockEvent); err != nil {
		t.Fatalf("decode block audit: %v", err)
	}
	if blockEvent.Reason == "" {
		t.Error("BLOCK audit event must record a non-empty Reason")
	}
	if blockEvent.RequestID == "" {
		t.Error("BLOCK audit event must record a non-empty RequestID")
	}

	// ALLOW path with a failing tool: execution error must be recorded.
	failProvider := policy.NewStaticProvider(map[string]*policy.Policy{
		"flaky": {Action: core.ActionAllow},
	})
	gw2, auditBuf2 := newTestGateway(failProvider, false)
	execErr := errors.New("connection reset")
	_, err = gw2.Process(context.Background(), "flaky", map[string]any{}, func(context.Context, map[string]any) (string, error) {
		return "", execErr
	})
	if !errors.Is(err, execErr) {
		t.Fatalf("expected exec error to propagate, got %v", err)
	}
	var allowEvent audit.AuditEvent
	if err := json.NewDecoder(auditBuf2).Decode(&allowEvent); err != nil {
		t.Fatalf("decode allow audit: %v", err)
	}
	if allowEvent.RequestID == "" {
		t.Error("ALLOW audit event must record a non-empty RequestID")
	}
	if allowEvent.Error != execErr.Error() {
		t.Errorf("expected audit Error %q, got %q", execErr.Error(), allowEvent.Error)
	}
}

// TestProcess_PolicyRedactFields_RedactsDeclaredFields verifies that fields a
// policy explicitly lists under redact_fields are redacted even when no
// inspector flagged them (the value is benign and the field name is not a known
// sensitive keyword). Covers flat paths, nested (dot) paths, and that absent
// fields are silently skipped without producing spurious findings.
func TestProcess_PolicyRedactFields_RedactsDeclaredFields(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"export": {
			Action:       core.ActionRedact,
			RedactFields: []string{"internal_token", "credentials.api_key", "does_not_exist"},
		},
	})
	// No inspectors: isolate policy-driven redaction from DLP findings.
	gw, auditBuf := newTestGateway(provider, false)

	var received map[string]any
	fn := func(_ context.Context, args map[string]any) (string, error) {
		received = args
		return "ok", nil
	}

	args := map[string]any{
		"internal_token": "supersecret-value", // benign value, non-keyword name → only policy redacts
		"name":           "John",
		"credentials":    map[string]any{"api_key": "sk_live_abc"},
	}
	if _, err := gw.Process(context.Background(), "export", args, fn); err != nil {
		t.Fatal(err)
	}

	// Flat field redacted; nested field redacted; untouched field preserved.
	if received["internal_token"] != core.RedactedPlaceholder {
		t.Errorf("expected policy redact_fields to mask 'internal_token', got %v", received["internal_token"])
	}
	if received["name"] != "John" {
		t.Errorf("expected 'name' to be preserved, got %v", received["name"])
	}
	creds := received["credentials"].(map[string]any)
	if creds["api_key"] != core.RedactedPlaceholder {
		t.Errorf("expected nested 'credentials.api_key' to be masked, got %v", creds["api_key"])
	}

	// Audit records a finding per present policy field (absent field skipped).
	var event audit.AuditEvent
	if err := json.NewDecoder(auditBuf).Decode(&event); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	seen := map[string]bool{}
	for _, f := range event.Findings {
		if f.Category != "POLICY/REDACT_FIELD" {
			t.Errorf("expected POLICY/REDACT_FIELD category, got %q", f.Category)
		}
		if f.Fingerprint == "" {
			t.Errorf("finding %q: expected non-empty fingerprint", f.FieldName)
		}
		seen[f.FieldName] = true
	}
	if !seen["internal_token"] || !seen["credentials.api_key"] {
		t.Errorf("expected findings for internal_token and credentials.api_key, got %v", seen)
	}
	if seen["does_not_exist"] {
		t.Error("absent field should not produce a finding")
	}
}

// TestProcess_ResponseInspection_OffByDefault confirms the stub is opt-in so
// the hot path (NFR2 <20µs) and existing behaviour are unchanged.
func TestProcess_ResponseInspection_OffByDefault(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"lookup": {Action: core.ActionAllow},
	})
	gw, _ := newTestGateway(provider, false, inspection.NewRegexInspector())
	// NOTE: WithResponseInspection() intentionally NOT called.

	fn := func(_ context.Context, _ map[string]any) (string, error) {
		return "SSN 123-45-6789", nil
	}
	result, err := gw.Process(context.Background(), "lookup", map[string]any{}, fn)
	if err != nil {
		t.Fatal(err)
	}
	if result != "SSN 123-45-6789" {
		t.Errorf("response inspection off by default; expected raw response, got %q", result)
	}
}
