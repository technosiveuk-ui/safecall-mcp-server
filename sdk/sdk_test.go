package sdk

import (
	"context"
	"errors"
	"testing"

	"github.com/technosiveuk-ui/safecall-mcp-server/audit"
	"github.com/technosiveuk-ui/safecall-mcp-server/core"
	"github.com/technosiveuk-ui/safecall-mcp-server/policy"
)

func TestBuilder_StrictDefaults_BlocksUnknown(t *testing.T) {
	gw := New().
		StrictDefaults().
		Build()

	fn := func(_ context.Context, _ map[string]any) (string, error) {
		t.Error("should not be called")
		return "", nil
	}

	secured := FuncInvoker("unknown_tool", gw, fn)
	_, err := secured(context.Background(), map[string]any{})
	if err == nil {
		t.Fatal("expected BLOCK error for unregistered tool")
	}

	var blocked *core.BlockedError
	if !errors.As(err, &blocked) {
		t.Errorf("expected BlockedError, got %T: %v", err, err)
	}
}

func TestBuilder_BuiltinDLP_RedactsSSN(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"query_db": {Action: core.ActionRedact},
	})

	gw := New().
		WithPolicyProvider(provider).
		BuiltinDLP().
		WithAuditEmitter(audit.NopEmitter{}).
		Build()

	var receivedArgs map[string]any
	fn := func(_ context.Context, args map[string]any) (string, error) {
		receivedArgs = args
		return "Result", nil
	}

	secured := FuncInvoker("query_db", gw, fn)
	result, err := secured(context.Background(), map[string]any{
		"ssn":  "123-45-6789",
		"name": "John Doe",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result != "Result" {
		t.Errorf("expected 'Result', got %q", result)
	}
	if receivedArgs["ssn"] != core.RedactedPlaceholder {
		t.Errorf("expected SSN to be redacted, got %q", receivedArgs["ssn"])
	}
	if receivedArgs["name"] != "John Doe" {
		t.Errorf("expected name unchanged, got %q", receivedArgs["name"])
	}
}

func TestBuilder_AllowPath(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"hello": {Action: core.ActionAllow},
	})

	gw := New().
		WithPolicyProvider(provider).
		WithAuditEmitter(audit.NopEmitter{}).
		Build()

	fn := func(_ context.Context, args map[string]any) (string, error) {
		return "hello " + args["name"].(string), nil
	}

	secured := FuncInvoker("hello", gw, fn)
	result, err := secured(context.Background(), map[string]any{"name": "world"})
	if err != nil {
		t.Fatal(err)
	}
	if result != "hello world" {
		t.Errorf("expected 'hello world', got %q", result)
	}
}

func TestBuilder_StrictDefaultAction_Override(t *testing.T) {
	gw := New().
		StrictDefaults().
		StrictDefaultAction(core.ActionRedact).
		BuiltinDLP().
		WithAuditEmitter(audit.NopEmitter{}).
		Build()

	var receivedArgs map[string]any
	fn := func(_ context.Context, args map[string]any) (string, error) {
		receivedArgs = args
		return "ok", nil
	}

	secured := FuncInvoker("any_tool", gw, fn)
	result, err := secured(context.Background(), map[string]any{
		"ssn": "123-45-6789",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result != "ok" {
		t.Errorf("expected 'ok', got %q", result)
	}
	if receivedArgs["ssn"] != core.RedactedPlaceholder {
		t.Errorf("expected SSN redacted, got %q", receivedArgs["ssn"])
	}
}

func TestBuilder_FieldNameCatch(t *testing.T) {
	provider := policy.NewStaticProvider(map[string]*policy.Policy{
		"auth": {Action: core.ActionRedact},
	})

	gw := New().
		WithPolicyProvider(provider).
		BuiltinDLP().
		WithAuditEmitter(audit.NopEmitter{}).
		Build()

	var receivedArgs map[string]any
	fn := func(_ context.Context, args map[string]any) (string, error) {
		receivedArgs = args
		return "ok", nil
	}

	// "password" field should be caught by FieldNameInspector even though
	// the value "hunter2" doesn't match any regex pattern.
	secured := FuncInvoker("auth", gw, fn)
	_, err := secured(context.Background(), map[string]any{
		"username": "admin",
		"password": "hunter2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if receivedArgs["password"] != core.RedactedPlaceholder {
		t.Errorf("expected password redacted by field name, got %q", receivedArgs["password"])
	}
}
