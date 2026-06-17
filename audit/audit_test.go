package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/technosiveuk-ui/safecall-mcp-server/core"
)

func TestWriterEmitter_EmitsJSON(t *testing.T) {
	var buf bytes.Buffer
	emitter := NewWriterEmitter(&buf)

	event := AuditEvent{
		Timestamp: time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC),
		ToolName:  "query_db",
		Action:    core.ActionBlock,
		Reason:    "strict defaults",
	}

	if err := emitter.Emit(context.Background(), event); err != nil {
		t.Fatal(err)
	}

	var decoded AuditEvent
	if err := json.NewDecoder(&buf).Decode(&decoded); err != nil {
		t.Fatalf("failed to decode emitted JSON: %v", err)
	}

	if decoded.ToolName != "query_db" {
		t.Errorf("expected tool_name 'query_db', got %q", decoded.ToolName)
	}
	if decoded.Action != core.ActionBlock {
		t.Errorf("expected action BLOCK, got %v", decoded.Action)
	}
}

// TestNewStderrAndStdoutEmitters_NonNil guards against nil-deref regressions
// for the stream-binding constructors (the JSON encoding logic itself is
// covered by TestWriterEmitter_EmitsJSON).
func TestNewStderrAndStdoutEmitters_NonNil(t *testing.T) {
	if e := NewStderrEmitter(); e == nil {
		t.Error("NewStderrEmitter returned nil")
	}
	if e := NewStdoutEmitter(); e == nil {
		t.Error("NewStdoutEmitter returned nil")
	}
}

func TestNopEmitter_NoError(t *testing.T) {
	emitter := NopEmitter{}
	err := emitter.Emit(context.Background(), AuditEvent{})
	if err != nil {
		t.Errorf("NopEmitter should never error, got: %v", err)
	}
}
