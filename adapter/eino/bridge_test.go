package eino

import (
	"errors"
	"testing"

	"github.com/technosiveuk-ui/safecall-mcp-server/core"
)

func TestIsInterruptError_Match(t *testing.T) {
	ie := &core.InterruptError{
		CheckpointID: "cp_test_123",
		ToolName:     "delete_db",
		Reason:       "requires approval",
	}

	result, ok := IsInterruptError(ie)
	if !ok {
		t.Fatal("expected IsInterruptError to return true")
	}
	if result.CheckpointID != "cp_test_123" {
		t.Errorf("expected checkpoint 'cp_test_123', got %q", result.CheckpointID)
	}
}

func TestIsInterruptError_NoMatch(t *testing.T) {
	err := errors.New("some other error")
	_, ok := IsInterruptError(err)
	if ok {
		t.Error("expected IsInterruptError to return false for non-interrupt error")
	}
}
