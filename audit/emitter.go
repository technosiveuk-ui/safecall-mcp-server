// Package audit defines the AuditEvent type and the pluggable Emitter
// interface. The SDK never writes directly to stdout or files — all audit
// output flows through an Emitter implementation.
package audit

import (
	"context"
	"time"

	"github.com/technosiveuk-ui/safecall-mcp-server/core"
)

// AuditEvent records a single enforcement decision.
type AuditEvent struct {
	// Timestamp is when the decision was made.
	Timestamp time.Time `json:"timestamp"`

	// ToolName identifies the tool that was called.
	ToolName string `json:"tool_name"`

	// RequestID is a process-unique identifier for the single Process call this
	// event records. Use it to correlate audit events (e.g. an INTERRUPT and its
	// later resume, or repeated findings) and to join with application logs.
	RequestID string `json:"request_id,omitempty"`

	// Action is the enforcement action taken (ALLOW, BLOCK, REDACT, INTERRUPT).
	Action core.Action `json:"action"`

	// Reason explains why this action was taken.
	Reason string `json:"reason,omitempty"`

	// Findings lists all sensitive-data detections.
	Findings []core.Finding `json:"findings,omitempty"`

	// CheckpointID is set only for INTERRUPT events.
	CheckpointID string `json:"checkpoint_id,omitempty"`

	// Duration is how long the tool execution took (zero for BLOCK/INTERRUPT).
	Duration time.Duration `json:"duration_ns"`

	// Error is populated if the tool execution returned an error.
	Error string `json:"error,omitempty"`
}

// Emitter is the interface for audit event output. Implementations must
// be safe for concurrent use.
type Emitter interface {
	// Emit writes a single audit event.
	Emit(ctx context.Context, event AuditEvent) error
}

// NopEmitter silently discards all events. Used when no emitter is configured.
type NopEmitter struct{}

// Emit discards the event.
func (NopEmitter) Emit(_ context.Context, _ AuditEvent) error { return nil }
