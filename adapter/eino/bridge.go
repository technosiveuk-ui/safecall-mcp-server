// Package eino is the Anti-Corruption Layer (ACL) that isolates all
// CloudWeGo Eino dependencies from the rest of the SDK.
//
// This is the ONLY package in the entire SDK that imports
// github.com/cloudwego/eino. No other package (core/, sdk/, gateway/,
// inspection/, policy/, audit/) may import Eino types.
//
// The bridge translates between:
//   - Domain side: core.InterruptError (pure Go)
//   - Eino side: compose.Interrupt (framework-specific)
package eino

import (
	"context"
	"errors"

	"github.com/cloudwego/eino/compose"
	"github.com/technosiveuk-ui/safecall-mcp-server/core"
)

// TranslateInterrupt converts a domain InterruptError into an Eino
// compose.Interrupt error. This is called when the gateway's INTERRUPT
// path needs to pause an Eino graph execution.
func TranslateInterrupt(ctx context.Context, ie *core.InterruptError) error {
	return compose.Interrupt(ctx, ie.CheckpointID)
}

// IsInterruptError checks whether an error wraps a core.InterruptError.
// This is useful for Eino graph handlers that need to detect and handle
// SafeCall interrupts.
func IsInterruptError(err error) (*core.InterruptError, bool) {
	var ie *core.InterruptError
	if errors.As(err, &ie) {
		return ie, true
	}
	return nil, false
}
