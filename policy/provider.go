// Package policy implements the policy evaluation engine. It defines the
// Provider interface (the open-core seam for enterprise policy backends)
// and ships a YamlProvider for local file-based policy configuration.
package policy

import (
	"context"

	"github.com/technosiveuk-ui/safecall-mcp-server/core"
)

// Policy defines the enforcement rules for a specific tool.
type Policy struct {
	// Action is the enforcement action to take.
	Action core.Action `yaml:"action" json:"action"`

	// RedactFields lists field names that should be redacted. Only meaningful
	// when Action == ActionRedact.
	RedactFields []string `yaml:"redact_fields,omitempty" json:"redact_fields,omitempty"`
}

// Provider loads policies for tool names. Implementations must be safe
// for concurrent use.
type Provider interface {
	// PolicyFor returns the policy for the named tool, or nil if no policy
	// is defined. A nil policy means "no explicit rule" — the Evaluator
	// decides whether to apply strict defaults.
	PolicyFor(ctx context.Context, toolName string) (*Policy, error)
}
