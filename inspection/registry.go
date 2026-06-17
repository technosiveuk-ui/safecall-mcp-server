package inspection

import (
	"context"

	"github.com/technosiveuk-ui/safecall-mcp-server/core"
)

// Registry chains multiple Inspectors and aggregates their findings.
// It is safe for concurrent use (the inspector slice is immutable after construction).
type Registry struct {
	inspectors []Inspector
}

// NewRegistry creates a Registry with the given inspectors.
func NewRegistry(inspectors ...Inspector) *Registry {
	// Defensive copy to prevent mutation after construction.
	dst := make([]Inspector, len(inspectors))
	copy(dst, inspectors)
	return &Registry{inspectors: dst}
}

// Inspect runs every registered Inspector sequentially and returns the
// aggregated list of findings.
func (r *Registry) Inspect(ctx context.Context, fields map[string]any) ([]core.Finding, error) {
	var all []core.Finding
	for _, insp := range r.inspectors {
		findings, err := insp.Inspect(ctx, fields)
		if err != nil {
			return nil, err
		}
		all = append(all, findings...)
	}
	return all, nil
}
