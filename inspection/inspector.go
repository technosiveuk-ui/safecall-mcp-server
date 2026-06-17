// Package inspection implements Data Loss Prevention (DLP) scanning for
// tool-call arguments and responses. It defines the Inspector interface and
// ships built-in inspectors for regex-based PII detection and field-name
// catching.
package inspection

import (
	"context"

	"github.com/technosiveuk-ui/safecall-mcp-server/core"
)

// Inspector scans a set of key-value fields and returns any sensitive-data
// findings. Implementations must be safe for concurrent use.
type Inspector interface {
	// Inspect examines the given fields and returns findings.
	// The prefix parameter is used for nested field attribution
	// (e.g. "user." when recursing into a nested map).
	Inspect(ctx context.Context, fields map[string]any) ([]core.Finding, error)
}
