package sdk

import (
	"context"

	"github.com/technosiveuk-ui/safecall-mcp-server/gateway"
)

// FuncInvoker wraps a standard Go function with the security gateway.
// This is the primary API for securing tool functions.
//
// Usage:
//
//	secured := sdk.FuncInvoker("query_db", gw, queryDatabase)
//	// secured has the same signature as queryDatabase
//	result, err := secured(ctx, args)
func FuncInvoker(
	toolName string,
	gw *gateway.Gateway,
	fn func(ctx context.Context, args map[string]any) (string, error),
) func(ctx context.Context, args map[string]any) (string, error) {
	return gateway.FuncInvoker(toolName, gw, fn)
}
