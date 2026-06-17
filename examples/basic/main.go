// Package main demonstrates the SafeCall SDK usage matching the PRD §7
// target usage example.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/technosiveuk-ui/safecall-mcp-server/sdk"
)

// queryDatabase is a raw, unprotected function that simulates a DB query.
func queryDatabase(ctx context.Context, args map[string]any) (string, error) {
	return fmt.Sprintf("Query result for: %v", args), nil
}

func main() {
	// 1. Build the security engine
	gw := sdk.New().
		StrictDefaults(). // Unmapped tools default to BLOCK
		BuiltinDLP().     // Load default PII/Secret regexes
		StdoutAudit().    // Log decisions to stdout
		Build()

	// 2. Wrap the function
	securedQueryDB := sdk.FuncInvoker("query_db", gw, queryDatabase)

	// 3. Test: call with sensitive data — should be blocked (no policy for query_db)
	fmt.Println("=== Test 1: Strict Defaults (BLOCK unregistered tool) ===")
	_, err := securedQueryDB(context.Background(), map[string]any{
		"ssn":  "123-45-6789",
		"name": "John Doe",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Blocked as expected: %v\n\n", err)
	}

	// 4. Test: call a completely unknown tool
	fmt.Println("=== Test 2: Unknown tool (BLOCK) ===")
	unknownTool := sdk.FuncInvoker("drop_tables", gw, func(_ context.Context, _ map[string]any) (string, error) {
		return "DROPPED!", nil
	})
	_, err = unknownTool(context.Background(), map[string]any{"table": "users"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Blocked as expected: %v\n\n", err)
	}

	fmt.Println("=== SafeCall SDK demo complete ===")
}
