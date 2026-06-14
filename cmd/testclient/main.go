package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	ctx := context.Background()

	// Connect to the SafeCall MCP Server
	clientTransport := &mcp.CommandTransport{
		Command: exec.Command("./server_bin"),
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "safecall-test-client"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer clientSession.Close()

	fmt.Println("Successfully connected to SafeCall MCP Server!")
	fmt.Println("------------------------------------------------")

	// Test 1: queryDatabase (Expected: BLOCK)
	fmt.Println("1. Calling 'queryDatabase' tool (Expect: Blocked by StrictDefaults)")
	res, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "queryDatabase",
		Arguments: map[string]any{
			"query": "SELECT * FROM users",
			"table": "users",
		},
	})
	printResult(res, err)

	// Test 2: echoTool (Expected: ALLOW)
	fmt.Println("\n2. Calling 'echoTool' tool (Expect: Allowed)")
	res, err = clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "echoTool",
		Arguments: map[string]any{
			"message": "Hello World!",
		},
	})
	printResult(res, err)

	// Test 3: processData (Expected: REDACT)
	fmt.Println("\n3. Calling 'processData' tool (Expect: api_key to be Redacted)")
	res, err = clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name: "processData",
		Arguments: map[string]any{
			"data":    "Some harmless data",
			"api_key": "super-secret-123",
		},
	})
	printResult(res, err)
}

func printResult(res *mcp.CallToolResult, err error) {
	if err != nil {
		fmt.Printf("   -> Error: %v\n", err)
		return
	}
	
	text := ""
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			text = tc.Text
		}
	}

	if res.IsError {
		fmt.Printf("   -> Rejected (IsError=true):\n      %v\n", text)
	} else {
		fmt.Printf("   -> Succeeded:\n      %v\n", text)
	}
}
