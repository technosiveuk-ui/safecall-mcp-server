# Securing the Agentic Loop: Introducing the Secure-by-Default SafeCall MCP Server

As AI agents transition from simple chat interfaces to active assistants capable of executing actions in the real world, the **Model Context Protocol (MCP)** has emerged as a powerful standard. Developed by Anthropic, MCP establishes an open interface for LLMs to query databases, read local files, and trigger APIs via standardized tool calling.

However, giving an LLM direct access to system tools creates a massive security challenge. LLMs are non-deterministic black boxes, susceptible to prompt injection, logic bypasses, and unexpected inputs. If an agent is granted access to a tool like `queryDatabase` or `runTerminalCommand`, how do we guarantee it won't be manipulated into executing arbitrary queries or exfiltrating sensitive credentials?

To address this, we are excited to release the **SafeCall MCP Server**—a secure-by-default, production-ready implementation of MCP that acts as a runtime firewall for AI tool executions.

---

## The Core Security Gap in MCP

In a standard MCP architecture, the client (such as Claude Desktop or a custom LLM orchestration framework) requests a tool execution from the MCP Server. The server executes the corresponding command and returns the response.

```
┌─────────────────┐                    ┌───────────────────┐
│   MCP Client    ├───────────────────►│    MCP Server     │
│   (LLM/Agent)   │   JSON-RPC (Stdio) │ (Executes Tool)   │
└─────────────────┘                    └───────────────────┘
```

This model assumes the client is trusted and the agent behaves predictably. But in reality:
1. **Unconstrained Tool Access**: If a server exposes 20 tools, a compromised or confused agent can invoke *any* of them, even those irrelevant to the active task context.
2. **Secrets & PII Exfiltration**: A prompt injection attack can trick the LLM into fetching sensitive user data or API keys and passing them to an external tool.
3. **No Safety Guardrails**: There is no interception layer to validate arguments, redact secrets, or block unauthorized tools *before* they are sent to the system.

---

## Introducing SafeCall MCP Server

The **SafeCall MCP Server** plugs this security gap by embedding the **SafeCall Go SDK**. It acts as an inline gateway (a "runtime firewall") that sits between the incoming JSON-RPC tool calls and your underlying Go execution code.

```
┌─────────────────────────────────────────────────────┐
│                 MCP Client (LLM)                    │
└──────────────────────┬──────────────────────────────┘
                       │ JSON-RPC (stdio)
┌──────────────────────▼──────────────────────────────┐
│               SafeCall MCP Server                   │
│                                                     │
│  ┌──────────────────────────────────────────────┐   │
│  │               SafeCall Gateway               │   │
│  │ inspect → evaluate → (allow|block|redact)    │   │
│  └───────────────────┬──────────────────────────┘   │
│                      │                              │
│  ┌───────────────────▼──────────────────────────┐   │
│  │          Underlying Go Function              │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

### Core Security Features

#### 1. Secure-by-Default (Strict Defaults)
In security, trust is earned, not assumed. The SafeCall MCP Server uses a **fail-closed** paradigm. By calling `.StrictDefaults()`, the security engine blocks any incoming tool request unless there is an explicit policy mapped to it. 
* If the LLM tries to call a tool named `queryDatabase` but no policy exists for it, SafeCall instantly blocks it and throws an authorization error—preventing accidental tool exposure.

#### 2. In-Flight Data Loss Prevention (DLP)
Sensitive variables like API keys, database credentials, Social Security Numbers, or credit cards can easily leak into LLM prompts and context windows. SafeCall scans incoming tool arguments on the hot path. If it detects a secret or PII, it automatically scrubs the argument with `***REDACTED***` before the tool executes.

#### 3. Low-Latency Execution
Adding security should not degrade the responsiveness of AI interactions. SafeCall is implemented in pure Go with zero framework bloat. The intercept-evaluate-redact pipeline executes in **under 20 microseconds (µs)** on the hot path, ensuring no perceptible latency is added to the agentic loop.

---

## How it Works: Code Walkthrough

Let’s look at how the SafeCall MCP Server is built. We instantiate a policy provider, configure the security gateway, wrap our sensitive functions, and register them with the official MCP Go SDK.

### 1. Configure the Gateway and Policies
First, we establish our security policy. In this example, we explicitly allow `echoTool`, set `processData` to redact secrets, and leave `queryDatabase` completely unmapped to trigger our strict defaults policy:

```go
package main

import (
	"context"
	"encoding/json"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/technosiveuk-ui/safecall-mcp-server/core"
	"github.com/technosiveuk-ui/safecall-mcp-server/policy"
	"github.com/technosiveuk-ui/safecall-mcp-server/sdk"
)

func main() {
	// 1. Build an in-memory policy provider
	staticProvider := policy.NewStaticProvider(map[string]*policy.Policy{
		"echoTool": {
			Action: core.ActionAllow,
		},
		"processData": {
			Action:       core.ActionRedact,
			RedactFields: []string{"secret_key"},
		},
		// "queryDatabase" is omitted to demonstrate StrictDefaults (BLOCK)
	})

	// 2. Build the SafeCall Security Gateway
	gw := sdk.New().
		WithPolicyProvider(staticProvider).
		StrictDefaults(). // Unmapped tools default to BLOCK (fail-closed)
		BuiltinDLP().     // Activate default PII and secrets scanning regexes
		Build()
```

### 2. Wrap and Expose Your Tools
Next, we wrap our Go functions using `sdk.FuncInvoker` and expose them to the MCP Server:

```go
	// 3. Wrap raw Go functions with the gateway
	securedQueryDB := sdk.FuncInvoker("queryDatabase", gw, queryDatabase)
	securedEcho := sdk.FuncInvoker("echoTool", gw, echoTool)
	securedProcess := sdk.FuncInvoker("processData", gw, processData)

	// 4. Initialize standard MCP Server
	server := mcp.NewServer(&mcp.Implementation{Name: "safecall-secure-server"}, nil)

	// Register the secured tools using standard mcp.AddTool
	mcp.AddTool(server, &mcp.Tool{
		Name:        "processData",
		Description: "Processes some data.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args processArgs) (*mcp.CallToolResult, any, error) {
		// Convert args to map[string]any for the gateway to inspect
		b, _ := json.Marshal(args)
		var mapArgs map[string]any
		json.Unmarshal(b, &mapArgs)

		// Invoking the tool through the security wrapper
		result, err := securedProcess(ctx, mapArgs)
		if err != nil {
			return nil, nil, err // Fails safe if blocked or error occurs
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: result}}}, nil, nil
	})
```

---

## Production Policies via YAML

While in-memory static policies are great for local testing, the SafeCall MCP Server can dynamically load policies from a local YAML file.

```go
provider, err := policy.NewYamlProvider("policies.yaml")
gw := sdk.New().
    WithPolicyProvider(provider).
    StrictDefaults().
    BuiltinDLP().
    Build()
```

### Example `policies.yaml`
```yaml
tools:
  query_db:
    action: REDACT
    redact_fields:
      - ssn
      - credit_card
  send_slack_message:
    action: ALLOW
  delete_database:
    action: BLOCK
```

To ensure your policies aren't tampered with, SafeCall enforces strict Unix permissions (`0600`) on the configuration files, maintaining high standards of secrets-at-rest hygiene.

---

## Architected for Enterprise Extensibility

The SafeCall SDK features a modular, open-core design that defines clear interfaces, paving the way for future enterprise-grade extensions:

| Interface | Open Source Implementation | Enterprise Roadmap |
|---|---|---|
| `policy.Provider` | `YamlProvider`, `StaticProvider` | Centralized Control Plane Provider |
| `inspection.Inspector` | `RegexInspector`, `FieldNameInspector` | Advanced DLP (e.g., Nightfall, Presidio) |
| `audit.Emitter` | `StdoutEmitter` | Cloud Audit Logs (SIEM / Splunk / Datadog) |
| `approval.Provider` | (Interface defined) | Human-in-the-Loop Slack / Teams prompts |

---

## Get Started Today

Secure tool execution is the missing link in reliable agentic architectures. By enforcing strict defaults, validating arguments, and redacting sensitive data at the SDK layer, you can deploy AI agents that execute tools with confidence.

Explore the repository, try the built-in test client, and build your own secure-by-default MCP Server:

👉 **GitHub Repository**: [technosiveuk-ui/safecal-mcp-server](https://github.com/technosiveuk-ui/safecal-mcp-server)  
👉 **SafeCall Go SDK**: [technosiveuk-ui/safecall-mcp-server](https://github.com/technosiveuk-ui/safecall-mcp-server)

Join our community and help us build a safer, more secure future for agentic AI!
