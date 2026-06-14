# SafeCall MCP Server

<p align="center">
  <img src="assets/safecall-banner.jpg" alt="SafeCall MCP Server" width="560">
</p>

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/safecall-dev/safecall-go-sdk.svg)](https://pkg.go.dev/github.com/safecall-dev/safecall-go-sdk)

**A Secure-by-Default AI Agent Tool execution server.**

The **SafeCall MCP Server** is a production-ready implementation of the Model Context Protocol (MCP) that embeds the [SafeCall Go SDK](https://github.com/safecall-dev/safecall-go-sdk). It ensures that your AI agents cannot execute arbitrary tools without explicit permission, providing strong security guardrails out of the box.

## Features

- 🚨 **Secure-by-Default (Fail-Closed)**: Powered by `StrictDefaults()`. Any tool call without an explicitly mapped policy is immediately blocked.
- 🔒 **Built-in DLP on the Hot Path**: Arguments are actively scanned for PII/Secrets (like `api_key`) and masked with `***REDACTED***` before execution.
- ⚡ **Zero Transport Coupling**: Uses standard `github.com/modelcontextprotocol/go-sdk` for MCP JSON-RPC over `stdio`.
- 🛡️ **Policy Enforcement**: Enforces ALLOW / BLOCK / REDACT per tool.
- 📝 **Sub-millisecond overhead**: Pure Go hot path, zero framework bloat.

## Quick Start

### 1. Build the Server

```bash
go build -o server_bin ./cmd/safecall-mcp-server
```

### 2. Run the Server

To start the server using the standard input/output transport:

```bash
./server_bin
```

*(Note: Once started, the server listens for JSON-RPC messages on `stdin` and writes to `stdout`. It will appear to hang as it waits for client messages. This is the expected behavior for an MCP `stdio` server.)*

## Running the Test Client

We provide a test client to verify the security enforcement paths. Ensure you have built the `server_bin` first as shown above.

```bash
# Run the test client
go run ./cmd/testclient
```

**Expected Output:**

The test client invokes three different tools to demonstrate the three core enforcement actions:

- `queryDatabase`: **Blocked** (No policy configured, caught by `StrictDefaults()`)
- `echoTool`: **Allowed** (Explicitly mapped to `ActionAllow`)
- `processData`: **Redacted** (Built-in DLP detects the `api_key` argument and automatically scrubs it)

## Architecture

The server wraps standard Go functions using `sdk.FuncInvoker` and exposes them via `mcp.AddTool`. The SafeCall Gateway intercepts all calls before they reach your underlying logic.

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

**Key Design Decisions:**
- **Hot Path Bypass:** The ALLOW/BLOCK/REDACT paths are pure Go, targeting <20µs overhead.
- **Fail-Closed:** Any error in the pipeline defaults to BLOCK. Unrecognized tools are blocked.

## Policy Configuration

The server currently uses an in-memory `StaticProvider` to demonstrate the paths in `cmd/safecall-mcp-server/main.go`. 

For production use, you can configure the SafeCall SDK to load from a local YAML file:

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

*(Note: The SafeCall SDK enforces `0600` permissions on Unix systems for `policies.yaml` to ensure secrets at rest discipline).*

## Open-Core Interfaces

The underlying SDK defines clean interfaces for enterprise extensibility:

| Interface | OSS Implementation | Enterprise (Future) |
|---|---|---|
| `policy.Provider` | `YamlProvider` | `ControlPlaneProvider` |
| `inspection.Inspector` | `RegexInspector`, `FieldNameInspector` | `NightfallInspector` |
| `audit.Emitter` | `StdoutEmitter` | `ControlPlaneEmitter` |
| `approval.Provider` | (interface only) | `SlackProvider`, `TeamsProvider` |

## License

Apache 2.0 — see [LICENSE](LICENSE).

Copyright (c) 2026 [Technosive Ltd.](https://github.com/technosiveuk-ui)
