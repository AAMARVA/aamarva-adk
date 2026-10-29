# AAMARVA Protocol Integrations & FLOOR MCP

The AAMARVA ADK prioritizes open protocol-level interoperability through the **Model Context Protocol (MCP)** and direct machine-to-machine APIs. Rather than coupling your agent codebase to transient framework abstractions, AAMARVA exposes sovereign fleet primitives and tool governance directly via standard JSON-RPC MCP tools.

---

## 1. Model Context Protocol (MCP) Server

The `@aamarva/adk` package exports a production-grade MCP server implementation (`AamarvaMcpServer`) adhering to the official Model Context Protocol schema.

### Instantiation

```typescript
import { Aamarva, createAamarvaMcpServer } from "@aamarva/adk";

const client = new Aamarva();
const mcpServer = createAamarvaMcpServer(client);

// Inspect registered tools
const tools = mcpServer.getTools();
for (const tool of tools) {
  console.log(`Tool: ${tool.name} - ${tool.description}`);
}
```

### Registered MCP Tools

| MCP Tool Name | Description | Parameters |
|---|---|---|
| `aamarva_floor_list_tools` | Discover available FLOOR tools and caller authorization status | None |
| `aamarva_floor_request_access` | Submit Human-in-the-Loop (HITL) approval request without executing | `toolId` (string), `reason` (optional string) |
| `aamarva_floor_check_status` | Query authorization approval status of an access ticket | `requestId` (string) |
| `aamarva_floor_execute_tool` | Execute an authorized tool with schema-validated arguments | `toolId` (string), `arguments` (object) |
| `aamarva_send_message` | Send End-to-End Encrypted message over an active connection channel | `connectionId` (string), `content` (string) |
| `aamarva_get_messages` | Retrieve and locally decrypt transcript from a direct channel | `connectionId` (string), `limit` (optional number) |
| `aamarva_cluster_send_message` | Broadcast message to multi-agent cluster with recipient restriction | `clusterId` (string), `ciphertext` (string), `nonce` (string), `recipients` (optional string array) |
| `aamarva_watchtower_activity` | Query recent fleet activity audit logs and state changes | `limit` (optional number) |

---

## 2. FLOOR MCP Tool Governance Flow

The FLOOR protocol establishes zero-trust execution boundaries for sensitive agent tools:

```text
Autonomous Agent / MCP Client
             |
             v
   aamarva_floor_list_tools
             |
             +---> [Status: "authorized"] ---> Execute tool directly
             |
             +---> [Status: "pending" / "unauthorized"]
                         |
                         v
             aamarva_floor_request_access
                         |
                         v
                 Human Operator (HITL)
                 [Reviews & Approves]
                         |
                         v
             aamarva_floor_check_status ("approved")
                         |
                         v
             Authorized execution workflow
```

---

## 3. Connecting MCP Clients

Any client supporting the Model Context Protocol (e.g., Claude Desktop, Cursor, IDE plugins, or custom agent runners) can execute AAMARVA tools using standard stdio or JSON-RPC dispatch:

```typescript
// Example JSON-RPC dispatch to AamarvaMcpServer
const toolResult = await mcpServer.handleCallTool("aamarva_floor_list_tools", {});
console.log(JSON.stringify(toolResult, null, 2));
```

---

## 4. Master Account Fleet Scoping

When invoking MCP tools on behalf of a subordinate fleet agent, configure `AAMARVA_TARGET_AGENT_ID` in your environment or initialize the underlying client with `targetAgentId`:

```typescript
const client = new Aamarva({
  agentId: "AMR-MASTER-001",
  apiKey: "sk_amr_master_key",
  targetAgentId: "AMR-SLAVE-002", // Scopes all MCP actions to AMR-SLAVE-002
});
const mcpServer = createAamarvaMcpServer(client);
```
