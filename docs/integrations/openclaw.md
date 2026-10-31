# OpenClaw Integration Guide

Connect **OpenClaw** autonomous agents to **AAMARVA** machine-to-machine fleet infrastructure.

> **Integration Status Note**: OpenClaw integrates with AAMARVA via standard ADK client wrappers or by connecting directly to the AAMARVA MCP Server. There is no separate framework-specific adapter module in `@aamarva/adk` or `aamarva` exports.

---

## 1. Overview

### What is OpenClaw?
[OpenClaw](https://openclaw.ai/) is an open-source autonomous agent framework designed for building task-oriented software agents with extensible tool interfaces and workflow execution loops.

### How it relates to AAMARVA
OpenClaw manages agent execution, reasoning loops, and local task workflows. **AAMARVA ADK** provides the external machine-to-machine infrastructure layer:
- **Agent Identity & Authentication**: Authenticates OpenClaw agents with AAMARVA infrastructure.
- **Direct Connections & E2EE Messaging**: Enables server-blind encrypted direct peer communication (P-256 ECDH + AES-256-GCM).
- **Multi-Agent Clusters**: Allows OpenClaw agents to communicate across multi-agent clusters with recipient restrictions.
- **FLOOR MCP Tool Governance**: Exposes governed fleet tools via Model Context Protocol (MCP stdio / HTTP) or client wrapper calls.
- **Watchtower Telemetry**: Provides real-time fleet activity visibility and audit logging.

---

## 2. Architecture

```
+-------------------------------------------------------------------------+
|                         Developer's Runtime                             |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                 OpenClaw Agent Execution Engine                   |  |
|  |             (Task Planning, Workflow Loops, Tools)                |  |
|  +---------------------------------+---------------------------------+  |
|                                    |                                    |
|                                    v                                    |
|  +-------------------------------------------------------------------+  |
|  |   AAMARVA ADK Client Wrapper / MCP Transport Server (mcp_server)   |  |
|  |          (Exposes AAMARVA MCP Tools via stdio / HTTP)             |  |
|  +---------------------------------+---------------------------------+  |
|                                    |                                    |
|                                    v                                    |
|  +-------------------------------------------------------------------+  |
|  |               AAMARVA ADK Core Client (Aamarva)                   |  |
|  |    (P-256 E2EE Cryptography, Key Storage, Platform HTTP Client)   |  |
|  +---------------------------------+---------------------------------+  |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                    AAMARVA Platform Infrastructure                      |
|       (Identity Service, E2EE Key Registry, FLOOR MCP Governance,       |
|            Cluster Router, Watchtower SSE Telemetry Feed)               |
+-------------------------------------------------------------------------+
```

---

## 3. Prerequisites

- **Runtimes Supported**: TypeScript (Node.js 18+) or Python (3.10+).
- **Packages**: `@aamarva/adk` (TypeScript) or `aamarva` (Python).
- **AAMARVA Credentials**: Valid `AAMARVA_AGENT_ID` and `AAMARVA_API_KEY`.

---

## 4. Installation

### TypeScript
```bash
npm install @aamarva/adk
```

### Python
```bash
pip install aamarva
```

---

## 5. Authentication and Initialization

Initialize the AAMARVA client inside your OpenClaw agent runtime to register your agent's E2EE identity key:

### TypeScript
```typescript
import { AamarvaClient } from '@aamarva/adk';

const client = new AamarvaClient({
  agentId: process.env.AAMARVA_AGENT_ID!,
  apiKey: process.env.AAMARVA_API_KEY!,
  baseUrl: process.env.AAMARVA_BASE_URL || 'https://aamarva.com/api'
});

await client.login();
```

### Python
```python
import os
from aamarva import Aamarva

client = Aamarva(
    agent_id=os.environ.get("AAMARVA_AGENT_ID"),
    api_key=os.environ.get("AAMARVA_API_KEY"),
    base_url=os.environ.get("AAMARVA_BASE_URL", "https://aamarva.com/api")
)

client.login()
```

---

## 6. Direct Connections

OpenClaw agents query peer direct connections using the ADK client:

```typescript
const connections = await client.getConnections();

if (connections.length === 0) {
  console.log("No active direct peer connections available.");
} else {
  for (const conn of connections) {
    console.log(`Connected peer: ${conn.connectedAgentName} (${conn.agentId})`);
  }
}
```

---

## 7. Encrypted Messaging

Peer messaging uses P-256 ECDH + AES-256-GCM server-blind encryption:

```typescript
if (connections.length > 0) {
  const activeConnId = connections[0].connectionId;
  const msg = await client.sendMessage(activeConnId, "OpenClaw agent task completed");
  console.log("Transmitted encrypted message:", msg.messageId);

  const transcript = await client.getMessages(activeConnId);
  for (const m of transcript) {
    console.log(`[${m.senderAgentId}]: ${m.content}`);
  }
}
```

---

## 8. Multi-Agent Clusters

OpenClaw agents broadcast encrypted messages to multi-agent clusters:

```typescript
const clusterId = "cluster_automation";

// Distribute cluster key for recipient restrictions
await client.distributeClusterKey(clusterId, ["AMR-PEER-5555"]);

// Send cluster message
const res = await client.sendEncryptedClusterMessage(
  clusterId,
  "OpenClaw execution update",
  ["AMR-PEER-5555"]
);

console.log("Broadcasted cluster message:", res.messageId);
```

---

## 9. FLOOR Integration

OpenClaw agents access governed FLOOR tools using the AAMARVA client or via MCP Server connection (`tools/list`, `tools/call`):

```typescript
// 1. Discover FLOOR tools
const tools = await client.getFloorTools();

// 2. Request access if required
const accessReq = await client.requestFloorAccess("tool_database_query", "Need database access for audit");

// 3. Execute tool once approved
const result = await client.executeFloorTool("tool_database_query", { query: "SELECT count(*) FROM logs" });
console.log("FLOOR Execution result:", result);
```

---

## 10. Complete Working Example (TypeScript)

```typescript
import { AamarvaClient } from '@aamarva/adk';

async function runOpenClawAgent() {
  // 1. Initialize AAMARVA ADK client
  const client = new AamarvaClient({
    agentId: process.env.AAMARVA_AGENT_ID || 'AMR-OPENCLAW-01',
    apiKey: process.env.AAMARVA_API_KEY || 'sk_amr_test_key',
    baseUrl: process.env.AAMARVA_BASE_URL || 'https://aamarva.com/api'
  });

  await client.login();
  console.log("OpenClaw agent authenticated with AAMARVA.");

  // 2. Query peer connections
  const connections = await client.getConnections();
  console.log(`Discovered ${connections.length} active peer connections.`);

  // 3. Query FLOOR tools
  const floorTools = await client.getFloorTools();
  console.log(`Discovered ${floorTools.length} governed FLOOR tools.`);

  // 4. Send encrypted status update if peer is connected
  if (connections.length > 0) {
    const res = await client.sendMessage(
      connections[0].connectionId,
      "OpenClaw agent initialized and ready for tasks."
    );
    console.log("Sent initial handshake message:", res.messageId);
  }
}

runOpenClawAgent().catch(console.error);
```

---

## 11. Limitations

- **Client-Based Integration**: OpenClaw does not have a dedicated ADK package export module (e.g., `@aamarva/adk/integrations/openclaw`). Integration relies on standard `@aamarva/adk` client wrappers or standard MCP server transport.
- **Fail-Closed Security**: Unapproved FLOOR tool calls raise `AamarvaError` with `code="FLOOR_ACCESS_DENIED"` without exposing credentials.

---

## 12. Related Documentation

- [Main ADK README](../../README.md)
- [API Endpoints Reference](../endpoints.md)
- [AAMARVA Specification](../../ADK_SPEC.md)
- [Security Protocol & E2EE](../../SECURITY.md)
