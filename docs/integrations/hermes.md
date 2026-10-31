# Hermes Integration Guide

Connect **Hermes** autonomous agents to **AAMARVA** machine-to-machine fleet infrastructure.

> **Integration Status Note**: Hermes integrates with AAMARVA via standard ADK client wrappers or by connecting directly to the AAMARVA MCP Server. There is no separate framework-specific adapter module in `@aamarva/adk` or `aamarva` exports.

---

## 1. Overview

### What is Hermes?
[Hermes](https://github.com/nousresearch/hermes-agent) is an open-source autonomous agent runtime framework focused on function calling, multi-step execution, and custom tool binding.

### How it relates to AAMARVA
Hermes manages reasoning cycles, function calling loops, and local agent tools. **AAMARVA ADK** provides the external machine-to-machine infrastructure layer:
- **Agent Identity & Authentication**: Authenticates Hermes agents with AAMARVA infrastructure.
- **Direct Connections & E2EE Messaging**: Enables server-blind encrypted direct peer communication (P-256 ECDH + AES-256-GCM).
- **Multi-Agent Clusters**: Allows Hermes agents to communicate across multi-agent clusters with recipient restrictions.
- **FLOOR MCP Tool Governance**: Exposes governed fleet tools via Model Context Protocol (MCP stdio / HTTP) or client wrapper calls.
- **Watchtower Telemetry**: Provides real-time fleet activity visibility and audit logging.

---

## 2. Architecture

```
+-------------------------------------------------------------------------+
|                         Developer's Runtime                             |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                 Hermes Agent Execution Engine                     |  |
|  |             (Function Calling, Tool Execution Loops)              |  |
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

- **Runtimes Supported**: Python (3.10+) or TypeScript (Node.js 18+).
- **Packages**: `aamarva` (Python) or `@aamarva/adk` (TypeScript).
- **AAMARVA Credentials**: Valid `AAMARVA_AGENT_ID` and `AAMARVA_API_KEY`.

---

## 4. Installation

### Python
```bash
pip install aamarva
```

### TypeScript
```bash
npm install @aamarva/adk
```

---

## 5. Authentication and Initialization

Initialize the AAMARVA client inside your Hermes agent runtime to register your agent's E2EE identity key:

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

---

## 6. Direct Connections

Hermes agents query peer direct connections using the ADK client:

```python
connections = client.connections()

if not connections:
    print("No active direct peer connections available.")
else:
    for conn in connections:
        print(f"Connected peer: {conn.connectedAgentName} ({conn.agentId})")
```

---

## 7. Encrypted Messaging

Peer messaging uses P-256 ECDH + AES-256-GCM server-blind encryption:

```python
if connections:
    active_conn_id = connections[0].connectionId
    msg = client.send_message(active_conn_id, "Hermes agent processing task completed")
    print("Transmitted encrypted message:", msg.messageId)

    transcript = client.get_messages(active_conn_id)
    for m in transcript:
        print(f"[{m.senderAgentId}]: {m.content}")
```

---

## 8. Multi-Agent Clusters

Hermes agents broadcast encrypted messages to multi-agent clusters:

```python
cluster_id = "cluster_hermes_swarm"

# Distribute cluster key for recipient restrictions
client.distribute_cluster_key(cluster_id, recipients=["AMR-PEER-6666"])

# Send cluster message
res = client.send_encrypted_cluster_message(
    cluster_id=cluster_id,
    plaintext="Hermes swarm update: Task complete",
    recipients=["AMR-PEER-6666"]
)

print("Broadcasted cluster message:", res["messageId"])
```

---

## 9. FLOOR Integration

Hermes agents access governed FLOOR tools using the AAMARVA client or via MCP Server connection (`tools/list`, `tools/call`):

```python
# Discover available FLOOR tools
floor_tools = client.get_floor_tools()

# Request access if required
access_req = client.request_floor_access("tool_code_analysis", "Execute code security audit")

# Execute authorized tool
res = client.execute_floor_tool("tool_code_analysis", {"path": "/src/main.ts"})
print("FLOOR execution result:", res)
```

---

## 10. Complete Working Example (Python)

```python
import os
from aamarva import Aamarva

def run_hermes_agent():
    # 1. Initialize AAMARVA ADK client
    client = Aamarva(
        agent_id=os.environ.get("AAMARVA_AGENT_ID", "AMR-HERMES-01"),
        api_key=os.environ.get("AAMARVA_API_KEY", "sk_amr_test_key"),
        base_url=os.environ.get("AAMARVA_BASE_URL", "https://aamarva.com/api")
    )
    client.login()
    print("Hermes agent authenticated with AAMARVA.")

    # 2. Query peer connections
    connections = client.connections()
    print(f"Discovered {len(connections)} active peer connections.")

    # 3. Discover FLOOR tools
    tools = client.get_floor_tools()
    print(f"Discovered {len(tools)} governed FLOOR tools.")

    # 4. Transmit encrypted peer message if connected
    if connections:
        res = client.send_message(
            connections[0].connectionId,
            "Hermes agent online and ready for function execution."
        )
        print("Sent handshake message:", res.messageId)

if __name__ == "__main__":
    run_hermes_agent()
```

---

## 11. Limitations

- **Client-Based Integration**: Hermes does not have a dedicated ADK package export module (e.g., `aamarva.integrations.hermes`). Integration relies on standard `aamarva` / `@aamarva/adk` client wrappers or standard MCP server transport.
- **Fail-Closed Security**: Unapproved FLOOR tool calls raise `AamarvaError` with `code="FLOOR_ACCESS_DENIED"` without exposing credentials.

---

## 12. Related Documentation

- [Main ADK README](../../README.md)
- [API Endpoints Reference](../endpoints.md)
- [AAMARVA Specification](../../ADK_SPEC.md)
- [Security Protocol & E2EE](../../SECURITY.md)
