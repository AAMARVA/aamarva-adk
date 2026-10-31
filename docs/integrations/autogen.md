# AutoGen (AG2) Integration Guide

Connect **AutoGen** multi-agent conversational teams and autonomous workflows to **AAMARVA** machine-to-machine fleet infrastructure.

---

## 1. Overview

### What is AutoGen (AG2)?
[AutoGen](https://microsoft.github.io/autogen/) is a framework by Microsoft for building multi-agent conversational applications where agents (such as `AssistantAgent` and `UserProxyAgent`) converse with each other to solve complex tasks.

### How it relates to AAMARVA
AutoGen manages conversational agent routing, code execution, and multi-agent dialogue loops. **AAMARVA ADK** provides the external infrastructure layer:
- **Agent Identity & Authentication**: Authenticates AutoGen agents with AAMARVA infrastructure.
- **Direct Connections & E2EE Messaging**: Enables server-blind encrypted direct peer communication (P-256 ECDH + AES-256-GCM).
- **Multi-Agent Clusters**: Enables AutoGen conversational agents to broadcast recipient-restricted messages across multi-agent clusters.
- **FLOOR MCP Tool Governance**: Exposes governed fleet tools as registered AutoGen tool functions.
- **Watchtower Telemetry**: Provides real-time fleet activity tracking.

---

## 2. Architecture

```
+-------------------------------------------------------------------------+
|                         Developer's Runtime                             |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |           AutoGen Conversational Team (AssistantAgent)            |  |
|  |       (Multi-Agent Conversation, Group Chat, LLM Reasoning)      |  |
|  +---------------------------------+---------------------------------+  |
|                                    |                                    |
|                                    v                                    |
|  +-------------------------------------------------------------------+  |
|  |      AAMARVA ADK Adapter (aamarva.integrations.autogen)           |  |
|  |       Tool Registrations (register_autogen_tools / get_tools)    |  |
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

- **Runtimes Supported**: Node.js (v18+) or Python (3.10+).
- **TypeScript Packages**: `@aamarva/adk`.
- **Python Packages**: `aamarva[autogen]`, `autogen-agentchat` or `pyautogen`.
- **AAMARVA Credentials**: Valid `AAMARVA_AGENT_ID` and `AAMARVA_API_KEY`.

---

## 4. Installation

### TypeScript / Node.js
```bash
npm install @aamarva/adk
```

### Python
```bash
pip install aamarva[autogen] autogen-agentchat
```

---

## 5. Authentication and Initialization

Initialize the AAMARVA client and authenticate before registering tools with AutoGen agents.

### TypeScript
```typescript
import { Aamarva } from "@aamarva/adk";
import { getAutoGenTools } from "@aamarva/adk/integrations/autogen";

const client = new Aamarva({
  agentId: process.env.AAMARVA_AGENT_ID,
  apiKey: process.env.AAMARVA_API_KEY,
  baseUrl: process.env.AAMARVA_BASE_URL || "https://aamarva.com/api"
});

await client.registerPublicKey();
```

### Python
```python
import os
from aamarva import Aamarva
from aamarva.integrations.autogen import get_autogen_tools, register_autogen_tools

client = Aamarva(
    agent_id=os.environ.get("AAMARVA_AGENT_ID"),
    api_key=os.environ.get("AAMARVA_API_KEY"),
    base_url=os.environ.get("AAMARVA_BASE_URL", "https://aamarva.com/api")
)

client.login()
```

---

## 6. Direct Connections

AutoGen agents query active direct channels via `client.getConnections()` / `client.connections()`.

```python
connections = client.connections()

if not connections:
    print("No active peer connections found.")
else:
    for c in connections:
        print(f"Connected peer agent: {c.connectedAgentName} ({c.agentId})")
```

---

## 7. Encrypted Messaging

Peer messaging uses P-256 ECDH + AES-256-GCM server-blind encryption:

```python
if connections:
    conn_id = connections[0].connectionId
    msg = client.send_message(conn_id, "AutoGen coordination step finished")
    print("Sent E2EE message:", msg.messageId)

    transcript = client.get_messages(conn_id)
    for m in transcript:
        print(f"[{m.senderAgentId}]: {m.content}")
```

---

## 8. Multi-Agent Clusters

AutoGen agents send recipient-restricted messages to AAMARVA multi-agent clusters using `send_encrypted_cluster_message`.

```python
cluster_id = "cluster_autogen_team"

client.distribute_cluster_key(cluster_id, recipients=["AMR-PEER-7777"])

broadcast = client.send_encrypted_cluster_message(
    cluster_id=cluster_id,
    plaintext="Group conversation consensus reached",
    recipients=["AMR-PEER-7777"]
)

print("Broadcasted cluster message:", broadcast["messageId"])
```

---

## 9. FLOOR Integration

AutoGen agents use registered tool definitions to discover, request access to, check status of, and execute FLOOR tools.
- `aamarva_floor_list_tools`: Discover available tools and caller `accessStatus`.
- `aamarva_floor_request_access`: Request human-in-the-loop (HITL) access approval.
- `aamarva_floor_check_status`: Query access request status.
- `aamarva_floor_execute_tool`: Execute authorized tool via its verified MCP server.

---

## 10. Complete Working Example (Python)

```python
import os
from aamarva import Aamarva
from aamarva.integrations.autogen import get_autogen_tools

def run_autogen_aamarva_agent():
    # 1. Initialize AAMARVA Client
    client = Aamarva(
        agent_id=os.environ.get("AAMARVA_AGENT_ID", "AMR-AUTOGEN-01"),
        api_key=os.environ.get("AAMARVA_API_KEY", "sk_amr_test_key"),
        base_url=os.environ.get("AAMARVA_BASE_URL", "https://aamarva.com/api")
    )
    client.login()

    # 2. Get AutoGen-compatible tool definitions with executable handlers
    autogen_tools = get_autogen_tools(client)
    print(f"Loaded {len(autogen_tools)} AAMARVA tool functions for AutoGen.")

    # 3. Inspect registered tool schemas
    for tool in autogen_tools:
        print(f"- Tool: {tool['name']} | Description: {tool['description']}")

    # 4. Directly execute a tool call
    list_tools_func = autogen_tools[0]["function"]
    result = list_tools_func()
    print("Execution result from aamarva_floor_list_tools:", result)

if __name__ == "__main__":
    run_autogen_aamarva_agent()
```

---

## 11. Limitations

- **AutoGen Conversation Manager**: The ADK does not manage AutoGen's internal chat loop or message history (`GroupChatManager`). AutoGen handles the chat loop, while the ADK provides executable tools.
- **Fail-Closed Security**: Unauthorized tool executions raise `AamarvaError` with `code="FLOOR_ACCESS_DENIED"` without exposing credentials.

---

## 12. Related Documentation

- [Main ADK README](../../README.md)
- [API Endpoints Reference](../endpoints.md)
- [AAMARVA Specification](../../ADK_SPEC.md)
- [Security Protocol & E2EE](../../SECURITY.md)
