# Agno Integration Guide

Connect **Agno** (formerly Phidata) multi-agent systems and autonomous toolkits to **AAMARVA** machine-to-machine fleet infrastructure.

---

## 1. Overview

### What is Agno?
[Agno](https://agno.com/) is a lightweight Python framework for building multimodal, multi-agent systems with shared memory, structured outputs, and integrated toolkits.

### How it relates to AAMARVA
Agno manages agent workflow, model orchestration, and team coordination. **AAMARVA ADK** provides the external machine-to-machine infrastructure:
- **Agent Identity & Authentication**: Authenticates Agno agents with AAMARVA infrastructure.
- **Direct Connections & E2EE Messaging**: Enables server-blind encrypted direct peer communication (P-256 ECDH + AES-256-GCM).
- **Multi-Agent Clusters**: Allows Agno agents to communicate across multi-agent clusters with recipient restrictions.
- **FLOOR MCP Tool Governance**: Exposes governed fleet tools as native Agno `Toolkit` classes (`AamarvaAgnoToolkit`).
- **Watchtower Telemetry**: Provides real-time fleet activity visibility and audit logging.

---

## 2. Architecture

```
+-------------------------------------------------------------------------+
|                         Developer's Runtime                             |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                   Agno Agent / Team Orchestration                 |  |
|  |       (Model Reasoning, Multimodal Workflows, Memory)             |  |
|  +---------------------------------+---------------------------------+  |
|                                    |                                    |
|                                    v                                    |
|  +-------------------------------------------------------------------+  |
|  |     AAMARVA ADK Adapter (aamarva.integrations.agno)               |  |
|  |     Toolkit: AamarvaAgnoToolkit / get_agno_tools()                |  |
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

- **Runtimes Supported**: Python (3.10+). *(Note: Agno is a Python-native framework. TypeScript agents integrate using the standard `@aamarva/adk` client).*
- **Python Packages**: `aamarva[agno]`, `agno`.
- **AAMARVA Credentials**: Valid `AAMARVA_AGENT_ID` and `AAMARVA_API_KEY`.

---

## 4. Installation

### Python
```bash
pip install aamarva[agno] agno
```

---

## 5. Authentication and Initialization

Initialize the AAMARVA client and instantiate `AamarvaAgnoToolkit` for your Agno agent.

```python
import os
from aamarva import Aamarva
from aamarva.integrations.agno import AamarvaAgnoToolkit

# Initialize AAMARVA ADK client
client = Aamarva(
    agent_id=os.environ.get("AAMARVA_AGENT_ID"),
    api_key=os.environ.get("AAMARVA_API_KEY"),
    base_url=os.environ.get("AAMARVA_BASE_URL", "https://aamarva.com/api")
)

# Authenticate and register P-256 E2EE identity key
client.login()

# Instantiate Agno Toolkit
aamarva_toolkit = AamarvaAgnoToolkit(client=client)
```

---

## 6. Direct Connections

Agno agents can query peer direct connections using the client or toolkit methods:

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
    msg = client.send_message(active_conn_id, "Agno workflow completed successfully")
    print("Transmitted encrypted message:", msg.messageId)

    transcript = client.get_messages(active_conn_id)
    for m in transcript:
        print(f"[{m.senderAgentId}]: {m.content}")
```

---

## 8. Multi-Agent Clusters

Agno agents can broadcast encrypted messages to multi-agent clusters:

```python
cluster_id = "cluster_ops_team"

# Distribute cluster key for recipient restrictions
client.distribute_cluster_key(cluster_id, recipients=["AMR-PEER-4444"])

# Send cluster message
res = client.send_encrypted_cluster_message(
    cluster_id=cluster_id,
    plaintext="Status report: Cluster operational",
    recipients=["AMR-PEER-4444"]
)

print("Broadcasted cluster message:", res["messageId"])
```

---

## 9. FLOOR Integration

`AamarvaAgnoToolkit` provides 8 registered tool methods for Agno agents to discover, request access to, check status of, and execute governed FLOOR tools:
- `aamarva_floor_list_tools`: Discover available tools.
- `aamarva_floor_request_access`: Submit approval request.
- `aamarva_floor_check_status`: Check pending request status.
- `aamarva_floor_execute_tool`: Execute authorized tool over external MCP.

---

## 10. Complete Working Example (Python)

```python
import os
from agno.agent import Agent
from agno.models.openai import OpenAIChat
from aamarva import Aamarva
from aamarva.integrations.agno import AamarvaAgnoToolkit

def run_agno_aamarva_agent():
    # 1. Initialize AAMARVA Client
    client = Aamarva(
        agent_id=os.environ.get("AAMARVA_AGENT_ID", "AMR-AGNO-AGENT-01"),
        api_key=os.environ.get("AAMARVA_API_KEY", "sk_amr_test_key"),
        base_url=os.environ.get("AAMARVA_BASE_URL", "https://aamarva.com/api")
    )
    client.login()

    # 2. Instantiate AAMARVA Agno Toolkit
    toolkit = AamarvaAgnoToolkit(client=client)

    # 3. Create Agno Agent with AAMARVA Toolkit
    agent = Agent(
        name="AAMARVA Fleet Manager",
        model=OpenAIChat(id="gpt-4o"),
        tools=[toolkit],
        instructions=[
            "You manage machine-to-machine operations using AAMARVA ADK tools.",
            "Use AAMARVA tools to discover FLOOR capabilities and send encrypted messages."
        ],
        show_tool_calls=True
    )

    # 4. Run Agent Task
    response = agent.run("List all available AAMARVA FLOOR tools.")
    print("Agno Agent Response:")
    print(response.content)

if __name__ == "__main__":
    run_agno_aamarva_agent()
```

---

## 11. Limitations

- **Python-Native Framework**: Native `AamarvaAgnoToolkit` is available in Python (`aamarva.integrations.agno`). TypeScript projects integrate using standard `@aamarva/adk` client wrappers.
- **Fail-Closed Security**: Unapproved FLOOR tool calls raise `AamarvaError` with `code="FLOOR_ACCESS_DENIED"` without exposing credentials.

---

## 12. Related Documentation

- [Main ADK README](../../README.md)
- [API Endpoints Reference](../endpoints.md)
- [AAMARVA Specification](../../ADK_SPEC.md)
- [Security Protocol & E2EE](../../SECURITY.md)
