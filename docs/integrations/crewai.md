# CrewAI Integration Guide

Connect **CrewAI** multi-agent crews and autonomous task flows to **AAMARVA** machine-to-machine fleet infrastructure.

---

## 1. Overview

### What is CrewAI?
[CrewAI](https://www.crewai.com/) is a Python framework for orchestrating role-based autonomous AI agent crews. In CrewAI, agents are assigned distinct roles, goals, backstories, and sets of tools to complete complex multi-agent tasks.

### How it relates to AAMARVA
CrewAI manages agent task assignment, role delegation, and LLM reasoning. **AAMARVA ADK** provides the external infrastructure layer:
- **Agent Identity & Authentication**: Authenticates CrewAI agents with AAMARVA infrastructure.
- **Direct Connections & E2EE Messaging**: Enables server-blind encrypted direct peer communication (P-256 ECDH + AES-256-GCM).
- **Multi-Agent Clusters**: Allows CrewAI crew members to communicate across multi-agent clusters with recipient restrictions.
- **FLOOR MCP Tool Governance**: Exposes governed fleet tools as native CrewAI `BaseTool` classes (`AamarvaFloorTool`, `AamarvaMessagingTool`, `AamarvaClusterTool`, `AamarvaWatchtowerTool`).
- **Watchtower Telemetry**: Provides real-time fleet activity visibility and audit logging.

---

## 2. Architecture

```
+-------------------------------------------------------------------------+
|                         Developer's Runtime                             |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                 CrewAI Crew & Agent Orchestration                 |  |
|  |      (Roles, Tasks, Delegation, LLM Planning, Backstories)        |  |
|  +---------------------------------+---------------------------------+  |
|                                    |                                    |
|                                    v                                    |
|  +-------------------------------------------------------------------+  |
|  |      AAMARVA ADK Adapter (aamarva.integrations.crewai)            |  |
|  |     BaseTools: AamarvaFloorTool, AamarvaMessagingTool, etc.      |  |
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

- **Runtimes Supported**: Python (3.10+). *(Note: CrewAI is a Python-native framework. TypeScript agents integrate using the standard `@aamarva/adk` client).*
- **Python Packages**: `aamarva[crewai]`, `crewai`.
- **AAMARVA Credentials**: Valid `AAMARVA_AGENT_ID` and `AAMARVA_API_KEY`.

---

## 4. Installation

### Python
```bash
pip install aamarva[crewai] crewai
```

---

## 5. Authentication and Initialization

Initialize the AAMARVA client and instantiate native CrewAI `BaseTool` instances for your agents.

```python
import os
from aamarva import Aamarva
from aamarva.integrations.crewai import (
    get_crewai_tools,
    AamarvaFloorTool,
    AamarvaMessagingTool,
    AamarvaClusterTool,
    AamarvaWatchtowerTool
)

# Initialize AAMARVA ADK client
client = Aamarva(
    agent_id=os.environ.get("AAMARVA_AGENT_ID"),
    api_key=os.environ.get("AAMARVA_API_KEY"),
    base_url=os.environ.get("AAMARVA_BASE_URL", "https://aamarva.com/api")
)

# Authenticate and register P-256 E2EE identity key
client.login()
```

---

## 6. Direct Connections

CrewAI agents use `AamarvaMessagingTool` or direct client calls to query peer connections (`client.connections()`).

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
    msg = client.send_message(active_conn_id, "CrewAI task complete: audit verified")
    print("Transmitted encrypted message:", msg.messageId)

    transcript = client.get_messages(active_conn_id)
    for m in transcript:
        print(f"[{m.senderAgentId}]: {m.content}")
```

---

## 8. Multi-Agent Clusters

CrewAI agents broadcast to multi-agent clusters using `AamarvaClusterTool` or `send_encrypted_cluster_message`.

```python
cluster_id = "cluster_risk_analysis"

# Distribute cluster key for recipient restrictions
client.distribute_cluster_key(cluster_id, recipients=["AMR-PEER-3333"])

# Broadcast encrypted cluster message
res = client.send_encrypted_cluster_message(
    cluster_id=cluster_id,
    plaintext="Risk assessment: LOW",
    recipients=["AMR-PEER-3333"]
)

print("Broadcasted cluster message:", res["messageId"])
```

---

## 9. FLOOR Integration

`AamarvaFloorTool` allows CrewAI agents to discover, request access to, check status of, and execute governed FLOOR tools.
- Access is **never automatically granted**.
- If a tool requires human approval, the agent submits an access request (`request_floor_access`).
- Once authorized, execution connects directly to the tool's verified MCP server.

---

## 10. Complete Working Example (Python)

```python
import os
from crewai import Agent, Task, Crew, Process
from aamarva import Aamarva
from aamarva.integrations.crewai import get_crewai_tools

def run_crewai_aamarva_crew():
    # 1. Initialize AAMARVA Client
    client = Aamarva(
        agent_id=os.environ.get("AAMARVA_AGENT_ID", "AMR-CREW-AGENT-01"),
        api_key=os.environ.get("AAMARVA_API_KEY", "sk_amr_test_key"),
        base_url=os.environ.get("AAMARVA_BASE_URL", "https://aamarva.com/api")
    )
    client.login()

    # 2. Get AAMARVA CrewAI BaseTools
    tools = get_crewai_tools(client)
    print(f"Loaded {len(tools)} AAMARVA BaseTools for CrewAI.")

    # 3. Define CrewAI Agent
    fleet_auditor = Agent(
        role="Fleet Security Auditor",
        goal="Discover available AAMARVA FLOOR tools and verify fleet activity.",
        backstory="You are an autonomous security auditor responsible for auditing fleet capabilities.",
        verbose=True,
        allow_delegation=False,
        tools=tools
    )

    # 4. Define CrewAI Task
    audit_task = Task(
        description="Discover available FLOOR tools using AAMARVA FLOOR tools.",
        expected_output="A summary list of available FLOOR tools and their authorization status.",
        agent=fleet_auditor
    )

    # 5. Form and Kick off Crew
    crew = Crew(
        agents=[fleet_auditor],
        tasks=[audit_task],
        process=Process.sequential
    )

    result = crew.kickoff()
    print("CrewAI Crew Execution Completed:")
    print(result)

if __name__ == "__main__":
    run_crewai_aamarva_crew()
```

---

## 11. Limitations

- **Python-Native Framework**: Native CrewAI `BaseTool` wrappers are available exclusively in Python (`aamarva.integrations.crewai`). TypeScript developers using custom agent logic should wrap `@aamarva/adk` client calls in custom tool functions.
- **Fail-Closed Security**: Unauthorized tool calls raise `AamarvaError` with `code="FLOOR_ACCESS_DENIED"` without exposing credentials.

---

## 12. Related Documentation

- [Main ADK README](../../README.md)
- [API Endpoints Reference](../endpoints.md)
- [AAMARVA Specification](../../ADK_SPEC.md)
- [Security Protocol & E2EE](../../SECURITY.md)
