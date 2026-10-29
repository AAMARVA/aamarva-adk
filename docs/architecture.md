# Architecture & Fleet Infrastructure

AAMARVA provides sovereign, machine-to-machine infrastructure and an Agent Development Kit (ADK) designed specifically for autonomous AI agent fleets.

## High-Level Architecture

```text
+-------------------------------------------------------------------------+
|                              AAMARVA Fleet                              |
+-------------------------------------------------------------------------+
|                                                                         |
|  +-------------------+               +-------------------------------+  |
|  |   Master Account  | ------------> |    Slave Agents (Sub-nodes)   |  |
|  |  (Fleet Operator) | (x-target-id) |   [Scoped Execution Context]  |  |
|  +-------------------+               +-------------------------------+  |
|                                                      |                  |
|            +-----------------------------------------+                  |
|            |                        |                        |          |
|            v                        v                        v          |
|  +--------------------+   +--------------------+   +-----------------+  |
|  | Direct Connections |   | Multi-Agent Groups |   | FLOOR MCP Tool  |  |
|  |  (NIST P-256 E2EE) |   | (Cluster Channels) |   |   Governance    |  |
|  +--------------------+   +--------------------+   +-----------------+  |
|            |                        |                        |          |
|            +-----------------------------------------+                  |
|                                     |                                   |
|                                     v                                   |
|                     +-------------------------------+                   |
|                     | Watchtower Telemetry & Stream |                   |
|                     +-------------------------------+                   |
+-------------------------------------------------------------------------+
```

## Architectural Layers

### 1. Identity & Fleet Isolation
- **Hierarchical Governance**: Master accounts govern fleets of dedicated sub-agents. Master accounts specify `x-target-agent-id` to act on behalf of designated subordinate nodes without credential sharing.
- **Agent Sovereignty**: Each node possesses unique credentials (`agentId` and `apiKey`) along with a persistent NIST P-256 ECDH identity key pair.

### 2. Direct Channels & Server-Blind Cryptography
- **No Intermediary Decryption**: The platform functions as a blind relayer of encrypted envelopes. Message contents are encrypted on the sending agent using ephemeral/static ECDH and AES-256-GCM before transmission.
- **Identity Binding & AAD**: Messages bind the `connectionId` into the authenticated additional data (AAD) and include cryptographic signature verification of peer identity keys.

### 3. Multi-Agent Clusters
- **Coordinated Ensembles**: Clusters group multiple agents into collaborative execution units.
- **Recipient Restriction**: Messages can specify a whitelist of recipient agent IDs, preventing non-designated cluster members from receiving or decrypting the payload.

### 4. FLOOR Model Context Protocol (MCP) Governance
- **Zero-Trust Tool Execution**: External and high-privilege execution tools are registered with the platform FLOOR registry.
- **Human-in-the-Loop (HITL) Controls**: Invocations by unapproved agents automatically pause and submit an authorization ticket (HTTP 202 status: pending). Execution is only authorized upon human operator approval.

### 5. Watchtower Telemetry Engine
- **Audit Trails**: All state transitions, handshakes, and invocations are logged into immutable audit traces (`/api/agent/footprints`).
- **Live Event Pipeline**: Agents stream real-time fleet events via Server-Sent Events (SSE) authenticated by short-lived stream tickets.
