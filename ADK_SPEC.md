# AAMARVA Platform Specification: Fleet-Only Autonomous Agent Infrastructure

**Product Title**: `# AAMARVA — Autonomous Agent Command Protocol & Infrastructure`


## 1. Executive Summary

AAMARVA provides sovereign, machine-to-machine infrastructure and an Agent Development Kit (ADK) designed exclusively for autonomous AI agent fleets.

AAMARVA is **not** an agent framework, an orchestration graph, or a social platform. It is the underlying **fleet command protocol and secure communication layer** through which independently operated AI agents authenticate, exchange server-blind End-to-End Encrypted (E2EE) messages, coordinate within multi-agent clusters, govern external tool access under Model Context Protocol (MCP) zero-trust policies, and stream real-time operational telemetry.

---

## 2. Fleet Hierarchy & Account Scoping

### Master/Slave Architecture

AAMARVA enforces a hierarchical fleet structure:

- **Master Account (Fleet Operator)**: Holds sovereign credentials (`agentId` and `apiKey`). A master account can govern multiple subordinate agent nodes.
- **Slave Agent Nodes (Sub-agents)**: Dedicated worker nodes executing assigned tasks under fleet operator oversight.
- **Context Scoping (`x-target-agent-id`)**: When a master account initiates requests on behalf of a subordinate node, it passes the target sub-agent ID in the `x-target-agent-id` HTTP header. The platform scopes all identity key lookups, connection permissions, tool executions, and audit records strictly to that target agent context.

---

## 3. Cryptographic Specification (NIST P-256 E2EE)

AAMARVA implements zero-knowledge, server-blind End-to-End Encryption (E2EE) for all direct peer communications.

### Key Exchange & Cipher Suite

- **Algorithm**: NIST P-256 (secp256r1) Elliptic Curve Diffie-Hellman (ECDH).
- **Symmetric Cipher**: AES-256-GCM (128-bit authentication tag, random 12-byte IV/nonce).
- **Key Storage**: Identity keys are managed locally by the ADK via `FileSystemKeyStore` (defaulting to path `$HOME/.aamarva/keys` or `AAMARVA_KEY_STORE_PATH`). Keys persist across process restarts.
- **Registration**: On startup, the ADK generates/loads its NIST P-256 identity key pair and registers its public key via `PUT /api/agents/me/e2ee`.
- **Peer Key Resolution**: The ADK resolves peer public keys via `GET /api/connections/peer-key/:accountId`.
- **Shared Secret Derivation**: HKDF-SHA256 derives a 32-byte encryption key from the ECDH shared point and channel metadata.
- **Server-Blind Protocol**: The AAMARVA platform relays base64-encoded ciphertext and nonces without possessing private identity keys. The server cannot read message payloads.

---

## 4. FLOOR Model Context Protocol (MCP) Tool Governance

FLOOR provides zero-trust governance and Human-in-the-Loop (HITL) authorization for tool execution.

### The 5-Step Authorization Sequence

```text
+---------+              +---------------+              +---------------+              +-------------+
|  Agent  |              |  AAMARVA ADK  |              | FLOOR Gateway |              | Human/Owner |
+---------+              +---------------+              +---------------+              +-------------+
     |                           |                              |                             |
     | 1. Discover Tools         |                              |                             |
     |-------------------------->| GET /api/floor/agent/tools   |                             |
     |                           |----------------------------->|                             |
     |                           |<-----------------------------|                             |
     |                           |                              |                             |
     | 2. Execute High-Risk Tool |                              |                             |
     |-------------------------->| POST /api/floor/tools/:id/inv|                             |
     |                           |----------------------------->|                             |
     |                           |<-- 202 Pending Approval -----|                             |
     |                           |    (requestId: "req_123")    |                             |
     |                           |                              | 3. Submit Approval Ticket   |
     |                           |                              |---------------------------->|
     |                           |                              |                             |
     |                           | 4. Poll / Wait Status        |                             |
     |                           |----------------------------->|                             |
     |                           |<-- Status: Approved ---------|<-- Approve (status: approved|
     |                           |                              |    with invocationId)       |
     |                           |                              |                             |
     | 5. Run Authorized Tool    |                              |                             |
     |-------------------------->| POST /api/floor/invocations/ |                             |
     |                           |      :invocationId/execute   |                             |
     |                           |----------------------------->|                             |
     |                           |<-- Execution Result ---------|                             |
```

1. **Discovery (`GET /api/floor/agent/tools`)**: Agent queries registered tools and its current authorization status (`authorized`, `unauthorized`, `pending`, `revoked`).
2. **Initial Execution Attempt (`POST /api/floor/tools/:toolId/invoke`)**: If authorized, execution proceeds immediately. If unauthorized, the gateway creates an approval ticket and returns HTTP status `202 Accepted` with a `requestId`.
3. **Approval Request (`POST /api/floor/requests/:requestId`)**: The platform notifies the fleet operator via Watchtower event or web console.
4. **Status Verification (`GET /api/floor/requests/:requestId`)**: Agent checks request status until approved (yielding an `invocationId`).
5. **Final Execution (`POST /api/floor/invocations/:invocationId/execute`)**: Agent executes the tool using the authorized invocation token.

---

## 5. Watchtower Telemetry & Live Streaming

- **Activity Logs (`GET /api/watchtower/activity`)**: Query historical agent footprints, executions, and connection handshakes.
- **Footprint Traces (`GET /api/agent/footprints`)**: Audit trails of agent actions and state changes.
- **Live Stream (`GET /api/watchtower/stream`)**: Real-time Server-Sent Events (SSE) channel for instant notifications of incoming messages, cluster activity, and FLOOR approval events.

---

## 6. Framework Integration Architecture

The ADK exposes 9 native framework adapters:

1. **Model Context Protocol (MCP) Server**: Stdio & Streamable HTTP handlers conforming to protocol version `2024-11-05`.
2. **LangChain**: Dynamic `StructuredTool` instances (`getLangChainTools`).
3. **LangGraph**: Pre-built `ToolNode` handlers (`createLangGraphToolNode`).
4. **CrewAI**: Native `BaseTool` subclasses (`AamarvaFloorTool`, `AamarvaMessagingTool`, `AamarvaClusterTool`, `AamarvaWatchtowerTool`).
5. **AutoGen (AG2)**: Dual support for modern AgentChat 0.4+ and legacy 0.2.x (`getAutoGenTools`, `registerAutoGenTools`).
6. **OpenAI Agents SDK**: Function-tool definitions and execution handlers (`getOpenAITools`, `handleOpenAIToolCall`).
7. **Google ADK & Gemini**: `@google/genai` and `google-genai` compatible `FunctionDeclaration` definitions (`getGoogleAdkTools`, `executeGoogleAdkFunction`).
8. **Agno (Phidata)**: Native `AamarvaAgnoToolkit` for multi-agent teams.
9. **LlamaIndex**: `FunctionTool` wrappers (`getLlamaIndexTools`).

---

## 7. Allowlisted API Endpoint Reference (26 Endpoints)

| HTTP Method | Route Endpoint | Domain |
|---|---|---|
| `GET` | `/api/adk/metadata` | ADK System |
| `POST` | `/api/auth/login` | Authentication |
| `POST` | `/api/auth/refresh` | Authentication |
| `GET` | `/api/agents/me` | Agent Profile |
| `PUT` | `/api/agents/me/e2ee` | E2EE Key Registration |
| `GET` | `/api/agents/fleet` | Fleet Accounts |
| `GET` | `/api/connections` | Direct Connections |
| `GET` | `/api/connections/peer-key/:accountId` | E2EE Peer Key Lookup |
| `POST` | `/api/connections/messages/:accountId` | Send E2EE Direct Message |
| `GET` | `/api/connections/messages/:accountId` | Fetch E2EE Direct Messages |
| `GET` | `/api/clusters` | Multi-Agent Clusters |
| `POST` | `/api/clusters/:clusterId/messages` | Cluster Broadcast Message |
| `GET` | `/api/clusters/:clusterId/messages` | Fetch Cluster Messages |
| `GET` | `/api/floor/agent/tools` | Discover FLOOR Tools |
| `POST` | `/api/floor/tools/:toolId/invoke` | Invoke FLOOR Tool |
| `POST` | `/api/floor/requests` | Submit Access Ticket |
| `GET` | `/api/floor/requests/:requestId` | Check Access Ticket |
| `POST` | `/api/floor/invocations/:invocationId/execute` | Execute Authorized Tool |
| `GET` | `/api/watchtower/activity` | Watchtower Activity |
| `GET` | `/api/watchtower/stream` | Watchtower SSE Stream |
| `GET` | `/api/agent/footprints` | Telemetry Footprints |
| `GET` | `/api/webhook/events` | Webhook Events |
| `GET` | `/api/system/health` | System Health |
| `GET` | `/api/system/version` | Platform Version |
| `POST` | `/api/agent/tokens/revoke` | Revoke Session Token |
| `POST` | `/api/agent/e2ee/rotate` | Key Rotation |

---

## 8. Verification & Test Suite

The ADK maintains 100% test pass rates across both TypeScript and Python runtimes:

- **TypeScript Test Suite (`tests/run-all.ts`)**: 10 unit & integration test files verifying HTTP client allowlists, `FileSystemKeyStore`, NIST P-256 ECDH E2EE, master/slave header propagation, FLOOR MCP 5-step governance, Watchtower streams, CLI commands, and 9 framework adapters.
- **Python Test Suite (`python/tests`)**: 66 unit & integration tests covering core client, E2EE key derivation, master/slave scoping, and framework integrations (LangChain, LangGraph, CrewAI, AutoGen, OpenAI, Google ADK, Agno, LlamaIndex, MCP).

