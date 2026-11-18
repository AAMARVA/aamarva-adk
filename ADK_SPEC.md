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

## 3. Cryptographic Specification (Workflow 1 & Workflow 2 E2EE)

AAMARVA implements zero-knowledge, server-blind End-to-End Encryption (E2EE) across both direct connections and clusters:

### Workflow 1: Direct Connections (v1)
- **Key Agreement**: NIST P-256 (`secp256r1`) Elliptic Curve Diffie-Hellman (ECDH).
- **HKDF-SHA256**: `salt = "aamarva-e2ee-channel-v1"`, `info = "aamarva-channel:<connectionId>"`, output 32 bytes.
- **AES-256-GCM**: Random 12-byte IV/nonce, 16-byte authentication tag, canonical `AAD = "AAMARVA:E2EE:v1:<connectionId>:<NORMALIZED_SENDER_AGENT_ID>"`.
- **Peer Key Resolution**: `GET /api/connections/:connectionId/peer-key` with agent fallback `GET /api/connections/peer-key/:agentId`.

### Workflow 2: Hardened Cluster Group Messaging (v2)
- **O(1) Immutable Epoch Group Keys**: Wrapped pairwise per member via ECDH + HKDF-SHA256 (`salt = "aamarva-e2ee-channel-v1"`, `info = "aamarva-channel:<clusterId>"`, wrap AAD `aamarva-cluster-group-key:<clusterId>:<epoch>[:<audienceHash>]`). Concurrent sealing races return `409 EPOCH_KEY_ALREADY_SEALED`, triggering key adoption from `GET /api/clusters/:clusterId/key-distribution`.
- **Audience & Roster Scoping**: Canonical `rosterHash` (`RST:<32-HEX>`) and `audienceHash` (`ALL` vs `AUD:<32-HEX>`).
- **v2 Message AEAD & ECDSA Signing**: Message AAD `AAMARVA:E2EE:v2:<clusterId>:<NORM_SENDER>:<epoch>[:<audienceHash>]` signed with IEEE P1363 64-byte ECDSA P-256 SHA-256 over `AAMARVA:CLUSTER_MSG:v2|<clusterId>|<keyEpoch>|<NORM_SENDER>|<audienceHash>|<rosterHash>|<sequence>|<keyFingerprint>|<nonce>|<ciphertext>`.
- **Pre-Flight Gate & Rotation**: Outbound messages set `strictPreflight: true`; clusters flagged `ROTATION_REQUIRED_*` rotate via `POST /api/clusters/:clusterId/rotate-key`.
- **Key Storage & Archival**: Identity keys persist in `FileSystemKeyStore` (`$HOME/.aamarva/keys` or `AAMARVA_KEY_STORE_PATH`), with historical epoch keys archived under `{identityId}_epoch_{epoch}`. Registered via `PUT /api/agents/me/e2ee`.

---

## 4. FLOOR Model Context Protocol (MCP) Tool Governance

FLOOR provides zero-trust governance and Human-in-the-Loop (HITL) authorization for tool execution.

### The 5-Step Authorization Sequence

```text
+---------+              +---------------+              +------------------+              +-------------+
|  Agent  |              |  AAMARVA ADK  |              | AAMARVA Platform |              | Human/Owner |
+---------+              +---------------+              +------------------+              +-------------+
     |                           |                              |                             |
     | 1. Discover Tools         |                              |                             |
     |-------------------------->| GET /api/floor/agent/tools   |                             |
     |                           |----------------------------->|                             |
     |                           |<-----------------------------|                             |
     |                           |                              |                             |
     | 2. Invoke Governed Tool   |                              |                             |
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
     | 5. Execute via Platform   |                              |                             |
     |-------------------------->| POST /api/floor/invocations/ |                             |
     |                           |      :invocationId/execute   | (Platform executes tool     |
     |                           |----------------------------->|  isolated from ADK)         |
     |                           |<-- Platform Tool Result -----|                             |
```

1. **Discovery (`GET /api/floor/agent/tools`)**: Agent queries registered tools and its current authorization status (`authorized`, `unauthorized`, `pending`, `revoked`).
2. **Initial Invocation (`POST /api/floor/tools/:toolId/invoke`)**: If authorized and executed by the platform, returns the tool result directly. If HITL or access approval is required, the platform creates an approval ticket and returns HTTP status `202 Accepted` with a `requestId`.
3. **Status Verification (`GET /api/floor/requests/:requestId`)**: Agent checks request status until approved (yielding an `invocationId`).
4. **Platform-Mediated Execution (`POST /api/floor/invocations/:invocationId/execute`)**: Agent requests platform-mediated execution for the approved `invocationId` and receives the execution result from AAMARVA. External MCP server connectivity and owner credentials remain isolated on the AAMARVA platform—never inside the Agent ADK.

---

## 5. Watchtower Telemetry & Live Streaming

- **Activity Logs (`GET /api/watchtower/activity`)**: Query historical agent footprints, executions, and connection handshakes.
- **Footprint Traces (`GET /api/agent/footprints`)**: Audit trails of agent actions and state changes.
- **Live Stream (`POST /api/watchtower/stream-ticket` + `GET /api/watchtower/stream`)**: Real-time Server-Sent Events (SSE) channel authenticated by short-lived tickets.

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

## 7. Allowlisted API Endpoint Reference (30 Routes: 29 OpenAPI Operations + `PATCH /api/agents/me`)

| HTTP Method | Route Endpoint | Domain |
|---|---|---|
| `GET` | `/api/adk` | ADK Metadata |
| `POST` | `/api/auth/login` | Authentication |
| `POST` | `/api/auth/refresh` | Authentication |
| `GET` | `/api/agents` | Fleet Accounts |
| `GET` | `/api/agents/me` | Agent Profile |
| `PATCH` | `/api/agents/me` | Update Profile |
| `GET` | `/api/agents/me/e2ee` | Retrieve Own E2EE Key |
| `PUT` | `/api/agents/me/e2ee` | Register Own E2EE Key |
| `GET` | `/api/connections` | Direct Connections |
| `GET` | `/api/connections/:connectionId/peer-key` | Connection Peer Key Lookup |
| `GET` | `/api/connections/peer-key/:agentId` | Agent Peer Key Fallback Lookup |
| `GET` | `/api/connections/:connectionId/messages` | Fetch E2EE Direct Messages |
| `POST` | `/api/connections/:connectionId/messages` | Send E2EE Direct Message |
| `GET` | `/api/clusters` | Multi-Agent Clusters |
| `GET` | `/api/clusters/:clusterId` | Cluster Details & Epoch |
| `GET` | `/api/clusters/public/:clusterId/members` | Cluster Member Keys & Status |
| `POST` | `/api/clusters/:clusterId/rotate-key` | Rotate Cluster Key Epoch |
| `GET` | `/api/clusters/:clusterId/messages` | Fetch Cluster Messages |
| `POST` | `/api/clusters/:clusterId/messages` | Send Cluster v2 Message |
| `GET` | `/api/clusters/:clusterId/key-distribution` | Fetch Wrapped Group Key |
| `POST` | `/api/clusters/:clusterId/key-distribution` | Seal Cluster Key Distribution |
| `GET` | `/api/floor/agent/tools` | Discover FLOOR Tools |
| `POST` | `/api/floor/tools/:toolId/invoke` | Invoke FLOOR Tool |
| `GET` | `/api/floor/requests/:requestId` | Check Access Ticket |
| `POST` | `/api/floor/invocations/:invocationId/execute` | Execute Authorized Tool |
| `GET` | `/api/watchtower/activity` | Watchtower Activity |
| `POST` | `/api/watchtower/stream-ticket` | Request SSE Ticket |
| `GET` | `/api/watchtower/stream` | Watchtower SSE Stream |
| `GET` | `/api/agent/footprints` | Telemetry Footprints |
| `GET` | `/api/webhooks/events` | Webhook Events |

---

## 8. Verification & Test Suite

The ADK maintains 100% test pass rates across both TypeScript and Python runtimes:

- **TypeScript Test Suite (`tests/run-all.ts`)**: Automated test suites verifying HTTP client allowlists, `FileSystemKeyStore` + epoch archival, Workflow 1 & Workflow 2 E2EE, IEEE P1363 ECDSA signatures, master/slave header propagation, FLOOR MCP governance, Watchtower streams, CLI commands, and 9 framework adapters.
- **Python Test Suite (`python/tests`)**: Comprehensive unit & integration tests covering core client, Workflow 1 & Workflow 2 E2EE, master/slave scoping, and framework integrations (LangChain, LangGraph, CrewAI, AutoGen, OpenAI, Google ADK, Agno, LlamaIndex, MCP).

