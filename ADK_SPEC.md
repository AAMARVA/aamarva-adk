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

## 4. Mandatory MCP Adapter Gateway & FLOOR Tool Governance

FLOOR provides zero-trust governance and Human-in-the-Loop (HITL) authorization for external Model Context Protocol (MCP) tool execution. Agents **never** receive external MCP server URLs or credentials and **cannot** invoke external MCP servers directly (`GATEWAY_EXECUTION_REQUIRED`). All external MCP traffic terminates strictly inside the AAMARVA Gateway enclave.

### Mandatory 7-Stage Gateway Execution Call Chain

```text
+---------+     +---------------+     +------------------+     +-----------------+     +--------------+
|  Agent  |     |  AAMARVA ADK  |     | FLOOR Control    |     | AAMARVA Gateway |     | External MCP |
+---------+     +---------------+     +------------------+     +-----------------+     +--------------+
     |                  |                      |                        |                       |
     | 0. Ensure X25519 Gateway Key            |                        |                       |
     |----------------->| PUT /api/agents/me/gateway-key                |                       |
     |                  |--------------------->|                        |                       |
     | 1. Discover Tools|                      |                        |                       |
     |----------------->| GET /api/floor/agent/tools (non-secret meta)  |                       |
     |                  |--------------------->|                        |                       |
     | 2. Invoke / HITL |                      |                        |                       |
     |----------------->| POST /api/floor/tools/:toolId/invoke          |                       |
     |                  |--------------------->|                        |                       |
     |                  |<-- 202 Pending (req) |                        |                       |
     |                  | GET /api/floor/requests/:requestId (HITL poll)|                       |
     |                  |<-- Approved (invId) -|                        |                       |
     | 3. Authorize     |                      |                        |                       |
     |                  | POST /api/floor/invocations/:invocationId/execute                     |
     |                  |--------------------->|                        |                       |
     |                  |<-- SignedExecutionInstruction (NO MCP URL/creds!)                     |
     |                  | [Verify issuer P-256 sig & FLOOR_CREDENTIAL_EXPOSURE check]           |
     | 4. Mint Token    |                      |                        |                       |
     |                  | POST /api/gateway/tokens (SignedExecutionInstruction)                 |
     |                  |---------------------------------------------->|                       |
     |                  |<-- GatewayTokenEnvelope (RFC 9180 HPKE Base) -|                       |
     | 5. Local HPKE Open                      |                        |                       |
     |                  | [Verify gateway P-256 sig via GET /api/gateway/keys]                  |
     |                  | [Decrypt token payload via local X25519 private key]                  |
     | 6. PoP Redeem    |                      |                        |                       |
     |                  | POST /api/gateway/mcp (token + nonce + P-256 Proof-of-Possession)     |
     |                  |---------------------------------------------->|                       |
     |                  |                      |        [Atomic single-use + nonce check]       |
     |                  |                      |        [Server-side MCP auth injection] ------>|
     |                  |                      |                        |<-- Tool Output -------|
     |<-- Tool Result --|<-- Sanitized MCP Execution Result ------------|                       |
```

1. **Agent X25519 Key Registration (`PUT /api/agents/me/gateway-key`)**: ADK generates a local X25519 encryption keypair, binds it with an ECDSA P-256 signature from the agent's identity key (`AAMARVA-AGENT-ENC-KEY:v1:...`), and registers the public JWK (`rotate` / `revoke` supported).
2. **Discovery (`GET /api/floor/agent/tools`)**: Agent queries registered tools and current authorization status (`authorized`, `unauthorized`, `pending`, `revoked`). Responses contain non-secret metadata only.
3. **Invocation & HITL Approval (`POST /api/floor/tools/:toolId/invoke` + `GET /api/floor/requests/:requestId`)**: Submits intended arguments/reason; if HITL approval is required, polls until approved with an authoritative `invocationId`.
4. **Signed Execution Instruction (`POST /api/floor/invocations/:invocationId/execute`)**: Returns an issuer-signed `SignedExecutionInstruction` (`aamarva.gateway.v1`) binding `agentId`, `agentKeyId`, `toolId`, `mcpServerId`, `gatewayId`, and `approvedArgsDigest`. **Zero external MCP URLs or credentials are returned**—ADKs fail closed (`FLOOR_CREDENTIAL_EXPOSURE`) if any credential or external MCP URL field appears.
5. **RFC 9180 HPKE Token Issuance (`POST /api/gateway/tokens`)**: Gateway validates the signed instruction and active X25519 key, mints a short-lived single-use token, and seals it to the agent's X25519 public key using **RFC 9180 HPKE Base Mode** (`DHKEM(X25519, HKDF-SHA256)` + `HKDF-SHA256` + `AES-256-GCM`) inside a P-256 signed `GatewayTokenEnvelope`.
6. **Trusted Key Verification & Local Decryption (`GET /api/gateway/keys`)**: ADK verifies the envelope's gateway signature against trusted keys from `GET /api/gateway/keys` and decrypts the token payload locally with its X25519 private key.
7. **Proof-of-Possession Redemption (`POST /api/gateway/mcp`)**: ADK signs a Proof-of-Possession (`AAMARVA:GW_POP:v1|...`) with its P-256 identity key binding token SHA-256, nonce, timestamp, and `approvedArgsDigest`. The gateway atomically consumes the single-use token and nonce (`409` on replay), injects server-side MCP credentials, executes the external MCP tool, and returns only the execution result. Direct external MCP calls are permanently blocked (`GATEWAY_EXECUTION_REQUIRED`).

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

## 7. Allowlisted API Endpoint Reference (38 Endpoints)

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
| `GET` | `/api/agents/me/gateway-key` | Retrieve Own Gateway X25519 Key |
| `PUT` | `/api/agents/me/gateway-key` | Register Gateway X25519 Key |
| `POST` | `/api/agents/me/gateway-key/rotate` | Rotate Gateway X25519 Key |
| `POST` | `/api/agents/me/gateway-key/revoke` | Revoke Gateway X25519 Key |
| `GET` | `/api/agents/:agentId/gateway-key` | Lookup Agent Gateway X25519 Key |
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
| `POST` | `/api/floor/invocations/:invocationId/execute` | Obtain Signed Execution Instruction |
| `GET` | `/api/gateway/keys` | Trusted Gateway & Issuer Keys |
| `POST` | `/api/gateway/tokens` | Issue HPKE Gateway Token Envelope |
| `POST` | `/api/gateway/mcp` | Redeem Single-Use Token & Execute MCP |
| `GET` | `/api/watchtower/activity` | Watchtower Activity |
| `POST` | `/api/watchtower/stream-ticket` | Request SSE Ticket |
| `GET` | `/api/watchtower/stream` | Watchtower SSE Stream |
| `GET` | `/api/agent/footprints` | Telemetry Footprints |
| `GET` | `/api/webhooks/events` | Webhook Events |

---

## 8. Verification & Test Suite

The ADK maintains 100% test pass rates across both TypeScript and Python runtimes:

- **TypeScript Test Suite (`tests/run-all.ts`)**: Automated test suites verifying HTTP client allowlists, `FileSystemKeyStore` + epoch archival, Workflow 1 & Workflow 2 E2EE, Mandatory MCP Adapter Gateway (RFC 9180 HPKE, signed instructions, Proof-of-Possession, atomic single-use enforcement, replay protection, credential isolation, zero direct external MCP execution), IEEE P1363 ECDSA signatures, master/slave header propagation, Watchtower streams, CLI commands, and 9 framework adapters.
- **Python Test Suite (`python/tests`)**: Comprehensive unit & integration tests covering core client, Workflow 1 & Workflow 2 E2EE, Mandatory MCP Adapter Gateway RFC 9180 HPKE + PoP + credential isolation, master/slave scoping, and framework integrations (LangChain, LangGraph, CrewAI, AutoGen, OpenAI, Google ADK, Agno, LlamaIndex, MCP), plus bidirectional TS <-> Python cryptographic interop (`tests/cross-language-e2ee.test.ts`).

