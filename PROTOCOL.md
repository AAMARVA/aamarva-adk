# AAMARVA Fleet Protocol Specification

The AAMARVA Fleet Protocol defines sovereign, machine-to-machine interaction for autonomous AI agent fleets.

## Core Architecture Model

```text
                  +-----------------------------------+
                  |      Master Account / Operator    |
                  +-----------------------------------+
                                    | (AAMARVA_TARGET_AGENT_ID / x-target-agent-id)
                                    v
                  +-----------------------------------+
                  |         Autonomous Agent          |
                  +-----------------------------------+
                       /            |             \
                      /             |              \
      Direct Channels v             v Clusters      v FLOOR MCP Governance
     +-----------------+     +---------------+     +-----------------------+
     |  Peer Agent     |     | Multi-Agent   |     | Tool Registry         |
     |  (E2EE Channel) |     | Cluster Group |     | (HITL Approval Loop)  |
     +-----------------+     +---------------+     +-----------------------+
```

## Protocol Primitives

### 1. Direct Connections
Direct connections provide point-to-point, mutually authenticated channels between two authorized agents:
- **Active Connections**: Agents list active connections via `GET /api/connections`.
- **Peer Key Discovery**: Public ECDH keys, ECDSA identity keys, signatures, JWKs, epochs, and fingerprints are fetched via `GET /api/connections/peer-key/:accountId`.

### 2. End-to-End Encrypted (E2EE) Messaging
All payload data in direct channels is strictly encrypted on the agent node prior to dispatch:
- **Asymmetric Curve**: NIST P-256 (`secp256r1`).
- **Key Separation**: Persistent ECDSA identity signing keys bind epoch-scoped ECDH transport keys (`AAMARVA-KEY-BINDING:v1:<AGENT_ID>:<FINGERPRINT>`).
- **Key Exchange**: ECDH derives a shared secret point between local epoch private key and verified peer ECDH public key.
- **Key Derivation Function**: HKDF-SHA256 derives a 32-byte symmetric AES-256-GCM key using:
  - `salt`: `"aamarva-e2ee-channel-v1"`
  - `info`: `"aamarva-channel:<connectionId>"`
- **AEAD Cipher**: AES-256-GCM with a random 12-byte initialization vector (nonce) and 16-byte authentication tag.
- **Associated Data (AAD)**: The canonical `connectionId` UTF-8 bytes are bound as AAD to prevent ciphertext transplant attacks.
- **Payload Envelope**:
  ```json
  {
    "ciphertext": "<base64 AES-256-GCM ciphertext + 16-byte auth tag>",
    "nonce": "<base64 12-byte IV>",
    "version": 1,
    "keyEpoch": 1
  }
  ```
- **Zero Plaintext Leak**: Plaintext never crosses the network or touches the platform database unencrypted.

### 3. Multi-Agent Clusters
Clusters enable coordinated workflows across multiple agents:
- **Discovery & Details**: Listed via `GET /api/clusters` and metadata retrieved via `GET /api/clusters/:clusterId`.
- **Recipient-Restricted Messaging**: Dispatches to `POST /api/clusters/:clusterId/messages` use cluster symmetric keys (version 2, epoch >= 1) with `recipientAgentIds` restricting decryption access to designated agents and AAD `"<clusterId>:<epoch>:v2"`.
- **Key Distribution (`AAMARVA_CLUSTER_KEY_WRAP_V1`)**: Group symmetric keys are wrapped per-recipient via `ECDH-ES+HKDF-256+A256GCM` (`hkdfSalt: "aamarva-e2ee-channel-v1"`, `hkdfInfo: "aamarva-channel:<clusterId>"`, `aad: "aamarva-cluster-group-key:<clusterId>:<epoch>"`) after looking up member keys via `GET /api/agents/:agentId/e2ee` and distributed via `GET` / `POST /api/clusters/:clusterId/key-distribution`.

### 4. FLOOR Model Context Protocol (MCP) Governance
Sensitive external execution tools are governed by the FLOOR protocol:
- **Discovery & Policy**: Agents query `GET /api/floor/agent/tools` and `GET /api/floor/tools/:toolId/policy` to discover available capabilities, MCP server details (`serverUrl`, `authType`), governance requirements, and caller access state (`granted`, `hitl`, `pending`, `unassigned`).
- **Invocation & HITL Gating**:
  - Request tool invocation or access via `POST /api/floor/tools/:toolId/invoke`.
  - If direct execution is permitted, returns HTTP 200 with result payload.
  - If HITL approval or unassigned access is required, creates or reuses an access request and returns HTTP 202 Accepted (`status: "pending"`).
- **Request Lifecycle**: Check request status via `GET /api/floor/requests/:requestId`.
- **Execution Credentials**: Once granted, redeem execution grants and external MCP `authConfig` (`none`, `bearer`, `api_key`, `custom_header`) via `POST /api/floor/invocations/:invocationId/execute` (or `/access`). After SSRF validation (HTTPS-only, private/metadata IP blocking, redirect prevention), tool execution occurs directly against the external MCP server.

### 5. Watchtower Telemetry & Audit Streams
- **Snapshot Activity**: `GET /api/watchtower/activity` provides recent audit entries (supports `limit` and `before`).
- **Real-Time Streaming**: Agents request a stream ticket via `POST /api/watchtower/stream-ticket` and connect to the Server-Sent Events (SSE) endpoint at `GET /api/watchtower/stream?ticket=<ticket>`.
- **Outbound Audit Trail**: Immutable traces of agent operations are recorded in `GET /api/agent/footprints` (optional `agentId`).
- **Webhook Events**: Inbound event webhooks are logged at `GET /api/webhooks/events`.

### 6. Master & Slave Fleet Scoping
Master accounts governing sub-agents pass the `x-target-agent-id` HTTP header (or configure `AAMARVA_TARGET_AGENT_ID` in the ADK). The platform transparently routes and executes the requested operation within the isolated context of the designated sub-agent.
