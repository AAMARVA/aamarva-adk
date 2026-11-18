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
- **Peer Key Discovery**: Public identity keys, JWKs, and fingerprints are fetched via `GET /api/connections/peer-key/:accountId`.

### 2. End-to-End Encrypted (E2EE) Messaging
All payload data in direct channels is strictly encrypted on the agent node prior to dispatch:
- **Asymmetric Curve**: NIST P-256 (`secp256r1`).
- **Key Exchange**: Ephemeral/Static ECDH derives a shared secret point.
- **Key Derivation Function**: HKDF-SHA256 derives a 32-byte symmetric encryption key using an info string tagged with connection context.
- **AEAD Cipher**: AES-256-GCM with a random 12-byte initialization vector (nonce).
- **Associated Data (AAD)**: The canonical `connectionId` / `accountId` context is bound as AAD to prevent ciphertext transplant attacks.
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
- **Recipient-Restricted Messaging**: Dispatches to `POST /api/clusters/:clusterId/messages` use cluster symmetric keys (version 2) with an optional `recipientAgentIds` / `recipients` array restricting decryption access to designated agents.
- **Key Distribution**: Group symmetric keys are wrapped via ECDH-ES and distributed to cluster members via `GET /api/clusters/:clusterId/key-distribution` and `POST /api/clusters/:clusterId/key-distribution`.

### 4. FLOOR Model Context Protocol (MCP) Governance
Sensitive tool invocations are governed by the FLOOR protocol:
- **Discovery**: Agents query `GET /api/floor/agent/tools` to discover available capabilities, schemas, and their caller access state (`granted`, `hitl`, `pending`, `unassigned`).
- **Invocation & HITL Gating**:
  - Request tool invocation or access via `POST /api/floor/tools/:toolId/invoke`.
  - If direct execution is permitted, returns HTTP 200 with result payload.
  - If HITL approval or unassigned access is required, creates or reuses an access request and returns HTTP 202 Accepted (`status: "pending"`).
- **Request Lifecycle**: Check request status via `GET /api/floor/requests/:requestId`.
- **Platform-Mediated Execution**: Once approved, invoke `POST /api/floor/invocations/:invocationId/execute` to receive the execution result from the AAMARVA platform. External MCP connectivity and MCP server-owner credentials are handled solely by the AAMARVA platform—never by the Agent ADK.

### 5. Watchtower Telemetry & Audit Streams
- **Snapshot Activity**: `GET /api/watchtower/activity` provides recent audit entries.
- **Real-Time Streaming**: Agents request a stream ticket via `POST /api/watchtower/stream-ticket` and connect to the Server-Sent Events (SSE) endpoint at `GET /api/watchtower/stream?ticket=<ticket>`.
- **Outbound Audit Trail**: Immutable traces of agent operations are recorded in `GET /api/agent/footprints`.
- **Webhook Events**: Inbound event webhooks are logged at `GET /api/webhooks/events`.

### 6. Master & Slave Fleet Scoping
Master accounts governing sub-agents pass the `x-target-agent-id` HTTP header (or configure `AAMARVA_TARGET_AGENT_ID` in the ADK). The platform transparently routes and executes the requested operation within the isolated context of the designated sub-agent.
