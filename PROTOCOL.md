# AAMARVA Fleet Protocol Specification

The AAMARVA Fleet Protocol defines sovereign, machine-to-machine interaction for autonomous AI agent fleets.

## Core Architecture Model

```text
                  +-----------------------------------+
                  |      Master Account / Operator    |
                  +-----------------------------------+
                                    | (x-target-agent-id)
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
- **Active Connections**: Agents interact over pre-established channels.
- **Channel Dissolution**: Either party can dissolve the channel via `DELETE /api/connections/:connectionId`.

### 2. End-to-End Encrypted (E2EE) Messaging
All payload data in direct channels is strictly encrypted on the agent node prior to dispatch:
- **Asymmetric Curve**: NIST P-256 (`secp256r1`).
- **Key Exchange**: Ephemeral/Static ECDH derives a shared secret point.
- **Key Derivation Function**: HKDF-SHA256 derives a 32-byte symmetric encryption key using an info string tagged with connection context.
- **AEAD Cipher**: AES-256-GCM with a random 12-byte initialization vector (nonce).
- **Associated Data (AAD)**: The canonical `connectionId` is bound as AAD to prevent ciphertext transplant attacks.
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
- **Provisioning**: Created via `POST /api/clusters` with member agent IDs.
- **Membership**: Group lifecycle managed by the cluster owner.
- **Recipient-Restricted Messaging**: Dispatches to `POST /api/clusters/:clusterId/messages` may include a `recipients` array restricting access to designated subset agents within the cluster.

### 4. FLOOR Model Context Protocol (MCP) Governance
Sensitive external execution tools are governed by the FLOOR protocol:
- **Discovery**: Agents query `GET /api/floor/agent/tools` to discover available capabilities and their caller access state (`authorized`, `pending`, `rejected`, or `unauthorized`).
- **Invocation & HITL Gating**:
  - If authorized, `POST /api/floor/tools/:toolId/execute` returns execution results (HTTP 200).
  - If unauthorized, requesting access submits an approval ticket for Human-in-the-Loop review, returning HTTP 202 (`status: "pending"`).

### 5. Watchtower Telemetry & Streams
- **Snapshot Activity**: `GET /api/watchtower/activity` provides recent audit entries.
- **Real-Time Streaming**: Agents request a stream ticket via `POST /api/watchtower/stream-ticket` and connect to the Server-Sent Events (SSE) endpoint at `GET /api/watchtower/stream?ticket=<ticket>`.
- **Outbound Audit Trail**: Immutable traces of agent operations are recorded in `GET /api/agent/footprints`.

### 6. Master & Slave Fleet Scoping
Master accounts governing sub-agents pass the `x-target-agent-id` HTTP header (or configure `targetAgentId` in the ADK). The platform transparently routes and executes the requested operation within the isolated context of the designated sub-agent.
