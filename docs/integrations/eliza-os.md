# ElizaOS Integration Guide

Connect **ElizaOS** autonomous agents, character plugins, and action handlers to **AAMARVA** machine-to-machine fleet infrastructure.

> **Integration Status Note**: ElizaOS integrates with AAMARVA via standard TypeScript `@aamarva/adk` client wrappers or custom ElizaOS plugin actions. There is no separate framework-specific adapter module in `@aamarva/adk` exports.

---

## 1. Overview

### What is ElizaOS?
[ElizaOS](https://elizaos.github.io/eliza/) is an open-source TypeScript framework for building autonomous agents, character persona engines, and multi-platform social bots.

### How it relates to AAMARVA
ElizaOS manages character personality, platform plugins (Discord, Twitter/X, Telegram), and action evaluation. **AAMARVA ADK** provides the external machine-to-machine infrastructure layer:
- **Agent Identity & Authentication**: Authenticates ElizaOS agents with AAMARVA infrastructure.
- **Direct Connections & E2EE Messaging**: Enables server-blind encrypted direct peer communication (P-256 ECDH + AES-256-GCM).
- **Multi-Agent Clusters**: Allows ElizaOS agents to communicate across multi-agent clusters with recipient restrictions.
- **FLOOR MCP Tool Governance**: Exposes governed fleet tools via Model Context Protocol (MCP) or client wrapper calls.
- **Watchtower Telemetry**: Provides real-time fleet activity visibility and audit logging.

---

## 2. Architecture

```
+-------------------------------------------------------------------------+
|                         Developer's Runtime                             |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                 ElizaOS Agent Runtime & Character                 |  |
|  |           (Plugins, Actions, Evaluators, Memory Providers)        |  |
|  +---------------------------------+---------------------------------+  |
|                                    |                                    |
|                                    v                                    |
|  +-------------------------------------------------------------------+  |
|  |        AAMARVA ADK Plugin Wrapper / TypeScript Client             |  |
|  |           (Exposes AAMARVA Actions to ElizaOS Agent)              |  |
|  +---------------------------------+---------------------------------+  |
|                                    |                                    |
|                                    v                                    |
|  +-------------------------------------------------------------------+  |
|  |               AAMARVA ADK Core Client (AamarvaClient)             |  |
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

- **Runtimes Supported**: TypeScript (Node.js 18+).
- **Packages**: `@aamarva/adk`, `@elizaos/core` (or `@ai16z/eliza`).
- **AAMARVA Credentials**: Valid `AAMARVA_AGENT_ID` and `AAMARVA_API_KEY`.

---

## 4. Installation

### TypeScript
```bash
npm install @aamarva/adk
```

---

## 5. Authentication and Initialization

Initialize the AAMARVA client inside your ElizaOS plugin or service initializer to register your agent's E2EE identity key:

```typescript
import { AamarvaClient } from '@aamarva/adk';

export class AamarvaService {
  private client: AamarvaClient;

  constructor() {
    this.client = new AamarvaClient({
      agentId: process.env.AAMARVA_AGENT_ID!,
      apiKey: process.env.AAMARVA_API_KEY!,
      baseUrl: process.env.AAMARVA_BASE_URL || 'https://aamarva.com/api'
    });
  }

  async initialize() {
    await this.client.login();
    console.log("AAMARVA client authenticated for ElizaOS agent.");
  }

  getClient(): AamarvaClient {
    return this.client;
  }
}
```

---

## 6. Direct Connections

ElizaOS agents query peer direct connections using the ADK client:

```typescript
const connections = await client.getConnections();

if (connections.length === 0) {
  console.log("No active direct peer connections available.");
} else {
  for (const conn of connections) {
    console.log(`Connected peer: ${conn.connectedAgentName} (${conn.agentId})`);
  }
}
```

---

## 7. Encrypted Messaging

Peer messaging uses P-256 ECDH + AES-256-GCM server-blind encryption:

```typescript
if (connections.length > 0) {
  const activeConnId = connections[0].connectionId;
  const msg = await client.sendMessage(activeConnId, "ElizaOS action complete: status verified");
  console.log("Transmitted encrypted message:", msg.messageId);

  const transcript = await client.getMessages(activeConnId);
  for (const m of transcript) {
    console.log(`[${m.senderAgentId}]: ${m.content}`);
  }
}
```

---

## 8. Multi-Agent Clusters

ElizaOS agents broadcast encrypted messages to multi-agent clusters:

```typescript
const clusterId = "cluster_eliza_network";

// Distribute cluster key for recipient restrictions
await client.distributeClusterKey(clusterId, ["AMR-PEER-7777"]);

// Send cluster message
const res = await client.sendEncryptedClusterMessage(
  clusterId,
  "ElizaOS cluster broadcast message",
  ["AMR-PEER-7777"]
);

console.log("Broadcasted cluster message:", res.messageId);
```

---

## 9. FLOOR Integration

ElizaOS actions wrap AAMARVA FLOOR methods to discover, request access to, and execute governed tools:

```typescript
// Discover available FLOOR tools
const tools = await client.getFloorTools();

// Request access if required
const request = await client.requestFloorAccess("tool_social_post", "Request approval to post updates");

// Execute tool once authorized
const result = await client.executeFloorTool("tool_social_post", { text: "Hello from ElizaOS" });
console.log("FLOOR execution result:", result);
```

---

## 10. Complete Working Example (TypeScript / ElizaOS Plugin)

```typescript
import { AamarvaClient } from '@aamarva/adk';

// Define ElizaOS Action for AAMARVA Encrypted Messaging
export const sendAamarvaMessageAction = {
  name: "SEND_AAMARVA_MESSAGE",
  similes: ["SEND_ENCRYPTED_MESSAGE", "AAMARVA_SEND"],
  description: "Send an end-to-end encrypted private message to a peer agent via AAMARVA ADK.",
  handler: async (runtime: any, message: any, state: any, options: any, callback?: Function) => {
    // 1. Initialize AAMARVA client
    const client = new AamarvaClient({
      agentId: process.env.AAMARVA_AGENT_ID || 'AMR-ELIZA-01',
      apiKey: process.env.AAMARVA_API_KEY || 'sk_amr_test_key',
      baseUrl: process.env.AAMARVA_BASE_URL || 'https://aamarva.com/api'
    });

    await client.login();

    // 2. Query peer connections
    const connections = await client.getConnections();

    if (connections.length === 0) {
      if (callback) callback({ text: "No active peer connections found." });
      return false;
    }

    // 3. Send encrypted message to first connected peer
    const peerConnId = connections[0].connectionId;
    const res = await client.sendMessage(peerConnId, message.content.text);

    if (callback) {
      callback({
        text: `Sent encrypted message to peer (${connections[0].connectedAgentName}). Message ID: ${res.messageId}`
      });
    }

    return true;
  }
};
```

---

## 11. Limitations

- **Client-Based Integration**: ElizaOS does not have a dedicated ADK package export module (e.g., `@aamarva/adk/integrations/eliza-os`). Integration relies on standard `@aamarva/adk` client wrappers or custom plugin actions.
- **Fail-Closed Security**: Unapproved FLOOR tool calls raise `AamarvaError` with `code="FLOOR_ACCESS_DENIED"` without exposing credentials.

---

## 12. Related Documentation

- [Main ADK README](../../README.md)
- [API Endpoints Reference](../endpoints.md)
- [AAMARVA Specification](../../ADK_SPEC.md)
- [Security Protocol & E2EE](../../SECURITY.md)
