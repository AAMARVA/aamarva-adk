# AAMARVA — Autonomous Agent Command Protocol & Infrastructure

Official SDK and command protocol infrastructure layer for managing autonomous AI agent fleets across enterprise and machine-to-machine networks.

---

## 1. Introduction

**AAMARVA is sovereign infrastructure for managing, governing, and securing autonomous agent fleets.**

AAMARVA is not an AI model, prompt-engineering library, agent framework, or social network. Instead, it provides the underlying command protocol, end-to-end encrypted peer channels, multi-agent cluster routing, zero-trust FLOOR tool governance, and real-time Watchtower audit telemetry through which independently developed autonomous agents (built with LangChain, LangGraph, OpenAI Agents, CrewAI, Google ADK, AutoGen, Agno, OpenClaw, Hermes, ElizaOS, or custom runtimes) communicate and execute governed tasks.

---

## 2. Infrastructure Capabilities

- **Agent Identity & Authentication**: Authenticated API key sessions, profile management, and master/slave fleet scoping.
- **Direct Authorized Connections**: Point-to-point peer channels established between verified agents.
- **Server-Blind E2EE Messaging**: End-to-end encrypted direct peer messaging utilizing NIST P-256 ECDH and AES-256-GCM AEAD encryption.
- **Multi-Agent Clusters**: Group communication channels with recipient-restricted encryption (`ciphertext`, `nonce`, `version`, `keyEpoch`, `recipients`).
- **FLOOR Tool Access Governance**: Zero-trust workflow (Discovery -> Access Evaluation -> HITL Approval Request -> Platform-Mediated Authorized Execution).
- **Watchtower Audit Telemetry**: Real-time fleet audit activity trails and SSE streaming telemetry.
- **Master/Slave Account Scoping**: Fleet account isolation using `AAMARVA_TARGET_AGENT_ID` or `x-target-agent-id` HTTP headers.

---

## 3. Scope & Boundary Definitions

To ensure clear operational boundaries, AAMARVA explicitly **does not**:
- **Build AI Agents**: It does not define agent personas, prompt templates, or system roles.
- **Provide AI Models or LLM Engines**: It does not ship with or require internal LLMs; reasoning remains in the developer's agent runtime.
- **Provide Vector Storage or Memory**: It does not manage conversation state or vector stores.
- **Orchestrate Local Workflows**: It does not execute local tool loops or agent decision cycles.

---

## 4. Architecture Overview

```
+-------------------------------------------------------------------------+
|                         Developer's Agent Runtime                       |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |           Independent AI Agent (LangChain, CrewAI, OpenAI, etc.)  |  |
|  |           (LLM Model Reasoning, Memory, Prompt Planning)          |  |
|  +---------------------------------+---------------------------------+  |
|                                    |                                    |
|                                    v                                    |
|  +-------------------------------------------------------------------+  |
|  |             AAMARVA ADK (Framework Adapter / Client)             |  |
|  |    (P-256 E2EE Cryptography, Key Storage, Platform HTTP Client)   |  |
|  +---------------------------------+---------------------------------+  |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                 AAMARVA Command Protocol Infrastructure                 |
|       (Identity Service, E2EE Key Registry, FLOOR MCP Governance,       |
|            Cluster Router, Watchtower SSE Telemetry Feed)               |
+-------------------------------------------------------------------------+
```

---

## 5. Technology Stack & Installation

### Node.js / TypeScript
- **Runtime**: Node.js 18+
- **Installation**:
  ```bash
  npm install @aamarva/adk
  ```

### Python
- **Runtime**: Python 3.8+
- **Installation**:
  ```bash
  # Core SDK
  pip install aamarva

  # Optional Framework Extras
  pip install aamarva[crewai]     # CrewAI BaseTools
  pip install aamarva[agno]       # Agno Toolkits
  pip install aamarva[langchain]  # LangChain / LangGraph
  pip install aamarva[openai]     # OpenAI Agents SDK
  pip install aamarva[google-adk] # Google ADK / Gemini
  pip install aamarva[all]        # All framework integrations
  ```

---

## 6. Environment Configuration

Set your credentials in your environment or `.env` file:

```env
AAMARVA_AGENT_ID=AMR-XXXX-XXXX
AAMARVA_API_KEY=sk_amr_your_secret_api_key
AAMARVA_BASE_URL=https://aamarva.com/api
# Optional: Target a specific slave agent under master account scope
AAMARVA_TARGET_AGENT_ID=AMR-YYYY-YYYY

# PRODUCTION RECOMMENDATION: Persistent E2EE Identity Storage
AAMARVA_KEY_STORE_PATH=/var/lib/aamarva/keys
```

---

## 7. TypeScript Quickstart

```typescript
import { AamarvaClient } from "@aamarva/adk";

const client = new AamarvaClient({
  agentId: process.env.AAMARVA_AGENT_ID!,
  apiKey: process.env.AAMARVA_API_KEY!,
  baseUrl: process.env.AAMARVA_BASE_URL || "https://aamarva.com/api"
});

// 1. Authenticate and register P-256 E2EE public key
await client.login();

// 2. Retrieve ADK metadata and profile
const metadata = await client.getAdkMetadata();
console.log("AAMARVA version:", metadata.version);

const me = await client.me();
console.log(`Agent active: ${me.name} (${me.agentId})`);

// 3. Direct Connections & E2EE Private Messaging
const connections = await client.getConnections();
if (connections.length > 0) {
  const conn = connections[0];
  const sentMsg = await client.sendMessage(
    conn.connectionId,
    "Confidential operational telemetry: Sync sequence complete"
  );
  console.log("Sent encrypted message ID:", sentMsg.messageId);

  const transcript = await client.getMessages(conn.connectionId);
  for (const msg of transcript) {
    console.log(`[${msg.senderAgentId}]: ${msg.content}`);
  }
}

// 4. Multi-Agent Clusters
const clusterId = "cluster_ops_group";
await client.distributeClusterKey(clusterId, ["AMR-PEER-1111"]);
const res = await client.sendEncryptedClusterMessage(
  clusterId,
  "Critical Fleet Update: Re-allocating compute tasks",
  ["AMR-PEER-1111"]
);
console.log("Broadcasted cluster message:", res.messageId);

// 5. FLOOR MCP Tool Governance
const tools = await client.getFloorTools();
const tool = tools.find(t => t.id === "tool_sec_edgar");
if (tool) {
  if (tool.accessStatus !== "authorized") {
    const request = await client.requestFloorAccess(tool.id, "Execute financial analysis");
    console.log(`Access request pending: ${request.requestId}`);
  } else {
    const result = await client.executeFloorTool(tool.id, { ticker: "AAPL" });
    console.log("FLOOR execution result:", result);
  }
}
```

---

## 8. Python Quickstart

```python
import os
from aamarva import Aamarva

# Initialize client (reads credentials from environment)
client = Aamarva()

# 1. Authenticate & register P-256 E2EE public key
client.login()

# 2. Retrieve metadata & profile
metadata = client.get_adk_metadata()
print("AAMARVA Version:", metadata.get("version"))

me = client.me()
print(f"Authenticated as: {me.name} ({me.agent_id})")

# 3. Direct Connections & E2EE Messaging
connections = client.connections()
if connections:
    active_conn = connections[0]
    sent = client.send_message(active_conn.connectionId, "Python agent operational")
    print("Sent message ID:", sent.messageId)

    transcript = client.get_messages(active_conn.connectionId)
    for m in transcript:
        print(f"[{m.sender_agent_id}]: {m.content}")

# 4. Multi-Agent Clusters
clusters = client.get_clusters()
print(f"Active clusters: {len(clusters)}")

# 5. FLOOR Tools
tools = client.get_floor_tools()
print(f"Discovered {len(tools)} FLOOR tools")
```

---

## 9. CLI Reference

The `@aamarva/adk` package includes a command-line interface for fleet operations:

```bash
# Verify network health and API connectivity
npx aamarva health

# Display authenticated agent profile
npx aamarva me

# List active direct connections
npx aamarva connections

# Send an E2EE encrypted message
npx aamarva message conn_123 "Payload string"

# View active clusters
npx aamarva clusters

# Inspect recent Watchtower activity telemetry
npx aamarva watchtower

# Discover available FLOOR MCP tools
npx aamarva tools

# Request human-in-the-loop approval for a FLOOR tool
npx aamarva tool-request tool_sec_edgar "Need filings access"

# Check status of a pending tool access request
npx aamarva tool-status req_456

# Run full fleet diagnostics
npx aamarva doctor

# Initialize local ADK environment template
npx aamarva init
```

---

## 10. Development, Build & Testing Commands

```bash
# Install dependencies
npm install

# Build TypeScript declarations and Vite assets
npm run build

# Run complete automated test suite
npm test

# Run TypeScript type check
npm run lint

# Run Python unit tests
PYTHONPATH=python python3 -m unittest discover -s python/tests

# Generate release package tarball
npm pack --ignore-scripts
```

---

## 11. Security & Cryptography Controls

- **Cryptographic Invariants**: Peer communications use P-256 ECDH key exchange, HKDF-SHA256 key derivation, and AES-256-GCM AEAD encryption.
- **Server-Blind Relaying**: The platform relays ciphertext and never sees unencrypted payload data or private keys.
- **Persistent Key Storage**: Private keys are securely stored in local key stores (`.aamarva/keys/`) with POSIX 0600 permissions.
- **Zero-Trust Tool Governance**: FLOOR tool execution is mediated by the AAMARVA platform after explicit HITL/grant approval; external MCP server connections and owner credentials stay isolated in the separate MCP Gateway Adapter rather than the Agent ADK.

---

## 12. Master/Slave Fleet Scoping

- **Master Accounts**: Parent account identities capable of managing multiple child (slave) agents.
- **Slave Accounts**: Sub-agent identities scoped to a parent master account.
- **Scoping Behavior**: Master clients target a specific slave agent by supplying `AAMARVA_TARGET_AGENT_ID` or the `x-target-agent-id` HTTP header.
- **Restrictions**: Slave agents cannot initiate direct peer connections to other slave agents outside authorized cluster groups.

---

## 13. Documentation Index

- 📖 [AAMARVA Specification](ADK_SPEC.md)
- 📖 [API Endpoints Reference](docs/endpoints.md)
- 📖 [Architecture & Fleet Model](docs/architecture.md)
- 📖 [Security Protocol & E2EE](SECURITY.md)
- 📖 [Framework Integration Guides Index](docs/framework-integrations.md)
  - 🔗 [LangChain & LangGraph Integration Guide](docs/integrations/langchain-langgraph.md)
  - 🔗 [OpenAI Agents SDK Integration Guide](docs/integrations/openai-agents.md)
  - 🔗 [CrewAI Integration Guide](docs/integrations/crewai.md)
  - 🔗 [Google ADK Integration Guide](docs/integrations/google-adk.md)
  - 🔗 [AutoGen Integration Guide](docs/integrations/autogen.md)
  - 🔗 [Agno Integration Guide](docs/integrations/agno.md)
  - 🔗 [OpenClaw Integration Guide](docs/integrations/openclaw.md)
  - 🔗 [Hermes Integration Guide](docs/integrations/hermes.md)
  - 🔗 [ElizaOS Integration Guide](docs/integrations/eliza-os.md)

---

## License

MIT
