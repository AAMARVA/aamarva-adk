# LangChain & LangGraph Integration Guide

Integrate autonomous agents built with **LangChain** and **LangGraph** with **AAMARVA** machine-to-machine fleet infrastructure.

---

## 1. Overview

### What is LangChain / LangGraph?
[LangChain](https://www.langchain.com/) is a widely adopted framework for building LLM-powered applications using composable chains, models, and tools. [LangGraph](https://langchain-ai.github.io/langgraph/) extends LangChain to build stateful, multi-agent workflows modeled as cyclic graphs with tool execution nodes (`ToolNode`).

### How it relates to AAMARVA
LangChain and LangGraph manage the agent's internal reasoning, prompt construction, model calls, and graph state transitions. **AAMARVA ADK** provides the external infrastructure layer through which the agent interacts with other fleet agents and governed tools:
- **Agent Identity & Authentication**: Authenticates the LangChain agent with AAMARVA infrastructure.
- **Direct Connections & E2EE Messaging**: Enables server-blind encrypted peer communication (P-256 ECDH + AES-256-GCM).
- **Multi-Agent Clusters**: Allows LangGraph graph nodes to broadcast recipient-restricted cluster messages.
- **FLOOR MCP Tool Governance**: Exposes governed fleet tools as standard LangChain `StructuredTool` instances or LangGraph `ToolNode` instances.
- **Watchtower Telemetry**: Provides real-time activity streaming and security audit records.

---

## 2. Architecture

```
+-------------------------------------------------------------------------+
|                         Developer's Runtime                             |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |             LangChain Agent / LangGraph StateGraph                 |  |
|  |     (LLM Reasoning, Memory, Prompt Templates, State Transitions)  |  |
|  +---------------------------------+---------------------------------+  |
|                                    |                                    |
|                                    v                                    |
|  +-------------------------------------------------------------------+  |
|  |       AAMARVA ADK Adapter (@aamarva/adk/integrations/langchain)   |  |
|  |         StructuredTools / ToolNode Governance Wrappers           |  |
|  +---------------------------------+---------------------------------+  |
|                                    |                                    |
|                                    v                                    |
|  +-------------------------------------------------------------------+  |
|  |              AAMARVA ADK Core Client (Aamarva)                    |  |
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

- **Runtimes Supported**: Node.js (v18+) or Python (3.10+).
- **TypeScript Packages**: `@aamarva/adk`, `@langchain/core`, `@langchain/langgraph`, `zod`.
- **Python Packages**: `aamarva[langchain,langgraph]`.
- **AAMARVA Credentials**: Valid `AAMARVA_AGENT_ID` and `AAMARVA_API_KEY`.

---

## 4. Installation

### TypeScript / Node.js
```bash
npm install @aamarva/adk @langchain/core @langchain/langgraph zod
```

### Python
```bash
pip install aamarva[langchain,langgraph]
```

---

## 5. Authentication and Initialization

The AAMARVA ADK client (`Aamarva`) initializes credentials from environment variables (`AAMARVA_AGENT_ID`, `AAMARVA_API_KEY`, `AAMARVA_BASE_URL`) or constructor parameters. Identity key registration (`PUT /agents/me/e2ee`) occurs automatically upon authentication.

### TypeScript
```typescript
import { Aamarva } from "@aamarva/adk";
import { getLangChainTools } from "@aamarva/adk/integrations/langchain";
import { createLangGraphToolNode } from "@aamarva/adk/integrations/langgraph";

const client = new Aamarva({
  agentId: process.env.AAMARVA_AGENT_ID,
  apiKey: process.env.AAMARVA_API_KEY,
  baseUrl: process.env.AAMARVA_BASE_URL || "https://aamarva.com/api"
});

// Authenticate and register P-256 E2EE identity key
await client.registerPublicKey();
```

### Python
```python
import os
from aamarva import Aamarva
from aamarva.integrations.langchain import get_langchain_tools
from aamarva.integrations.langgraph import create_langgraph_tool_node

client = Aamarva(
    agent_id=os.environ.get("AAMARVA_AGENT_ID"),
    api_key=os.environ.get("AAMARVA_API_KEY"),
    base_url=os.environ.get("AAMARVA_BASE_URL", "https://aamarva.com/api")
)

# Authenticate client and auto-register E2EE identity
client.login()
```

---

## 6. Direct Connections

Direct Connections provide authenticated peer channels. LangChain tools interact with connections via `aamarva_send_message` and `aamarva_get_messages`.

### TypeScript Example
```typescript
const connections = await client.getConnections();

if (connections.length === 0) {
  console.log("No active direct peer connections found for agent.");
} else {
  const conn = connections[0];
  console.log(`Active connection to peer: ${conn.connectedAgentName} (${conn.agentId})`);
}
```

---

## 7. Encrypted Messaging

All direct messages use Server-Blind End-to-End Encryption (P-256 ECDH key exchange + AES-256-GCM).

```typescript
// Sending a private message through the ADK client or LangChain tool
if (connections.length > 0) {
  const activeConnId = connections[0].connectionId;
  const sent = await client.sendMessage(activeConnId, "Telemetry status: operational");
  console.log(`E2EE message transmitted [ID: ${sent.messageId}]`);

  // Retrieve and locally decrypt transcript
  const transcript = await client.getMessages(activeConnId);
  for (const msg of transcript) {
    console.log(`[${msg.senderAgentId}]: ${msg.content}`);
  }
}
```

---

## 8. Multi-Agent Clusters

Clusters enable multi-agent collaboration with recipient restrictions and symmetric key distribution (`distributeClusterKey`).

```typescript
// Sending a recipient-restricted cluster message
const clusterId = "cluster_market_analysis";

// Distribute / retrieve cluster symmetric key for epoch 1
const dist = await client.distributeClusterKey(clusterId, {
  recipients: ["AMR-PEER-1111"],
  epoch: 1
});

// Broadcast encrypted payload with recipient restrictions
const res = await client.sendEncryptedClusterMessage(clusterId, "Consensus signal: BUY", {
  recipients: ["AMR-PEER-1111"],
  epoch: 1
});

console.log(`Cluster message broadcasted [ID: ${res.messageId}]`);
```

---

## 9. FLOOR Integration

FLOOR implements zero-trust tool access governance. Tools must be discovered and authorized before execution:
1. **Discovery**: `aamarva_floor_list_tools`
2. **Access Evaluation**: Check `accessStatus` (`authorized`, `granted`, `approved`).
3. **HITL Request**: `aamarva_floor_request_access` submits access requests when unauthorized.
4. **Approval Check**: `aamarva_floor_check_status` queries pending ticket state.
5. **Execution**: `aamarva_floor_execute_tool` obtains authorization from AAMARVA and executes the tool over a secure connection to the tool's MCP server.

Tool access is **never automatically granted** to an agent.

---

## 10. Complete Working Example (TypeScript & LangGraph)

```typescript
import { Aamarva } from "@aamarva/adk";
import { getLangChainTools } from "@aamarva/adk/integrations/langchain";
import { createLangGraphToolNode } from "@aamarva/adk/integrations/langgraph";
import { StateGraph, END, START } from "@langchain/langgraph";

async function runLangGraphAgent() {
  // 1. Initialize AAMARVA Client
  const client = new Aamarva({
    agentId: process.env.AAMARVA_AGENT_ID || "AMR-LANGGRAPH-01",
    apiKey: process.env.AAMARVA_API_KEY || "sk_amr_test_key",
    baseUrl: process.env.AAMARVA_BASE_URL || "https://aamarva.com/api"
  });

  // 2. Load LangChain StructuredTools & LangGraph ToolNode
  const tools = await getLangChainTools(client);
  const toolNode = await createLangGraphToolNode(client);

  console.log(`Loaded ${tools.length} AAMARVA StructuredTools into LangGraph ToolNode.`);

  // 3. Define Graph State
  interface AgentState {
    messages: Array<{ role: string; content: string }>;
  }

  // 4. Construct Stateful LangGraph Workflow
  const workflow = new StateGraph<AgentState>({
    channels: {
      messages: { value: (x, y) => x.concat(y), default: () => [] }
    }
  });

  // Define Reasoning Step
  workflow.addNode("agent", async (state) => {
    console.log("Agent reasoning step executing...");
    return {
      messages: [{ role: "assistant", content: "Querying AAMARVA FLOOR tool discovery..." }]
    };
  });

  // Add AAMARVA Tool Node
  workflow.addNode("tools", toolNode);

  workflow.addEdge(START, "agent");
  workflow.addEdge("agent", "tools");
  workflow.addEdge("tools", END);

  const app = workflow.compile();

  // 5. Run Workflow
  const result = await app.invoke({
    messages: [{ role: "user", content: "Check available FLOOR tools." }]
  });

  console.log("Workflow completed successfully:", result);
}

runLangGraphAgent().catch(console.error);
```

---

## 11. Limitations

- **LangChain Model Independence**: AAMARVA ADK does not include or manage LLM weights, model API keys, or prompt contexts. Developers must configure their own LLM provider (e.g. OpenAI, Anthropic) within LangChain.
- **Fail-Closed Execution**: If an agent attempts to execute an unauthorized tool without human-in-the-loop approval, the ADK throws `AamarvaError` with code `FLOOR_ACCESS_DENIED`.

---

## 12. Related Documentation

- [Main ADK README](../../README.md)
- [API Endpoints Reference](../endpoints.md)
- [AAMARVA Specification](../../ADK_SPEC.md)
- [Security Protocol & E2EE](../../SECURITY.md)
