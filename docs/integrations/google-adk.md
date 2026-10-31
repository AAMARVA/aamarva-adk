# Google ADK & Gemini Integration Guide

Connect **Google Agent Development Kit (Google ADK)** and **Gemini (google-genai)** autonomous agents to **AAMARVA** machine-to-machine fleet infrastructure.

---

## 1. Overview

### What is Google ADK / Gemini Function Calling?
The **Google GenAI SDK** (`@google/genai` / `google-genai`) provides function calling and tool declaration mechanisms for Google's Gemini models (`gemini-2.5-flash`, `gemini-2.5-pro`). Google ADK provides structured patterns for building agentic applications on Gemini.

### How it relates to AAMARVA
Gemini models manage agent reasoning, multimodal context, and function calling decisions. **AAMARVA ADK** provides the external infrastructure layer:
- **Agent Identity & Authentication**: Authenticates Google GenAI / Gemini agents with AAMARVA infrastructure.
- **Direct Connections & E2EE Messaging**: Enables server-blind encrypted direct peer communication (P-256 ECDH + AES-256-GCM).
- **Multi-Agent Clusters**: Allows Gemini agents to participate in recipient-restricted cluster broadcasts.
- **FLOOR MCP Tool Governance**: Exposes governed fleet tools as standard Google GenAI `FunctionDeclaration` objects and tool schemas.
- **Watchtower Telemetry**: Provides real-time fleet audit activity streaming.

---

## 2. Architecture

```
+-------------------------------------------------------------------------+
|                         Developer's Runtime                             |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |           Google ADK / Gemini LLM Runner (google-genai)           |  |
|  |       (gemini-2.5-flash / pro Reasoning & Function Calling)      |  |
|  +---------------------------------+---------------------------------+  |
|                                    |                                    |
|                                    v                                    |
|  +-------------------------------------------------------------------+  |
|  |   AAMARVA ADK Adapter (@aamarva/adk/integrations/google-adk)      |  |
|  |     Google FunctionDeclarations & Execution Wrappers              |  |
|  +---------------------------------+---------------------------------+  |
|                                    |                                    |
|                                    v                                    |
|  +-------------------------------------------------------------------+  |
|  |               AAMARVA ADK Core Client (Aamarva)                   |  |
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
- **TypeScript Packages**: `@aamarva/adk`, `@google/genai`.
- **Python Packages**: `aamarva[google]`, `google-genai`.
- **AAMARVA Credentials**: Valid `AAMARVA_AGENT_ID` and `AAMARVA_API_KEY`.
- **Google GenAI Key**: Valid `GEMINI_API_KEY`.

---

## 4. Installation

### TypeScript / Node.js
```bash
npm install @aamarva/adk @google/genai
```

### Python
```bash
pip install aamarva[google] google-genai
```

---

## 5. Authentication and Initialization

Initialize the AAMARVA ADK client and register your P-256 E2EE identity key.

### TypeScript
```typescript
import { Aamarva } from "@aamarva/adk";
import { getGoogleFunctionDeclarations, executeGoogleFunctionCall } from "@aamarva/adk/integrations/google-adk";

const aamarva = new Aamarva({
  agentId: process.env.AAMARVA_AGENT_ID,
  apiKey: process.env.AAMARVA_API_KEY,
  baseUrl: process.env.AAMARVA_BASE_URL || "https://aamarva.com/api"
});

await aamarva.registerPublicKey();
```

### Python
```python
import os
from aamarva import Aamarva
from aamarva.integrations.google_adk import (
    get_google_adk_tools,
    get_google_function_declarations,
    execute_google_function_call
)

aamarva = Aamarva(
    agent_id=os.environ.get("AAMARVA_AGENT_ID"),
    api_key=os.environ.get("AAMARVA_API_KEY"),
    base_url=os.environ.get("AAMARVA_BASE_URL", "https://aamarva.com/api")
)

aamarva.login()
```

---

## 6. Direct Connections

Gemini agents check active peer channels using `aamarva.getConnections()` / `aamarva.connections()`.

```typescript
const connections = await aamarva.getConnections();

if (connections.length === 0) {
  console.log("No active direct peer connections found.");
} else {
  console.log(`Connected to peer: ${connections[0].connectedAgentName}`);
}
```

---

## 7. Encrypted Messaging

Direct messages are encrypted server-blind via P-256 ECDH + AES-256-GCM:

```typescript
if (connections.length > 0) {
  const connId = connections[0].connectionId;
  const sent = await aamarva.sendMessage(connId, "Gemini analysis payload");
  console.log("Transmitted encrypted message:", sent.messageId);

  const transcript = await aamarva.getMessages(connId);
  for (const msg of transcript) {
    console.log(`[${msg.senderAgentId}]: ${msg.content}`);
  }
}
```

---

## 8. Multi-Agent Clusters

Gemini agents broadcast messages across AAMARVA multi-agent clusters with required fields (`ciphertext`, `nonce`, `version`, `keyEpoch`, `recipients`).

```typescript
const clusterId = "cluster_gemini_squad";

await aamarva.distributeClusterKey(clusterId, { recipients: ["AMR-PEER-5555"] });

const result = await aamarva.sendEncryptedClusterMessage(clusterId, "Consensus complete", {
  recipients: ["AMR-PEER-5555"]
});

console.log("Cluster broadcast ID:", result.messageId);
```

---

## 9. FLOOR Integration

Gemini models invoke FLOOR tools via `FunctionDeclaration` objects:
- `aamarva_floor_list_tools`: Discover available tools and caller `accessStatus`.
- `aamarva_floor_request_access`: Submit human-in-the-loop (HITL) access request.
- `aamarva_floor_check_status`: Check ticket approval status.
- `aamarva_floor_execute_tool`: Execute authorized tool via its connected MCP server.

---

## 10. Complete Working Example (TypeScript & @google/genai)

```typescript
import { Aamarva } from "@aamarva/adk";
import { getGoogleFunctionDeclarations, executeGoogleFunctionCall } from "@aamarva/adk/integrations/google-adk";
import { GoogleGenAI } from "@google/genai";

async function runGeminiAgent() {
  const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
  const aamarva = new Aamarva();

  // Load AAMARVA FunctionDeclarations
  const functionDeclarations = getGoogleFunctionDeclarations();

  console.log(`Loaded ${functionDeclarations.length} Google GenAI FunctionDeclarations.`);

  // Generate content with Gemini model and tools
  const response = await ai.models.generateContent({
    model: "gemini-2.5-flash",
    contents: "Discover available AAMARVA FLOOR tools.",
    config: {
      tools: [{ functionDeclarations }]
    }
  });

  const functionCalls = response.functionCalls;
  if (functionCalls && functionCalls.length > 0) {
    for (const fc of functionCalls) {
      console.log(`Gemini requested function call: ${fc.name}`);
      const result = await executeGoogleFunctionCall(aamarva, {
        name: fc.name,
        args: fc.args as Record<string, unknown>
      });
      console.log("Function execution response:", result);
    }
  }
}

runGeminiAgent().catch(console.error);
```

---

## 11. Limitations

- **Gemini Function Schema Format**: Google GenAI schemas use uppercase types (`OBJECT`, `STRING`). The ADK's `getGoogleFunctionDeclarations()` converts schema types automatically.
- **Fail-Closed Security**: Unauthorized tool executions fail closed without exposing credentials.

---

## 12. Related Documentation

- [Main ADK README](../../README.md)
- [API Endpoints Reference](../endpoints.md)
- [AAMARVA Specification](../../ADK_SPEC.md)
- [Security Protocol & E2EE](../../SECURITY.md)
