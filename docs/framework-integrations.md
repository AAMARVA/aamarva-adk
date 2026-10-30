# AAMARVA ADK Framework Integrations & Protocol Guide

The AAMARVA Agent Development Kit (ADK) provides native, standards-compliant integrations for established AI agent frameworks and protocols across TypeScript and Python.

Integrations are organized as separate modular exports, ensuring the core ADK remains thin, framework-independent, and secure. All integrations strictly preserve the 26-endpoint allowlist and AAMARVA FLOOR zero-trust authorization workflow.

---

## Table of Contents

1. [Architecture & Installation](#1-architecture--installation)
2. [Model Context Protocol (MCP) Server](#2-model-context-protocol-mcp-server)
   - [Protocol Lifecycle & Tools](#protocol-lifecycle--tools)
   - [Stdio Transport](#stdio-transport)
   - [Streamable HTTP Transport](#streamable-http-transport)
   - [Python MCP Server](#python-mcp-server)
3. [Priority 1 Framework Integrations](#3-priority-1-framework-integrations)
   - [LangChain](#langchain)
   - [LangGraph](#langgraph)
   - [CrewAI](#crewai)
   - [AutoGen (AG2)](#autogen-ag2)
   - [OpenAI Agents SDK & Function Calling](#openai-agents-sdk--function-calling)
   - [Google ADK & Gemini](#google-adk--gemini)
4. [Priority 2 Framework Integrations](#4-priority-2-framework-integrations)
   - [Agno (Phidata)](#agno-phidata)
   - [LlamaIndex](#llamaindex)
5. [Security, Governance & Fail-Closed Guarantees](#5-security-governance--fail-closed-guarantees)

---

## 1. Architecture & Installation

### TypeScript (npm)

The core `@aamarva/adk` package contains zero mandatory framework dependencies. Framework integrations are imported via dedicated submodules:

```bash
npm install @aamarva/adk
```

Install only the framework adapters you require:
```bash
# Model Context Protocol
npm install @modelcontextprotocol/sdk

# LangChain & LangGraph
npm install @langchain/core @langchain/langgraph

# OpenAI
npm install openai

# Google ADK / Gemini
npm install @google/genai
```

Import cleanly in TypeScript / ESM:
```typescript
import { Aamarva } from "@aamarva/adk";
import { createAamarvaMcpServer, startStdioMcpServer } from "@aamarva/adk/integrations/mcp";
import { getOpenAITools, handleOpenAIToolCall } from "@aamarva/adk/integrations/openai";
import { getLangChainTools } from "@aamarva/adk/integrations/langchain";
import { createLangGraphToolNode } from "@aamarva/adk/integrations/langgraph";
import { getGoogleAdkTools } from "@aamarva/adk/integrations/google-adk";
import { getAutoGenTools, registerAutoGenTools } from "@aamarva/adk/integrations/autogen";
import { getLlamaIndexTools } from "@aamarva/adk/integrations/llamaindex";
```

### Python (pip)

The core `aamarva` package has zero third-party dependencies. Install framework extras on demand:

```bash
# Install core
pip install aamarva

# Install specific framework extras
pip install aamarva[mcp]
pip install aamarva[langchain]
pip install aamarva[langgraph]
pip install aamarva[crewai]
pip install aamarva[autogen]
pip install aamarva[openai]
pip install aamarva[google]
pip install aamarva[agno]
pip install aamarva[llamaindex]

# Install all framework integrations
pip install aamarva[all]
```

Import cleanly in Python:
```python
from aamarva import Aamarva
from aamarva.integrations.mcp import AamarvaMcpServer, create_aamarva_mcp_server
from aamarva.integrations.openai import get_openai_tools, handle_openai_tool_call
from aamarva.integrations.langchain import get_langchain_tools
from aamarva.integrations.langgraph import create_langgraph_tool_node
from aamarva.integrations.crewai import get_crewai_tools, AamarvaFloorTool
from aamarva.integrations.autogen import get_autogen_tools, register_autogen_tools
from aamarva.integrations.google_adk import get_google_adk_tools
from aamarva.integrations.agno import AamarvaAgnoToolkit, get_agno_tools
from aamarva.integrations.llamaindex import get_llamaindex_tools
```

---

## 2. Model Context Protocol (MCP) Server

AAMARVA provides a genuine, standards-compliant MCP server built on the official Model Context Protocol specifications (protocol version `2024-11-05`), featuring full protocol lifecycle negotiation, `tools/list`, and `tools/call`.

### Registered MCP Tools

| MCP Tool Name | Description | Parameters |
|---|---|---|
| `aamarva_floor_list_tools` | Discover available FLOOR tools and caller authorization status | None |
| `aamarva_floor_request_access` | Submit Human-in-the-Loop (HITL) approval request | `toolId` (string), `reason` (optional string) |
| `aamarva_floor_check_status` | Query authorization approval status of an access ticket | `requestId` (string) |
| `aamarva_floor_execute_tool` | Execute an authorized tool with schema-validated arguments | `toolId` (string), `arguments` (object) |
| `aamarva_send_message` | Send End-to-End Encrypted message over an active connection channel | `connectionId` (string), `content` (string) |
| `aamarva_get_messages` | Retrieve and locally decrypt transcript from a direct channel | `connectionId` (string) |
| `aamarva_cluster_send_message` | Broadcast message to multi-agent cluster with recipient restriction | `clusterId`, `ciphertext`, `nonce`, `recipients` |
| `aamarva_watchtower_activity` | Query recent fleet activity audit logs and state changes | `limit` (optional number) |
| `aamarva_agent_footprints` | Retrieve agent audit footprints trace | None |
| `aamarva_webhook_events` | Retrieve webhook delivery logs | None |
| `aamarva_get_agents` | Query fleet accounts (master and slave agents) | `q`, `page`, `limit` |
| `aamarva_get_clusters` | Query agent cluster memberships | None |

### Stdio Transport

Used for local orchestration, Claude Desktop, Cursor, or agent subprocesses:

```typescript
import { Aamarva } from "@aamarva/adk";
import { startStdioMcpServer } from "@aamarva/adk/integrations/mcp";

const client = new Aamarva();
const { server, transport } = await startStdioMcpServer(client);
console.log("AAMARVA MCP Stdio Server running.");
```

### Streamable HTTP Transport

Used for remote microservices, webhooks, and containerized deployments with SSE streaming:

```typescript
import http from "node:http";
import { Aamarva } from "@aamarva/adk";
import { createStreamableHttpMcpHandler } from "@aamarva/adk/integrations/mcp";

const client = new Aamarva();
const mcpHttpHandler = createStreamableHttpMcpHandler(client);

const server = http.createServer(async (req, res) => {
  if (req.url === "/mcp" || req.url?.startsWith("/mcp?")) {
    await mcpHttpHandler(req, res);
  } else {
    res.writeHead(404).end("Not Found");
  }
});

server.listen(3000, () => {
  console.log("AAMARVA Streamable HTTP MCP Server listening on port 3000");
});
```

### Python MCP Server

```python
from aamarva import Aamarva
from aamarva.integrations.mcp import AamarvaMcpServer

client = Aamarva()
server = AamarvaMcpServer(client)

# Run over standard I/O
server.run_stdio_server()
```

---

## 3. Priority 1 Framework Integrations

### LangChain

Exposes dynamic `StructuredTool` instances with `.invoke()`, `.call()`, and input schemas.

```typescript
import { Aamarva } from "@aamarva/adk";
import { getLangChainTools } from "@aamarva/adk/integrations/langchain";
import { ChatOpenAI } from "@langchain/openai";

const client = new Aamarva();
const tools = await getLangChainTools(client);

const model = new ChatOpenAI({ model: "gpt-4o" }).bindTools(tools);
const response = await model.invoke("List my available sovereign FLOOR tools");
```

```python
from aamarva import Aamarva
from aamarva.integrations.langchain import get_langchain_tools

client = Aamarva()
tools = get_langchain_tools(client)

# Execute tool directly
result = tools[0].invoke({})
print("Available tools:", result)
```

### LangGraph

Provides pre-built `ToolNode` handlers processing messages and tool calls inside a `StateGraph`.

```typescript
import { Aamarva } from "@aamarva/adk";
import { createLangGraphToolNode } from "@aamarva/adk/integrations/langgraph";
import { StateGraph, MessagesAnnotation } from "@langchain/langgraph";

const client = new Aamarva();
const toolNode = await createLangGraphToolNode(client);

const graph = new StateGraph(MessagesAnnotation)
  .addNode("tools", toolNode)
  // ... configure graph edges
  .compile();
```

```python
from aamarva import Aamarva
from aamarva.integrations.langgraph import create_langgraph_tool_node

client = Aamarva()
tool_node = create_langgraph_tool_node(client)

state = {
    "messages": [
        {"role": "assistant", "tool_calls": [{"id": "call_1", "name": "aamarva_floor_list_tools", "args": {}}]}
    ]
}
result = tool_node(state)
print("Tool output messages:", result["messages"])
```

### CrewAI

> **Note**: CrewAI is a Python-first framework. The AAMARVA integration provides genuine `BaseTool` subclasses (`AamarvaFloorTool`, `AamarvaMessagingTool`, `AamarvaClusterTool`, `AamarvaWatchtowerTool`).

```python
from crewai import Agent, Task, Crew
from aamarva import Aamarva
from aamarva.integrations.crewai import get_crewai_tools

client = Aamarva()
tools = get_crewai_tools(client)

researcher = Agent(
    role="Sovereign Fleet Auditor",
    goal="Inspect fleet health and discover approved tools",
    backstory="Autonomous agent with sovereign access to AAMARVA fleet primitives.",
    tools=tools,
    verbose=True,
)

task = Task(
    description="Query Watchtower activity and list available tools.",
    expected_output="Summary report of fleet operations.",
    agent=researcher,
)

crew = Crew(agents=[researcher], tasks=[task])
crew.kickoff()
```

### AutoGen (AG2 & AgentChat 0.4+)

AAMARVA natively supports both modern **AutoGen AgentChat 0.4+** (`autogen-agentchat>=0.4.0`) via typed tool definitions, and legacy **AutoGen 0.2.x** via `register_for_llm` and `register_for_execution`.

```python
from aamarva import Aamarva
from aamarva.integrations.autogen import get_autogen_agentchat_tools, register_legacy_autogen_tools

client = Aamarva()

# Modern AutoGen 0.4+ tool definitions:
agentchat_tools = get_autogen_agentchat_tools(client)

# Legacy AutoGen 0.2.x ConversableAgent registration:
# from autogen import ConversableAgent
# assistant = ConversableAgent("assistant", llm_config={"model": "gpt-4o"})
# user_proxy = ConversableAgent("user_proxy", human_input_mode="NEVER")
# register_legacy_autogen_tools(assistant, user_proxy, client)
```

```typescript
import { Aamarva } from "@aamarva/adk";
import { getAutoGenTools, registerAutoGenTools } from "@aamarva/adk/integrations/autogen";

const client = new Aamarva();
const tools = getAutoGenTools(client);
```

### OpenAI Agents SDK & Function Calling

Conforms to both the OpenAI Agents SDK (`OpenAIAgentTool` instances with schema validation and native `.execute()`) and standard Chat Completions `type: "function"` definitions.

```typescript
import OpenAI from "openai";
import { Aamarva } from "@aamarva/adk";
import { getOpenAITools, handleOpenAIToolCall } from "@aamarva/adk/integrations/openai";

const openai = new OpenAI();
const aamarva = new Aamarva();

const tools = getOpenAITools(aamarva);

const runner = await openai.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "Check my Watchtower security telemetry" }],
  tools,
});

const toolCall = runner.choices[0].message.tool_calls?.[0];
if (toolCall) {
  const toolResponse = await handleOpenAIToolCall(aamarva, toolCall);
  console.log("Tool response message:", toolResponse);
}
```

```python
from openai import OpenAI
from aamarva import Aamarva
from aamarva.integrations.openai import get_openai_tools, handle_openai_tool_call

openai = OpenAI()
client = Aamarva()
tools = get_openai_tools(client)

response = openai.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "List available FLOOR tools"}],
    tools=tools,
)

tool_call = response.choices[0].message.tool_calls[0]
tool_message = handle_openai_tool_call(client, tool_call.model_dump())
print("Tool result:", tool_message)
```

### Google ADK & Gemini

Conforms to the modern `@google/genai` TypeScript SDK and `google-genai` Python SDK `FunctionDeclaration` schema.

```typescript
import { GoogleGenAI } from "@google/genai";
import { Aamarva } from "@aamarva/adk";
import { getGoogleAdkTools, executeGoogleAdkFunction } from "@aamarva/adk/integrations/google-adk";

const ai = new GoogleGenAI();
const client = new Aamarva();
const aamarvaTools = getGoogleAdkTools(client);

const response = await ai.models.generateContent({
  model: "gemini-2.5-flash",
  contents: "Discover available tools in my sovereign fleet",
  config: {
    tools: [aamarvaTools],
  },
});

const call = response.functionCalls?.[0];
if (call) {
  const result = await executeGoogleAdkFunction(client, call);
  console.log("Function response:", result);
}
```

```python
from google import genai
from aamarva import Aamarva
from aamarva.integrations.google_adk import get_google_adk_tools, execute_google_adk_function

ai = genai.Client()
client = Aamarva()
tools = get_google_adk_tools(client)

response = ai.models.generate_content(
    model="gemini-2.5-flash",
    contents="List available fleet tools",
    config={"tools": [tools]},
)
```

---

## 4. Priority 2 Framework Integrations

### Agno (Phidata)

> **Note**: Agno is a Python-first framework. The AAMARVA integration provides `AamarvaAgnoToolkit` for multi-agent teams and sovereign coordination.

```python
from agno.agent import Agent
from aamarva import Aamarva
from aamarva.integrations.agno import AamarvaAgnoToolkit

client = Aamarva()
toolkit = AamarvaAgnoToolkit(client=client)

agent = Agent(
    name="Sovereign Agent",
    tools=[toolkit],
    show_tool_calls=True,
)
agent.print_response("Check active peer connections and list tools")
```

### LlamaIndex

Provides genuine `FunctionTool` wrappers for LlamaIndex query engines and agents.

```typescript
import { Aamarva } from "@aamarva/adk";
import { getLlamaIndexTools } from "@aamarva/adk/integrations/llamaindex";

const client = new Aamarva();
const tools = await getLlamaIndexTools(client);
```

```python
from aamarva import Aamarva
from aamarva.integrations.llamaindex import get_llamaindex_tools

client = Aamarva()
tools = get_llamaindex_tools(client)
```

---

## 5. Security, Governance & Fail-Closed Guarantees

All framework adapters strictly enforce AAMARVA security invariants:

1. **Approved Endpoint Allowlist Only**: Every API call routes through the existing 26-endpoint allowlist enforced in `src/http.ts` and `python/aamarva/http.py`. No raw HTTP requests or unapproved pathways are ever introduced.
2. **FLOOR Zero-Trust Access Control**: Executing an unauthorized, pending, or revoked FLOOR tool immediately fails closed (`FLOOR_ACCESS_DENIED`). Adapters catch this failure safely and return structured error messages without crashing the runtime.
3. **No Credential Leaks**: Tokens, session keys, and internal platform credentials are never exposed in tool error responses or JSON-RPC payloads.
4. **End-to-End Encryption**: Peer messages and cluster packages use native curve P-256 E2EE encryption before leaving the host process.
