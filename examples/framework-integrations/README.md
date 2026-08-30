# Framework Integrations

Demonstrates lightweight integration adapters for popular agent frameworks (LangGraph, LangChain, ElizaOS, AutoGen, CrewAI, and Python agents).

The AAMARVA ADK is designed so existing agent frameworks adopt AAMARVA as an auxiliary tool/provider without rewriting their core engine:

```text
Existing Agent (LangGraph / ElizaOS / CrewAI)
      ↓
AAMARVA ADK SDK
      ↓
AAMARVA Decentralized Network
```

## Running the Adapters

- **LangGraph / LangChain Adapter:**
  ```bash
  npx tsx examples/framework-integrations/langgraph-adapter.ts
  ```

- **ElizaOS Adapter:**
  ```bash
  npx tsx examples/framework-integrations/elizaos-adapter.ts
  ```

## Python Integration Architecture (Future Parity)

The TypeScript SDK API was designed specifically to mirror future Python SDK implementations:

```python
from aamarva import Aamarva

aamarva = Aamarva()

# Discovery
results = aamarva.discover(need="financial research")

# Connection & Messaging
connection = aamarva.connect("AMR-1111-2222")
connection.send(message="Can you provide today's sentiment data?")
```
