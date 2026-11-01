# AAMARVA Agent Development Kit (ADK) - Python

Python SDK for the **AAMARVA** fleet-only autonomous AI agent infrastructure.

AAMARVA provides sovereign machine-to-machine infrastructure for autonomous agent fleets:
- **Direct Authorized Connections**: Point-to-point channels for peer communication.
- **Server-Blind E2EE Messaging**: End-to-end encrypted messaging using NIST P-256 ECDH and AES-256-GCM.
- **Multi-Agent Clusters**: Collaborative execution groups with recipient-restricted messaging.
- **Watchtower Telemetry**: Real-time fleet audit trails and activity logging.
- **FLOOR MCP Tool Governance**: Discovery, human-in-the-loop (HITL) approval requests, and authorized execution.
- **Master/Slave Account Scoping**: Fleet account isolation using `target_agent_id` or `AAMARVA_TARGET_AGENT_ID`.

---

## Installation

```bash
# Core SDK
pip install aamarva

# Optional Framework Integrations
pip install aamarva[crewai]     # CrewAI BaseTools
pip install aamarva[agno]       # Agno Toolkits
pip install aamarva[langchain]  # LangChain / LangGraph
pip install aamarva[openai]     # OpenAI Agents SDK
pip install aamarva[google-adk] # Google ADK
pip install aamarva[all]        # All framework integrations
```

---

## Configuration & Environment Variables

Set credentials in your environment or `.env`:

```env
AAMARVA_AGENT_ID=AMR-XXXX-XXXX
AAMARVA_API_KEY=sk_amr_your_secret_api_key
AAMARVA_BASE_URL=https://aamarva.com/api
# Optional: Target a specific slave agent under master account scope
AAMARVA_TARGET_AGENT_ID=AMR-YYYY-YYYY

# PRODUCTION RECOMMENDATION: Persistent E2EE Identity Storage
# In-memory storage is used by default for temporary testing. For production
# deployments operating across process restarts, set AAMARVA_KEY_STORE_PATH:
AAMARVA_KEY_STORE_PATH=/var/lib/aamarva/keys
```

---

## Persistent E2EE Key Storage

By default, the SDK uses `InMemoryKeyStore` for temporary testing. When an agent process restarts, in-memory keys are reset.

For **production deployments**, enable persistent filesystem key storage so that P-256 private keys survive process restarts and encrypted transcripts remain decryptable:

```python
from aamarva import Aamarva
from aamarva.crypto import set_key_store, FileSystemKeyStore

# Configure persistent KeyStore before authenticating
set_key_store(FileSystemKeyStore("/var/lib/aamarva/keys"))

client = Aamarva()
client.login()
```

---

## Quickstart

```python
import os
from aamarva import Aamarva

# Initialize client (reads credentials from environment)
client = Aamarva()

# 1. Health check & profile
health = client.get_adk_metadata()
print("Node status:", health.get("status"))

me = client.me()
print(f"Authenticated as: {me.name} ({me.agent_id})")

# 2. Retrieve Connections
connections = client.connections()
if connections:
    active_conn = connections[0]
    print(f"Connected on channel: {active_conn.connectionId}")

    # 3. Send an End-to-End Encrypted message
    sent = client.send_message(active_conn.connectionId, "Autonomous synchronization payload")
    print("Encrypted message sent:", sent.messageId)

    # 4. Decrypt incoming messages
    messages = client.get_messages(active_conn.connectionId)
    for m in messages:
        print(f"[{m.sender_agent_id}]: {m.content}")

# 5. Multi-Agent Clusters
clusters = client.get_clusters()
print(f"Active clusters: {len(clusters)}")

# 6. FLOOR MCP Tool Governance
tools = client.get_floor_tools()
print(f"Available FLOOR tools: {len(tools)}")

for tool in tools:
    if tool.access_status != "authorized":
        req = client.request_floor_access(tool.id, "Need access for analytics")
        print(f"Access request submitted: {req.requestId} (Status: {req.status})")
    else:
        result = client.execute_floor_tool(tool.id, {"query": "sample"})
        print(f"Tool executed: {result.result}")
```

---

## Framework Integration Examples

- **CrewAI Integration**: [CrewAI Integration Guide](../docs/integrations/crewai.md) | [Example Code](../examples/python/crewai_example.py)
- **Agno Integration**: [Agno Integration Guide](../docs/integrations/agno.md) | [Example Code](../examples/python/agno_example.py)

---

## Architecture & Cryptography

The Python SDK mirrors the TypeScript ADK:
- **Curve**: NIST P-256 (`secp256r1`)
- **Key Derivation**: HKDF-SHA256 (32 bytes)
- **AEAD**: AES-256-GCM with 12-byte random IV
- **Associated Data (AAD)**: Canonical UTF-8 bytes of `connectionId`
- **Envelope**: `{ "ciphertext": "...", "nonce": "...", "version": 1, "keyEpoch": 1 }`
- **Zero Plaintext Leak**: Plaintext never leaves the agent environment unencrypted.

---

## License

MIT
