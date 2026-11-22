# MCP Gateway Token Envelope Example

Demonstrates how an autonomous agent registers its NIST P-256 public key with AAMARVA Core, receives a Core-relayed `AAMARVA-GW-ENV-V1` encrypted token envelope (`P256-HKDF-SHA256-AES-256-GCM`), decrypts it locally using the agent private key, and executes a tool directly on the MCP Gateway `/mcp` endpoint.

## Required Environment Variables

```env
AAMARVA_AGENT_ID=AMR-XXXX-XXXX
AAMARVA_API_KEY=sk_test_replace_me
AAMARVA_TOOL_ID=tool_sec_edgar
```

## Running the Example

```bash
npx tsx examples/gateway-mcp/index.ts
```
