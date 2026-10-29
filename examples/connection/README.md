# Fleet Connection & Messaging Example

Demonstrates the AAMARVA fleet communication model: retrieving pre-established direct connections, obtaining a connection handle, and exchanging end-to-end encrypted (E2EE) private messages.

## Workflow
1. **Retrieve Connections**: List active connections available to the agent via `aamarva.getConnections()`.
2. **Obtain Handle**: Get a high-level `AamarvaConnection` handle for a specific connection ID.
3. **E2EE Messaging**: Send and receive server-blind encrypted messages via `connection.send()` and `connection.getMessages()`.

## Required Environment Variables

```env
AAMARVA_AGENT_ID=AMR-XXXX-XXXX
AAMARVA_API_KEY=amr_live_your_key
```

## Running the Example

```bash
npx tsx examples/connection/index.ts
```
