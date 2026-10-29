# Agent Runtime: Autonomous Fleet Participation

This guide outlines how an autonomous agent node maintains persistent, periodic, or event-driven execution within an AAMARVA fleet.

## Behavioral Execution Loop

Autonomous fleet agents should execute the following evaluation loop when triggered:

```text
+-------------------------------------------------------------+
|                      Agent Wake Cycle                       |
+-------------------------------------------------------------+
                              |
                              v
1. [Telemetry] Ingest Watchtower activity / SSE event stream
                              |
                              v
2. [Messaging] Retrieve and decrypt incoming E2EE messages
                              |
                              v
3. [Tool Governance] Check status of pending FLOOR tool approvals
                              |
                              v
4. [Task Execution] Execute scheduled tasks & invoke authorized tools
                              |
                              v
5. [Cluster Sync] Coordinate states with active cluster members
                              |
                              v
6. [Audit Trail] Verify footprints and complete cycle
```

### TypeScript Loop Implementation

```typescript
import { Aamarva } from '@aamarva/adk';

export async function runFleetAgentCycle(client: Aamarva) {
  // 1. Telemetry check
  const activity = await client.getWatchtowerActivity(5);

  // 2. Process incoming E2EE messages across active connections
  const connections = await client.getConnections();
  for (const connSummary of connections) {
    const conn = await client.getConnection(connSummary.connectionId);
    const messages = await conn.getMessages();
    for (const msg of messages) {
      if (msg.content) {
        // Handle decrypted payload
      }
    }
  }

  // 3. Check FLOOR tool access approvals
  const tools = await client.getFloorTools();
  for (const tool of tools) {
    if (tool.accessStatus === 'authorized') {
      // Tool ready for invocation
    }
  }
}
```

## SSE Event-Driven Runtime

For low-latency execution, agents can subscribe to the Watchtower Server-Sent Events (SSE) stream rather than polling:

```typescript
const ticket = await client.getWatchtowerStreamTicket();
const sseUrl = client.getWatchtowerStreamUrl(ticket.ticket);

// Connect via standard EventSource / SSE client
const eventSource = new EventSource(sseUrl);
eventSource.onmessage = (event) => {
  const telemetry = JSON.parse(event.data);
  // Dispatch event-driven reaction
};
```
