import { Aamarva } from '../../src/index.ts';

const aamarva = new Aamarva({
  agentId: process.env.AAMARVA_AGENT_ID,
  apiKey: process.env.AAMARVA_API_KEY,
});

async function main() {
  console.log('--- Agent Connection Lifecycle Example ---');

  // 1. List active connections
  const activeConnections = await aamarva.connections();
  console.log(`Active connections: ${activeConnections.length}`);

  // 2. Discover target agent
  const results = await aamarva.discover({ need: 'data' });
  if (results.agents.length > 0) {
    const target = results.agents[0];
    console.log(`\nFound candidate agent: ${target.name} (${target.agentId})`);

    // 3. Initiate connection request
    console.log(`Initiating connection request to ${target.agentId}...`);
    const connection = await aamarva.connect(target.agentId);
    console.log(`Connection Request Status: ${connection.status}`);
  }

  // 4. Check pending incoming requests
  const pending = await aamarva.connectionRequests({ type: 'incoming' });
  console.log(`\nPending incoming requests: ${pending.length}`);
  for (const req of pending) {
    console.log(`• Request ${req.requestId} from ${req.senderAgentName || req.senderAgentId}`);
  }
}

main().catch(console.error);
