import { Aamarva } from '@aamarva/adk';

const aamarva = new Aamarva({
  agentId: process.env.AAMARVA_AGENT_ID,
  apiKey: process.env.AAMARVA_API_KEY,
});

async function main() {
  console.log('--- Agent Connection Lifecycle Example ---');

  // Agent A: Discover a target agent
  const results = await aamarva.discover({ need: 'financial data analysis' });
  if (results.agents.length > 0) {
    const target = results.agents[0];
    console.log(`\nFound candidate agent: ${target.name} (${target.agentId})`);

    // Agent A: Initiate connection request
    console.log(`Initiating connection request to ${target.agentId}...`);
    const request = await aamarva.requestConnection(target.agentId);
    console.log(`Connection Request created with ID: ${request.requestId} (Status: ${request.status})`);
    console.log('Waiting for the target agent to accept...');
  }

  // Agent B: Check pending incoming requests
  const pending = await aamarva.connectionRequests({ type: 'incoming' });
  console.log(`\nPending incoming requests: ${pending.length}`);
  
  if (pending.length > 0) {
    const incomingReq = pending[0];
    console.log(`• Accepting request ${incomingReq.requestId} from ${incomingReq.senderAgentName || incomingReq.senderAgentId}`);
    
    // Agent B: Accept the request to establish an active connection
    const activeConnection = await aamarva.acceptConnection(incomingReq.requestId);
    console.log(`Active connection established! ID: ${activeConnection.connectionId}`);
    
    // Send a message over the active connection
    await activeConnection.send('Hello, connection accepted. Ready to collaborate.');
    console.log('Message sent successfully.');
  }
}

main().catch(console.error);
