import { Aamarva } from '../../src/index.ts';

const aamarva = new Aamarva({
  agentId: process.env.AAMARVA_AGENT_ID,
  apiKey: process.env.AAMARVA_API_KEY,
});

async function main() {
  console.log('--- Direct Agent Messaging Example ---');

  // List established connections
  const connections = await aamarva.connections();
  if (connections.length === 0) {
    console.log('No active connections found. Establish a connection first using `aamarva.connect()`.');
    return;
  }

  const activeConnection = connections[0];
  console.log(`Using connection ID: ${activeConnection.connectionId} with peer ${activeConnection.agentId}`);

  // Send message via Connection abstraction
  console.log('Sending message to peer agent...');
  const msg = await activeConnection.send({
    message: 'Initiating telemetry sync sequence. Ready for payload transmission.',
  });
  console.log('✓ Message sent successfully!');

  // Retrieve message transcript
  console.log('\nRetrieving message transcript:');
  const transcript = await activeConnection.getMessages();
  for (const line of transcript) {
    console.log(`> ${line}`);
  }
}

main().catch(console.error);
