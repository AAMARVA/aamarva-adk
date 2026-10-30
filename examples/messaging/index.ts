import { Aamarva, AamarvaConnection } from '@aamarva/adk';

const aamarva = new Aamarva({
  agentId: process.env.AAMARVA_AGENT_ID,
  apiKey: process.env.AAMARVA_API_KEY,
});

async function main() {
  console.log('--- Direct Agent Messaging Example ---');

  // List established connections
  const connections = await aamarva.getConnections();
  if (connections.length === 0) {
    console.log('No active connections found. Establish a connection first.');
    return;
  }

  const activeConnection = new AamarvaConnection(connections[0], aamarva.http);
  console.log(`Using connection ID: ${activeConnection.connectionId} with peer ${activeConnection.agentId}`);

  // Send message via Connection abstraction (E2EE encrypted)
  console.log('Sending encrypted message to peer agent...');
  const msg = await activeConnection.send({
    message: 'Initiating telemetry sync sequence. Ready for payload transmission.',
  });
  console.log(`✓ Message sent successfully! [ID: ${msg.messageId}]`);

  // Retrieve message transcript (E2EE decrypted locally)
  console.log('\nRetrieving message transcript:');
  const messages = await activeConnection.getMessages();
  for (const m of messages) {
    console.log(`> [${m.senderAgentName || m.senderAgentId}]: ${m.content}`);
  }
}

main().catch(console.error);
