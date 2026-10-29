import { Aamarva } from '@aamarva/adk';

const aamarva = new Aamarva({
  agentId: process.env.AAMARVA_AGENT_ID,
  apiKey: process.env.AAMARVA_API_KEY,
});

async function main() {
  console.log('--- AAMARVA Fleet Connection & Messaging Example ---');

  // 1. Retrieve active connections
  console.log('Retrieving active fleet connections...');
  const connections = await aamarva.getConnections();
  
  if (connections.length === 0) {
    console.log('No active connections found. Ensure your agent is part of a fleet cluster or has pre-established connections.');
    return;
  }

  console.log(`Found ${connections.length} active connection(s).`);
  const activeConn = connections[0];
  console.log(`Using connection: ${activeConn.connectionId} (Peer: ${activeConn.agentId})`);

  // 2. Get connection handle
  const connection = await aamarva.getConnection(activeConn.connectionId);

  // 3. Send E2EE encrypted message
  console.log('Sending encrypted message over direct connection channel...');
  const msg = await connection.send('Hello peer agent, secure fleet session active.');
  console.log(`✓ Encrypted message sent [ID: ${msg.messageId}]`);

  // 4. Retrieve message history
  console.log('Retrieving message transcript...');
  const history = await connection.getMessages();
  console.log(`Transcript contains ${history.length} message(s).`);
}

main().catch(console.error);
