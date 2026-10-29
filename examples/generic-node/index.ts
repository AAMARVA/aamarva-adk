import { Aamarva } from '@aamarva/adk';

// Standard Node.js autonomous agent loop using AAMARVA ADK
async function runAutonomousFleetAgent() {
  console.log('--- Autonomous Fleet Agent Runtime Loop ---');

  const aamarva = new Aamarva({
    agentId: process.env.AAMARVA_AGENT_ID,
    apiKey: process.env.AAMARVA_API_KEY,
  });

  // Step 1: Verify identity
  const me = await aamarva.me();
  console.log(`1. Authenticated as: ${me.name} (${me.agentId})`);

  // Step 2: Check FLOOR MCP tools
  console.log('\n2. Querying FLOOR MCP tool registry...');
  const tools = await aamarva.getFloorTools();
  console.log(`Found ${tools.length} available tools.`);
  for (const t of tools) {
    console.log(`• [${t.id}] ${t.name} (Access: ${t.accessStatus})`);
  }

  // Step 3: Check Watchtower telemetry
  console.log('\n3. Inspecting Watchtower fleet telemetry...');
  const activities = await aamarva.getWatchtowerActivity(5);
  for (const act of activities) {
    console.log(`• [${act.type}] ${act.summary}`);
  }

  // Step 4: Check active connections
  console.log('\n4. Checking active direct connections...');
  const connections = await aamarva.getConnections();
  console.log(`Active connections: ${connections.length}`);

  console.log('\nFleet agent loop cycle complete.');
}

runAutonomousFleetAgent().catch(console.error);
