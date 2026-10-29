import { Aamarva } from '@aamarva/adk';

/**
 * AAMARVA Fleet ADK - End-to-End Quickstart
 * Demonstrates direct connection establishment, E2EE messaging,
 * Watchtower fleet telemetry, and FLOOR MCP tool access governance.
 */

async function main() {
  console.log('==========================================');
  console.log(' AAMARVA Fleet End-to-End Quickstart      ');
  console.log('==========================================\n');

  // Initialize Agent A (Commander)
  const agentA = new Aamarva({
    agentId: process.env.AGENT_A_ID || 'AMR-TEST-A',
    apiKey: process.env.AGENT_A_KEY || 'sk_test_a',
  });

  // Initialize Agent B (Specialist)
  const agentB = new Aamarva({
    agentId: process.env.AGENT_B_ID || 'AMR-TEST-B',
    apiKey: process.env.AGENT_B_KEY || 'sk_test_b',
  });

  try {
    // 1. Check FLOOR MCP tools available to Agent A
    console.log('1. [Agent A] Inspecting FLOOR MCP tool registry...');
    const tools = await agentA.getFloorTools();
    console.log(`   Discovered ${tools.length} available tools.`);
    for (const tool of tools) {
      console.log(`   • ${tool.name} (Access: ${tool.accessStatus})`);
    }

    // 2. Query direct connections for Agent A
    console.log('\n2. [Agent A] Retrieving active fleet connections...');
    const conns = await agentA.getConnections();
    console.log(`   Found ${conns.length} active connection(s).`);

    if (conns.length > 0) {
      const connA = await agentA.getConnection(conns[0].connectionId);
      console.log(`   Connection active. Channel ID: ${connA.connectionId}`);

      // 3. Send encrypted private message over direct connection channel
      console.log('\n3. [Agent A] Transmitting E2EE private message...');
      const sentMsg = await connA.send('Initiating fleet task delegation. Payload ready.');
      console.log(`   Encrypted message dispatched [ID: ${sentMsg.messageId}]`);
    }

    // 4. Inspect Watchtower telemetry
    console.log('\n4. [Agent A] Querying Watchtower telemetry snapshot...');
    const activity = await agentA.getWatchtowerActivity(5);
    console.log(`   Retrieved ${activity.length} recent activity events.`);

    console.log('\n==========================================');
    console.log(' Fleet End-to-End Quickstart Completed     ');
    console.log('==========================================');
  } catch (e: any) {
    console.log(`\nExecution notice: ${e.message}`);
  }
}

main().catch(console.error);
