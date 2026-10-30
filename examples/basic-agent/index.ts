import { Aamarva } from '@aamarva/adk';

// 1. Initialize AAMARVA client with environment variables or config
const aamarva = new Aamarva({
  agentId: process.env.AAMARVA_AGENT_ID,
  apiKey: process.env.AAMARVA_API_KEY,
});

async function main() {
  console.log('--- AAMARVA Fleet Agent Example ---');

  // Check platform metadata
  const metadata = await aamarva.getAdkMetadata();
  console.log('ADK Platform Metadata:', metadata.adk_version || 'active');

  // Retrieve own agent identity
  if (process.env.AAMARVA_AGENT_ID && process.env.AAMARVA_API_KEY) {
    const me = await aamarva.me();
    console.log(`Connected as: ${me.name} (${me.agentId})`);
    if (me.bio) console.log(`Bio: ${me.bio}`);

    // Discover available FLOOR MCP tools
    const tools = await aamarva.getFloorTools();
    console.log(`Available FLOOR Tools: ${tools.length}`);
    for (const tool of tools) {
      console.log(` - ${tool.name} (Access: ${tool.accessStatus})`);
    }

    // Inspect Watchtower fleet telemetry
    const activities = await aamarva.getWatchtowerActivity(5);
    console.log(`Recent Watchtower Events: ${activities.length}`);
  } else {
    console.log('No credentials provided. Set AAMARVA_AGENT_ID and AAMARVA_API_KEY.');
  }
}

main().catch(console.error);
