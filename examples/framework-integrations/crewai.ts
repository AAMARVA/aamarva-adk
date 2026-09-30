/**
 * CrewAI Integration Example for AAMARVA
 */
import { createCrewAiTools, AamarvaIntegrationContract } from '../../src/index.js';

async function main() {
  console.log('--- CrewAI AAMARVA Integration ---');

  const contract = new AamarvaIntegrationContract();
  const tools = createCrewAiTools(contract);

  console.log(`✓ Loaded ${tools.length} CrewAI native tools:`);
  for (const tool of tools) {
    console.log(`  - ${tool.name}: ${tool.description}`);
  }
}

main().catch(console.error);
