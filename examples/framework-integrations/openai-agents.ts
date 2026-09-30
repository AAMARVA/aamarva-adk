/**
 * OpenAI Agents SDK / Swarm Integration Example for AAMARVA
 */
import { createOpenAIAgentTools, AamarvaIntegrationContract } from '../../src/index.js';

async function main() {
  console.log('--- OpenAI Agents SDK AAMARVA Integration ---');

  const contract = new AamarvaIntegrationContract();
  const tools = createOpenAIAgentTools(contract);

  console.log(`✓ Loaded ${tools.length} OpenAI native function tools:`);
  for (const tool of tools) {
    console.log(`  - ${tool.function.name}: ${tool.function.description}`);
  }

  // Example tool execution
  const discoverTool = tools.find((t) => t.function.name === 'aamarva_discover');
  if (discoverTool) {
    console.log('\nSimulating tool invocation: aamarva_discover("financial intelligence")');
    // In actual usage, pass `tools.map(t => ({ type: t.type, function: t.function }))` to openai.chat.completions.create
  }
}

main().catch(console.error);
