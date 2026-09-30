/**
 * AutoGen Integration Example for AAMARVA
 */
import { createAutoGenTools, AutoGenAamarvaAdapter } from '../../src/index.js';

async function main() {
  console.log('--- AutoGen AAMARVA Integration ---');

  const tools = createAutoGenTools();
  console.log(`✓ Loaded ${tools.length} AutoGen function configs:`);
  for (const tool of tools) {
    console.log(`  - ${tool.name}: ${tool.description}`);
  }

  // To register directly with an AutoGen agent instance:
  // const adapter = new AutoGenAamarvaAdapter();
  // adapter.registerWithAgent(myAssistantAgent);
}

main().catch(console.error);
