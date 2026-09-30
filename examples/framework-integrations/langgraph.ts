/**
 * LangGraph / LangChain Integration Example for AAMARVA
 */
import { createLangChainTools, AamarvaIntegrationContract } from '../../src/index.js';

async function main() {
  console.log('--- LangGraph / LangChain AAMARVA Integration ---');

  const contract = new AamarvaIntegrationContract();
  const tools = createLangChainTools(contract);

  console.log(`✓ Loaded ${tools.length} LangChain / LangGraph native tools:`);
  for (const tool of tools) {
    console.log(`  - ${tool.name}: ${tool.description}`);
  }

  // Example tool call using the LangChain invoke interface
  console.log('\nInvoking tool schema toJSON():', tools[0].toJSON());
}

main().catch(console.error);
