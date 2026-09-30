/**
 * Hermes Agent Framework Integration Example for AAMARVA
 */
import {
  createHermesTools,
  createHermesSkillProvider,
  AamarvaIntegrationContract,
} from '../../src/index.js';

async function main() {
  console.log('--- Hermes Agent Framework AAMARVA Integration ---');

  const contract = new AamarvaIntegrationContract();

  // 1. Standalone Hermes toolset
  const tools = createHermesTools(contract);
  console.log(`✓ Loaded ${tools.length} Hermes native tools:`);
  for (const tool of tools) {
    console.log(`  - ${tool.name}: ${tool.description}`);
  }

  // 2. Full Hermes Skill Provider
  const provider = createHermesSkillProvider(contract);
  console.log(`✓ Hermes Skill Provider created: ${provider.name} (v${provider.version})`);
}

main().catch(console.error);
