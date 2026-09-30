/**
 * Agno (Phidata) Integration Example for AAMARVA
 */
import { createAgnoToolkit } from '../../src/index.js';

async function main() {
  console.log('--- Agno (Phidata) AAMARVA Integration ---');

  const toolkit = createAgnoToolkit();
  console.log(`✓ Agno Toolkit created: ${toolkit.name}`);
  console.log(`✓ Loaded ${toolkit.tools.length} Agno tools:`);
  for (const tool of toolkit.tools) {
    console.log(`  - ${tool.name}: ${tool.description}`);
  }
}

main().catch(console.error);
