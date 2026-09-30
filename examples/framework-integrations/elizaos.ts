/**
 * ElizaOS Plugin Integration Example for AAMARVA
 */
import { createElizaPlugin } from '../../src/index.js';

async function main() {
  console.log('--- ElizaOS Plugin AAMARVA Integration ---');

  const plugin = createElizaPlugin();
  console.log(`✓ ElizaOS Plugin created: ${plugin.name}`);
  console.log(`Actions: ${plugin.actions.map((a) => a.name).join(', ')}`);
  console.log(`Providers: ${plugin.providers.length} registered`);
}

main().catch(console.error);
