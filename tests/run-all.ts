import { execSync } from 'child_process';

console.log('==================================================');
console.log('   RUNNING ALL AAMARVA FLEET ADK TEST SUITES      ');
console.log('==================================================\n');

try {
  console.log('▶ [1/8] Running Contract & Specification Validation...');
  execSync('npx tsx tests/adk.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [2/8] Running Fleet SDK & Developer Experience Suite...');
  execSync('npx tsx tests/sdk.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [3/8] Running Fleet Contract & FLOOR MCP Suite...');
  execSync('npx tsx tests/fleet-contract.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [4/8] Running CLI Fleet Diagnostics & Command Suite...');
  execSync('npx tsx tests/cli-integration.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [5/8] Running E2EE Cryptographic Hardening Suite...');
  execSync('npx tsx tests/crypto-hardening.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [6/8] Running TypeScript & Python Cross-Language E2EE Interoperability Test...');
  execSync('npx tsx tests/cross-language-e2ee.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [7/8] Running Python Fleet ADK & E2EE Test Suite...');
  execSync('PYTHONPATH=python python3 -m unittest discover -s python/tests', { stdio: 'inherit' });

  console.log('\n▶ [8/10] Running FLOOR MCP Access Control Test Suite...');
  execSync('npx tsx tests/floor-mcp.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [9/10] Running Framework Integrations & Multi-Framework Suite...');
  execSync('npx tsx tests/framework-integrations.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [10/10] Running NPM Pack & Clean Consumer App Installation Test...');
  execSync('npx tsx tests/package-pack.test.ts', { stdio: 'inherit' });

  console.log('\n==================================================');
  console.log('  ALL AAMARVA TEST SUITES PASSED WITH 100% SUCCESS ');
  console.log('==================================================');
} catch (err) {
  console.error('\n✖ Test suite execution encountered an error.');
  process.exit(1);
}
