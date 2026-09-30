import { execSync } from 'child_process';

console.log('==================================================');
console.log('   RUNNING ALL AAMARVA ADK TEST SUITES            ');
console.log('==================================================\n');

try {
  console.log('▶ [1/8] Running Contract & Specification Validation...');
  execSync('npx tsx tests/adk.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [2/8] Running SDK & Developer Experience Suite...');
  execSync('npx tsx tests/sdk.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [3/8] Running Common Integration Contract Suite...');
  execSync('npx tsx tests/integration-contract.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [4/9] Running Framework Native Adapters Suite (LangGraph, Hermes, CrewAI, etc.)...');
  execSync('npx tsx tests/framework-adapters.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [5/9] Running Real Framework Validation & Runtime Simulation Suite...');
  execSync('npx tsx tests/real-framework-validation.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [6/9] Running CLI One-Click Integration & Doctor Suite...');
  execSync('npx tsx tests/cli-integration.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [7/9] Running E2EE Cryptographic Hardening Suite...');
  execSync('npx tsx tests/crypto-hardening.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [8/9] Running TypeScript & Python Cross-Language E2EE Interoperability Test...');
  execSync('npx tsx tests/cross-language-e2ee.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [9/9] Running Python ADK, Integrations & E2EE Test Suite...');
  execSync('PYTHONPATH=python python3 -m unittest discover -s python/tests', { stdio: 'inherit' });

  console.log('\n▶ Running NPM Pack & Clean Installation Test...');
  execSync('npx tsx tests/package-pack.test.ts', { stdio: 'inherit' });

  console.log('\n==================================================');
  console.log('  ALL AAMARVA TEST SUITES PASSED WITH 100% SUCCESS ');
  console.log('==================================================');
} catch (err) {
  console.error('\n✖ Test suite execution encountered an error.');
  process.exit(1);
}
