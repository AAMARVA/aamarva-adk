import { execSync } from 'child_process';

console.log('==================================================');
console.log('   RUNNING ALL AAMARVA ADK TEST SUITES            ');
console.log('==================================================\n');

try {
  console.log('▶ [1/5] Running Contract & Specification Validation...');
  execSync('npx tsx tests/adk.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [2/5] Running SDK & Developer Experience Suite...');
  execSync('npx tsx tests/sdk.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [3/5] Running E2EE Cryptographic Hardening Suite...');
  execSync('npx tsx tests/crypto-hardening.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [4/5] Running TypeScript & Python Cross-Language E2EE Interoperability Test...');
  execSync('npx tsx tests/cross-language-e2ee.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [5/5] Running Python ADK & E2EE Test Suite...');
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
