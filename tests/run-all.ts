import { execSync } from 'child_process';

console.log('==================================================');
console.log('   RUNNING ALL AAMARVA ADK TEST SUITES            ');
console.log('==================================================\n');

try {
  console.log('▶ [1/3] Running Contract & Specification Validation...');
  execSync('npx tsx tests/adk.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [2/3] Running SDK & Developer Experience Suite...');
  execSync('npx tsx tests/sdk.test.ts', { stdio: 'inherit' });

  console.log('\n▶ [3/3] Running NPM Pack & Clean Installation Test...');
  execSync('npx tsx tests/package-pack.test.ts', { stdio: 'inherit' });

  console.log('\n==================================================');
  console.log('  ALL AAMARVA TEST SUITES PASSED WITH 100% SUCCESS ');
  console.log('==================================================');
} catch (err) {
  console.error('\n✖ Test suite execution encountered an error.');
  process.exit(1);
}
