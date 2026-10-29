import assert from 'node:assert';
import { runCli, printHelp, handleDoctor } from '../src/cli.js';

async function runCliIntegrationTests() {
  console.log('--- Starting Fleet CLI Integration Test Suite ---');

  // 1. Help routing
  console.log('Testing CLI help output...');
  let helpOutput = '';
  const originalLog = console.log;
  console.log = (...args: any[]) => {
    helpOutput += args.join(' ') + '\n';
  };

  try {
    printHelp();
    assert.ok(helpOutput.includes('AAMARVA Fleet Agent Development Kit'));
    assert.ok(helpOutput.includes('connections'));
    assert.ok(helpOutput.includes('message <connId> <text>'));
    assert.ok(helpOutput.includes('watchtower [limit]'));
    assert.ok(helpOutput.includes('tools'));
    assert.ok(helpOutput.includes('tool-request'));
    assert.ok(helpOutput.includes('tool-status'));
    
    // Confirmed removal
    assert.ok(!helpOutput.includes('connect <agentId>'));
    assert.ok(!helpOutput.includes('requests'));
    assert.ok(!helpOutput.includes('accept <requestId>'));
    assert.ok(!helpOutput.includes('emit <capability>'));
    assert.ok(!helpOutput.includes('intake <need>'));
    assert.ok(!helpOutput.includes('discover <query>'));
  } finally {
    console.log = originalLog;
  }
  console.log('✓ CLI help output verified.');

  // 2. Doctor diagnostics
  console.log('Testing "aamarva doctor" diagnostics...');
  let doctorOutput = '';
  console.log = (...args: any[]) => {
    doctorOutput += args.join(' ') + '\n';
  };

  try {
    await handleDoctor();
    assert.ok(doctorOutput.includes('AAMARVA FLEET DIAGNOSTICS'));
    assert.ok(doctorOutput.includes('Fleet-Only Agent Infrastructure'));
  } finally {
    console.log = originalLog;
  }
  console.log('✓ "aamarva doctor" executed cleanly.');

  // 3. Command router
  console.log('Testing CLI router...');
  let routerOutput = '';
  console.log = (...args: any[]) => {
    routerOutput += args.join(' ') + '\n';
  };

  try {
    await runCli(['help']);
    assert.ok(routerOutput.includes('Usage:'));
  } finally {
    console.log = originalLog;
  }
  console.log('✓ CLI router verified.');

  console.log('--- ALL FLEET CLI INTEGRATION TESTS PASSED ---');
}

runCliIntegrationTests().catch((err) => {
  console.error('CLI test failed:', err);
  process.exit(1);
});
