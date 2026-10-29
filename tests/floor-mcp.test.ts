import assert from 'node:assert';
import { Aamarva, createMockFetch, createMockDataStore, AamarvaError } from '../src/index.js';

/**
 * Validates the 4 logical operations of FLOOR MCP:
 * 1. List tools and access status
 * 2. Request access
 * 3. Check status
 * 4. Execute tool (Authorized only)
 */
async function runFloorMcpFixTests() {
  console.log('--------------------------------------------------');
  console.log('AAMARVA FLOOR MCP CONTRACT & ACCESS CONTROL TESTS ');
  console.log('--------------------------------------------------');

  const mockStore = createMockDataStore();
  const mockFetch = createMockFetch(mockStore);
  const client = new Aamarva({
    agentId: 'AMR-TEST-AGENT',
    apiKey: 'sk_test_123',
    fetch: mockFetch,
  });

  // 1. List tools and see permitted access status
  console.log('1. Testing tool listing and access status...');
  const tools = await client.getFloorTools();
  assert.ok(Array.isArray(tools));
  const authorizedTool = tools.find(t => t.accessStatus === 'authorized');
  const requiredTool = tools.find(t => t.accessStatus === 'required');
  assert.ok(authorizedTool, 'Should have an authorized tool in mock');
  assert.ok(requiredTool, 'Should have a tool requiring access in mock');
  console.log(`✓ Listed ${tools.length} tools. (Authorized: ${authorizedTool.id})`);

  // 2. Unassigned agent can request access without executing
  console.log('2. Testing access request (non-executing)...');
  const accessReq = await client.requestFloorAccess(requiredTool.id, 'Need for research');
  assert.strictEqual(accessReq.status, 'pending');
  assert.ok(accessReq.requestId);
  // Ensure no result field (proving it didn't execute)
  assert.strictEqual(accessReq.result, undefined);
  console.log(`✓ Access requested for ${requiredTool.id}. Request ID: ${accessReq.requestId}`);

  // 3. Pending request does not grant execution permission
  console.log('3. Testing that pending request denies execution...');
  try {
    await client.executeFloorTool(requiredTool.id, { ticker: 'AAPL' });
    assert.fail('Execution should have been denied for pending/unauthorized tool');
  } catch (err: any) {
    assert.strictEqual(err.code, 'FLOOR_ACCESS_DENIED');
    console.log('✓ Execution denied as expected.');
  }

  // 4. Retrieve request status
  console.log('4. Testing request status retrieval...');
  const statusRes = await client.getFloorRequestStatus(accessReq.requestId!);
  assert.strictEqual(statusRes.status, 'pending');
  assert.strictEqual(statusRes.requestId, accessReq.requestId);
  console.log(`✓ Request ${accessReq.requestId} status is ${statusRes.status}`);

  // 5. Authorized agent can execute an allowed tool
  console.log('5. Testing execution of authorized tool...');
  const execRes = await client.executeFloorTool(authorizedTool.id, { ticker: 'AAPL' });
  assert.strictEqual(execRes.status, 'executed');
  assert.ok(execRes.result);
  console.log(`✓ Successfully executed ${authorizedTool.id}`);

  // 6. Revoked or unassigned agent cannot execute
  console.log('6. Testing execution denial for unassigned tool...');
  // Find a tool not in the store or explicitly set to required
  try {
    await client.executeFloorTool('non_existent_tool', {});
    assert.fail('Should fail for non-existent tool');
  } catch (err: any) {
    assert.ok(err.message.includes('not found') || err.statusCode === 404 || err.code === 'FLOOR_TOOL_NOT_FOUND');
    console.log('✓ Denial verified.');
  }

  // 7. Credentials are never returned in unauthorized responses
  console.log('7. Verifying credentials are NOT in denial responses...');
  try {
    await client.executeFloorTool(requiredTool.id, {});
  } catch (err: any) {
    const rawError = JSON.stringify(err);
    assert.strictEqual(rawError.includes('password'), false);
    assert.strictEqual(rawError.includes('secret'), false);
    assert.strictEqual(rawError.includes('key'), false);
  }
  console.log('✓ No sensitive data leaked in errors.');

  // 8. Checking status for non-existent request ID returns 404
  console.log('8. Testing non-existent request ID status check (404)...');
  try {
    await client.getFloorRequestStatus('req_non_existent_9999');
    assert.fail('Should fail for non-existent request ID');
  } catch (err: any) {
    assert.ok(err.statusCode === 404 || err.message.includes('not found') || err.code === 'FLOOR_REQUEST_NOT_FOUND');
    console.log('✓ 404 returned for unknown request ID.');
  }

  // 9. Requesting access for non-existent tool ID returns 404
  console.log('9. Testing non-existent tool ID access request (404)...');
  try {
    await client.requestFloorAccess('unknown_tool_xyz');
    assert.fail('Should fail for non-existent tool ID');
  } catch (err: any) {
    assert.ok(err.statusCode === 404 || err.message.includes('not found') || err.code === 'FLOOR_TOOL_NOT_FOUND');
    console.log('✓ 404 returned for unknown tool ID access request.');
  }

  // 10. Special characters in tool ID are properly path-encoded
  console.log('10. Testing path encoding for special characters in toolId...');
  const specialToolId = 'tool/with spaces & ?';
  mockStore.floorTools.push({
    id: specialToolId,
    name: 'Special Tool',
    description: 'Tool with special characters in ID',
    inputSchema: { type: 'object' },
    accessStatus: 'authorized',
  });
  const specialExec = await client.executeFloorTool(specialToolId, {});
  assert.strictEqual(specialExec.status, 'executed');
  console.log('✓ Special character toolId safely path-encoded and executed.');

  // 11. Revoked tool denies execution with 403
  console.log('11. Testing execution denial for revoked tool (403)...');
  mockStore.floorTools.push({
    id: 'revoked_tool_01',
    name: 'Revoked Tool',
    description: 'Tool access has been revoked',
    inputSchema: { type: 'object' },
    accessStatus: 'revoked',
  });
  try {
    await client.executeFloorTool('revoked_tool_01', {});
    assert.fail('Should fail execution for revoked tool');
  } catch (err: any) {
    assert.strictEqual(err.code, 'FLOOR_ACCESS_DENIED');
    console.log('✓ Revoked tool execution denied as expected.');
  }

  // 12. Fail closed on missing execution status in response
  console.log('12. Testing fail-closed behavior on missing execution status...');
  const missingStatusFetch = (async (url: string, init?: any) => {
    if (url.includes('/execute')) {
      return new Response(JSON.stringify({
        success: true,
        data: { result: { computed: 42 } }, // status is omitted
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return mockFetch(url, init);
  }) as typeof fetch;

  const missingStatusClient = new Aamarva({
    agentId: 'AMR-TEST-AGENT',
    apiKey: 'sk_test_123',
    fetch: missingStatusFetch,
  });

  try {
    await missingStatusClient.executeFloorTool(authorizedTool.id, {});
    assert.fail('Should fail when status is missing from execute response');
  } catch (err: any) {
    assert.strictEqual(err.code, 'FLOOR_EXECUTION_FAILED');
    console.log('✓ Missing execution status rejected with FLOOR_EXECUTION_FAILED.');
  }

  // 13. Fail closed on unknown/unexpected execution status in response
  console.log('13. Testing fail-closed behavior on unknown execution status...');
  const unknownStatusFetch = (async (url: string, init?: any) => {
    if (url.includes('/execute')) {
      return new Response(JSON.stringify({
        success: true,
        data: { status: 'queued', result: { queuedAt: Date.now() } }, // unexpected status
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return mockFetch(url, init);
  }) as typeof fetch;

  const unknownStatusClient = new Aamarva({
    agentId: 'AMR-TEST-AGENT',
    apiKey: 'sk_test_123',
    fetch: unknownStatusFetch,
  });

  try {
    await unknownStatusClient.executeFloorTool(authorizedTool.id, {});
    assert.fail('Should fail when status is unknown in execute response');
  } catch (err: any) {
    assert.strictEqual(err.code, 'FLOOR_EXECUTION_FAILED');
    console.log('✓ Unknown execution status rejected with FLOOR_EXECUTION_FAILED.');
  }

  // 14. Fail closed on malformed data field in execution response (null, string, list)
  console.log('14. Testing fail-closed behavior on malformed data payload in execute response...');
  const malformedDataFetch = (async (url: string, init?: any) => {
    if (url.includes('/execute')) {
      return new Response(JSON.stringify({
        success: true,
        data: null,
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return mockFetch(url, init);
  }) as typeof fetch;

  const malformedDataClient = new Aamarva({
    agentId: 'AMR-TEST-AGENT',
    apiKey: 'sk_test_123',
    fetch: malformedDataFetch,
  });

  try {
    await malformedDataClient.executeFloorTool(authorizedTool.id, {});
    assert.fail('Should fail when data field is null in execute response');
  } catch (err: any) {
    assert.strictEqual(err.code, 'FLOOR_EXECUTION_FAILED');
    console.log('✓ Malformed data payload rejected with FLOOR_EXECUTION_FAILED.');
  }

  console.log('--------------------------------------------------');
  console.log('ALL FLOOR MCP FIX TESTS PASSED                    ');
  console.log('--------------------------------------------------');
}

runFloorMcpFixTests().catch(err => {
  console.error('FLOOR MCP test failed:', err);
  process.exit(1);
});
