import assert from 'node:assert';
import { Aamarva, createMockFetch, createMockDataStore, AamarvaError, GATEWAY_PROTOCOL_VERSION } from '../src/index.js';
import {
  computeArgsDigest,
  exportX25519PublicKeyJWK,
  getLocalAgentEncryptionKeyPair,
  signGatewayInstruction,
} from '../src/crypto.js';
import { invokeExternalMcpTool } from '../src/mcp-executor.js';

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
  assert.ok(execRes.status === 'approved' || execRes.status === 'executed');
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
  assert.ok(specialExec.status === 'approved' || specialExec.status === 'executed');
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

  // 12. Direct external MCP executor fails closed
  console.log('12. Verifying invokeExternalMcpTool is disabled (GATEWAY_EXECUTION_REQUIRED)...');
  await assert.rejects(
    () =>
      invokeExternalMcpTool({
        serverUrl: 'https://mcp.weather.internal/sse',
        toolId: authorizedTool.id,
        args: { ticker: 'AAPL' },
      }),
    (err: any) => err?.code === 'GATEWAY_EXECUTION_REQUIRED'
  );
  console.log('✓ Direct external MCP executor blocked with GATEWAY_EXECUTION_REQUIRED.');

  // 13. Fail closed on missing execution status in response
  console.log('13. Testing fail-closed behavior on missing execution status...');
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

  // 14. Fail closed on unknown/unexpected execution status in response
  console.log('14. Testing fail-closed behavior on unknown execution status...');
  const unknownStatusFetch = (async (url: string, init?: any) => {
    if (url.includes('/execute')) {
      return new Response(JSON.stringify({
        success: true,
        data: { status: 'queued', result: { queuedAt: Date.now() } },
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

  // 15. Fail closed on malformed data field in execution response
  console.log('15. Testing fail-closed behavior on malformed data payload in execute response...');
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

  // Helper to build authentic signed gateway instructions against mockStore's trusted issuer
  const buildSignedInstruction = (overrides: Record<string, any> = {}, agentId = 'AMR-TEST-AGENT') => {
    const xKp = getLocalAgentEncryptionKeyPair(agentId);
    const approvedArguments = overrides.approvedArguments ?? {
      ticker: 'AAPL',
      nested: { k1: 'v1' },
    };
    const unsigned: any = {
      version: GATEWAY_PROTOCOL_VERSION,
      instructionId: overrides.instructionId || 'inst_floor_test_1',
      issuer: 'aamarva-floor',
      audience: mockStore.trustedGatewayKeys!.gatewayId,
      gatewayId: mockStore.trustedGatewayKeys!.gatewayId,
      agentId,
      agentKeyId: xKp.keyId,
      agentKeyVersion: xKp.keyVersion,
      agentPublicKey: exportX25519PublicKeyJWK(xKp.publicKey),
      invocationId: overrides.invocationId || 'inv_1',
      mcpServerId: overrides.mcpServerId || 'mcp_srv_sec_edgar',
      toolId: overrides.toolId || authorizedTool.id,
      approvedArguments,
      approvedArgsDigest: overrides.approvedArgsDigest ?? computeArgsDigest(approvedArguments),
      scope: overrides.scope ?? 'tool:invoke',
      decision: overrides.decision ?? 'approved',
      iat: new Date().toISOString(),
      exp: overrides.exp ?? new Date(Date.now() + 600_000).toISOString(),
      issuerKeyId: overrides.issuerKeyId || mockStore.trustedGatewayKeys!.issuerKeyId,
    };
    return {
      ...unsigned,
      signature: overrides.signature ?? signGatewayInstruction(mockStore.trustedGatewayKeys!.issuerPrivateKey, unsigned),
    };
  };

  const futureIso = () => new Date(Date.now() + 600_000).toISOString();
  const pastIso = () => new Date(Date.now() - 10_000).toISOString();

  // 16. Gateway-only FLOOR execution contract + canonical key-order-insensitive argument binding
  console.log('16-45. Testing gateway-only contract, credential isolation & zero direct MCP requests...');
  {
    const callOrder: string[] = [];
    const submitted = {
      nested: { a: [true, { x: 8, y: 9 }], b: 2 },
      ticker: 'AAPL',
    };
    const canonicalApproved = {
      ticker: 'AAPL',
      nested: { b: 2, a: [true, { y: 9, x: 8 }] },
    };

    const gwContractFetch = (async (url: string, init?: any) => {
      if (url.includes('/execute')) {
        callOrder.push('floor:execute');
        const inst = buildSignedInstruction({
          invocationId: 'inv_docs_1',
          instructionId: 'inst_docs_1',
          approvedArguments: canonicalApproved,
        }, 'AMR-TEST-AGENT');
        return new Response(JSON.stringify({
          success: true,
          data: {
            status: 'approved',
            invocationId: 'inv_docs_1',
            toolId: authorizedTool.id,
            tool: { id: authorizedTool.id, name: authorizedTool.name },
            agentId: 'AMR-TEST-AGENT',
            mcpServerId: 'mcp_srv_sec_edgar',
            gatewayId: mockStore.trustedGatewayKeys!.gatewayId,
            gatewayUrl: mockStore.trustedGatewayKeys!.gatewayUrl,
            instructionId: 'inst_docs_1',
            approvedArgsDigest: computeArgsDigest(canonicalApproved),
            approvedArguments: canonicalApproved,
            verificationInfo: {
              verified: true,
              toolId: authorizedTool.id,
              agentId: 'AMR-TEST-AGENT',
            },
            scope: 'tool:invoke',
            expiresAt: futureIso(),
            instruction: inst,
          },
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      if (url.includes('/gateway/tokens')) {
        callOrder.push('gateway:tokens');
      }
      if (url.includes('/gateway/mcp')) {
        callOrder.push('gateway:mcp');
      }
      return mockFetch(url, init);
    }) as typeof fetch;

    const gwClient = new Aamarva({
      agentId: 'AMR-TEST-AGENT',
      apiKey: 'sk_test_123',
      fetch: gwContractFetch,
    });

    const docsRes = await gwClient.executeFloorTool(authorizedTool.id, submitted, {
      invocationId: 'inv_docs_1',
      requiredScope: 'tool:invoke',
      requireApprovedArguments: true,
    });
    assert.strictEqual(docsRes.status, 'approved');
    assert.deepStrictEqual(callOrder, ['floor:execute', 'gateway:tokens', 'gateway:mcp']);
    assert.strictEqual((docsRes as any).serverUrl, undefined);
    assert.strictEqual((docsRes as any).auth, undefined);
    assert.strictEqual(mockStore.directMcpCalls!.length, 0);
    console.log('✓ Mandatory gateway call sequence, key-order-insensitive arg binding, and zero direct MCP calls verified.');
  }

  // Target-agent (slave) scoping succeeds only when instruction & response match targetAgentId
  {
    const slaveClient = new Aamarva({
      agentId: 'AMR-MASTER-01',
      targetAgentId: 'AMR-SLAVE-01',
      apiKey: 'sk_master_123',
      fetch: mockFetch,
    });
    await slaveClient.ensureGatewayKeyRegistered();
    const slaveRes = await slaveClient.executeFloorTool(
      authorizedTool.id,
      { ticker: 'MSFT' }
    );
    assert.strictEqual(slaveRes.status, 'approved');
    assert.strictEqual(mockStore.directMcpCalls!.length, 0);
    console.log('✓ Target-agent (x-target-agent-id) scoped gateway authorization verified.');
  }

  // Exhaustive negative failure scenarios (zero token mints, zero gateway MCP calls, zero credential leaks)
  const validBase = () => {
    const inst = buildSignedInstruction({}, 'AMR-TEST-AGENT');
    return {
      status: 'approved',
      invocationId: 'inv_1',
      toolId: authorizedTool.id,
      agentId: 'AMR-TEST-AGENT',
      mcpServerId: 'mcp_srv_sec_edgar',
      gatewayId: mockStore.trustedGatewayKeys!.gatewayId,
      gatewayUrl: mockStore.trustedGatewayKeys!.gatewayUrl,
      instructionId: inst.instructionId,
      approvedArgsDigest: inst.approvedArgsDigest,
      instruction: inst,
      verificationInfo: { verified: true, toolId: authorizedTool.id, agentId: 'AMR-TEST-AGENT' },
      grant: {
        grantId: 'g_1',
        status: 'active',
        agentId: 'AMR-TEST-AGENT',
        toolId: authorizedTool.id,
        scope: 'tool:invoke',
        expiresAt: futureIso(),
      },
      approvedArguments: { ticker: 'AAPL', nested: { k1: 'v1' } },
    };
  };

  const authFailScenarios: Array<{
    name: string;
    response: any;
    submittedArgs?: Record<string, unknown>;
    clientConfig?: { agentId?: string; targetAgentId?: string };
    execOptions?: Record<string, unknown>;
    httpStatus?: number;
  }> = [
    { name: 'missing signed instruction', response: { success: true, data: { ...validBase(), instruction: undefined } } },
    { name: 'forged instruction signature', response: { success: true, data: { ...validBase(), instruction: buildSignedInstruction({ signature: Buffer.alloc(64, 7).toString('base64') }) } } },
    { name: 'exposed serverUrl', response: { success: true, data: { ...validBase(), serverUrl: 'https://mcp.example.internal/rpc' } } },
    { name: 'exposed auth object', response: { success: true, data: { ...validBase(), auth: { type: 'bearer', token: 'super_secret_mcp_token_do_not_leak' } } } },
    { name: 'exposed grantToken', response: { success: true, data: { ...validBase(), grantToken: 'secret_tok' } } },
    { name: 'empty grant object {}', response: { success: true, data: { ...validBase(), grant: {} } } },
    { name: 'missing grant.status', response: { success: true, data: { ...validBase(), grant: { grantId: 'g1', agentId: 'AMR-TEST-AGENT', expiresAt: futureIso() } } } },
    { name: 'pending execution status', response: { success: true, data: { ...validBase(), status: 'pending', grant: { ...validBase().grant, status: 'pending' } } } },
    { name: 'rejected execution status', response: { success: true, data: { ...validBase(), status: 'rejected', grant: { ...validBase().grant, status: 'rejected' } } } },
    { name: 'expired grant.expiresAt', response: { success: true, data: { ...validBase(), grant: { ...validBase().grant, expiresAt: pastIso() } } } },
    { name: 'expired top-level expiresAt', response: { success: true, data: { ...validBase(), expiresAt: pastIso() } } },
    { name: 'expired instruction.exp', response: { success: true, data: { ...validBase(), instruction: buildSignedInstruction({ exp: pastIso() }) } } },
    { name: 'malformed non-ISO expiresAt ("9999")', response: { success: true, data: { ...validBase(), grant: { ...validBase().grant, expiresAt: '9999' } } } },
    { name: 'revoked grant status', response: { success: true, data: { ...validBase(), grant: { ...validBase().grant, status: 'revoked' } } } },
    { name: 'revoked scope token', response: { success: true, data: { ...validBase(), grant: { ...validBase().grant, scope: 'revoked' } } } },
    { name: 'missing requiredScope', response: { success: true, data: validBase() }, execOptions: { requiredScope: 'admin:write' } },
    { name: 'malformed gatewayUrl scheme (ftp://)', response: { success: true, data: { ...validBase(), gatewayUrl: 'ftp://gateway.example.internal/rpc' } } },
    { name: 'malformed gatewayUrl string', response: { success: true, data: { ...validBase(), gatewayUrl: 'not-a-valid-url' } } },
    { name: 'verificationInfo.verified false', response: { success: true, data: { ...validBase(), verificationInfo: { verified: false, toolId: authorizedTool.id, agentId: 'AMR-TEST-AGENT' } } } },
    { name: 'verificationInfo.verified string "true"', response: { success: true, data: { ...validBase(), verificationInfo: { verified: 'true', toolId: authorizedTool.id, agentId: 'AMR-TEST-AGENT' } } } },
    { name: 'mismatched grant.agentId', response: { success: true, data: { ...validBase(), grant: { ...validBase().grant, agentId: 'AMR-HIJACKED' } } } },
    { name: 'master agentId returned instead of slave targetAgentId', response: { success: true, data: { ...validBase(), agentId: 'AMR-MASTER-01', grant: { ...validBase().grant, agentId: 'AMR-MASTER-01' }, verificationInfo: { verified: true, toolId: authorizedTool.id, agentId: 'AMR-MASTER-01' }, instruction: buildSignedInstruction({}, 'AMR-MASTER-01') } }, clientConfig: { agentId: 'AMR-MASTER-01', targetAgentId: 'AMR-SLAVE-01' } },
    { name: 'fleetId mismatch', response: { success: true, data: { ...validBase(), fleetId: 'fleet_other' } }, execOptions: { fleetId: 'fleet_prod' } },
    { name: 'mismatched invocationId', response: { success: true, data: { ...validBase(), invocationId: 'inv_WRONG' } } },
    { name: 'mismatched grant.toolId', response: { success: true, data: { ...validBase(), grant: { ...validBase().grant, toolId: 'wrong_tool' } } } },
    { name: 'top-level tool mismatched', response: { success: true, data: { ...validBase(), toolId: 'wrong_tool' } } },
    { name: 'modified nested argument', response: { success: true, data: validBase() }, submittedArgs: { ticker: 'AAPL', nested: { k1: 'TAMPERED' } } },
    { name: 'extra unauthorized argument', response: { success: true, data: validBase() }, submittedArgs: { ticker: 'AAPL', nested: { k1: 'v1' }, adminOverride: true } },
    { name: 'malformed approvedArguments array', response: { success: true, data: { ...validBase(), approvedArguments: ['bad'] } } },
    { name: 'missing approvedArguments when required', response: { success: true, data: { ...validBase(), approvedArguments: undefined } }, execOptions: { requireApprovedArguments: true } },
    { name: 'post-discovery 403 revocation on /execute', response: { success: false, error: 'FLOOR_ACCESS_DENIED', message: 'Revoked' }, httpStatus: 403 },
  ];

  for (const scenario of authFailScenarios) {
    let gatewayTokenOrMcpCalls = 0;
    const scenarioFetch = (async (url: string, init?: any) => {
      if (url.includes('/floor/tools/') && url.endsWith('/invoke')) {
        return new Response(JSON.stringify({
          success: true,
          data: { invocationId: 'inv_1', toolId: authorizedTool.id, status: 'approved' },
        }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      if (url.includes('/execute')) {
        return new Response(JSON.stringify(scenario.response), {
          status: scenario.httpStatus || 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (url.includes('/gateway/tokens') || url.includes('/gateway/mcp') || url.includes('/mcp')) {
        gatewayTokenOrMcpCalls++;
      }
      return mockFetch(url, init);
    }) as typeof fetch;

    const scenarioClient = new Aamarva({
      agentId: scenario.clientConfig?.agentId || 'AMR-TEST-AGENT',
      ...(scenario.clientConfig?.targetAgentId ? { targetAgentId: scenario.clientConfig.targetAgentId } : {}),
      apiKey: 'sk_test_123',
      fetch: scenarioFetch,
    });

    try {
      await scenarioClient.executeFloorTool(
        authorizedTool.id,
        scenario.submittedArgs ?? { ticker: 'AAPL', nested: { k1: 'v1' } },
        scenario.execOptions as any
      );
      assert.fail(`Should have failed for scenario: ${scenario.name}`);
    } catch (err: any) {
      assert.strictEqual(gatewayTokenOrMcpCalls, 0, `Zero gateway token/MCP calls expected for ${scenario.name}`);
      const serializedErr = `${err?.message || ''} ${JSON.stringify(err || {})}`;
      assert.strictEqual(serializedErr.includes('super_secret_mcp_token_do_not_leak'), false, `Secret leaked in error for ${scenario.name}`);
      assert.strictEqual(serializedErr.includes('secret_tok'), false, `Token leaked in error for ${scenario.name}`);
    }
  }
  console.log(`✓ Verified zero gateway/MCP executions and zero credential leaks across ${authFailScenarios.length} failure scenarios.`);

  console.log('--------------------------------------------------');
  console.log('ALL FLOOR MCP GATEWAY TESTS PASSED                ');
  console.log('--------------------------------------------------');
}

runFloorMcpFixTests().catch(err => {
  console.error('FLOOR MCP test failed:', err);
  process.exit(1);
});
