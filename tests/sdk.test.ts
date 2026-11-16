import assert from 'assert';
import { Aamarva } from '../src/client.js';
import { createMockFetch, createMockDataStore } from '../src/mock.js';
import {
  AamarvaError,
  AamarvaAuthError,
  AamarvaForbiddenError,
  AamarvaNotFoundError,
  AamarvaValidationError,
  AamarvaTimeoutError,
} from '../src/errors.js';
import {
  normalizeAgent,
  normalizeConnection,
  normalizeMessage,
  normalizeCluster,
  normalizeFloorTool,
  normalizeFloorRequestStatus,
} from '../src/normalize.js';
import { AamarvaConnection } from '../src/connection.js';

async function runSdkTests() {
  console.log('--------------------------------------------------');
  console.log('AAMARVA FLEET ADK - SDK TEST SUITE               ');
  console.log('--------------------------------------------------');

  const mockStore = createMockDataStore();
  const mockFetch = createMockFetch(mockStore);

  // 1. Client Initialization
  console.log('1. Testing Aamarva client instantiation & fleet scope...');
  const client = new Aamarva({
    agentId: 'AMR-1111-2222',
    apiKey: 'sec_mock_key_123',
    baseUrl: 'https://aamarva.com/api',
    targetAgentId: 'AMR-SLAVE-01',
    fetch: mockFetch,
  });
  assert.ok(client, 'Aamarva client should instantiate');
  assert.strictEqual(client.http.getBaseUrl(), 'https://aamarva.com/api');
  assert.strictEqual(client.getTargetAgentId(), 'AMR-SLAVE-01');
  console.log('✓ Client initialization and fleet scope verified.');

  // 2. Unapproved Endpoint Rejection (Endpoint Allowlist Security Invariant)
  console.log('2. Testing endpoint allowlist enforcement...');
  try {
    await client.http.request({ method: 'GET', path: '/health', auth: false });
    assert.fail('/health should be rejected by endpoint allowlist');
  } catch (err: any) {
    assert.ok(err instanceof AamarvaError);
    assert.strictEqual(err.code, 'ENDPOINT_NOT_ALLOWED');
  }

  try {
    await client.http.request({ method: 'POST', path: '/auth/register', auth: false });
    assert.fail('/auth/register should be rejected by endpoint allowlist');
  } catch (err: any) {
    assert.ok(err instanceof AamarvaError);
    assert.strictEqual(err.code, 'ENDPOINT_NOT_ALLOWED');
  }

  try {
    await client.http.request({ method: 'POST', path: '/clusters', auth: true });
    assert.fail('/clusters POST should be rejected by endpoint allowlist');
  } catch (err: any) {
    assert.ok(err instanceof AamarvaError);
    assert.strictEqual(err.code, 'ENDPOINT_NOT_ALLOWED');
  }
  console.log('✓ Unapproved endpoint rejection verified.');

  // 3. Identity and Profile
  console.log('3. Testing authentication & me() profile retrieval...');
  const me = await client.me();
  assert.strictEqual(me.agentId, 'AMR-1111-2222');
  assert.strictEqual(me.name, 'Financial Analysis Agent');

  const updatedProfile = await client.updateProfile({ name: 'Financial Analysis Agent Pro' });
  assert.strictEqual(updatedProfile.name, 'Financial Analysis Agent Pro');

  // Fleet Account Listing & E2EE Public Key Retrieval
  const fleetAgents = await client.getAgents({ q: 'Financial', limit: 5 });
  assert.ok(Array.isArray(fleetAgents));
  assert.ok(fleetAgents.length > 0);
  assert.strictEqual(fleetAgents[0].agentId, 'AMR-1111-2222');

  // Verify response parsing when server returns data.agents object with total, page, limit
  const mockFetchWithObj = (async (url: string, init?: any) => {
    if (url.includes('/agents')) {
      return new Response(JSON.stringify({
        success: true,
        data: {
          agents: [{ agentId: 'AMR-STRUCTURED-1', name: 'Structured Agent' }],
          total: 1,
          page: 1,
          limit: 10,
        },
      }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return mockFetch(url, init);
  }) as typeof fetch;
  const clientWithObj = new Aamarva({ agentId: 'AMR-1111-2222', apiKey: 'sec_key', fetch: mockFetchWithObj });
  const structuredAgents = await clientWithObj.getAgents();
  assert.strictEqual(structuredAgents.length, 1);
  assert.strictEqual(structuredAgents[0].agentId, 'AMR-STRUCTURED-1');

  // Verify response parsing when server returns data array directly
  const mockFetchWithArr = (async (url: string, init?: any) => {
    if (url.includes('/agents')) {
      return new Response(JSON.stringify({
        success: true,
        data: [{ agentId: 'AMR-ARRAY-1', name: 'Array Agent' }],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return mockFetch(url, init);
  }) as typeof fetch;
  const clientWithArr = new Aamarva({ agentId: 'AMR-1111-2222', apiKey: 'sec_key', fetch: mockFetchWithArr });
  const arrayAgents = await clientWithArr.getAgents();
  assert.strictEqual(arrayAgents.length, 1);
  assert.strictEqual(arrayAgents[0].agentId, 'AMR-ARRAY-1');

  const ownE2eeKey = await client.getAgentE2eeKey();
  assert.ok(ownE2eeKey);
  const aliasE2eeKey = await client.getRegisteredPublicKey();
  assert.ok(aliasE2eeKey);
  console.log('✓ me() profile retrieval, profile update, getAgents() (both formats), and getAgentE2eeKey() verified.');

  // 4. Direct Connections
  console.log('4. Testing connection retrieval and management...');
  const connections = await client.getConnections();
  assert.ok(Array.isArray(connections));
  assert.ok(connections.length > 0);

  const connInfo = connections[0];
  const directConn = new AamarvaConnection(connInfo, client.http);
  assert.strictEqual(directConn.connectionId, connInfo.connectionId);

  console.log('✓ Connection retrieval verified.');

  // 6. E2EE Private Messaging
  console.log('6. Testing E2EE private messaging...');
  const sentMsg = await directConn.send('Confidential fleet payload synchronization');
  assert.ok(sentMsg.messageId);
  assert.strictEqual(sentMsg.content, 'Confidential fleet payload synchronization');

  const messages = await directConn.getMessages();
  assert.ok(Array.isArray(messages));
  console.log('✓ E2EE private messaging verified.');

  // 7. Multi-Agent Clusters & Recipient-Restricted Messaging
  console.log('7. Testing multi-agent clusters & recipient-restricted messaging...');
  const clusters = await client.getClusters();
  assert.ok(Array.isArray(clusters));
  assert.ok(clusters.length > 0);

  const cluster = await client.getCluster('cluster_987654');
  assert.strictEqual(cluster.name, 'Market Arbitrage Cluster');

  const clusterMsgRes = await client.sendClusterMessage('cluster_987654', {
    ciphertext: 'bW9ja19jaXBoZXJ0ZXh0',
    nonce: 'bW9ja19ub25jZQ==',
    recipients: ['AMR-5555-6666'],
  });
  assert.ok(clusterMsgRes.messageId);

  const clusterMsgs = await client.getClusterMessages('cluster_987654');
  assert.ok(Array.isArray(clusterMsgs));

  const keyDist = await client.getClusterKeyDistribution('cluster_987654', 2);
  assert.ok(keyDist);
  assert.strictEqual(keyDist.clusterId, 'cluster_987654');
  assert.strictEqual(keyDist.epoch, 2);
  console.log('✓ Clusters, recipient-restricted messaging, and cluster key distribution verified.');

  // 8. FLOOR MCP Tool Governance
  console.log('8. Testing FLOOR MCP tool governance...');
  const tools = await client.getFloorTools();
  assert.ok(Array.isArray(tools));
  assert.ok(tools.length >= 2);
  const secTool = tools.find((t) => t.id === 'tool_sec_edgar');
  assert.ok(secTool);
  assert.strictEqual(secTool.accessStatus, 'authorized');

  // HITL Access Request without executing tool
  const accessReq = await client.requestFloorAccess('tool_market_depth', 'Need market depth');
  assert.strictEqual(accessReq.status, 'pending');
  assert.ok(accessReq.requestId);

  // Check request status
  const statusRes = await client.getFloorRequestStatus(accessReq.requestId!);
  assert.strictEqual(statusRes.status, 'pending');

  // Authorized execution
  const execRes = await client.executeFloorTool('tool_sec_edgar', { ticker: 'AAPL' });
  assert.ok(execRes.status === 'approved' || execRes.status === 'executed');
  assert.ok(execRes.result);

  console.log('✓ FLOOR MCP tool governance (discovery, HITL request, status, execution) verified.');

  // 9. Endpoint Existence & Removal Assertions
  console.log('9. Testing that removed endpoints do NOT exist and preserved endpoints exist on client...');
  const rawClient = client as any;
  assert.strictEqual(rawClient.createCluster, undefined);
  assert.strictEqual(rawClient.updateCluster, undefined);
  assert.strictEqual(rawClient.disbandCluster, undefined);
  assert.strictEqual(rawClient.register, undefined);
  assert.strictEqual(rawClient.logout, undefined);
  assert.strictEqual(rawClient.checkEmail, undefined);
  assert.strictEqual(rawClient.rotateApiKey, undefined);
  assert.strictEqual(rawClient.deleteAccount, undefined);
  assert.strictEqual(rawClient.deleteMe, undefined);
  assert.strictEqual(rawClient.health, undefined);
  assert.strictEqual(rawClient.getConnection, undefined);
  assert.strictEqual(rawClient.closeConnection, undefined);
  assert.strictEqual(typeof rawClient.getWatchtowerActivity, 'function');
  assert.strictEqual(typeof rawClient.getWatchtowerStreamTicket, 'function');
  assert.strictEqual(typeof rawClient.getWatchtowerStreamUrl, 'function');
  assert.strictEqual(typeof rawClient.getFootprints, 'function');
  assert.strictEqual(typeof rawClient.getWebhookEvents, 'function');
  assert.strictEqual(rawClient.discover, undefined);
  assert.strictEqual(rawClient.discoverAgents, undefined);
  assert.strictEqual(rawClient.discoverPosts, undefined);
  assert.strictEqual(rawClient.emit, undefined);
  assert.strictEqual(rawClient.intake, undefined);
  assert.strictEqual(rawClient.getPosts, undefined);
  assert.strictEqual(rawClient.createPost, undefined);
  assert.strictEqual(rawClient.deletePost, undefined);
  assert.strictEqual(rawClient.getReplies, undefined);
  assert.strictEqual(rawClient.createReply, undefined);
  assert.strictEqual(rawClient.submitReview, undefined);
  assert.strictEqual(rawClient.connectFromReply, undefined);
  assert.strictEqual(rawClient.requestConnection, undefined);
  assert.strictEqual(rawClient.establishConnection, undefined);
  assert.strictEqual(rawClient.acceptConnectionRequest, undefined);
  assert.strictEqual(rawClient.rejectConnectionRequest, undefined);
  assert.strictEqual(rawClient.getConnectionRequests, undefined);
  assert.strictEqual(rawClient.getFloorTemporaryAccess, undefined);
  assert.strictEqual(rawClient.invokeFloorTool, undefined);
  console.log('✓ Legacy removal assertions verified.');


  // 11. Public-Key Registration Tests across all authentication paths
  console.log('11. Testing automatic public-key registration & idempotency across all auth paths...');
  let e2eePutCalls = 0;
  let lastE2eePayload: any = null;
  const keyTestFetch = (async (url: string, init?: any) => {
    if (url.endsWith('/agents/me/e2ee') && init?.method === 'PUT') {
      e2eePutCalls++;
      lastE2eePayload = JSON.parse(init.body || '{}');
      return new Response(JSON.stringify({ success: true, message: 'Key registered' }), { status: 200 });
    }
    return mockFetch(url, init);
  }) as typeof fetch;

  const keyClient = new Aamarva({
    agentId: 'AMR-1111-2222',
    apiKey: 'sec_mock_key_123',
    fetch: keyTestFetch,
  });

  // A. Explicit login triggers registration
  await keyClient.login();
  assert.strictEqual(e2eePutCalls, 1, 'Explicit login should automatically trigger public key registration');
  assert.ok(lastE2eePayload.publicKey, 'Public key must be registered');
  assert.strictEqual(JSON.stringify(lastE2eePayload).includes('PRIVATE KEY'), false, 'Private key MUST NEVER be transmitted');
  assert.strictEqual(JSON.stringify(lastE2eePayload).includes('password'), false, 'Password MUST NEVER be in registration payload');
  assert.strictEqual(JSON.stringify(lastE2eePayload).includes('token'), false, 'Token MUST NEVER be in registration payload');

  // B. Repeated authentication checks do not cause registration storms (Idempotency)
  await keyClient.registerPublicKey();
  await keyClient.http.ensureAuthenticated();
  assert.strictEqual(e2eePutCalls, 1, 'Repeated key registration calls with same identity and fingerprint must be skipped (idempotent)');

  // B2. Switching agent identity with same key fingerprint MUST trigger a new registration
  keyClient.http.setCredentials('AMR-NEW-IDENTITY-999', 'sec_mock_key_123', true);
  await keyClient.registerPublicKey();
  assert.strictEqual(e2eePutCalls, 2, 'Switching agent identity with same key fingerprint MUST trigger a new registration');

  // C. Automatic authentication with credentials triggers registration
  let autoAuthKeyCalls = 0;
  const autoAuthFetch = (async (url: string, init?: any) => {
    if (url.endsWith('/agents/me/e2ee') && init?.method === 'PUT') {
      autoAuthKeyCalls++;
      return new Response(JSON.stringify({ success: true, message: 'Key registered' }), { status: 200 });
    }
    return mockFetch(url, init);
  }) as typeof fetch;

  const autoClient = new Aamarva({
    agentId: 'AMR-2222-3333',
    apiKey: 'sec_mock_key_123',
    fetch: autoAuthFetch,
  });
  await autoClient.getConnections();
  assert.strictEqual(autoAuthKeyCalls, 1, 'Automatic authentication path MUST trigger public-key registration');

  // D. Already-configured access token triggers required registration on authenticated call
  let tokenAuthKeyCalls = 0;
  const tokenAuthFetch = (async (url: string, init?: any) => {
    if (url.endsWith('/agents/me/e2ee') && init?.method === 'PUT') {
      tokenAuthKeyCalls++;
      return new Response(JSON.stringify({ success: true, message: 'Key registered' }), { status: 200 });
    }
    return mockFetch(url, init);
  }) as typeof fetch;

  const tokenClient = new Aamarva({
    agentId: 'AMR-TOKEN-ONLY',
    accessToken: 'mock_existing_access_token_999',
    fetch: tokenAuthFetch,
  });
  await tokenClient.getConnections();
  assert.strictEqual(tokenAuthKeyCalls, 1, 'Already-configured access token MUST trigger public-key registration on authenticated request');

  // E2. Test setCredentials token preservation semantics
  const regClient = new Aamarva({ agentId: 'AMR-PRESERVE', apiKey: 'sk_preserve', fetch: mockFetch });
  regClient.http.setTokens({ accessToken: 'at_preserved_1', refreshToken: 'rt_preserved_1' });
  regClient.http.setCredentials('AMR-PRESERVE', 'sk_preserve', true);
  assert.strictEqual(regClient.http.getTokens().accessToken, 'at_preserved_1', 'setCredentials with preserveTokens=true must not clear tokens');
  assert.strictEqual(regClient.http.getAgentId(), 'AMR-PRESERVE');

  regClient.http.setCredentials('AMR-PRESERVE-2', 'sk_preserve_2', { preserveTokens: true });
  assert.strictEqual(regClient.http.getTokens().accessToken, 'at_preserved_1', 'setCredentials with {preserveTokens: true} must not clear tokens');

  regClient.http.setCredentials('AMR-OVERWRITE', 'sk_overwrite', { tokens: { accessToken: 'at_new_1', refreshToken: 'rt_new_1' } });
  assert.strictEqual(regClient.http.getTokens().accessToken, 'at_new_1', 'setCredentials with explicit tokens must install new tokens');

  regClient.http.setCredentials('AMR-CLEARED', 'sk_cleared', false);
  assert.strictEqual(regClient.http.getTokens().accessToken, undefined, 'setCredentials with preserveTokens=false must clear tokens');


  // E4. Public key registration validates response payload and retries on subsequent call
  let malformedCount = 0;
  let responseBody: string = 'Internal Server Error';
  let responseContentType: string = 'text/plain';
  const malformedRegFetch = (async (url: string, init?: any) => {
    if (url.endsWith('/agents/me/e2ee') && init?.method === 'PUT') {
      malformedCount++;
      return new Response(responseBody, {
        status: 200,
        headers: { 'content-type': responseContentType },
      });
    }
    return mockFetch(url, init);
  }) as typeof fetch;

  const malformedClient = new Aamarva({
    agentId: 'AMR-MALFORMED-TS',
    apiKey: 'sk_malformed',
    fetch: malformedRegFetch,
  });

  // 1. Non-JSON plain text response ({ message: "Internal Server Error" }) MUST be rejected
  try {
    await malformedClient.registerPublicKey({ force: true });
    assert.fail('Should fail on non-JSON text fallback response');
  } catch (err: any) {
    assert.strictEqual(err.code, 'E2EE_KEY_REGISTRATION_FAILED');
  }

  // 2. Explicit error response fails
  responseContentType = 'application/json';
  responseBody = JSON.stringify({ success: false, message: 'Invalid signature' });
  try {
    await malformedClient.registerPublicKey({ force: true });
    assert.fail('Should fail on success=false response');
  } catch (err: any) {
    assert.strictEqual(err.code, 'E2EE_KEY_REGISTRATION_FAILED');
  }

  // 3. Valid JSON response succeeds and caches
  responseContentType = 'application/json';
  responseBody = JSON.stringify({ success: true, message: 'Key registered' });
  await malformedClient.registerPublicKey({ force: true });
  assert.strictEqual(malformedCount, 3);

  // F. Token refresh triggers registration when needed
  let refreshKeyCalls = 0;
  const refreshFetch = (async (url: string, init?: any) => {
    if (url.endsWith('/agents/me/e2ee') && init?.method === 'PUT') {
      refreshKeyCalls++;
      return new Response(JSON.stringify({ success: true, message: 'Key registered' }), { status: 200 });
    }
    return mockFetch(url, init);
  }) as typeof fetch;

  const refreshClient = new Aamarva({
    agentId: 'AMR-REFRESH-AGENT',
    apiKey: 'sk_mock_refresh',
    refreshToken: 'mock_refresh_token_valid',
    fetch: refreshFetch,
  });
  const refreshSuccess = await refreshClient.http.refreshAccessToken();
  assert.strictEqual(refreshSuccess, true);
  assert.strictEqual(refreshKeyCalls, 1, 'Successful token refresh MUST trigger public-key registration when needed');

  // G. Server rejection produces visible error on login
  const rejectFetch = (async (url: string, init?: any) => {
    if (url.endsWith('/agents/me/e2ee') && init?.method === 'PUT') {
      return new Response(JSON.stringify({ success: false, message: 'Server rejected key' }), { status: 400 });
    }
    return mockFetch(url, init);
  }) as typeof fetch;

  const rejectClient = new Aamarva({
    agentId: 'AMR-REJECT-AGENT',
    apiKey: 'sk_mock_reject',
    fetch: rejectFetch,
  });
  try {
    await rejectClient.login();
    assert.fail('Should fail when server rejects key registration');
  } catch (err: any) {
    assert.ok(err instanceof AamarvaError);
    assert.strictEqual(err.code, 'E2EE_KEY_REGISTRATION_FAILED');
  }

  console.log('✓ Public-key registration across all authentication paths verified.');

  // 12. Cluster Sender ID and Authoritative Master Recipient Tests
  console.log('12. Testing cluster message compulsory sender ID & authoritative master recipient resolution...');

  // A. Test all supported master/owner field aliases
  const aliasFields = ['masterId', 'master_id', 'masterAgentId', 'master_agent_id', 'ownerAgentId', 'owner_agent_id'];
  for (const field of aliasFields) {
    let payloadSent: any = null;
    const aliasFetch = (async (url: string, init?: any) => {
      if (url.endsWith('/agents/me') && init?.method === 'GET') {
        return new Response(JSON.stringify({
          success: true,
          data: {
            agentId: 'AMR-SLAVE-NODE',
            name: 'Slave Node',
            [field]: 'AMR-MASTER-ALIAS-OK',
          },
        }), { status: 200 });
      }
      if (url.includes('/clusters/') && url.endsWith('/messages') && init?.method === 'POST') {
        payloadSent = JSON.parse(init.body || '{}');
        return new Response(JSON.stringify({ success: true, messageId: 'msg_alias_test' }), { status: 201 });
      }
      return mockFetch(url, init);
    }) as typeof fetch;

    const aliasClient = new Aamarva({
      agentId: 'AMR-SLAVE-NODE',
      apiKey: 'sec_key_123',
      fetch: aliasFetch,
    });

    await aliasClient.sendClusterMessage('cluster_alias', {
      ciphertext: 'bW9ja19jaXBoZXI=',
      nonce: 'bW9ja19ub25jZQ==',
    });

    assert.ok(payloadSent.recipients.includes('AMR-MASTER-ALIAS-OK'), `Field alias "${field}" must resolve to master recipient`);
  }

  // B. Test that conflicting master fields FAIL CLOSED
  const conflictFetch = (async (url: string, init?: any) => {
    if (url.endsWith('/agents/me') && init?.method === 'GET') {
      return new Response(JSON.stringify({
        success: true,
        data: {
          agentId: 'AMR-SLAVE-CONFLICT',
          name: 'Conflicted Slave',
          masterId: 'AMR-MASTER-A',
          ownerAgentId: 'AMR-MASTER-B', // Conflicting master
        },
      }), { status: 200 });
    }
    return mockFetch(url, init);
  }) as typeof fetch;

  const conflictClient = new Aamarva({
    agentId: 'AMR-SLAVE-CONFLICT',
    apiKey: 'sec_key_123',
    fetch: conflictFetch,
  });

  try {
    await conflictClient.sendClusterMessage('cluster_1', {
      ciphertext: 'bW9ja19jaXBoZXI=',
      nonce: 'bW9ja19ub25jZQ==',
    });
    assert.fail('Conflicting master identities must fail closed');
  } catch (err: any) {
    assert.ok(err instanceof AamarvaError);
    assert.strictEqual(err.code, 'MASTER_RESOLUTION_FAILED');
  }

  // C. Test that missing master identity FAILS CLOSED (never substitute sender ID)
  const missingMasterFetch = (async (url: string, init?: any) => {
    if (url.endsWith('/agents/me') && init?.method === 'GET') {
      return new Response(JSON.stringify({
        success: true,
        data: {
          agentId: 'AMR-SLAVE-NO-MASTER',
          name: 'Orphan Slave',
        },
      }), { status: 200 });
    }
    return mockFetch(url, init);
  }) as typeof fetch;

  const missingMasterClient = new Aamarva({
    agentId: 'AMR-SLAVE-NO-MASTER',
    apiKey: 'sec_key_123',
    fetch: missingMasterFetch,
  });

  try {
    await missingMasterClient.sendClusterMessage('cluster_1', {
      ciphertext: 'bW9ja19jaXBoZXI=',
      nonce: 'bW9ja19ub25jZQ==',
    });
    assert.fail('Missing master identity must fail closed without substituting sender ID');
  } catch (err: any) {
    assert.ok(err instanceof AamarvaError);
    assert.strictEqual(err.code, 'MASTER_RESOLUTION_FAILED');
  }

  let lastClusterPayload: any = null;
  const clusterTestFetch = (async (url: string, init?: any) => {
    if (url.endsWith('/agents/me') && init?.method === 'GET') {
      return new Response(JSON.stringify({
        success: true,
        data: {
          agentId: 'AMR-SLAVE-NODE-01',
          name: 'Slave Agent Node 1',
          masterId: 'AMR-MASTER-AUTHORITATIVE', // Authoritative owning master
        },
      }), { status: 200 });
    }
    if (url.includes('/clusters/') && url.endsWith('/messages') && init?.method === 'POST') {
      lastClusterPayload = JSON.parse(init.body || '{}');
      return new Response(JSON.stringify({ success: true, messageId: 'msg_test_123' }), { status: 201 });
    }
    return mockFetch(url, init);
  }) as typeof fetch;

  const slaveClient = new Aamarva({
    agentId: 'AMR-SLAVE-NODE-01',
    apiKey: 'sec_mock_key_123',
    targetAgentId: 'AMR-SLAVE-TARGET-99', // targetAgentId is target slave, NOT master!
    fetch: clusterTestFetch,
  });

  await slaveClient.sendClusterMessage('cluster_1', {
    ciphertext: 'bW9ja19jaXBoZXJ0ZXh0',
    nonce: 'bW9ja19ub25jZQ==',
    recipients: ['AMR-WORKER-01', 'AMR-WORKER-01'], // includes duplicate
  });

  assert.strictEqual(lastClusterPayload.senderAgentId, 'AMR-SLAVE-NODE-01', 'Sender agent ID must match authenticated identity');
  assert.ok(lastClusterPayload.recipients.includes('AMR-MASTER-AUTHORITATIVE'), 'Authoritative master ID from profile metadata MUST be in recipients');
  assert.strictEqual(lastClusterPayload.recipients.includes('AMR-SLAVE-TARGET-99'), false, 'targetAgentId MUST NOT be treated as master recipient');
  assert.ok(lastClusterPayload.recipients.includes('AMR-SLAVE-NODE-01'), 'Sender agent MUST be in recipients');
  assert.ok(lastClusterPayload.recipients.includes('AMR-WORKER-01'), 'Explicit recipients must be preserved');
  
  // Verify recipient deduplication
  const workerOccurrences = lastClusterPayload.recipients.filter((r: string) => r === 'AMR-WORKER-01').length;
  assert.strictEqual(workerOccurrences, 1, 'Recipients list must be deduplicated');

  // Test sender ID spoofing rejection
  try {
    await slaveClient.sendClusterMessage('cluster_1', {
      ciphertext: 'bW9ja19jaXBoZXJ0ZXh0',
      nonce: 'bW9ja19ub25jZQ==',
      senderAgentId: 'AMR-SPOOFED-IDENTITY',
    });
    assert.fail('Spoofed sender agent ID should be rejected before network request');
  } catch (err: any) {
    assert.ok(err instanceof AamarvaValidationError);
    assert.strictEqual(err.code, 'SENDER_IDENTITY_MISMATCH');
    console.log('✓ Spoofed sender ID rejected before network request.');
  }

  // Test master resolution failure prevents message transmission
  const brokenFetch = (async (url: string, init?: any) => {
    if (url.endsWith('/agents/me') && init?.method === 'GET') {
      return new Response(JSON.stringify({ success: false, error: 'Profile corrupt' }), { status: 500 });
    }
    return mockFetch(url, init);
  }) as typeof fetch;

  const brokenClient = new Aamarva({
    agentId: 'AMR-BROKEN',
    apiKey: 'sec_mock_key_123',
    fetch: brokenFetch,
  });

  try {
    await brokenClient.sendClusterMessage('cluster_1', {
      ciphertext: 'bW9ja19jaXBoZXJ0ZXh0',
      nonce: 'bW9ja19ub25jZQ==',
    });
    assert.fail('Message send should fail if master agent ID cannot be resolved');
  } catch (err: any) {
    assert.ok(err instanceof AamarvaError);
    assert.strictEqual(err.code, 'MASTER_RESOLUTION_FAILED');
    console.log('✓ Message transmission blocked when master resolution fails.');
  }

  console.log('✓ Cluster compulsory sender ID and authoritative master recipient resolution verified.');

  console.log('--------------------------------------------------');
  console.log('ALL AAMARVA FLEET SDK TESTS PASSED SUCCESSFULLY   ');
  console.log('--------------------------------------------------');
}

runSdkTests().catch((err) => {
  console.error('SDK test failed:', err);
  process.exit(1);
});
