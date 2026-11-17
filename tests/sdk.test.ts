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
import {
  getLocalIdentityKeyPair,
  exportPublicKeyJWK,
  computeKeyFingerprint,
  computeGroupKeyFingerprint,
  computeRosterHash,
  computeAudienceHash,
  signClusterMessageV2,
  signIdentityBinding,
  generateECKeyPair,
} from '../src/crypto.js';

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

  try {
    await client.http.request({ method: 'POST', path: '/agents/me/e2ee', auth: true });
    assert.fail('POST /agents/me/e2ee should be rejected by endpoint allowlist');
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

  // Verify slave-scoped client preserves x-target-agent-id and cannot bypass backend avatar restriction
  try {
    await client.updateProfile({ avatar: 'https://example.com/slave-avatar.png' });
    assert.fail('Slave-scoped avatar update must be rejected by backend (x-target-agent-id preserved)');
  } catch (err: any) {
    assert.ok(err instanceof AamarvaForbiddenError);
    assert.strictEqual(err.statusCode, 403);
  }

  // Verify master client (no targetAgentId) can update avatar alongside name and bio
  const masterClient = new Aamarva({
    agentId: 'AMR-1111-2222',
    apiKey: 'sec_mock_key_123',
    baseUrl: 'https://aamarva.com/api',
    fetch: createMockFetch(),
  });
  const masterUpdated = await masterClient.updateProfile({
    name: 'Master Operator',
    bio: 'Primary controller',
    avatar: 'https://example.com/master-avatar.png',
  });
  assert.strictEqual(masterUpdated.avatar, 'https://example.com/master-avatar.png');

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

  let capturedConnQueryUrl = '';
  const pagedConnFetch = (async (url: string, init?: any) => {
    if (url.includes('/connections')) {
      capturedConnQueryUrl = url;
    }
    return mockFetch(url, init);
  }) as typeof fetch;
  const pagedClient = new Aamarva({
    agentId: 'AMR-1111-2222',
    apiKey: 'sec_mock_key_123',
    fetch: pagedConnFetch,
  });
  await pagedClient.getConnections();
  assert.strictEqual(capturedConnQueryUrl.includes('page='), false);
  assert.strictEqual(capturedConnQueryUrl.includes('limit='), false);
  await pagedClient.getConnections({ page: 1, limit: 10 });
  assert.ok(capturedConnQueryUrl.includes('page=1'));
  assert.ok(capturedConnQueryUrl.includes('limit=10'));

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

  // Incomplete sendClusterMessage must fail closed (no unsigned/v1 bypass)
  await assert.rejects(
    async () => {
      await client.sendClusterMessage('cluster_987654', {
        ciphertext: 'bW9ja19jaXBoZXJ0ZXh0',
        nonce: 'MTIzNDU2Nzg5MDEy',
        recipients: ['AMR-5555-6666'],
      });
    },
    (err: any) => err?.code === 'INVALID_CLUSTER_KEY_EPOCH'
  );

  // Valid Workflow 2 encrypted cluster send verifies full pipeline
  const clusterMsgRes = await client.sendEncryptedClusterMessage('cluster_987654', 'Cluster sync message', {
    recipients: ['AMR-5555-6666'],
  });
  assert.ok(clusterMsgRes.messageId);

  const clusterMsgs = await client.getClusterMessages('cluster_987654');
  assert.ok(Array.isArray(clusterMsgs));

  const keyDist = await client.getClusterKeyDistribution('cluster_987654', {
    epoch: 1,
    audienceHash: clusterMsgRes.audienceHash,
  });
  assert.ok(keyDist);
  assert.strictEqual(keyDist.clusterId, 'cluster_987654');
  assert.strictEqual(keyDist.epoch, 1);

  let capturedKeyDistUrl = '';
  const keyDistFetch = (async (url: string, init?: any) => {
    if (url.includes('/key-distribution')) {
      capturedKeyDistUrl = url;
      const parsed = new URL(url);
      const ep = Number(parsed.searchParams.get('epoch') || '1');
      const aud = parsed.searchParams.get('audienceHash');
      return new Response(
        JSON.stringify({
          success: true,
          data: {
            clusterId: 'cluster_987654',
            epoch: ep,
            ...(aud ? { audienceHash: aud } : {}),
            keyFingerprint: 'SHA256:' + Array(32).fill('00').join(':'),
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }
    return mockFetch(url, init);
  }) as typeof fetch;
  const kdClient = new Aamarva({ agentId: 'AMR-1111-2222', apiKey: 'sec_mock_key_123', fetch: keyDistFetch });
  await kdClient.getClusterKeyDistribution('cluster_987654');
  assert.strictEqual(capturedKeyDistUrl.includes('?'), false);
  const kdWithAud = await kdClient.getClusterKeyDistribution('cluster_987654', {
    epoch: 3,
    audienceHash: 'aud_sha256_xyz',
  });
  assert.ok(capturedKeyDistUrl.includes('epoch=3'));
  assert.ok(capturedKeyDistUrl.includes('audienceHash=aud_sha256_xyz'));
  assert.strictEqual((kdWithAud as any).audienceHash, 'aud_sha256_xyz');
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
  assert.ok(lastE2eePayload.fingerprint, 'Fingerprint must be registered');
  assert.ok(lastE2eePayload.identityKey, 'Identity key must be registered');
  assert.ok(lastE2eePayload.signature, 'Signature must be registered');
  assert.strictEqual(lastE2eePayload.allowRotation, true);
  assert.strictEqual(lastE2eePayload.keyEpoch, 1);
  assert.strictEqual('keyVersion' in lastE2eePayload, false, 'Legacy keyVersion MUST NOT be sent');
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

  // 12. Cluster Sender ID and Authoritative Master Recipient Tests (Workflow 2 Hardened)
  console.log('12. Testing cluster message compulsory sender ID & authoritative master recipient resolution...');

  const buildSignedClusterEnvelope = (
    agentId: string,
    clusterId: string,
    activeRoster: string[],
    targetedRecipients: string[],
    keyEpoch = 1
  ) => {
    const kp = getLocalIdentityKeyPair(agentId);
    const pubJwk = exportPublicKeyJWK(kp.publicKey);
    const pubFp = computeKeyFingerprint(pubJwk);
    const rosterHash = computeRosterHash(activeRoster);
    const audienceHash = computeAudienceHash(targetedRecipients, activeRoster);
    const keyFingerprint = computeGroupKeyFingerprint(Buffer.alloc(32, 0x42));
    const ciphertext = 'bW9ja19jaXBoZXJ0ZXh0';
    const nonce = 'MTIzNDU2Nzg5MDEy';
    const signature = signClusterMessageV2(kp.privateKey, {
      clusterId,
      keyEpoch,
      senderAgentId: agentId,
      audienceHash,
      rosterHash,
      sequence: '',
      keyFingerprint,
      nonce,
      ciphertext,
    });
    return {
      pubJwk,
      pubFp,
      opts: {
        ciphertext,
        nonce,
        version: 2,
        keyEpoch,
        recipients: targetedRecipients,
        audienceHash,
        rosterHash,
        keyFingerprint,
        signature,
        strictPreflight: true,
      },
    };
  };

  // A. Test all supported master/owner field aliases with authoritative Workflow 2 verification
  const aliasFields = ['masterId', 'master_id', 'masterAgentId', 'master_agent_id', 'ownerAgentId', 'owner_agent_id'];
  for (const field of aliasFields) {
    let payloadSent: any = null;
    const env = buildSignedClusterEnvelope(
      'AMR-SLAVE-NODE',
      'cluster_alias',
      ['AMR-SLAVE-NODE', 'AMR-MASTER-ALIAS-OK'],
      ['AMR-SLAVE-NODE', 'AMR-MASTER-ALIAS-OK']
    );
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
      if (url.endsWith('/clusters/cluster_alias') && init?.method === 'GET') {
        return new Response(JSON.stringify({
          success: true,
          data: {
            clusterId: 'cluster_alias',
            name: 'Alias Cluster',
            epoch: 1,
            keyEpoch: 1,
            rotationStatus: 'NONE',
            rosterHash: env.opts.rosterHash,
          },
        }), { status: 200 });
      }
      if (url.endsWith('/clusters/public/cluster_alias/members') && init?.method === 'GET') {
        return new Response(JSON.stringify({
          success: true,
          data: [
            { agentId: 'AMR-SLAVE-NODE', publicKey: env.pubJwk, keyFingerprint: env.pubFp, keyEpoch: 1 },
            { agentId: 'AMR-MASTER-ALIAS-OK', keyEpoch: 1 },
          ],
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

    await aliasClient.sendClusterMessage('cluster_alias', env.opts);

    assert.ok(payloadSent.recipients.includes('AMR-MASTER-ALIAS-OK'), `Field alias "${field}" must resolve to master recipient`);
  }

  // B. Test that conflicting master fields FAIL CLOSED
  const conflictEnv = buildSignedClusterEnvelope('AMR-SLAVE-CONFLICT', 'cluster_1', ['AMR-SLAVE-CONFLICT', 'AMR-MASTER-A'], ['AMR-SLAVE-CONFLICT', 'AMR-MASTER-A']);
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
    await conflictClient.sendClusterMessage('cluster_1', conflictEnv.opts);
    assert.fail('Conflicting master identities must fail closed');
  } catch (err: any) {
    assert.ok(err instanceof AamarvaError);
    assert.strictEqual(err.code, 'MASTER_RESOLUTION_FAILED');
  }

  // C. Test that missing master identity FAILS CLOSED (never substitute sender ID)
  const missingMasterEnv = buildSignedClusterEnvelope('AMR-SLAVE-NO-MASTER', 'cluster_1', ['AMR-SLAVE-NO-MASTER'], ['AMR-SLAVE-NO-MASTER']);
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
    await missingMasterClient.sendClusterMessage('cluster_1', missingMasterEnv.opts);
    assert.fail('Missing master identity must fail closed without substituting sender ID');
  } catch (err: any) {
    assert.ok(err instanceof AamarvaError);
    assert.strictEqual(err.code, 'MASTER_RESOLUTION_FAILED');
  }

  let lastClusterPayload: any = null;
  const slaveRoster = ['AMR-SLAVE-NODE-01', 'AMR-MASTER-AUTHORITATIVE', 'AMR-WORKER-01'];
  const slaveEnv = buildSignedClusterEnvelope('AMR-SLAVE-NODE-01', 'cluster_1', slaveRoster, ['AMR-SLAVE-NODE-01', 'AMR-MASTER-AUTHORITATIVE', 'AMR-WORKER-01']);
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
    if (url.endsWith('/clusters/cluster_1') && init?.method === 'GET') {
      return new Response(JSON.stringify({
        success: true,
        data: {
          clusterId: 'cluster_1',
          name: 'Cluster 1',
          epoch: 1,
          keyEpoch: 1,
          rotationStatus: 'NONE',
          rosterHash: slaveEnv.opts.rosterHash,
        },
      }), { status: 200 });
    }
    if (url.endsWith('/clusters/public/cluster_1/members') && init?.method === 'GET') {
      return new Response(JSON.stringify({
        success: true,
        data: [
          { agentId: 'AMR-SLAVE-NODE-01', publicKey: slaveEnv.pubJwk, keyFingerprint: slaveEnv.pubFp, keyEpoch: 1 },
          { agentId: 'AMR-MASTER-AUTHORITATIVE', keyEpoch: 1 },
          { agentId: 'AMR-WORKER-01', keyEpoch: 1 },
        ],
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
    ...slaveEnv.opts,
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

  // Test cluster message payload validation BEFORE any HTTP calls
  let unexpectedHttpCalls = 0;
  const noHttpFetch = (async () => {
    unexpectedHttpCalls++;
    throw new Error('HTTP call should not happen on invalid cluster payload');
  }) as typeof fetch;
  const strictClusterClient = new Aamarva({
    agentId: 'AMR-STRICT-01',
    apiKey: 'sec_mock_key_123',
    fetch: noHttpFetch,
  });

  const baseValidForPrecheck = {
    ciphertext: 'Y2lwaGVy',
    nonce: 'MTIzNDU2Nzg5MDEy',
    version: 2,
    keyEpoch: 1,
    audienceHash: 'ALL',
    rosterHash: computeRosterHash(['AMR-STRICT-01']),
    keyFingerprint: computeGroupKeyFingerprint(Buffer.alloc(32, 1)),
    signature: Buffer.alloc(64, 1).toString('base64'),
    strictPreflight: true,
  };
  const invalidClusterPayloads: Array<{ label: string; opts: any }> = [
    { label: 'version=1', opts: { ...baseValidForPrecheck, version: 1 } },
    { label: 'version=3', opts: { ...baseValidForPrecheck, version: 3 } },
    { label: 'missing keyEpoch', opts: { ...baseValidForPrecheck, keyEpoch: undefined } },
    { label: 'keyEpoch=0', opts: { ...baseValidForPrecheck, keyEpoch: 0 } },
    { label: 'keyEpoch=-1', opts: { ...baseValidForPrecheck, keyEpoch: -1 } },
    { label: 'keyEpoch=1.5', opts: { ...baseValidForPrecheck, keyEpoch: 1.5 } },
    { label: 'nonce invalid base64', opts: { ...baseValidForPrecheck, nonce: 'not-base64!' } },
    { label: 'nonce 10 bytes', opts: { ...baseValidForPrecheck, nonce: 'bW9ja19ub25jZQ==' } },
    { label: 'nonce 16 bytes', opts: { ...baseValidForPrecheck, nonce: 'AAAAAAAAAAAAAAAAAAAAAA==' } },
    { label: 'strictPreflight omitted', opts: { ...baseValidForPrecheck, strictPreflight: undefined } },
    { label: 'strictPreflight false', opts: { ...baseValidForPrecheck, strictPreflight: false } },
    { label: 'missing audienceHash', opts: { ...baseValidForPrecheck, audienceHash: undefined } },
    { label: 'bad audienceHash', opts: { ...baseValidForPrecheck, audienceHash: 'SUBSET_BAD' } },
    { label: 'missing rosterHash', opts: { ...baseValidForPrecheck, rosterHash: undefined } },
    { label: 'bad rosterHash', opts: { ...baseValidForPrecheck, rosterHash: 'RST:SHORT' } },
    { label: 'missing keyFingerprint', opts: { ...baseValidForPrecheck, keyFingerprint: undefined } },
    { label: 'bad keyFingerprint', opts: { ...baseValidForPrecheck, keyFingerprint: 'SHA256:SHORT' } },
    { label: 'missing signature', opts: { ...baseValidForPrecheck, signature: undefined } },
    { label: 'non-64-byte signature', opts: { ...baseValidForPrecheck, signature: 'c2hvcnQ=' } },
  ];
  for (const tc of invalidClusterPayloads) {
    try {
      await strictClusterClient.sendClusterMessage('cluster_1', tc.opts);
      assert.fail(`Expected AamarvaValidationError for ${tc.label}`);
    } catch (err: any) {
      assert.ok(err instanceof AamarvaValidationError, `${tc.label} must throw AamarvaValidationError`);
    }
  }
  assert.strictEqual(unexpectedHttpCalls, 0, 'Invalid cluster payloads must fail before any HTTP calls');
  console.log('✓ Cluster strict validation (version===2, integer keyEpoch>=1, 12-byte base64 nonce, Workflow 2 envelope) verified.');

  // Test sender ID spoofing rejection
  try {
    await slaveClient.sendClusterMessage('cluster_1', {
      ...slaveEnv.opts,
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
    await brokenClient.sendClusterMessage('cluster_1', slaveEnv.opts);
    assert.fail('Message send should fail if master agent ID cannot be resolved');
  } catch (err: any) {
    assert.ok(err instanceof AamarvaError);
    assert.strictEqual(err.code, 'MASTER_RESOLUTION_FAILED');
    console.log('✓ Message transmission blocked when master resolution fails.');
  }

  console.log('✓ Cluster compulsory sender ID and authoritative master recipient resolution verified.');

  // 13. Workflow 2 Cluster E2EE End-to-End, 409 Race Adoption, Rotation & Strict Preflight
  console.log('13. Testing Workflow 2 cluster E2EE, audience scoping, 409 race adoption, rotation & strictPreflight...');
  const wf2Store = createMockDataStore();
  wf2Store.clusters = [
    {
      id: 'cluster_wf2',
      clusterId: 'cluster_wf2',
      name: 'Workflow 2 Hardened Cluster',
      ownerAgentId: 'AMR-0000-MASTER',
      epoch: 1,
      keyEpoch: 1,
      membersCount: 3,
      members: ['AMR-1111-2222', 'AMR-5555-6666', 'AMR-0000-MASTER'],
      rotationStatus: 'NONE',
      createdAt: new Date().toISOString(),
    },
  ];
  wf2Store.clusterMembers['cluster_wf2'] = ['AMR-1111-2222', 'AMR-5555-6666', 'AMR-0000-MASTER'];
  wf2Store.clusterMessages['cluster_wf2'] = [];
  const wf2Fetch = createMockFetch(wf2Store);

  const wf2Client = new Aamarva({
    agentId: 'AMR-1111-2222',
    apiKey: 'sec_mock_key_123',
    fetch: wf2Fetch,
  });

  // 13a. New lookup & member endpoints
  const peerByAgent = await wf2Client.getPeerKeyByAgent('AMR-3333-4444');
  assert.ok(peerByAgent.publicKey);
  assert.ok(peerByAgent.fingerprint?.startsWith('SHA256:'));

  const clMembers = await wf2Client.getClusterMembers('cluster_wf2');
  assert.strictEqual(clMembers.length, 3);
  assert.ok(clMembers.every((m) => m.publicKey && m.keyFingerprint));

  // 13b. Broadcast ALL vs Targeted Subgroup Audience Encryption & Decryption
  const allSecret = 'WF2_SECRET_ALL_MEMBERS_PAYLOAD';
  const sentAll = await wf2Client.sendEncryptedClusterMessage('cluster_wf2', allSecret);
  assert.strictEqual(sentAll.version, 2);
  assert.strictEqual(sentAll.keyEpoch, 1);
  assert.strictEqual(sentAll.audienceHash, 'ALL');
  assert.ok(sentAll.rosterHash?.startsWith('RST:'));
  assert.ok(sentAll.keyFingerprint?.startsWith('SHA256:'));
  assert.ok(sentAll.signature);
  assert.strictEqual(JSON.stringify(wf2Store.clusterMessages['cluster_wf2']).includes(allSecret), false);

  const decryptedAll = await wf2Client.decryptClusterMessage('cluster_wf2', sentAll);
  assert.strictEqual(decryptedAll, allSecret);

  // Targeted subgroup (AMR-1111-2222 + AMR-0000-MASTER, excluding AMR-5555-6666)
  const subSecret = 'WF2_SECRET_SUBGROUP_ONLY';
  const sentSub = await wf2Client.sendEncryptedClusterMessage('cluster_wf2', subSecret, {
    recipients: ['AMR-1111-2222', 'AMR-0000-MASTER'],
  });
  assert.ok(sentSub.audienceHash?.startsWith('AUD:'), 'Subgroup must produce AUD:<32-hex> audienceHash');
  const decryptedSub = await wf2Client.decryptClusterMessage('cluster_wf2', sentSub);
  assert.strictEqual(decryptedSub, subSecret);

  // Tampering signature must fail verification when verifySignature is enabled
  await assert.rejects(
    async () => {
      await wf2Client.decryptClusterMessage(
        'cluster_wf2',
        {
          ...sentSub,
          signature: Buffer.alloc(64, 0).toString('base64'),
        },
        { verifySignature: true }
      );
    },
    (err: any) => err?.code === 'CLUSTER_SIGNATURE_INVALID'
  );

  // 13c. ROTATION_REQUIRED handling (autoRotate=false fails closed, autoRotate=true rotates epoch)
  wf2Store.clusters[0].rotationStatus = 'ROTATION_REQUIRED_MEMBER_REMOVED';
  await assert.rejects(
    async () => {
      await wf2Client.sendEncryptedClusterMessage('cluster_wf2', 'Should fail without autoRotate', {
        autoRotate: false,
      });
    },
    (err: any) => err?.code === 'CLUSTER_ROTATION_REQUIRED'
  );

  const rotatedSent = await wf2Client.sendEncryptedClusterMessage('cluster_wf2', 'Auto rotated payload');
  assert.strictEqual(rotatedSent.keyEpoch, 2, 'Auto-rotation must advance keyEpoch to 2');
  assert.strictEqual(await wf2Client.decryptClusterMessage('cluster_wf2', rotatedSent), 'Auto rotated payload');

  // 13d. 409 EPOCH_KEY_ALREADY_SEALED race condition adoption
  let simulateRaceOnce = true;
  const raceFetch = (async (url: string, init?: any) => {
    if (url.includes('/clusters/cluster_wf2/key-distribution') && init?.method === 'POST' && simulateRaceOnce) {
      simulateRaceOnce = false;
      // Simulate peer having already sealed epoch 2 ALL key before our POST
      const parsedBody = JSON.parse(init.body || '{}');
      const key = `cluster_wf2:${parsedBody.epoch || 2}:${parsedBody.audienceHash || 'ALL'}`;
      wf2Store.clusterKeyDistributions![key] = {
        clusterId: 'cluster_wf2',
        epoch: parsedBody.epoch || 2,
        audienceHash: parsedBody.audienceHash || 'ALL',
        rosterHash: parsedBody.rosterHash,
        keyFingerprint: parsedBody.keyFingerprint,
        senderAgentId: parsedBody.senderAgentId,
        recipients: parsedBody.recipients,
      };
      return new Response(
        JSON.stringify({
          success: false,
          code: 'EPOCH_KEY_ALREADY_SEALED',
          error: 'Epoch key already sealed by peer agent',
        }),
        { status: 409, headers: { 'Content-Type': 'application/json' } }
      );
    }
    return wf2Fetch(url, init);
  }) as typeof fetch;

  const raceClient = new Aamarva({
    agentId: 'AMR-1111-2222',
    apiKey: 'sec_mock_key_123',
    fetch: raceFetch,
  });
  const raceMsg = await raceClient.sendEncryptedClusterMessage('cluster_wf2', 'Race recovery secret', { epoch: 2 });
  assert.strictEqual(await raceClient.decryptClusterMessage('cluster_wf2', raceMsg), 'Race recovery secret');

  // 13e. strictPreflight rejection when fingerprint mismatches sealed key (even with valid local signature)
  const badFpEnv = {
    ...sentAll,
    keyEpoch: 2,
    keyFingerprint: 'SHA256:' + Array(32).fill('FF').join(':'),
    strictPreflight: true,
  };
  await assert.rejects(
    async () => {
      await wf2Client.sendClusterMessage('cluster_wf2', badFpEnv);
    },
    (err: any) => err instanceof AamarvaError
  );
  console.log('✓ Workflow 2 cluster E2EE, audience isolation, 409 race recovery, rotation, and strictPreflight verified.');

  // 14. Fail-Closed Security Hardening Regression Tests (Direct Connection + Cluster)
  console.log('14. Testing fail-closed security invariants for Direct Connection & Cluster...');

  // 14a. Direct Connection: Missing/invalid peerKeyEpoch and connectionId mismatch must fail closed
  for (const badPeerRes of [
    { label: 'missing peerKeyEpoch', payload: { peerAgentId: 'AMR-PEER-X', connectionId: 'conn_bad' } },
    { label: 'peerKeyEpoch=0', payload: { peerAgentId: 'AMR-PEER-X', connectionId: 'conn_bad', peerKeyEpoch: 0 } },
    { label: 'connectionId mismatch', payload: { peerAgentId: 'AMR-PEER-X', connectionId: 'conn_WRONG', peerKeyEpoch: 1 } },
  ]) {
    const peerKp = generateECKeyPair();
    const peerJwk = exportPublicKeyJWK(peerKp.publicKey);
    const peerFp = computeKeyFingerprint(peerJwk);
    const peerSig = signIdentityBinding(peerKp.privateKey, 'AMR-PEER-X', peerFp);
    const badConnFetch = (async (url: string, init?: any) => {
      if (url.endsWith('/agents/me/e2ee')) {
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      }
      if (url.includes('/peer-key')) {
        return new Response(JSON.stringify({
          success: true,
          data: {
            ...badPeerRes.payload,
            peerE2eePublicKey: peerJwk,
            peerKeyFingerprint: peerFp,
            peerIdentityKey: peerJwk,
            peerKeySignature: peerSig,
          },
        }), { status: 200 });
      }
      return mockFetch(url, init);
    }) as typeof fetch;

    const badConnClient = new Aamarva({ agentId: 'AMR-LOCAL-X', apiKey: 'sk_test', fetch: badConnFetch });
    await assert.rejects(
      async () => badConnClient.sendMessage('conn_bad', 'secret', { peerAgentId: 'AMR-PEER-X' }),
      (err: any) => err?.code === 'PEER_KEY_VERIFICATION_FAILED',
      `Direct send must fail closed on ${badPeerRes.label}`
    );
  }

  // 14b. decryptClusterMessage fail-closed checks (verifySignature: false, missing sig, non-member sender, contradicting pubkey, sealed rosterHash mismatch)
  await assert.rejects(
    async () => wf2Client.decryptClusterMessage('cluster_wf2', sentSub, { verifySignature: false }),
    (err: any) => err?.code === 'CLUSTER_SIGNATURE_INVALID'
  );
  await assert.rejects(
    async () => wf2Client.decryptClusterMessage('cluster_wf2', { ...sentSub, version: 1 }),
    (err: any) => err?.code === 'INVALID_CLUSTER_MESSAGE_VERSION'
  );
  await assert.rejects(
    async () => wf2Client.decryptClusterMessage('cluster_wf2', { ...sentSub, senderAgentId: 'AMR-OUTSIDER' }),
    (err: any) => err?.code === 'CLUSTER_MEMBERSHIP_INVALID'
  );
  const attackerKp = generateECKeyPair();
  await assert.rejects(
    async () => wf2Client.decryptClusterMessage('cluster_wf2', sentSub, { senderPublicKey: exportPublicKeyJWK(attackerKp.publicKey) }),
    (err: any) => err?.code === 'CLUSTER_SIGNATURE_INVALID'
  );
  const wrongRosterHash = 'RST:' + '0'.repeat(32);
  const signedWrongRosterSig = signClusterMessageV2(getLocalIdentityKeyPair('AMR-1111-2222').privateKey, {
    clusterId: 'cluster_wf2',
    keyEpoch: rotatedSent.keyEpoch!,
    senderAgentId: rotatedSent.senderAgentId!,
    audienceHash: rotatedSent.audienceHash!,
    rosterHash: wrongRosterHash,
    sequence: '',
    keyFingerprint: rotatedSent.keyFingerprint!,
    nonce: rotatedSent.nonce!,
    ciphertext: rotatedSent.ciphertext!,
  });
  await assert.rejects(
    async () => wf2Client.decryptClusterMessage('cluster_wf2', {
      ...rotatedSent,
      rosterHash: wrongRosterHash,
      signature: signedWrongRosterSig,
    }),
    (err: any) => err?.code === 'ROSTER_HASH_MISMATCH'
  );

  // 14c. sendClusterMessage rejects non-member recipient, ROTATION_REQUIRED, and stale epoch
  await assert.rejects(
    async () => slaveClient.sendClusterMessage('cluster_1', { ...slaveEnv.opts, recipients: ['AMR-OUTSIDER-999'] }),
    (err: any) => err?.code === 'CLUSTER_MEMBERSHIP_INVALID'
  );
  await assert.rejects(
    async () => wf2Client.sendClusterMessage('cluster_wf2', { ...sentAll, strictPreflight: true, keyEpoch: 1 }),
    (err: any) => err?.code === 'CLUSTER_INVALID_EPOCH'
  );

  // 14d. Non-404 error during getClusterKeyEntry must NOT trigger distributeClusterKey fallback
  let distCalledOn403 = false;
  const err403Fetch = (async (url: string, init?: any) => {
    if (url.includes('/clusters/cluster_wf2/key-distribution') && init?.method === 'GET') {
      return new Response(JSON.stringify({ success: false, error: 'Forbidden' }), { status: 403 });
    }
    if (url.includes('/clusters/cluster_wf2/key-distribution') && init?.method === 'POST') {
      distCalledOn403 = true;
    }
    return wf2Fetch(url, init);
  }) as typeof fetch;
  const err403Client = new Aamarva({ agentId: 'AMR-1111-2222', apiKey: 'sk_test', fetch: err403Fetch });
  await assert.rejects(
    async () => err403Client.sendEncryptedClusterMessage('cluster_wf2', 'Should not auto-distribute on 403'),
    (err: any) => err instanceof AamarvaError
  );
  assert.strictEqual(distCalledOn403, false, '403 on key fetch must NOT fall back to distributeClusterKey');

  // 14e. rotateClusterKey rejects non-monotonic epoch
  const staleRotateFetch = (async (url: string, init?: any) => {
    if (url.includes('/rotate-key') && init?.method === 'POST') {
      return new Response(JSON.stringify({ success: true, data: { clusterId: 'cluster_wf2', epoch: 2, keyEpoch: 2 } }), { status: 200 });
    }
    return wf2Fetch(url, init);
  }) as typeof fetch;
  const staleRotateClient = new Aamarva({ agentId: 'AMR-1111-2222', apiKey: 'sk_test', fetch: staleRotateFetch });
  await assert.rejects(
    async () => staleRotateClient.rotateClusterKey('cluster_wf2', { currentEpoch: 2 }),
    (err: any) => err?.code === 'CLUSTER_ROTATION_FAILED'
  );

  // 14f. getClusterKey requires explicit epoch
  await assert.rejects(
    async () => wf2Client.getClusterKey('cluster_wf2'),
    (err: any) => err?.code === 'CLUSTER_INVALID_EPOCH'
  );
  console.log('✓ All fail-closed Direct Connection & Cluster Phase 3/4 invariants verified.');

  console.log('--------------------------------------------------');
  console.log('ALL AAMARVA FLEET SDK TESTS PASSED SUCCESSFULLY   ');
  console.log('--------------------------------------------------');
}

runSdkTests().catch((err) => {
  console.error('SDK test failed:', err);
  process.exit(1);
});
