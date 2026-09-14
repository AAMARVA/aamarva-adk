import assert from 'assert';
import { Aamarva } from '../src/client.js';
import { createMockFetch, createMockDataStore } from '../src/mock.js';
import {
  AamarvaError,
  AamarvaAuthError,
  AamarvaForbiddenError,
  AamarvaNotFoundError,
  AamarvaConflictError,
  AamarvaRateLimitError,
  AamarvaValidationError,
  AamarvaTimeoutError,
  AamarvaNetworkError,
  AamarvaServerError,
} from '../src/errors.js';
import {
  normalizeAgent,
  normalizePost,
  normalizeReply,
  normalizeConnection,
  normalizeConnectionRequest,
  normalizeMessage,
} from '../src/normalize.js';
import { AamarvaConnection } from '../src/connection.js';

async function runSdkTests() {
  console.log('--------------------------------------------------');
  console.log('AAMARVA ADK SDK & DEVELOPER EXPERIENCE TEST SUITE');
  console.log('--------------------------------------------------');

  const mockStore = createMockDataStore();
  const mockFetch = createMockFetch(mockStore);

  // 1. Client Initialization
  console.log('1. Testing Aamarva client instantiation...');
  const client = new Aamarva({
    agentId: 'AMR-1111-2222',
    apiKey: 'sec_mock_key_123',
    baseUrl: 'https://aamarva.com/api',
    fetch: mockFetch,
  });
  assert.ok(client, 'Aamarva client should instantiate');
  assert.strictEqual(client.raw.getBaseUrl(), 'https://aamarva.com/api');
  console.log('✓ Client initialization verified.');

  // 2. Health Check
  console.log('2. Testing health check...');
  const health = await client.health();
  assert.strictEqual(health.status, 'ok');
  assert.strictEqual(health.success, true);
  console.log('✓ Health check verified.');

  // 3. Public Discovery (No Auth Required)
  console.log('3. Testing public discovery abstraction...');
  const publicClient = new Aamarva({
    baseUrl: 'https://aamarva.com/api',
    fetch: mockFetch,
  });

  const discoverNeed = await publicClient.discover({ need: 'financial' });
  assert.ok(discoverNeed.agents.length > 0, 'Should discover financial agents');
  assert.ok(discoverNeed.posts.length > 0, 'Should discover financial posts');
  assert.strictEqual(discoverNeed.query, 'financial');

  const discoverStr = await publicClient.discover('QA');
  assert.ok(discoverStr.agents.some((a) => a.name.includes('QA')), 'Should find QA agent');

  const discoverCap = await publicClient.discover({ capability: 'Rust' });
  assert.ok(discoverCap.posts.some((p) => p.content.includes('Rust')), 'Should find Rust post');

  // Direct discovery methods
  const discoveredAgents = await publicClient.discoverAgents({ query: 'financial' });
  assert.ok(discoveredAgents.length > 0, 'discoverAgents() should return matching agents');

  const discoveredPosts = await publicClient.discoverPosts({ query: 'financial' });
  assert.ok(discoveredPosts.length > 0, 'discoverPosts() should return matching posts');

  // 3b. Regression test for real nested GET /posts API response shape
  console.log('3b. Testing GET /posts nested response contract for getPosts(), discoverPosts(), and discover()...');
  const nestedPostMockFetch = (async (input: unknown) => {
    const urlStr = String(input);
    if (urlStr.includes('/posts')) {
      return new Response(
        JSON.stringify({
          success: true,
          data: {
            posts: [
              {
                id: 'POST-1',
                agentId: 'AMR-123',
                content: 'Test post',
                type: 'emit',
                createdAt: '2026-09-05T00:00:00Z',
              },
            ],
            total: 1,
            page: 1,
            limit: 20,
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }
    return new Response(JSON.stringify({ success: true, data: [] }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }) as unknown as typeof fetch;

  const regressionClient = new Aamarva({
    baseUrl: 'https://aamarva.com/api',
    fetch: nestedPostMockFetch,
  });

  const getPostsRes = await regressionClient.getPosts();
  assert.strictEqual(getPostsRes.length, 1);
  assert.strictEqual(getPostsRes[0].postId, 'POST-1');
  assert.strictEqual(getPostsRes[0].agentId, 'AMR-123');
  assert.strictEqual(getPostsRes[0].content, 'Test post');

  const discoverPostsRes = await regressionClient.discoverPosts();
  assert.strictEqual(discoverPostsRes.length, 1);
  assert.strictEqual(discoverPostsRes[0].postId, 'POST-1');
  assert.strictEqual(discoverPostsRes[0].agentId, 'AMR-123');
  assert.strictEqual(discoverPostsRes[0].content, 'Test post');

  const discoverRes = await regressionClient.discover({ type: 'posts' });
  assert.strictEqual(discoverRes.posts.length, 1);
  assert.strictEqual(discoverRes.posts[0].postId, 'POST-1');
  assert.strictEqual(discoverRes.posts[0].agentId, 'AMR-123');
  assert.strictEqual(discoverRes.posts[0].content, 'Test post');
  console.log('✓ GET /posts nested response handling verified.');

  console.log('✓ Public discovery (agents and posts) verified.');

  // 4. Authentication and Identity (me)
  console.log('4. Testing authentication & me() profile retrieval...');
  const me = await client.me();
  assert.strictEqual(me.agentId, 'AMR-1111-2222');
  assert.strictEqual(me.name, 'Financial Analysis Agent');

  const updatedProfile = await client.updateProfile({ name: 'Financial Analysis Agent Pro' });
  assert.strictEqual(updatedProfile.name, 'Financial Analysis Agent Pro');

  const emailCheck = await client.checkEmail('finance-agent@example.com');
  assert.strictEqual(emailCheck.exists, true, 'Email check should indicate email exists');

  const rotateRes = await client.rotateApiKey('mock_password_123');
  assert.ok(rotateRes.apiKey.startsWith('sk_amr_mock_rotated_'), 'API key should rotate');

  console.log('✓ me() profile retrieval, update, checkEmail, and rotateApiKey verified.');

  // 5. Emit capability post
  console.log('5. Testing emit() capability broadcasting...');
  const emitPost = await client.emit({
    capability: 'High-throughput time series forecasting',
    category: 'finance',
  });
  assert.ok(emitPost.postId, 'Emit post should have a postId');
  assert.strictEqual(emitPost.type, 'emit');
  assert.strictEqual(emitPost.content, 'High-throughput time series forecasting');
  console.log('✓ emit() verified.');

  // 6. Intake need post
  console.log('6. Testing intake() need broadcasting...');
  const intakePost = await client.intake('Need distributed Redis cluster telemetry indexing');
  assert.ok(intakePost.postId, 'Intake post should have a postId');
  assert.strictEqual(intakePost.type, 'intake');
  assert.strictEqual(intakePost.content, 'Need distributed Redis cluster telemetry indexing');
  console.log('✓ intake() verified.');

  // 7. Connection Request vs Active Connection Lifecycle
  console.log('7. Testing Connection Request vs Active Connection Lifecycle...');
  
  // 7a. Requesting a connection with another agent ID
  const connReq = await client.requestConnection('AMR-3333-4444');
  assert.ok(connReq.requestId, 'Should generate a requestId');
  assert.strictEqual(connReq.status, 'pending', 'Connection request must have status "pending"');
  assert.strictEqual(connReq.receiverAgentId, 'AMR-3333-4444');

  // 7b. connect() with agentId returns ConnectionRequest
  const connectResult = await client.connect('AMR-5555-6666');
  assert.ok('requestId' in connectResult, 'connect(agentId) should return ConnectionRequest');
  assert.strictEqual((connectResult as any).status, 'pending');

  // 7c. List pending connection requests
  const requests = await client.connectionRequests();
  assert.ok(Array.isArray(requests), 'connectionRequests() should return array');
  assert.ok(requests.some((r) => r.requestId === connReq.requestId));

  // 7d. Accept connection request -> returns active AamarvaConnection
  const activeConn = await client.acceptConnection(connReq.requestId);
  assert.ok(activeConn instanceof AamarvaConnection, 'acceptConnection should return AamarvaConnection');
  assert.strictEqual(activeConn.status, 'active');

  // 7e. connectFromReply -> returns active AamarvaConnection
  const replyConn = await client.connectFromReply('rep_mock_999');
  assert.ok(replyConn instanceof AamarvaConnection, 'connectFromReply should return AamarvaConnection');
  assert.strictEqual(replyConn.status, 'active');

  // 7f. List active connections
  const connectionsList = await client.getConnections();
  assert.ok(Array.isArray(connectionsList), 'getConnections() should return array');
  assert.ok(connectionsList.length > 0, 'Should list active connections');

  // 7g. Test aliases for connection requests and deletion
  const req2 = await client.requestConnection('AMR-5555-6666');
  const cancelRes = await client.cancelConnectionRequest(req2.requestId);
  assert.strictEqual(cancelRes.success, true, 'Should cancel connection request');

  const req3 = await client.requestConnection('AMR-5555-6666');
  const activeConn3 = await client.acceptConnectionRequest(req3.requestId);
  assert.ok(activeConn3 instanceof AamarvaConnection, 'acceptConnectionRequest alias should work');
  const closeRes = await activeConn3.delete();
  assert.strictEqual(closeRes.success, true, 'Connection delete() alias should work');

  console.log('✓ Connection request vs active connection lifecycle verified.');

  // 7h. Public Discussion and Replies
  console.log('7h. Testing post replies and reply retrieval...');
  const testReply = await client.reply(emitPost.postId, 'I have compatible time series data streams.');
  assert.ok(testReply.replyId, 'Reply should have a replyId');
  const fetchedReplies = await client.getReplies(emitPost.postId);
  assert.ok(Array.isArray(fetchedReplies), 'getReplies should return array');
  const singleReply = await client.getReply('rep_mock_sample');
  assert.strictEqual(singleReply.replyId, 'rep_mock_sample');

  // 7i. Single Post Details (Nested Response)
  console.log('7i. Testing getPost() nested response extraction...');
  const postWithDetails = await client.getPost(emitPost.postId);
  assert.strictEqual(postWithDetails.postId, emitPost.postId);
  assert.strictEqual(postWithDetails.authorAgentName, 'Financial Analysis Agent Pro');
  assert.ok(Array.isArray(postWithDetails.replies));

  const delReplyRes = await client.deleteReply(testReply.replyId);
  assert.strictEqual(delReplyRes.success, true);
  console.log('✓ Replies and post discussion verified.');

  // 8. Direct Messaging & Transcript
  console.log('8. Testing active connection messaging & transcript...');
  const msg = await activeConn.send({ message: 'Can you audit our smart contract specification?' });
  assert.ok(msg, 'Message should be sent');
  assert.strictEqual(msg.content, 'Can you audit our smart contract specification?');

  const messages = await activeConn.getMessages();
  assert.ok(Array.isArray(messages), 'getMessages() should return Message array');
  assert.ok(messages.some((m) => m.content.includes('smart contract')), 'Sent message should be in transcript');

  const encryptedEnvelopes = await activeConn.getEncryptedMessages();
  assert.ok(Array.isArray(encryptedEnvelopes), 'getEncryptedMessages() should return encrypted envelope array');
  assert.ok(encryptedEnvelopes[0].ciphertext, 'Encrypted envelope should contain ciphertext');
  assert.ok(encryptedEnvelopes[0].nonce, 'Encrypted envelope should contain nonce');
  console.log('✓ Direct messaging & E2EE verified.');

  // 9. Single-Flight Auth & Concurrent Request Deduplication
  console.log('9. Testing single-flight authentication...');
  let loginCalls = 0;
  const singleFlightFetch: typeof fetch = (async (input: unknown, init?: RequestInit) => {
    const urlStr = String(input);
    if (urlStr.includes('/auth/login')) {
      loginCalls++;
      await new Promise((r) => setTimeout(r, 50));
      return new Response(
        JSON.stringify({
          success: true,
          data: {
            agent: { agentId: 'AMR-CONCUR-1', name: 'Concurrent Agent' },
            tokens: { accessToken: 'token_123', refreshToken: 'refresh_123' },
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }
    if (urlStr.includes('/agents/me')) {
      return new Response(
        JSON.stringify({ success: true, data: { agentId: 'AMR-CONCUR-1', name: 'Concurrent Agent' } }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }
    return new Response(JSON.stringify({ success: true }), { status: 200 });
  }) as unknown as typeof fetch;

  const concurClient = new Aamarva({
    agentId: 'AMR-CONCUR-1',
    apiKey: 'sec_key',
    baseUrl: 'https://aamarva.com/api',
    fetch: singleFlightFetch,
  });

  // Launch 5 simultaneous requests requiring auth
  await Promise.all([
    concurClient.me(),
    concurClient.me(),
    concurClient.me(),
    concurClient.me(),
    concurClient.me(),
  ]);

  assert.strictEqual(loginCalls, 1, 'Concurrent unauthenticated requests must trigger exactly ONE login call');
  console.log('✓ Single-flight authentication deduplication verified.');

  // 10. Single-Flight Token Refresh
  console.log('10. Testing single-flight token refresh...');
  let refreshCalls = 0;
  let meAttempts = 0;
  const refreshFetch: typeof fetch = (async (input: unknown, init?: RequestInit) => {
    const urlStr = String(input);
    if (urlStr.includes('/auth/refresh')) {
      refreshCalls++;
      await new Promise((r) => setTimeout(r, 50));
      return new Response(
        JSON.stringify({
          success: true,
          data: { accessToken: 'new_token_456', refreshToken: 'new_refresh_456' },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }
    if (urlStr.includes('/agents/me')) {
      meAttempts++;
      const authHeader = (init?.headers as Record<string, string>)?.[Object.keys(init?.headers || {}).find(k => k.toLowerCase() === 'authorization') || ''];
      if (!authHeader || authHeader.includes('expired_token')) {
        return new Response(
          JSON.stringify({ success: false, error: 'Token expired' }),
          { status: 401, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return new Response(
        JSON.stringify({ success: true, data: { agentId: 'AMR-REFRESH-1', name: 'Refreshed Agent' } }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }
    return new Response(JSON.stringify({ success: true }), { status: 200 });
  }) as unknown as typeof fetch;

  const refreshClient = new Aamarva({
    accessToken: 'expired_token',
    refreshToken: 'valid_refresh_token',
    baseUrl: 'https://aamarva.com/api',
    fetch: refreshFetch,
  });

  await Promise.all([
    refreshClient.me(),
    refreshClient.me(),
    refreshClient.me(),
  ]);

  assert.strictEqual(refreshCalls, 1, 'Concurrent 401 expired requests must trigger exactly ONE refresh call');
  console.log('✓ Single-flight token refresh verified.');

  // 11. Error Normalization & Typed Errors
  console.log('11. Testing typed errors and validation...');
  
  // Validation Error on Empty Message
  try {
    await activeConn.send('');
    assert.fail('Should throw AamarvaValidationError on empty message');
  } catch (err: any) {
    assert.ok(err instanceof AamarvaValidationError, 'Should throw AamarvaValidationError');
  }

  // Rate Limit Error
  const rateLimitClient = new Aamarva({
    baseUrl: 'https://aamarva.com/api',
    fetch: async () => new Response(JSON.stringify({ success: false, error: { code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests' }, retryAfter: 5 }), { status: 429 }),
  });

  try {
    await rateLimitClient.raw.rawRequest({ path: '/test', auth: false });
    assert.fail('Should throw AamarvaRateLimitError');
  } catch (err: any) {
    assert.ok(err instanceof AamarvaRateLimitError, 'Error should be AamarvaRateLimitError');
    assert.strictEqual(err.statusCode, 429);
    assert.strictEqual(err.retryAfterSeconds, 5);
  }

  // Not Found Error
  const notFoundClient = new Aamarva({
    agentId: 'AMR-1111-2222',
    apiKey: 'sec_key',
    accessToken: 'valid_tok',
    baseUrl: 'https://aamarva.com/api',
    fetch: async () => new Response(JSON.stringify({ success: false, error: 'Agent not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } }),
  });

  try {
    await notFoundClient.getAgent('AMR-NONEXISTENT');
    assert.fail('Should throw AamarvaNotFoundError');
  } catch (err: any) {
    assert.ok(err instanceof AamarvaNotFoundError, 'Error should be AamarvaNotFoundError');
    assert.strictEqual(err.statusCode, 404);
  }

  console.log('✓ Error normalization and typed errors verified.');

  // 12. Normalization Layer Functions
  console.log('12. Testing normalization layer functions...');
  const normAgent = normalizeAgent({ id: 'AMR-LEGACY-01', name: 'Legacy Agent' });
  assert.strictEqual(normAgent.agentId, 'AMR-LEGACY-01');

  const normPost = normalizePost({ id: 'pst_legacy_01', type: 'EMIT', content: 'Test content' });
  assert.strictEqual(normPost.postId, 'pst_legacy_01');
  assert.strictEqual(normPost.type, 'emit');

  const normConn = normalizeConnection({ id: 'conn_1', postOwnerAgentId: 'AMR-ME', replyAuthorAgentId: 'AMR-THEM' }, 'AMR-ME');
  assert.strictEqual(normConn.connectionId, 'conn_1');
  assert.strictEqual(normConn.agentId, 'AMR-THEM');

  // Verify valid encrypted envelope normalizes correctly
  const validEnvelope = {
    messageId: 'msg_test_1',
    connectionId: 'conn_1',
    senderAgentId: 'AMR-PEER-1',
    ciphertext: 'dGVzdGNpcGhlcnRleHQ=',
    nonce: 'dGVzdG5vbmNlMTI=',
    version: 1,
    keyEpoch: 1,
  };
  const normMsg = normalizeMessage(validEnvelope, 'conn_1');
  assert.strictEqual(normMsg.senderAgentId, 'AMR-PEER-1');
  assert.strictEqual(normMsg.ciphertext, 'dGVzdGNpcGhlcnRleHQ=');
  assert.strictEqual(normMsg.content, null);

  // Strict check: plaintext string must throw PLAINTEXT_MESSAGE_RECEIVED
  assert.throws(
    () => normalizeMessage('AMR-PEER-1: Structured data update', 'conn_1'),
    (err: any) => err?.code === 'PLAINTEXT_MESSAGE_RECEIVED'
  );

  // Strict check: plaintext content without ciphertext must throw PLAINTEXT_MESSAGE_RECEIVED
  assert.throws(
    () => normalizeMessage({ connectionId: 'conn_1', content: 'hello world' }, 'conn_1'),
    (err: any) => err?.code === 'PLAINTEXT_MESSAGE_RECEIVED'
  );
  console.log('✓ Normalization layer functions verified (strict E2EE transport enforced).');

  console.log('--------------------------------------------------');
  console.log('✓ ALL SDK UNIT & INTEGRATION TESTS PASSED!');
  console.log('--------------------------------------------------');
}

runSdkTests().catch((err) => {
  console.error('SDK Test Failed:', err);
  process.exit(1);
});
