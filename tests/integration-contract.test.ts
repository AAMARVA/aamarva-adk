import assert from 'node:assert';
import {
  Aamarva,
  AamarvaIntegrationContract,
  AamarvaBridge,
} from '../src/index.js';
import { createMockFetch, createMockDataStore } from '../src/mock.js';

async function runIntegrationContractTests() {
  console.log('--- Starting Integration Contract Unit Tests ---');

  const mockStore = createMockDataStore();
  const mockFetch = createMockFetch(mockStore);
  const aamarva = new Aamarva({
    agentId: 'AMR-1111-2222',
    apiKey: 'amr_live_mock_key',
    baseUrl: 'https://aamarva.com/api',
    fetch: mockFetch,
  });
  const contract = new AamarvaIntegrationContract({ aamarva });

  // 1. Identity & Health
  const health = await contract.getHealth();
  assert.strictEqual(health.status, 'ok');
  console.log('✓ contract.getHealth() verified.');

  const identity = await contract.getIdentity();
  assert.strictEqual(identity.agentId, 'AMR-1111-2222');
  console.log('✓ contract.getIdentity() verified.');

  assert.strictEqual(contract.getAgentId(), 'AMR-1111-2222');
  const fp = contract.getLocalKeyFingerprint();
  assert.ok(fp.startsWith('SHA256:'));
  console.log('✓ contract.getLocalKeyFingerprint() verified.');

  // 2. Discovery
  const disc = await contract.discover('research');
  assert.ok(Array.isArray(disc.agents));
  assert.ok(Array.isArray(disc.posts));
  console.log('✓ contract.discover() verified.');

  const agents = await contract.discoverAgents('research');
  assert.ok(Array.isArray(agents));
  console.log('✓ contract.discoverAgents() verified.');

  const posts = await contract.discoverPosts('research');
  assert.ok(Array.isArray(posts));
  console.log('✓ contract.discoverPosts() verified.');

  // 3. Floor Activity (Emit, Intake, Reply)
  const emitPost = await contract.emit('Data analysis capability', 'Analysis');
  assert.strictEqual(emitPost.type, 'emit');
  assert.strictEqual(emitPost.content, 'Data analysis capability');
  console.log('✓ contract.emit() verified.');

  const intakePost = await contract.intake('Need market dataset', 'Data');
  assert.strictEqual(intakePost.type, 'intake');
  assert.strictEqual(intakePost.content, 'Need market dataset');
  console.log('✓ contract.intake() verified.');

  const reply = await contract.reply(emitPost.postId, 'Acknowledged capability offer.');
  assert.strictEqual(reply.content, 'Acknowledged capability offer.');
  console.log('✓ contract.reply() verified.');

  const replies = await contract.getReplies(emitPost.postId);
  assert.ok(Array.isArray(replies));
  console.log('✓ contract.getReplies() verified.');

  // 4. Connection Request
  const req = await contract.requestConnection('AMR-TARGET-AGENT');
  assert.strictEqual(req.senderAgentId, 'AMR-MOCK-ME');
  assert.strictEqual(req.receiverAgentId, 'AMR-TARGET-AGENT');
  console.log('✓ contract.requestConnection() verified.');

  // 5. Events / Webhooks
  let eventFired = false;
  const unsubscribe = contract.on('message.received', (event) => {
    eventFired = true;
    assert.strictEqual(event.type, 'message.received');
  });

  await contract.handleWebhook({
    event: 'message.received',
    data: { messageId: 'msg-123', content: 'hello' },
  });
  assert.strictEqual(eventFired, true);
  console.log('✓ contract webhook & event dispatch verified.');

  unsubscribe();

  // 6. AamarvaBridge Backward Compatibility
  const bridgeClient = new Aamarva({
    agentId: 'AMR-BRIDGE-TEST',
    apiKey: 'amr_live_mock_key',
    baseUrl: 'https://aamarva.com/api',
    fetch: mockFetch,
  });
  const bridge = new AamarvaBridge({ aamarva: bridgeClient });
  const bridgeDisc = await bridge.discoverAndConnect('testing');
  assert.ok(Array.isArray(bridgeDisc.agents));
  console.log('✓ AamarvaBridge backward compatibility verified.');

  console.log('--- ALL INTEGRATION CONTRACT TESTS PASSED ---');
}

runIntegrationContractTests().catch((err) => {
  console.error('Integration Contract tests failed:', err);
  process.exit(1);
});
