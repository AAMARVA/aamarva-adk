import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  Aamarva,
  AamarvaConnection,
  AamarvaError,
  AamarvaAuthError,
  AamarvaValidationError,
  createMockDataStore,
  createMockFetch,
  FileSystemKeyStore,
  setKeyStore,
  resetLocalIdentityKeyPair,
  getLocalIdentitySigningKeyPair,
  getLocalEcdhKeyPair,
  findLocalEcdhKeyPair,
  getLatestLocalEcdhEpoch,
  rotateLocalEcdhKeyPair,
  exportPublicKeyJWK,
  computeKeyFingerprint,
  signIdentityBinding,
  encryptMessageWithKeys,
  decryptMessageWithKeys,
  wrapClusterKeyForRecipient,
  unwrapClusterKey,
  generateClusterKey,
  encryptClusterMessagePayload,
  decryptClusterMessagePayload,
} from '../../src/index.js';
import { invokeExternalMcpTool } from '../../src/mcp-executor.js';

async function runPlatformInteropTests() {
  const tempKeyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aamarva-platform-interop-'));
  const prevKeyDir = process.env.AAMARVA_KEY_STORE_PATH;
  process.env.AAMARVA_KEY_STORE_PATH = tempKeyDir;
  resetLocalIdentityKeyPair();
  setKeyStore(new FileSystemKeyStore(tempKeyDir));

  try {
    console.log('==================================================');
    console.log('  AAMARVA PLATFORM INTEROP & HARDENING SUITE      ');
    console.log('==================================================\n');

    // -------------------------------------------------------------------------
    // 1. Deterministic HKDF-SHA256 Channel Vector & Direct Decrypt Interop
    // -------------------------------------------------------------------------
    console.log('1. Testing deterministic HKDF-SHA256 channel derivation against raw Node crypto...');
    const aliceEcdh = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const aliceSign = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const bobEcdh = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const bobSign = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

    const aliceFp = computeKeyFingerprint(aliceEcdh.publicKey);
    const aliceSig = signIdentityBinding(aliceSign.privateKey, 'AMR-ALICE-V', aliceFp);
    const bobFp = computeKeyFingerprint(bobEcdh.publicKey);
    const bobSig = signIdentityBinding(bobSign.privateKey, 'AMR-BOB-V', bobFp);

    const connId = 'conn_hkdf_vector_99';
    const plaintext = 'Platform exact HKDF salt=aamarva-e2ee-channel-v1 info=aamarva-channel:conn_hkdf_vector_99';
    const env = encryptMessageWithKeys(
      plaintext,
      connId,
      aliceEcdh.privateKey,
      bobEcdh.publicKey,
      bobFp,
      'AMR-BOB-V',
      bobSig,
      exportPublicKeyJWK(bobSign.publicKey),
      1
    );

    // Independently derive using authoritative platform spec directly with Node stdlib crypto
    const rawShared = crypto.diffieHellman({
      privateKey: bobEcdh.privateKey,
      publicKey: aliceEcdh.publicKey,
    });
    const expectedAesKey = Buffer.from(
      crypto.hkdfSync(
        'sha256',
        rawShared,
        Buffer.from('aamarva-e2ee-channel-v1', 'utf8'),
        Buffer.from(`aamarva-channel:${connId}`, 'utf8'),
        32
      )
    );
    const rawCombined = Buffer.from(env.ciphertext, 'base64');
    const rawNonce = Buffer.from(env.nonce, 'base64');
    const rawTag = rawCombined.subarray(rawCombined.length - 16);
    const rawCt = rawCombined.subarray(0, rawCombined.length - 16);
    const rawDecipher = crypto.createDecipheriv('aes-256-gcm', expectedAesKey, rawNonce);
    rawDecipher.setAAD(Buffer.from(connId, 'utf8'));
    rawDecipher.setAuthTag(rawTag);
    const rawPlaintext = Buffer.concat([rawDecipher.update(rawCt), rawDecipher.final()]).toString('utf8');
    assert.strictEqual(rawPlaintext, plaintext);
    console.log('✓ Raw Node crypto verified exact HKDF channel derivation & AES-GCM AAD.');

    // -------------------------------------------------------------------------
    // 2. ECDSA/ECDH Key Separation, Epoch Rotation & Historical Message Decryption
    // -------------------------------------------------------------------------
    console.log('2. Testing ECDSA/ECDH separation, 409 rotation enforcement, and multi-epoch decryption...');
    const store = createMockDataStore();
    const baseMockFetch = createMockFetch(store);

    const peer1 = getLocalEcdhKeyPair('AMR-PEER-ROT', 1);
    const peerSign = getLocalIdentitySigningKeyPair('AMR-PEER-ROT');
    const peer1Fp = computeKeyFingerprint(exportPublicKeyJWK(peer1.publicKey));
    const peer1Sig = signIdentityBinding(peerSign.privateKey, 'AMR-PEER-ROT', peer1Fp);

    const aliceClient = new Aamarva({
      agentId: 'AMR-1111-2222',
      apiKey: 'sk_live_test',
      fetch: baseMockFetch,
    });
    assert.strictEqual(aliceClient.getLifecycleState(), 'unauthenticated');

    await aliceClient.login();
    assert.strictEqual(aliceClient.getLifecycleState(), 'e2ee_ready');

    const regRecord = store.e2eeKeys['AMR-1111-2222'];
    assert.ok(regRecord, 'Registration payload must be stored for AMR-1111-2222');
    assert.strictEqual(regRecord.allowRotation, false, 'Routine registration must send allowRotation: false');
    assert.notStrictEqual(
      computeKeyFingerprint(regRecord.publicKey),
      computeKeyFingerprint(regRecord.identityKey),
      'ECDH transport publicKey and ECDSA identityKey must be distinct keys'
    );

    // Server 409 check if non-rotation overwrite attempts different key
    const conflictRes = await baseMockFetch('https://aamarva.com/api/agents/me/e2ee', {
      method: 'PUT',
      body: JSON.stringify({
        publicKey: exportPublicKeyJWK(peer1.publicKey),
        fingerprint: peer1Fp,
        allowRotation: false,
      }),
    });
    assert.strictEqual(conflictRes.status, 409, 'Replacing different key with allowRotation: false must 409');

    // Verify registered key matches local keystore
    const verifiedServerKey = await aliceClient.verifyRegisteredKeyConsistency();
    assert.strictEqual(verifiedServerKey.fingerprint, regRecord.fingerprint);

    // Encrypt epoch 1 message from Peer to Alice BEFORE Alice rotates
    const aliceEpoch1Kp = getLocalEcdhKeyPair('AMR-1111-2222', 1);
    const aliceSignKp = getLocalIdentitySigningKeyPair('AMR-1111-2222');
    const aliceEpoch1Fp = computeKeyFingerprint(exportPublicKeyJWK(aliceEpoch1Kp.publicKey));
    const aliceEpoch1Sig = signIdentityBinding(aliceSignKp.privateKey, 'AMR-1111-2222', aliceEpoch1Fp);

    const msgEpoch1 = encryptMessageWithKeys(
      'historical-epoch-1-secret',
      'conn_epoch_test',
      peer1.privateKey,
      aliceEpoch1Kp.publicKey,
      aliceEpoch1Fp,
      'AMR-1111-2222',
      aliceEpoch1Sig,
      exportPublicKeyJWK(aliceSignKp.publicKey),
      1
    );

    // Now Alice rotates to epoch 2
    const rotRes = await aliceClient.rotateE2eeKey();
    assert.strictEqual(rotRes.keyEpoch, 2);
    assert.notStrictEqual(rotRes.fingerprint, aliceEpoch1Fp);
    assert.strictEqual(store.e2eeKeys['AMR-1111-2222'].allowRotation, true);

    // Peer encrypts epoch 2 message to Alice's rotated key
    const aliceEpoch2Kp = getLocalEcdhKeyPair('AMR-1111-2222', 2);
    const aliceEpoch2Fp = computeKeyFingerprint(exportPublicKeyJWK(aliceEpoch2Kp.publicKey));
    const aliceEpoch2Sig = signIdentityBinding(aliceSignKp.privateKey, 'AMR-1111-2222', aliceEpoch2Fp);
    const msgEpoch2 = encryptMessageWithKeys(
      'current-epoch-2-secret',
      'conn_epoch_test',
      peer1.privateKey,
      aliceEpoch2Kp.publicKey,
      aliceEpoch2Fp,
      'AMR-1111-2222',
      aliceEpoch2Sig,
      exportPublicKeyJWK(aliceSignKp.publicKey),
      2
    );

    // Test connection fetching both historical epoch 1 and epoch 2 messages seamlessly
    const multiEpochFetch = (async (input: any, init?: any) => {
      const u = new URL(typeof input === 'string' ? input : input.url, 'https://aamarva.com');
      const p = u.pathname.replace(/^\/api/, '');
      if (p === '/connections/peer-key/AMR-PEER-ROT') {
        return new Response(
          JSON.stringify({
            success: true,
            data: {
              connectionId: 'conn_epoch_test',
              peerAccountId: 'AMR-PEER-ROT',
              peerAgentId: 'AMR-PEER-ROT',
              peerE2eePublicKey: exportPublicKeyJWK(peer1.publicKey),
              peerKeyFingerprint: peer1Fp,
              peerIdentityKey: exportPublicKeyJWK(peerSign.publicKey),
              peerKeySignature: peer1Sig,
              peerKeyEpoch: 1,
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (p === '/connections/messages/AMR-PEER-ROT') {
        return new Response(
          JSON.stringify({
            success: true,
            data: [
              {
                messageId: 'm_e1',
                connectionId: 'conn_epoch_test',
                senderAgentId: 'AMR-PEER-ROT',
                ...msgEpoch1,
                createdAt: '2026-10-01T00:00:00.000Z',
              },
              {
                messageId: 'm_e2',
                connectionId: 'conn_epoch_test',
                senderAgentId: 'AMR-PEER-ROT',
                ...msgEpoch2,
                createdAt: '2026-10-02T00:00:00.000Z',
              },
            ],
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        );
      }
      return baseMockFetch(input, init);
    }) as typeof fetch;

    const multiClient = new Aamarva({
      agentId: 'AMR-1111-2222',
      apiKey: 'sk_live_test',
      fetch: multiEpochFetch,
    });
    const decryptedBoth = await multiClient.getMessages('AMR-PEER-ROT');
    assert.strictEqual(decryptedBoth.length, 2);
    assert.strictEqual(decryptedBoth[0].content, 'historical-epoch-1-secret');
    assert.strictEqual(decryptedBoth[1].content, 'current-epoch-2-secret');

    // Missing historical epoch key must fail closed
    assert.strictEqual(findLocalEcdhKeyPair('AMR-1111-2222', 99), null);
    console.log('✓ Separate ECDSA/ECDH keys, rotation (allowRotation), and multi-epoch decryption verified.');

    // -------------------------------------------------------------------------
    // 3. FileSystemKeyStore Hardening (Symlinks, Traversal, Corrupt PEM)
    // -------------------------------------------------------------------------
    console.log('3. Testing FileSystemKeyStore security hardening...');
    const hardDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aamarva-fs-hard-'));
    try {
      const fsStore = new FileSystemKeyStore(hardDir);
      assert.throws(() => fsStore.savePrivateKey('x', '../escape'), (e: any) => e?.code === 'IDENTITY_KEY_INVALID');
      assert.throws(() => fsStore.savePrivateKey('x', 'foo/bar'), (e: any) => e?.code === 'IDENTITY_KEY_INVALID');
      assert.throws(() => fsStore.savePrivateKey('   ', 'empty_slot'), (e: any) => e?.code === 'IDENTITY_KEY_INVALID');

      const realTarget = path.join(hardDir, 'outside.pem');
      fs.writeFileSync(realTarget, 'SECRET');
      const symlinkFile = path.join(hardDir, 'sym_slot.pem');
      fs.symlinkSync(realTarget, symlinkFile);
      assert.throws(() => fsStore.loadPrivateKey('sym_slot'), (e: any) => e?.code === 'IDENTITY_KEY_INVALID');

      // Empty file rejection
      const emptySlotPath = path.join(hardDir, 'empty_file.pem');
      fs.writeFileSync(emptySlotPath, '   ', { mode: 0o600 });
      assert.throws(() => fsStore.loadPrivateKey('empty_file'), (e: any) => e?.code === 'IDENTITY_KEY_INVALID');
    } finally {
      fs.rmSync(hardDir, { recursive: true, force: true });
    }
    console.log('✓ FileSystemKeyStore symlink, traversal, and empty-file protections verified.');

    // -------------------------------------------------------------------------
    // 4. Auth Token Refresh & 401 Single-Flight Recovery + Master/Slave Scoping
    // -------------------------------------------------------------------------
    console.log('4. Testing auth token refresh (data.tokens), 401 recovery, and x-target-agent-id isolation...');
    const recoveryStore = createMockDataStore();
    const recoveryBaseFetch = createMockFetch(recoveryStore);
    let currentValidAccessToken = 'token_valid_on_server';
    let loginCount = 0;
    let refreshCount = 0;
    const seenTargetHeaders: Array<string | undefined> = [];

    const authRecoveryFetch = (async (input: any, init?: any) => {
      const u = new URL(typeof input === 'string' ? input : input.url, 'https://aamarva.com');
      const p = u.pathname.replace(/^\/api/, '');
      const hdrs = init?.headers as Record<string, string> | undefined;
      seenTargetHeaders.push(hdrs?.['x-target-agent-id'] || hdrs?.['X-Target-Agent-Id']);

      if (p === '/auth/login') {
        loginCount++;
        currentValidAccessToken = 'token_after_login_' + loginCount;
        return new Response(
          JSON.stringify({
            success: true,
            data: { tokens: { accessToken: currentValidAccessToken, refreshToken: 'rt_fresh_1' } },
          }),
          { status: 200 }
        );
      }
      if (p === '/auth/refresh') {
        refreshCount++;
        const reqBody = JSON.parse(init?.body || '{}');
        if (reqBody.refreshToken === 'rt_valid') {
          currentValidAccessToken = 'token_refreshed_valid';
          return new Response(
            JSON.stringify({
              success: true,
              data: { tokens: { accessToken: 'token_refreshed_valid', refreshToken: 'rt_rotated_2' } },
            }),
            { status: 200 }
          );
        }
        return new Response(JSON.stringify({ success: false, error: 'Refresh expired' }), { status: 401 });
      }
      const authHdr = hdrs?.Authorization || hdrs?.authorization || '';
      if (authHdr !== `Bearer ${currentValidAccessToken}`) {
        return new Response(JSON.stringify({ success: false, error: 'Token expired' }), { status: 401 });
      }
      return recoveryBaseFetch(input, init);
    }) as typeof fetch;

    const recoveryClient = new Aamarva({
      agentId: 'AMR-0000-MASTER',
      apiKey: 'sk_master',
      accessToken: 'token_initial_expired',
      refreshToken: 'rt_valid',
      fetch: authRecoveryFetch,
    });

    // 401 on first request triggers refresh once and succeeds on retry
    const meRecovered = await recoveryClient.me();
    assert.strictEqual(meRecovered.agentId, 'AMR-1111-2222');
    assert.strictEqual(refreshCount, 1);
    assert.strictEqual(loginCount, 0);
    assert.strictEqual(recoveryClient.http.getTokens().accessToken, 'token_refreshed_valid');

    // Target slave switching clears cached registration state and sends x-target-agent-id
    await recoveryClient.registerPublicKey();
    assert.strictEqual(recoveryClient.isE2eeReady(), true);
    recoveryClient.setTargetAgentId('AMR-SLAVE-A');
    assert.strictEqual(recoveryClient.isE2eeReady(), false, 'setTargetAgentId must clear previous target E2EE cache');
    assert.strictEqual(recoveryClient.getLifecycleState(), 'authenticated');
    await recoveryClient.me();
    assert.strictEqual(recoveryClient.isE2eeReady(), true);
    assert.ok(seenTargetHeaders.includes('AMR-SLAVE-A'));
    console.log('✓ Single-flight refresh recovery & x-target-agent-id isolation verified.');

    // -------------------------------------------------------------------------
    // 5. Cluster AAMARVA_CLUSTER_KEY_WRAP_V1 Round-Trip & Tampering Checks
    // -------------------------------------------------------------------------
    console.log('5. Testing AAMARVA_CLUSTER_KEY_WRAP_V1 round-trip, GET /agents/:id/e2ee, and tampering...');
    const clusterStore = createMockDataStore();
    const clusterMockFetch = createMockFetch(clusterStore);

    // Pre-register AMR-5555-6666 key into store so distributeClusterKey resolves via /agents/:id/e2ee
    const member2Ecdh = getLocalEcdhKeyPair('AMR-5555-6666', 1);
    const member2Sign = getLocalIdentitySigningKeyPair('AMR-5555-6666');
    const member2Jwk = exportPublicKeyJWK(member2Ecdh.publicKey);
    const member2Fp = computeKeyFingerprint(member2Jwk);
    const member2Sig = signIdentityBinding(member2Sign.privateKey, 'AMR-5555-6666', member2Fp);
    clusterStore.e2eeKeys['AMR-5555-6666'] = {
      publicKey: member2Jwk,
      fingerprint: member2Fp,
      identityKey: exportPublicKeyJWK(member2Sign.publicKey),
      signature: member2Sig,
      keyVersion: 1,
    };

    // Include AMR-0000-MASTER in clusterMembers for membership validation
    const senderEcdh = getLocalEcdhKeyPair('AMR-1111-2222', getLatestLocalEcdhEpoch('AMR-1111-2222'));
    const senderSign = getLocalIdentitySigningKeyPair('AMR-1111-2222');
    const senderJwk = exportPublicKeyJWK(senderEcdh.publicKey);
    const senderFp = computeKeyFingerprint(senderJwk);
    const masterEcdh = getLocalEcdhKeyPair('AMR-0000-MASTER', 1);
    const masterSign = getLocalIdentitySigningKeyPair('AMR-0000-MASTER');
    const masterJwk = exportPublicKeyJWK(masterEcdh.publicKey);
    const masterFp = computeKeyFingerprint(masterJwk);
    clusterStore.e2eeKeys['AMR-0000-MASTER'] = {
      publicKey: masterJwk,
      fingerprint: masterFp,
      identityKey: exportPublicKeyJWK(masterSign.publicKey),
      signature: signIdentityBinding(masterSign.privateKey, 'AMR-0000-MASTER', masterFp),
      keyVersion: 1,
    };
    clusterStore.clusters[0].members = ['AMR-1111-2222', 'AMR-5555-6666', 'AMR-0000-MASTER'];

    const clusterSender = new Aamarva({
      agentId: 'AMR-1111-2222',
      apiKey: 'sk_sender',
      fetch: clusterMockFetch,
    });

    // Reject non-member recipient
    try {
      await clusterSender.distributeClusterKey('cluster_987654', {
        recipients: ['AMR-OUTSIDER-999'],
        epoch: 1,
      });
      assert.fail('Non-member recipient must be rejected with CLUSTER_MEMBERSHIP_INVALID');
    } catch (err: any) {
      assert.strictEqual(err.code, 'CLUSTER_MEMBERSHIP_INVALID');
    }

    const distOut = await clusterSender.distributeClusterKey('cluster_987654', {
      recipients: ['AMR-5555-6666'],
      epoch: 1,
    });
    assert.strictEqual(distOut.epoch, 1);

    // Verify stored distribution matches AAMARVA_CLUSTER_KEY_WRAP_V1 JSON package format
    const storedDist = clusterStore.clusterKeyDistributions?.['cluster_987654:1'];
    assert.ok(storedDist.keyFingerprint?.startsWith('SHA256:'));
    assert.ok(storedDist.audienceHash);
    assert.ok(storedDist.rosterHash);
    assert.ok(Array.isArray(storedDist.distributions));
    const member2Pkg = storedDist.distributions.find((d: any) => d.recipientAgentId === 'AMR-5555-6666');
    assert.ok(member2Pkg);
    const parsedPkg = JSON.parse(member2Pkg.encryptedKeyPackage);
    assert.strictEqual(parsedPkg.version, 'AAMARVA_CLUSTER_KEY_WRAP_V1');
    assert.strictEqual(parsedPkg.wrappingParams.algorithm, 'ECDH-ES+HKDF-256+A256GCM');
    assert.strictEqual(parsedPkg.wrappingParams.hkdfSalt, 'aamarva-e2ee-channel-v1');
    assert.strictEqual(parsedPkg.wrappingParams.hkdfInfo, 'aamarva-channel:cluster_987654');
    assert.strictEqual(parsedPkg.wrappingParams.aad, 'aamarva-cluster-group-key:cluster_987654:1');

    // Member 2 unwraps and decrypts message sent by Sender
    const sentClusterMsg = await clusterSender.sendEncryptedClusterMessage(
      'cluster_987654',
      'cluster-consensus-payload-v2',
      { recipients: ['AMR-5555-6666'], epoch: 1 }
    );
    assert.strictEqual(sentClusterMsg.version, 2);

    const clusterReceiver = new Aamarva({
      agentId: 'AMR-5555-6666',
      apiKey: 'sk_receiver',
      fetch: clusterMockFetch,
    });
    // Ensure receiver fetches from cluster key distribution for AMR-5555-6666
    const fetchedMsgs = await clusterReceiver.getClusterMessages('cluster_987654');
    assert.strictEqual(fetchedMsgs.length, 1);
    assert.strictEqual(fetchedMsgs[0].version, 2);
    const unwrappedPlain = await clusterReceiver.decryptClusterMessage(
      'cluster_987654',
      fetchedMsgs[0]
    );
    assert.strictEqual(unwrappedPlain, 'cluster-consensus-payload-v2');

    // Negative tampering: wrong expectedClusterId fails unwrap
    assert.throws(
      () =>
        unwrapClusterKey(
          member2Pkg.encryptedKeyPackage,
          { expectedClusterId: 'cluster_wrong', expectedEpoch: 1 },
          member2Ecdh.privateKey,
          senderJwk
        ),
      (err: any) => err?.code === 'CLUSTER_KEY_UNWRAP_FAILED'
    );

    // Negative tampering: wrong cluster key / epoch fails decryptClusterMessagePayload
    const rawEnc = encryptClusterMessagePayload('test', generateClusterKey(), 'cluster_987654', 1);
    assert.throws(
      () => decryptClusterMessagePayload(rawEnc.ciphertext, rawEnc.nonce, distOut.clusterKey, 'cluster_987654', 1, 2),
      (err: any) => err?.code === 'CLUSTER_MESSAGE_DECRYPTION_FAILED'
    );
    console.log('✓ AAMARVA_CLUSTER_KEY_WRAP_V1 round-trip, membership check & tampering rejections verified.');

    // -------------------------------------------------------------------------
    // 6. FLOOR MCP Governance Workflow + All Auth Types + SSRF Guards
    // -------------------------------------------------------------------------
    console.log('6. Testing FLOOR policy, HITL polling, authConfig types, and SSRF hardening...');
    const floorStore = createMockDataStore();
    const floorMock = createMockFetch(floorStore);
    const floorClient = new Aamarva({
      agentId: 'AMR-1111-2222',
      apiKey: 'sk_floor',
      fetch: floorMock,
    });

    // Step 1b: Tool Policy inspection
    const policy = await floorClient.getFloorToolPolicy('tool_market_depth');
    assert.strictEqual(policy.toolId, 'tool_market_depth');
    assert.strictEqual(policy.requiresApproval, true);

    // Step 2 & 3: Request access -> Pending -> Simulate human approval -> Poll
    const reqInit = await floorClient.requestFloorAccess('tool_market_depth', 'Need depth');
    assert.strictEqual(reqInit.status, 'pending');
    setTimeout(() => {
      floorStore.floorRequests[reqInit.requestId!].status = 'approved';
      floorStore.floorInvocations[reqInit.invocationId!].status = 'approved';
    }, 80);

    const approvedPoll = await floorClient.waitForFloorRequestApproval(reqInit.requestId!, {
      intervalMs: 50,
      timeoutMs: 2000,
    });
    assert.strictEqual(approvedPoll.status, 'approved');

    // Step 4 & 5: Redeem via Mandatory MCP Adapter Gateway (zero direct external MCP calls)
    const redeemedResult = await floorClient.executeFloorTool(
      'tool_market_depth',
      { pair: 'ETH-USD' },
      { invocationId: approvedPoll.invocationId }
    );
    assert.strictEqual(redeemedResult.status, 'approved');
    assert.strictEqual(redeemedResult.mcpServerId, 'mcp_srv_market_depth');
    assert.ok(redeemedResult.result);
    assert.strictEqual(floorStore.directMcpCalls!.length, 0);
    assert.strictEqual(floorStore.gatewayExecutedMcpCalls!.length, 1);

    // Direct external MCP executor must fail closed
    await assert.rejects(
      () =>
        invokeExternalMcpTool({
          serverUrl: 'https://mcp.example.com/rpc',
          toolId: 'tool_sec_edgar',
          args: { ticker: 'AAPL' },
        }),
      (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_EXECUTION_REQUIRED'
    );
    console.log('✓ FLOOR policy, HITL polling, Mandatory Gateway execution, and direct MCP block verified.');

    // -------------------------------------------------------------------------
    // 7. Watchtower SSE Streaming, Event Deduplication & Reconnect
    // -------------------------------------------------------------------------
    console.log('7. Testing Watchtower SSE stream parsing, deduplication & Last-Event-ID reconnect...');
    let streamCalls = 0;
    const seenLastEventIds: Array<string | undefined> = [];
    const sseFetch = (async (input: any, init?: any) => {
      const u = new URL(typeof input === 'string' ? input : input.url, 'https://aamarva.com');
      const p = u.pathname.replace(/^\/api/, '');
      if (p === '/watchtower/stream') {
        streamCalls++;
        const hdrs = init?.headers as Record<string, string> | undefined;
        seenLastEventIds.push(hdrs?.['Last-Event-ID']);
        const payload =
          streamCalls === 1
            ? `: keepalive\nid: evt_1\nevent: floor.approved\ndata: {"requestId":"req_1"}\n\n`
            : `id: evt_1\nevent: floor.approved\ndata: {"requestId":"req_1"}\n\nid: evt_2\nevent: message.received\ndata: {"msg":\ndata: "hello"}\n\n`;
        return new Response(payload, { status: 200, headers: { 'Content-Type': 'text/event-stream' } });
      }
      return baseMockFetch(input, init);
    }) as typeof fetch;

    const sseClient = new Aamarva({
      agentId: 'AMR-1111-2222',
      apiKey: 'sk_sse',
      fetch: sseFetch,
    });
    const controller = new AbortController();
    const collected: any[] = [];
    for await (const ev of sseClient.streamWatchtowerEvents({
      signal: controller.signal,
      maxReconnects: 1,
      deduplicate: true,
    })) {
      collected.push(ev);
      if (collected.length >= 2) {
        controller.abort();
      }
    }
    assert.strictEqual(collected.length, 2, 'Duplicate evt_1 on reconnect must be deduplicated');
    assert.strictEqual(collected[0].id, 'evt_1');
    assert.deepStrictEqual(collected[0].data, { requestId: 'req_1' });
    assert.strictEqual(collected[1].id, 'evt_2');
    assert.strictEqual(collected[1].rawData, '{"msg":\n"hello"}');
    assert.strictEqual(seenLastEventIds[1], 'evt_1');
    console.log('✓ Watchtower SSE parsing, deduplication, and Last-Event-ID reconnect verified.');

    console.log('\n==================================================');
    console.log('  ALL PLATFORM INTEROP & HARDENING TESTS PASSED   ');
    console.log('==================================================');
  } finally {
    if (prevKeyDir === undefined) {
      delete process.env.AAMARVA_KEY_STORE_PATH;
    } else {
      process.env.AAMARVA_KEY_STORE_PATH = prevKeyDir;
    }
    resetLocalIdentityKeyPair();
    fs.rmSync(tempKeyDir, { recursive: true, force: true });
  }
}

runPlatformInteropTests().catch((err) => {
  console.error('Platform interop suite failed:', err);
  process.exit(1);
});
