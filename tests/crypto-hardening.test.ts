import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  WORKFLOW_HKDF_SALT,
  generateECKeyPair,
  exportPublicKeyJWK,
  normalizeAgentId,
  canonicalMemberSet,
  computeKeyFingerprint,
  computeGroupKeyFingerprint,
  computeRosterHash,
  computeAudienceHash,
  verifyPeerKey,
  createDirectMessageAadV1,
  encryptMessageWithKeys,
  decryptMessageWithKeys,
  generateClusterKey,
  createClusterWrapAadV2,
  createClusterMessageAadV2,
  createClusterSigningPayloadV2,
  signClusterMessageV2,
  verifyClusterMessageSignatureV2,
  wrapClusterKeyForRecipient,
  unwrapClusterKey,
  encryptClusterMessagePayload,
  decryptClusterMessagePayload,
  InMemoryKeyStore,
  FileSystemKeyStore,
  setKeyStore,
  resetLocalIdentityKeyPair,
  getLocalIdentityKeyPair,
  getLocalPublicKeyPem,
  signIdentityBinding,
  createIdentityBindingString,
  verifyIdentityBinding,
} from '../src/crypto.js';
import { normalizeMessage } from '../src/normalize.js';
import { Aamarva } from '../src/client.js';
import { AamarvaConnection } from '../src/connection.js';

async function runCryptoHardeningTests() {
  console.log('--- Starting Crypto & Security Hardening Tests ---');


  // Test 0: Deterministic canonical JWK fingerprint vector
  // This verifies the exact JSON.stringify behavior and SHA256 hashing.
  const deterministicJwk = {
    crv: "P-256",
    kty: "EC",
    x: "jLYmaATt9D2gC2__7gx69gTccElDh3sT3WoKxzeeQN4",
    y: "L4iSoXO7btNvGCd0dPDKOXIWO6JgiVTUWTz7YCppkdI"
  };
  const expectedFingerprint = "SHA256:D6:7D:AF:63:1E:5F:B3:6A:1A:56:FA:A2:54:1D:CA:83:4A:8E:BA:A9:7B:14:3C:2D:45:FD:CF:99:38:E6:E6:7A";
  const actualFingerprint = computeKeyFingerprint(deterministicJwk);
  assert.strictEqual(actualFingerprint, expectedFingerprint, "Deterministic canonical JWK fingerprint did not match expected hardcoded vector.");
  
  // Verify fingerprint formatting
  assert.ok(actualFingerprint.startsWith('SHA256:'), "Fingerprint must start with SHA256:");
  assert.ok(/^SHA256:[0-9A-F:]+$/.test(actualFingerprint), "Fingerprint must use uppercase hex and colons");
  assert.strictEqual(actualFingerprint.split(':').length, 33, "Fingerprint must have exactly 32 hex bytes separated by colons plus the SHA256 prefix");
  console.log('✓ Deterministic fingerprint vector test passed.');

  // Test 0b: Agent ID canonicalization in identity binding
  const bindingUpper = createIdentityBindingString('AMR-ALPHA-99', expectedFingerprint);
  const bindingLower = createIdentityBindingString('  amr-alpha-99  ', expectedFingerprint);
  const bindingMixed = createIdentityBindingString('AmR-AlPhA-99', expectedFingerprint);
  assert.strictEqual(bindingUpper, `AAMARVA-KEY-BINDING:v1:AMR-ALPHA-99:${expectedFingerprint}`);
  assert.strictEqual(bindingLower, bindingUpper, "Lowercase/padded agentId must produce identical uppercase canonical binding string");
  assert.strictEqual(bindingMixed, bindingUpper, "Mixed-case agentId must produce identical uppercase canonical binding string");
  console.log('✓ Agent ID canonicalization test passed.');

  // Test 1: Normal encryption / decryption round-trip
  const aliceKeyPair = generateECKeyPair();
  const bobKeyPair = generateECKeyPair();
  const alicePubPem = aliceKeyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const bobPubPem = bobKeyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const bobFingerprint = computeKeyFingerprint(bobPubPem);
  const aliceFingerprint = computeKeyFingerprint(alicePubPem);

  const connId = 'conn-secure-test-01';
  const plaintext = 'Secret payload: telemetry authorization token 99283';

  const aliceIdentityJwk = aliceKeyPair.publicKey.export({ format: 'jwk' });
  const bobIdentityJwk = bobKeyPair.publicKey.export({ format: 'jwk' });
  const bobIdentitySignature = signIdentityBinding(bobKeyPair.privateKey, 'AMR-BOB', bobFingerprint);
  const aliceIdentitySignature = signIdentityBinding(aliceKeyPair.privateKey, 'AMR-ALICE', aliceFingerprint);
  const envelope = encryptMessageWithKeys(
    plaintext,
    connId,
    aliceKeyPair.privateKey,
    bobPubPem,
    bobFingerprint,
    'AMR-BOB',
    bobIdentitySignature,
    bobIdentityJwk,
    1
  );

  assert.strictEqual(envelope.version, 1);
  assert.strictEqual(envelope.keyEpoch, 1);
  assert.ok(envelope.ciphertext && typeof envelope.ciphertext === 'string');
  assert.ok(envelope.nonce && typeof envelope.nonce === 'string');

  const decrypted = decryptMessageWithKeys(
    envelope,
    connId,
    bobKeyPair.privateKey,
    alicePubPem,
    aliceFingerprint,
    'AMR-ALICE',
    aliceIdentitySignature,
    aliceIdentityJwk
  );
  assert.strictEqual(decrypted, plaintext);
  console.log('✓ Normal encryption/decryption round-trip passed.');

  // Test 2: Tampered ciphertext fails
  const tamperedCiphertextBytes = Buffer.from(envelope.ciphertext, 'base64');
  tamperedCiphertextBytes[0] ^= 0xff;
  const tamperedCiphertextEnv = {
    ...envelope,
    ciphertext: tamperedCiphertextBytes.toString('base64'),
  };
  assert.throws(
    () => decryptMessageWithKeys(tamperedCiphertextEnv, connId, bobKeyPair.privateKey, alicePubPem, aliceFingerprint, 'AMR-ALICE', aliceIdentitySignature, aliceIdentityJwk),
    (err: any) => err?.code === 'MESSAGE_DECRYPTION_FAILED',
    'Tampered ciphertext must fail decryption with MESSAGE_DECRYPTION_FAILED'
  );
  console.log('✓ Tampered ciphertext correctly rejected.');

  // Test 3: Tampered nonce fails
  const tamperedNonceBytes = Buffer.from(envelope.nonce, 'base64');
  tamperedNonceBytes[0] ^= 0xff;
  const tamperedNonceEnv = {
    ...envelope,
    nonce: tamperedNonceBytes.toString('base64'),
  };
  assert.throws(
    () => decryptMessageWithKeys(tamperedNonceEnv, connId, bobKeyPair.privateKey, alicePubPem, aliceFingerprint, 'AMR-ALICE', aliceIdentitySignature, aliceIdentityJwk),
    (err: any) => err?.code === 'MESSAGE_DECRYPTION_FAILED',
    'Tampered nonce must fail decryption with MESSAGE_DECRYPTION_FAILED'
  );
  console.log('✓ Tampered nonce correctly rejected.');

  // Test 4: Wrong private key fails
  const eveKeyPair = generateECKeyPair();
  assert.throws(
    () => decryptMessageWithKeys(envelope, connId, eveKeyPair.privateKey, alicePubPem, aliceFingerprint, 'AMR-ALICE', aliceIdentitySignature, aliceIdentityJwk),
    (err: any) => err?.code === 'MESSAGE_DECRYPTION_FAILED',
    'Wrong private key must fail decryption with MESSAGE_DECRYPTION_FAILED'
  );
  console.log('✓ Wrong private key rejected.');

  // Test 5: Wrong peer public key fails
  const charlieKeyPair = generateECKeyPair();
  const charliePubPem = charlieKeyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const charlieFingerprint = computeKeyFingerprint(charliePubPem);
  const charlieIdentityJwk = charlieKeyPair.publicKey.export({ format: 'jwk' });
  const charlieIdentitySignature = signIdentityBinding(charlieKeyPair.privateKey, 'AMR-CHARLIE', charlieFingerprint);
  assert.throws(
    () => decryptMessageWithKeys(envelope, connId, bobKeyPair.privateKey, charliePubPem, charlieFingerprint, 'AMR-CHARLIE', charlieIdentitySignature, charlieIdentityJwk),
    (err: any) => err?.code === 'MESSAGE_DECRYPTION_FAILED',
    'Wrong peer public key must fail decryption'
  );
  console.log('✓ Wrong peer key rejected.');

  // Test 6: Wrong connection ID (AAD) fails
  assert.throws(
    () => decryptMessageWithKeys(envelope, 'wrong-conn-id', bobKeyPair.privateKey, alicePubPem, aliceFingerprint, 'AMR-ALICE', aliceIdentitySignature, aliceIdentityJwk),
    (err: any) => err?.code === 'MESSAGE_DECRYPTION_FAILED',
    'Wrong connection ID/AAD must fail authentication tag check'
  );
  console.log('✓ Wrong connection ID / AAD rejected.');

  // Test 7: Malformed envelope fails
  assert.throws(
    () => decryptMessageWithKeys({ ciphertext: '', nonce: '' } as any, connId, bobKeyPair.privateKey, alicePubPem, aliceFingerprint, 'AMR-ALICE', aliceIdentitySignature, aliceIdentityJwk),
    (err: any) => err?.code === 'MESSAGE_INVALID_ENVELOPE',
    'Missing ciphertext or nonce must fail with MESSAGE_INVALID_ENVELOPE'
  );
  // Short ciphertext lacking tag (less than 16 bytes)
  const shortEnv = { ciphertext: Buffer.from('tooshort').toString('base64'), nonce: envelope.nonce };
  assert.throws(
    () => decryptMessageWithKeys(shortEnv as any, connId, bobKeyPair.privateKey, alicePubPem, aliceFingerprint, 'AMR-ALICE', aliceIdentitySignature, aliceIdentityJwk),
    (err: any) => err?.code === 'MESSAGE_INVALID_ENVELOPE',
    'Ciphertext shorter than auth tag must fail with MESSAGE_INVALID_ENVELOPE'
  );
  console.log('✓ Malformed envelope rejected.');

  // Test 8: Invalid peer fingerprint fails
  assert.throws(
    () => verifyPeerKey(bobPubPem, '0000000000000000000000000000000000000000000000000000000000000000', 'AMR-BOB', bobIdentitySignature, bobIdentityJwk),
    (err: any) => err?.code === 'PEER_KEY_VERIFICATION_FAILED',
    'Mismatched fingerprint must fail with PEER_KEY_VERIFICATION_FAILED'
  );
  // Missing or empty peer key fails
  assert.throws(
    () => verifyPeerKey('', '', '', '', ''),
    (err: any) => err?.code === 'PEER_KEY_UNAVAILABLE',
    'Empty peer key must fail with PEER_KEY_UNAVAILABLE'
  );
  console.log('✓ Peer key validation and fingerprint matching verified.');

  // Test 9: Reject non-P256 curve key
  const ed25519Key = crypto.generateKeyPairSync('ed25519');
  const ed25519PubPem = ed25519Key.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  assert.throws(
    () => verifyPeerKey(ed25519PubPem, bobFingerprint, 'AMR-BOB', bobIdentitySignature, bobIdentityJwk),
    (err: any) => err?.code === 'PEER_KEY_VERIFICATION_FAILED',
    'Non-P-256 key must be rejected'
  );
  console.log('✓ Non-P-256 curve rejected.');

  // Test 10: KeyStore abstraction (InMemory and FileSystem)
  const memStore = new InMemoryKeyStore();
  assert.strictEqual(memStore.loadPrivateKey('id1'), null);
  memStore.savePrivateKey('TEST_PEM_CONTENT', 'id1');
  assert.strictEqual(memStore.loadPrivateKey('id1'), 'TEST_PEM_CONTENT');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aamarva-keystore-'));
  const fsStore = new FileSystemKeyStore(tmpDir);
  assert.strictEqual(fsStore.loadPrivateKey('id2'), null);
  fsStore.savePrivateKey('FS_PEM_CONTENT', 'id2');
  assert.strictEqual(fsStore.loadPrivateKey('id2'), 'FS_PEM_CONTENT');
  // Check file exists with restricted permissions
  const keyFile = path.join(tmpDir, 'id2.pem');
  assert.ok(fs.existsSync(keyFile));
  const stats = fs.statSync(keyFile);
  // mode & 0o777 should be 0o600 on POSIX
  if (process.platform !== 'win32') {
    assert.strictEqual(stats.mode & 0o777, 0o600);
  }
  fs.rmSync(tmpDir, { recursive: true, force: true });
  console.log('✓ KeyStore abstraction (InMemory & FileSystem) verified.');

  // Test 10b: Persistent KeyStore across process restart verification
  const persistentDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aamarva-persistent-'));
  setKeyStore(new FileSystemKeyStore(persistentDir));

  // 1. Generate/load persistent key for Alice
  const aliceKeyPair1 = getLocalIdentityKeyPair('AMR-ALICE-PERSISTENT');
  const alicePubJwk1 = exportPublicKeyJWK(aliceKeyPair1.publicKey);
  const aliceFp1 = computeKeyFingerprint(alicePubJwk1);
  const alicePubPem1 = getLocalPublicKeyPem('AMR-ALICE-PERSISTENT');
  const aliceSig1 = signIdentityBinding(aliceKeyPair1.privateKey, 'AMR-ALICE-PERSISTENT', aliceFp1);

  // Bob generates key
  const bobKeyPairPersistent = generateECKeyPair();
  const bobPubPemPersistent = bobKeyPairPersistent.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const bobFpPersistent = computeKeyFingerprint(exportPublicKeyJWK(bobKeyPairPersistent.publicKey));
  const bobSigPersistent = signIdentityBinding(bobKeyPairPersistent.privateKey, 'AMR-BOB', bobFpPersistent);

  // Alice encrypts message to Bob before process restart
  const secretPayload = "Secret message surviving agent process restart";
  const envelopePersistent = encryptMessageWithKeys(
    secretPayload,
    'conn-persist-1',
    aliceKeyPair1.privateKey,
    bobPubPemPersistent,
    bobFpPersistent,
    'AMR-BOB',
    bobSigPersistent,
    exportPublicKeyJWK(bobKeyPairPersistent.publicKey)
  );

  // 2. Simulate Process Restart: Clear in-memory key cache & reset active KeyStore
  resetLocalIdentityKeyPair();
  setKeyStore(new FileSystemKeyStore(persistentDir));

  // 3. Load Alice's key from disk after restart
  const aliceKeyPair2 = getLocalIdentityKeyPair('AMR-ALICE-PERSISTENT');
  const alicePubJwk2 = exportPublicKeyJWK(aliceKeyPair2.publicKey);
  const aliceFp2 = computeKeyFingerprint(alicePubJwk2);
  const alicePubPem2 = getLocalPublicKeyPem('AMR-ALICE-PERSISTENT');

  // Assert keys match across process restarts
  assert.strictEqual(aliceFp1, aliceFp2, 'Public key fingerprint must match across process restarts');
  assert.strictEqual(alicePubPem1, alicePubPem2, 'Public key PEM must match across process restarts');

  // Verify Bob decrypts message encrypted before restart using Alice's key loaded after restart
  const decryptedPostRestart = decryptMessageWithKeys(
    envelopePersistent,
    'conn-persist-1',
    bobKeyPairPersistent.privateKey,
    alicePubPem2,
    aliceFp2,
    'AMR-ALICE-PERSISTENT',
    aliceSig1,
    alicePubJwk2
  );
  assert.strictEqual(decryptedPostRestart, secretPayload, 'Message must be decryptable after process restart');

  fs.rmSync(persistentDir, { recursive: true, force: true });
  resetLocalIdentityKeyPair();
  console.log('✓ Persistent FileSystemKeyStore key survival across process restart verified.');

  // Test 11: Strict message normalization
  assert.throws(
    () => normalizeMessage('Raw plaintext string message', 'conn-1'),
    (err: any) => err?.code === 'PLAINTEXT_MESSAGE_RECEIVED',
    'Raw plaintext string must throw PLAINTEXT_MESSAGE_RECEIVED'
  );
  assert.throws(
    () => normalizeMessage({ connectionId: 'conn-1', content: 'unencrypted content' }, 'conn-1'),
    (err: any) => err?.code === 'PLAINTEXT_MESSAGE_RECEIVED',
    'Plaintext content dict must throw PLAINTEXT_MESSAGE_RECEIVED'
  );
  assert.throws(
    () => normalizeMessage({ connectionId: 'conn-1', ciphertext: 'abc' }, 'conn-1'),
    (err: any) => err?.code === 'MESSAGE_INVALID_ENVELOPE',
    'Missing nonce/version/keyEpoch must throw MESSAGE_INVALID_ENVELOPE'
  );
  console.log('✓ Strict message normalization tests passed.');

  // Test 12: PLAINTEXT LEAK TEST
  // Assert that connection.send() and client.sendMessage() NEVER transmit the original plaintext
  let capturedBody: any = null;
  const bobIdentityKp = generateECKeyPair();
  const bobIdentitySignature2 = signIdentityBinding(bobIdentityKp.privateKey, 'AMR-BOB', bobFingerprint);
  const mockHttp = {
    agentId: 'AMR-ALICE',
    request: async (opts: any) => {
      if (opts.path === '/agents/me/e2ee') {
        return { success: true };
      }
      if (opts.path === '/connections/conn-leak-test/peer-key') {
        const bobPubJwk = bobKeyPair.publicKey.export({ format: 'jwk' });
        const bobIdentityJwk = bobIdentityKp.publicKey.export({ format: 'jwk' });
        return {
          success: true,
          data: {
            peerAgentId: 'AMR-BOB',
            peerE2eePublicKey: bobPubJwk,
            peerKeyFingerprint: bobFingerprint,
            peerIdentityKey: bobIdentityJwk,
            peerKeySignature: bobIdentitySignature2,
            peerKeyEpoch: 1,
          },
        };
      }
      if (opts.path === '/connections/conn-leak-test/messages' && opts.method === 'POST') {
        capturedBody = opts.body;
        return {
          success: true,
          data: {
            messageId: 'msg-leak-test-1',
            connectionId: 'conn-leak-test',
            senderAgentId: 'AMR-ALICE',
            ciphertext: opts.body.ciphertext,
            nonce: opts.body.nonce,
            version: opts.body.version,
            keyEpoch: opts.body.keyEpoch,
            createdAt: new Date().toISOString(),
          },
        };
      }
      return { success: true };
    },
  };

  const client = new Aamarva({ agentId: 'AMR-ALICE', apiKey: 'test-key' });
  (client as any).http = mockHttp;

  const sensitiveSecret = 'SUPER_CONFIDENTIAL_PLAINTEXT_987654321';
  const sentMsg = await client.sendMessage('conn-leak-test', { content: sensitiveSecret, peerAgentId: 'AMR-BOB' });
  assert.strictEqual(sentMsg.content, sensitiveSecret);

  // Crucial check: original plaintext must NOT appear anywhere in the POST JSON body!
  const serializedBody = JSON.stringify(capturedBody);
  assert.ok(
    !serializedBody.includes(sensitiveSecret),
    'CRITICAL SECURITY LEAK: Plaintext was found in the POST JSON request body!'
  );
  assert.ok(capturedBody.ciphertext && typeof capturedBody.ciphertext === 'string');
  assert.ok(capturedBody.nonce && typeof capturedBody.nonce === 'string');
  assert.strictEqual(capturedBody.version, 1);
  assert.strictEqual(capturedBody.keyEpoch, 1);
  assert.strictEqual(capturedBody.content, undefined);
  assert.strictEqual(capturedBody.message, undefined);

  // Test via AamarvaConnection.send()
  capturedBody = null;
  const conn = new AamarvaConnection(
    {
      connectionId: 'conn-leak-test',
      agentId: 'AMR-BOB',
      status: 'active',
      createdAt: new Date().toISOString(),
    },
    mockHttp as any
  );
  const connSecret = 'ANOTHER_HIGHLY_SENSITIVE_PAYLOAD_ABCXYZ';
  await conn.send(connSecret);
  const connSerialized = JSON.stringify(capturedBody);
  assert.ok(
    !connSerialized.includes(connSecret),
    'CRITICAL SECURITY LEAK: Plaintext was found in connection.send() POST JSON body!'
  );
  assert.strictEqual(capturedBody.content, undefined);
  console.log('✓ Plaintext leak tests passed: original plaintext NEVER present in request payloads.');

  // Test 13: Workflow 1 HKDF-SHA256 & Canonical AAD Exact Wire Verification
  assert.strictEqual(WORKFLOW_HKDF_SALT, 'aamarva-e2ee-channel-v1');
  const wf1ConnId = 'conn_wf1_exact_001';
  const wf1Plain = 'Exact Workflow 1 wire format payload';
  const wf1Env = encryptMessageWithKeys(
    wf1Plain,
    wf1ConnId,
    aliceKeyPair.privateKey,
    bobPubPem,
    bobFingerprint,
    'AMR-BOB',
    bobIdentitySignature,
    bobIdentityJwk,
    1,
    'amr-alice'
  );
  // Manually decrypt using raw Node crypto HKDF + canonical AAD to prove spec compliance
  const rawSecret = crypto.diffieHellman({
    privateKey: bobKeyPair.privateKey,
    publicKey: crypto.createPublicKey(alicePubPem),
  });
  const rawAesKey = crypto.hkdfSync(
    'sha256',
    rawSecret,
    Buffer.from('aamarva-e2ee-channel-v1', 'utf8'),
    Buffer.from(`aamarva-channel:${wf1ConnId}`, 'utf8'),
    32
  );
  const rawIv = Buffer.from(wf1Env.nonce, 'base64');
  const rawCombined = Buffer.from(wf1Env.ciphertext, 'base64');
  const rawDecipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(rawAesKey), rawIv);
  rawDecipher.setAAD(Buffer.from(createDirectMessageAadV1(wf1ConnId, 'AMR-ALICE'), 'utf8'));
  rawDecipher.setAuthTag(rawCombined.subarray(rawCombined.length - 16));
  const manualPlain = Buffer.concat([
    rawDecipher.update(rawCombined.subarray(0, rawCombined.length - 16)),
    rawDecipher.final(),
  ]).toString('utf8');
  assert.strictEqual(manualPlain, wf1Plain);

  // Mismatched senderAgentId in Workflow 1 AAD MUST fail
  assert.throws(
    () =>
      decryptMessageWithKeys(
        wf1Env,
        wf1ConnId,
        bobKeyPair.privateKey,
        alicePubPem,
        aliceFingerprint,
        'AMR-ALICE',
        aliceIdentitySignature,
        aliceIdentityJwk,
        'AMR-EVE'
      ),
    (err: any) => err?.code === 'MESSAGE_DECRYPTION_FAILED'
  );
  console.log('✓ Workflow 1 HKDF-SHA256 + canonical AAD exact wire verification passed.');

  // Test 14: Workflow 2 Audience Hash, Roster Hash, Group Key Wrap/Unwrap & IEEE P1363 Signing
  assert.strictEqual(normalizeAgentId('  amr-alpha-01 '), 'AMR-ALPHA-01');
  assert.deepStrictEqual(
    canonicalMemberSet(['amr-b', 'AMR-A', 'amr-b', ' AMR-C ']),
    ['AMR-A', 'AMR-B', 'AMR-C']
  );

  const roster1 = computeRosterHash(['AMR-B', 'AMR-A', 'AMR-C']);
  const roster2 = computeRosterHash(['amr-c', 'amr-a', 'amr-b', 'AMR-A']);
  assert.ok(/^RST:[0-9A-F]{32}$/.test(roster1), 'Roster hash must match RST:<32-HEX>');
  assert.strictEqual(roster1, roster2, 'Roster hash must be order-independent and canonical');

  // Audience ALL vs targeted AUD:<32-HEX>
  const activeRoster = ['AMR-MASTER', 'AMR-ALICE', 'AMR-BOB'];
  assert.strictEqual(computeAudienceHash([], activeRoster), 'ALL');
  assert.strictEqual(computeAudienceHash(['AMR-BOB', 'AMR-MASTER', 'AMR-ALICE'], activeRoster), 'ALL');
  const audSub1 = computeAudienceHash(['AMR-BOB', 'AMR-ALICE'], activeRoster);
  const audSub2 = computeAudienceHash(['amr-alice', 'amr-bob'], activeRoster);
  assert.ok(/^AUD:[0-9A-F]{32}$/.test(audSub1), 'Subgroup audience hash must match AUD:<32-HEX>');
  assert.strictEqual(audSub1, audSub2, 'Audience hash must be order-independent and canonical');

  assert.strictEqual(
    createClusterWrapAadV2('clu_1', 2, 'ALL'),
    'aamarva-cluster-group-key:clu_1:2'
  );
  assert.strictEqual(
    createClusterWrapAadV2('clu_1', 2, audSub1),
    `aamarva-cluster-group-key:clu_1:2:${audSub1}`
  );
  assert.strictEqual(
    createClusterMessageAadV2('clu_1', 'amr-alice', 2, 'ALL'),
    'AAMARVA:E2EE:v2:clu_1:AMR-ALICE:2'
  );
  assert.strictEqual(
    createClusterMessageAadV2('clu_1', 'amr-alice', 2, audSub1),
    `AAMARVA:E2EE:v2:clu_1:AMR-ALICE:2:${audSub1}`
  );

  // Wrap & Unwrap subgroup key + cross-audience rejection + fingerprint mismatch check
  const clusterSymKey = generateClusterKey();
  const groupFp = computeGroupKeyFingerprint(clusterSymKey);
  assert.ok(/^SHA256:([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(groupFp));

  const wrappedSub = wrapClusterKeyForRecipient(clusterSymKey, bobPubPem, aliceKeyPair.privateKey, {
    clusterId: 'clu_1',
    epoch: 2,
    audienceHash: audSub1,
    rosterHash: roster1,
    keyFingerprint: groupFp,
    senderAgentId: 'AMR-ALICE',
    recipientAgentId: 'AMR-BOB',
  });
  const unwrappedSub = unwrapClusterKey(
    wrappedSub.encryptedKeyPackage,
    wrappedSub.nonce,
    bobKeyPair.privateKey,
    alicePubPem,
    {
      clusterId: 'clu_1',
      epoch: 2,
      audienceHash: audSub1,
      expectedKeyFingerprint: groupFp,
    }
  );
  assert.deepStrictEqual(unwrappedSub, clusterSymKey);

  // Wrong expectedKeyFingerprint fails
  assert.throws(
    () =>
      unwrapClusterKey(wrappedSub.encryptedKeyPackage, wrappedSub.nonce, bobKeyPair.privateKey, alicePubPem, {
        clusterId: 'clu_1',
        epoch: 2,
        audienceHash: audSub1,
        expectedKeyFingerprint: 'SHA256:' + Array(32).fill('00').join(':'),
      }),
    (err: any) => err?.code === 'CLUSTER_KEY_FINGERPRINT_MISMATCH'
  );

  // Tampering wrapped AAD metadata rejects unwrap
  const tamperedPkg = { ...wrappedSub.encryptedKeyPackage, aad: 'aamarva-cluster-group-key:clu_1:2' };
  assert.throws(
    () =>
      unwrapClusterKey(tamperedPkg, wrappedSub.nonce, bobKeyPair.privateKey, alicePubPem, {
        clusterId: 'clu_1',
        epoch: 2,
        audienceHash: 'ALL',
      }),
    (err: any) => err?.code === 'CLUSTER_KEY_UNWRAP_FAILED'
  );

  // Message encrypt/decrypt + IEEE P1363 64-byte WebCrypto-compatible ECDSA verification
  const clEnc = encryptClusterMessagePayload('Subgroup directive 42', clusterSymKey, 'clu_1', 2, audSub1, 'AMR-ALICE');
  assert.strictEqual(
    decryptClusterMessagePayload(clEnc.ciphertext, clEnc.nonce, clusterSymKey, 'clu_1', 2, 2, audSub1, 'AMR-ALICE'),
    'Subgroup directive 42'
  );
  assert.throws(
    () => decryptClusterMessagePayload(clEnc.ciphertext, clEnc.nonce, clusterSymKey, 'clu_1', 2, 2, 'ALL', 'AMR-ALICE'),
    (err: any) => err?.code === 'CLUSTER_MESSAGE_DECRYPTION_FAILED'
  );

  const signingParams = {
    clusterId: 'clu_1',
    keyEpoch: 2,
    senderAgentId: 'AMR-ALICE',
    audienceHash: audSub1,
    rosterHash: roster1,
    sequence: 7,
    keyFingerprint: groupFp,
    nonce: clEnc.nonce,
    ciphertext: clEnc.ciphertext,
  };
  const p1363Sig = signClusterMessageV2(aliceKeyPair.privateKey, signingParams);
  assert.strictEqual(Buffer.from(p1363Sig, 'base64').length, 64, 'ECDSA v2 signature must be raw 64-byte IEEE P1363');
  assert.strictEqual(verifyClusterMessageSignatureV2(alicePubPem, signingParams, p1363Sig), true);
  assert.strictEqual(
    verifyClusterMessageSignatureV2(alicePubPem, { ...signingParams, sequence: 8 }, p1363Sig),
    false,
    'Tampered sequence must invalidate ECDSA signature'
  );

  // Cross-verify raw 64-byte IEEE P1363 signature with WebCrypto subtle.verify
  const subtleKey = await globalThis.crypto.subtle.importKey(
    'jwk',
    aliceIdentityJwk as any,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );
  const subtleOk = await globalThis.crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    subtleKey,
    Buffer.from(p1363Sig, 'base64'),
    Buffer.from(createClusterSigningPayloadV2(signingParams), 'utf8')
  );
  assert.strictEqual(subtleOk, true, 'WebCrypto subtle.verify must accept 64-byte IEEE P1363 signature');

  // Epoch-archived identity key isolation + active key fallback
  const epochDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aamarva-epoch-'));
  const epochStore = new FileSystemKeyStore(epochDir);
  setKeyStore(epochStore);
  const kpEp1 = generateECKeyPair();
  const kpEp2 = generateECKeyPair();
  epochStore.savePrivateKey(kpEp1.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), 'AMR-EPOCH-TEST_epoch_1');
  epochStore.savePrivateKey(kpEp2.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), 'AMR-EPOCH-TEST_epoch_2');
  const ep1 = getLocalIdentityKeyPair('AMR-EPOCH-TEST', 1);
  const ep2 = getLocalIdentityKeyPair('AMR-EPOCH-TEST', 2);
  const epActive = getLocalIdentityKeyPair('AMR-EPOCH-TEST', 99); // unarchived epoch falls back to active key
  assert.strictEqual(
    computeKeyFingerprint(exportPublicKeyJWK(ep1.publicKey)),
    computeKeyFingerprint(exportPublicKeyJWK(kpEp1.publicKey))
  );
  assert.strictEqual(
    computeKeyFingerprint(exportPublicKeyJWK(ep2.publicKey)),
    computeKeyFingerprint(exportPublicKeyJWK(kpEp2.publicKey))
  );
  assert.notStrictEqual(
    computeKeyFingerprint(exportPublicKeyJWK(ep1.publicKey)),
    computeKeyFingerprint(exportPublicKeyJWK(ep2.publicKey))
  );
  assert.strictEqual(
    computeKeyFingerprint(exportPublicKeyJWK(epActive.publicKey)),
    computeKeyFingerprint(exportPublicKeyJWK(getLocalIdentityKeyPair('AMR-EPOCH-TEST').publicKey))
  );
  resetLocalIdentityKeyPair();
  fs.rmSync(epochDir, { recursive: true, force: true });
  console.log('✓ Workflow 2 hashes, subgroup key wrapping, IEEE P1363 signing & epoch key archival verified.');

  console.log('--- ALL CRYPTO HARDENING TESTS PASSED ---');
}

runCryptoHardeningTests().catch((err) => {
  console.error('Crypto hardening tests failed:', err);
  process.exit(1);
});
