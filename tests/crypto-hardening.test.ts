import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  generateECKeyPair,
  computeKeyFingerprint,
  verifyPeerKey,
  encryptMessageWithKeys,
  decryptMessageWithKeys,
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
  const sentMsg = await client.sendMessage('conn-leak-test', sensitiveSecret, 'AMR-BOB');
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

  console.log('--- ALL CRYPTO HARDENING TESTS PASSED ---');
}

runCryptoHardeningTests().catch((err) => {
  console.error('Crypto hardening tests failed:', err);
  process.exit(1);
});
