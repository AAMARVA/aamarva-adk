import assert from 'node:assert';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  generateECKeyPair,
  computeKeyFingerprint,
  computeGroupKeyFingerprint,
  computeRosterHash,
  computeAudienceHash,
  encryptMessageWithKeys,
  decryptMessageWithKeys,
  signIdentityBinding,
  generateClusterKey,
  wrapClusterKeyForRecipient,
  unwrapClusterKey,
  encryptClusterMessagePayload,
  decryptClusterMessagePayload,
  signClusterMessageV2,
  verifyClusterMessageSignatureV2,
} from '../src/crypto.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const pyScript = path.join(__dirname, 'py_e2ee_interop.py');

function isPythonCryptographyAvailable(): boolean {
  try {
    const res = spawnSync('python3', ['-c', 'from cryptography.hazmat.primitives.asymmetric import ec'], {
      encoding: 'utf-8',
    });
    return res.status === 0;
  } catch {
    return false;
  }
}

function callPython(cmd: string, inputData?: any) {
  const res = spawnSync('python3', [pyScript, cmd], {
    input: inputData ? JSON.stringify(inputData) : undefined,
    encoding: 'utf-8',
    env: { ...process.env, PYTHONPATH: path.join(__dirname, '../python') },
  });
  if (res.error) {
    throw res.error;
  }
  if (res.status !== 0) {
    throw new Error(`Python process exited with status ${res.status}: ${res.stderr}`);
  }
  return JSON.parse(res.stdout);
}

async function runCrossLanguageE2EETest() {
  console.log('--- Starting Cross-Language E2EE Interoperability Test ---');

  if (!isPythonCryptographyAvailable()) {
    console.log('ℹ [Notice] Python "cryptography" package is not installed in the current environment.');
    console.log('Skipping cross-language E2EE subprocess test (TypeScript standalone E2EE suite verified all crypto algorithms).');
    console.log('--- CROSS-LANGUAGE TEST SKIPPED GRACEFULLY ---');
    return;
  }

  // 1. TypeScript generates Agent A keys
  const agentAKeyPair = generateECKeyPair();
  const agentAPubPem = agentAKeyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const agentAFingerprint = computeKeyFingerprint(agentAPubPem);

  // 2. Python generates Agent B keys
  const agentBKeys = callPython('gen-key');
  const agentBPrivPem = agentBKeys.privateKey;
  const agentBPubPem = agentBKeys.publicKey;
  const agentBFingerprint = agentBKeys.fingerprint;
  const agentAIdentityJwk = agentAKeyPair.publicKey.export({ format: 'jwk' });
  const agentAIdentitySignature = signIdentityBinding(agentAKeyPair.privateKey, 'AMR-TYPESCRIPT', agentAFingerprint);

  assert.ok(agentAPubPem.includes('BEGIN PUBLIC KEY'));
  assert.ok(agentBPubPem.includes('BEGIN PUBLIC KEY'));
  assert.strictEqual(agentBFingerprint, computeKeyFingerprint(agentBPubPem));

  const connectionId = 'conn_cross_lang_interop_42';

  // 3. Workflow 1: TypeScript encrypts "hello from TypeScript" for Agent B with senderAgentId
  const messageFromTS = 'hello from TypeScript';
  const agentBIdentityJwk = agentBKeys.identityKey;
  const agentBIdentitySignature = agentBKeys.identitySignature;
  const envelopeFromTS = encryptMessageWithKeys(
    messageFromTS,
    connectionId,
    agentAKeyPair.privateKey,
    agentBPubPem,
    agentBFingerprint,
    'AMR-PYTHON',
    agentBIdentitySignature,
    agentBIdentityJwk,
    1,
    'AMR-TYPESCRIPT'
  );

  // 4. Python decrypts using Agent B private key and canonical senderAgentId
  const pyDecryptRes = callPython('decrypt', {
    envelope: envelopeFromTS,
    connectionId,
    privateKey: agentBPrivPem,
    peerPubPem: agentAPubPem,
    peerFingerprint: agentAFingerprint,
    peerAgentId: 'AMR-TYPESCRIPT',
    peerSignature: agentAIdentitySignature,
    peerIdentityKey: agentAIdentityJwk,
    senderAgentId: 'AMR-TYPESCRIPT',
  });

  assert.strictEqual(pyDecryptRes.success, true, `Python decryption failed: ${pyDecryptRes.error}`);
  assert.strictEqual(pyDecryptRes.plaintext, 'hello from TypeScript');
  console.log('✓ Workflow 1 TypeScript -> Python decryption verified.');

  // Negative check: mismatched senderAgentId fails in Python
  const pyWrongSenderRes = callPython('decrypt', {
    envelope: envelopeFromTS,
    connectionId,
    privateKey: agentBPrivPem,
    peerPubPem: agentAPubPem,
    peerFingerprint: agentAFingerprint,
    peerAgentId: 'AMR-TYPESCRIPT',
    peerSignature: agentAIdentitySignature,
    peerIdentityKey: agentAIdentityJwk,
    senderAgentId: 'AMR-SPOOFED',
  });
  assert.strictEqual(pyWrongSenderRes.success, false);
  assert.strictEqual(pyWrongSenderRes.code, 'MESSAGE_DECRYPTION_FAILED');

  // 5. Reverse: Python encrypts "hello from Python" for Agent A
  const messageFromPy = 'hello from Python';
  const pyEncryptRes = callPython('encrypt', {
    plaintext: messageFromPy,
    connectionId,
    privateKey: agentBPrivPem,
    peerPubPem: agentAPubPem,
    peerFingerprint: agentAFingerprint,
    peerAgentId: 'AMR-TYPESCRIPT',
    peerSignature: agentAIdentitySignature,
    peerIdentityKey: agentAIdentityJwk,
    keyEpoch: 1,
    senderAgentId: 'AMR-PYTHON',
  });

  assert.strictEqual(pyEncryptRes.success, true, `Python encryption failed: ${pyEncryptRes.error}`);
  const envelopeFromPy = pyEncryptRes.envelope;

  // 6. TypeScript decrypts using Agent A private key
  const tsDecrypted = decryptMessageWithKeys(
    envelopeFromPy,
    connectionId,
    agentAKeyPair.privateKey,
    agentBPubPem,
    agentBFingerprint,
    'AMR-PYTHON',
    agentBIdentitySignature,
    agentBIdentityJwk,
    'AMR-PYTHON'
  );
  assert.strictEqual(tsDecrypted, 'hello from Python');
  console.log('✓ Workflow 1 Python -> TypeScript decryption verified.');

  // 7. Negative test: Tampered ciphertext from TS fails in Python
  const tamperedBytes = Buffer.from(envelopeFromTS.ciphertext, 'base64');
  tamperedBytes[2] ^= 0xff;
  const tamperedEnv = { ...envelopeFromTS, ciphertext: tamperedBytes.toString('base64') };
  const pyTamperedRes = callPython('decrypt', {
    envelope: tamperedEnv,
    connectionId,
    privateKey: agentBPrivPem,
    peerPubPem: agentAPubPem,
    peerFingerprint: agentAFingerprint,
    peerAgentId: 'AMR-TYPESCRIPT',
    peerSignature: agentAIdentitySignature,
    peerIdentityKey: agentAIdentityJwk,
    senderAgentId: 'AMR-TYPESCRIPT',
  });
  assert.strictEqual(pyTamperedRes.success, false);
  assert.strictEqual(pyTamperedRes.code, 'MESSAGE_DECRYPTION_FAILED');

  // 8. Negative test: Tampered ciphertext from Python fails in TS
  const pyTamperedBytes = Buffer.from(envelopeFromPy.ciphertext, 'base64');
  pyTamperedBytes[2] ^= 0xff;
  const tamperedPyEnv = { ...envelopeFromPy, ciphertext: pyTamperedBytes.toString('base64') };
  assert.throws(
    () =>
      decryptMessageWithKeys(
        tamperedPyEnv,
        connectionId,
        agentAKeyPair.privateKey,
        agentBPubPem,
        agentBFingerprint,
        'AMR-PYTHON',
        agentBIdentitySignature,
        agentBIdentityJwk,
        'AMR-PYTHON'
      ),
    (err: any) => err?.code === 'MESSAGE_DECRYPTION_FAILED'
  );

  // 9. Workflow 2: Cross-Language Cluster Key Wrap/Unwrap + Sign/Verify + Audience Scoping
  const clusterId = 'cluster_interop_v2';
  const epoch = 3;
  const roster = ['AMR-TYPESCRIPT', 'AMR-PYTHON', 'AMR-AUDITOR'];
  const targetedAudience = ['AMR-TYPESCRIPT', 'AMR-PYTHON'];
  const rosterHash = computeRosterHash(roster);
  const audienceHash = computeAudienceHash(targetedAudience, roster);
  assert.ok(rosterHash.startsWith('RST:'));
  assert.ok(audienceHash.startsWith('AUD:'));

  const clusterKey = generateClusterKey();
  const groupKeyFp = computeGroupKeyFingerprint(clusterKey);

  // TS wraps subgroup key for Python -> Python unwraps and matches exact bytes
  const tsWrapped = wrapClusterKeyForRecipient(
    clusterKey,
    agentBPubPem,
    agentAKeyPair.privateKey,
    {
      clusterId,
      epoch,
      audienceHash,
      rosterHash,
      keyFingerprint: groupKeyFp,
      senderAgentId: 'AMR-TYPESCRIPT',
      recipientAgentId: 'AMR-PYTHON',
    }
  );
  const pyUnwrapRes = callPython('cluster-unwrap', {
    encryptedKeyPackage: tsWrapped.encryptedKeyPackage,
    nonce: tsWrapped.nonce,
    recipientPrivPem: agentBPrivPem,
    senderPubPem: agentAPubPem,
    clusterId,
    epoch,
    audienceHash,
    expectedKeyFingerprint: groupKeyFp,
  });
  assert.strictEqual(pyUnwrapRes.success, true, `Python unwrap failed: ${pyUnwrapRes.error}`);
  assert.strictEqual(pyUnwrapRes.clusterKeyB64, clusterKey.toString('base64'));

  // TS encrypts & IEEE P1363 ECDSA signs -> Python verifies signature and decrypts
  const tsClusterEnc = encryptClusterMessagePayload(
    'Cluster Workflow 2 message from TS',
    clusterKey,
    clusterId,
    epoch,
    audienceHash,
    'AMR-TYPESCRIPT'
  );
  const tsClusterSig = signClusterMessageV2(agentAKeyPair.privateKey, {
    clusterId,
    keyEpoch: epoch,
    senderAgentId: 'AMR-TYPESCRIPT',
    audienceHash,
    rosterHash,
    sequence: 10,
    keyFingerprint: groupKeyFp,
    nonce: tsClusterEnc.nonce,
    ciphertext: tsClusterEnc.ciphertext,
  });
  const pyVerifyDecrypt = callPython('cluster-verify-decrypt', {
    ciphertext: tsClusterEnc.ciphertext,
    nonce: tsClusterEnc.nonce,
    clusterKeyB64: clusterKey.toString('base64'),
    clusterId,
    epoch,
    audienceHash,
    rosterHash,
    senderAgentId: 'AMR-TYPESCRIPT',
    sequence: 10,
    keyFingerprint: groupKeyFp,
    signature: tsClusterSig,
    senderPubPem: agentAPubPem,
  });
  assert.strictEqual(pyVerifyDecrypt.success, true);
  assert.strictEqual(pyVerifyDecrypt.signatureValid, true);
  assert.strictEqual(pyVerifyDecrypt.plaintext, 'Cluster Workflow 2 message from TS');

  // Python encrypts & IEEE P1363 ECDSA signs -> TS verifies signature and decrypts
  const pyClusterSend = callPython('cluster-sign-encrypt', {
    plaintext: 'Cluster Workflow 2 reply from Python',
    clusterKeyB64: clusterKey.toString('base64'),
    clusterId,
    epoch,
    audienceHash,
    rosterHash,
    senderAgentId: 'AMR-PYTHON',
    sequence: 11,
    senderPrivPem: agentBPrivPem,
  });
  assert.strictEqual(pyClusterSend.success, true);
  const tsSigValid = verifyClusterMessageSignatureV2(
    agentBPubPem,
    {
      clusterId,
      keyEpoch: epoch,
      senderAgentId: 'AMR-PYTHON',
      audienceHash,
      rosterHash,
      sequence: 11,
      keyFingerprint: pyClusterSend.keyFingerprint,
      nonce: pyClusterSend.nonce,
      ciphertext: pyClusterSend.ciphertext,
    },
    pyClusterSend.signature
  );
  assert.strictEqual(tsSigValid, true);
  const tsClusterPlain = decryptClusterMessagePayload(
    pyClusterSend.ciphertext,
    pyClusterSend.nonce,
    clusterKey,
    clusterId,
    epoch,
    2,
    audienceHash,
    'AMR-PYTHON'
  );
  assert.strictEqual(tsClusterPlain, 'Cluster Workflow 2 reply from Python');
  console.log('✓ Workflow 2 TS <-> Python wrap/unwrap, IEEE P1363 ECDSA sign/verify, and decrypt verified.');

  console.log('--- ALL CROSS-LANGUAGE E2EE INTEROPERABILITY TESTS PASSED ---');
}

runCrossLanguageE2EETest().catch((err) => {
  console.error('Cross-language test failed:', err);
  process.exit(1);
});
