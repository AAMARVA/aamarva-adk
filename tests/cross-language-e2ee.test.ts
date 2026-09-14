import assert from 'node:assert';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  generateECKeyPair,
  computeKeyFingerprint,
  encryptMessageWithKeys,
  decryptMessageWithKeys,
  signIdentityBinding
} from '../src/crypto.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const pyScript = path.join(__dirname, 'py_e2ee_interop.py');

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

  // 3. TypeScript encrypts "hello from TypeScript" for Agent B
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
    1
  );

  console.log('TypeScript encrypted envelope:', {
    ciphertextLength: envelopeFromTS.ciphertext.length,
    nonceLength: envelopeFromTS.nonce.length,
    version: envelopeFromTS.version,
    keyEpoch: envelopeFromTS.keyEpoch,
  });

  // 4. Python decrypts using Agent B private key
  const pyDecryptRes = callPython('decrypt', {
    envelope: envelopeFromTS,
    connectionId,
    privateKey: agentBPrivPem,
    peerPubPem: agentAPubPem,
    peerFingerprint: agentAFingerprint,
    peerAgentId: 'AMR-TYPESCRIPT',
    peerSignature: agentAIdentitySignature,
    peerIdentityKey: agentAIdentityJwk,
  });

  assert.strictEqual(pyDecryptRes.success, true, `Python decryption failed: ${pyDecryptRes.error}`);
  assert.strictEqual(
    pyDecryptRes.plaintext,
    'hello from TypeScript',
    `Decrypted plaintext must be exactly "hello from TypeScript", got "${pyDecryptRes.plaintext}"`
  );
  console.log('✓ TypeScript -> Python decryption verified: exact match ("hello from TypeScript")');

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
  });

  assert.strictEqual(pyEncryptRes.success, true, `Python encryption failed: ${pyEncryptRes.error}`);
  const envelopeFromPy = pyEncryptRes.envelope;

  console.log('Python encrypted envelope:', {
    ciphertextLength: envelopeFromPy.ciphertext.length,
    nonceLength: envelopeFromPy.nonce.length,
    version: envelopeFromPy.version,
    keyEpoch: envelopeFromPy.keyEpoch,
  });

  // 6. TypeScript decrypts using Agent A private key
  const tsDecrypted = decryptMessageWithKeys(
    envelopeFromPy,
    connectionId,
    agentAKeyPair.privateKey,
    agentBPubPem,
    agentBFingerprint,
    'AMR-PYTHON',
    agentBIdentitySignature,
    agentBIdentityJwk
  );

  assert.strictEqual(
    tsDecrypted,
    'hello from Python',
    `Decrypted plaintext must be exactly "hello from Python", got "${tsDecrypted}"`
  );
  console.log('✓ Python -> TypeScript decryption verified: exact match ("hello from Python")');

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
  });
  assert.strictEqual(pyTamperedRes.success, false);
  assert.strictEqual(pyTamperedRes.code, 'MESSAGE_DECRYPTION_FAILED');
  console.log('✓ Tampered TS ciphertext correctly rejected by Python AEAD authentication.');

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
        agentBIdentityJwk
      ),
    (err: any) => err?.code === 'MESSAGE_DECRYPTION_FAILED'
  );
  console.log('✓ Tampered Python ciphertext correctly rejected by TypeScript AEAD authentication.');

  console.log('--- ALL CROSS-LANGUAGE E2EE INTEROPERABILITY TESTS PASSED ---');
}

runCrossLanguageE2EETest().catch((err) => {
  console.error('Cross-language test failed:', err);
  process.exit(1);
});
