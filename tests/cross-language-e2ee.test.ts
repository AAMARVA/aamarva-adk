import assert from 'node:assert';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
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
  GATEWAY_ENVELOPE_VERSION,
  GATEWAY_ENVELOPE_ALGORITHM,
  buildGatewayTokenEnvelopeHkdfInfo,
  createGatewayTokenEnvelopeAad,
  deriveGatewayEnvelopeKey,
  decryptGatewayTokenEnvelope,
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

function runGatewayCrossLanguageInterop() {
  console.log('--- Running TS <-> Python MCP Gateway Token Envelope Interop ---');
  const fixturePath = path.join(__dirname, 'fixtures', 'gateway-token-envelope.v1.json');
  const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf-8'));

  const activeEnv = fixture.active.envelope;
  const tsDerivedHex = deriveGatewayEnvelopeKey(
    fixture.recipientPrivateKeyPem,
    activeEnv.ephemeralPublicKeyPem,
    activeEnv.saltBase64,
    activeEnv.agentId,
    activeEnv.tokenId
  ).toString('hex');
  const pyDerivedRes = callPython('gateway-derive-key', {
    privateKeyPem: fixture.recipientPrivateKeyPem,
    ephemeralPublicKeyPem: activeEnv.ephemeralPublicKeyPem,
    saltBase64: activeEnv.saltBase64,
    agentId: activeEnv.agentId,
    tokenId: activeEnv.tokenId,
  });

  assert.strictEqual(pyDerivedRes.success, true, `Python gateway-derive-key failed: ${pyDerivedRes.error}`);
  assert.strictEqual(tsDerivedHex, fixture.active.expectedDerivedKeyHex);
  assert.strictEqual(pyDerivedRes.keyHex, tsDerivedHex, 'TS and Python MUST derive identical HKDF key');
  assert.strictEqual(
    buildGatewayTokenEnvelopeHkdfInfo(activeEnv.agentId, activeEnv.tokenId),
    fixture.active.hkdfInfo
  );
  assert.strictEqual(pyDerivedRes.hkdfInfo, fixture.active.hkdfInfo);
  assert.strictEqual(createGatewayTokenEnvelopeAad(activeEnv), fixture.active.aadString);

  // Decrypt fixture in TS and Python
  const tsAadStr = createGatewayTokenEnvelopeAad(activeEnv);
  assert.strictEqual(tsAadStr, fixture.active.aadString);
  assert.ok(!tsAadStr.startsWith('aamarva-mcp-gateway:'), 'AAD must NOT contain legacy prefix');

  const tsPlaintext = decryptGatewayTokenEnvelope(activeEnv, fixture.recipientPrivateKeyPem, {
    expectedAgentId: activeEnv.agentId,
    expectedAccountId: activeEnv.accountId,
    expectedTokenId: activeEnv.tokenId,
    expectedGatewayId: activeEnv.gatewayId,
    expectedMcpServerId: activeEnv.mcpServerId,
    toolName: 'sec_edgar_search',
  });
  assert.deepStrictEqual(tsPlaintext, fixture.active.expectedPlaintext);

  const pyDecryptRes = callPython('gateway-decrypt', {
    envelope: activeEnv,
    privateKeyPem: fixture.recipientPrivateKeyPem,
    expectedAgentId: activeEnv.agentId,
    expectedAccountId: activeEnv.accountId,
    expectedTokenId: activeEnv.tokenId,
    expectedGatewayId: activeEnv.gatewayId,
    expectedMcpServerId: activeEnv.mcpServerId,
    toolName: 'sec_edgar_search',
  });
  assert.strictEqual(pyDecryptRes.success, true, `Python gateway-decrypt failed: ${pyDecryptRes.error}`);
  assert.strictEqual(pyDecryptRes.aadString, tsAadStr, 'TS and Python MUST produce identical AAD string');
  assert.strictEqual(
    pyDecryptRes.aadHex,
    Buffer.from(tsAadStr, 'utf8').toString('hex'),
    'TS and Python MUST produce identical AAD bytes'
  );
  assert.deepStrictEqual(pyDecryptRes.plaintext, tsPlaintext);

  // Also test fresh dynamic Gateway envelope generated with raw node:crypto
  const recipientKp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const recipientPrivPem = recipientKp.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const recipientPubPem = recipientKp.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const ephKp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const ephPubPem = ephKp.publicKey.export({ type: 'spki', format: 'pem' }).toString();

  const dynMeta = {
    version: GATEWAY_ENVELOPE_VERSION,
    algorithm: GATEWAY_ENVELOPE_ALGORITHM,
    tokenId: 'gw_tok_dyn_999',
    gatewayId: 'gw_eu_west_02',
    mcpServerId: 'srv_weather_07',
    agentId: 'AMR-DYN-007',
    accountId: 'acc_dyn_4242',
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
  };
  const dynSalt = crypto.randomBytes(32);
  const dynIv = crypto.randomBytes(12);
  const dynShared = crypto.diffieHellman({
    privateKey: ephKp.privateKey,
    publicKey: crypto.createPublicKey(recipientPubPem),
  });
  const dynHkdfInfo = `aamarva-mcp-gateway:token-envelope:v1:${dynMeta.agentId}:${dynMeta.tokenId}`;
  const dynKey = Buffer.from(crypto.hkdfSync('sha256', dynShared, dynSalt, Buffer.from(dynHkdfInfo, 'utf8'), 32));
  const dynAad = JSON.stringify({
    accountId: dynMeta.accountId,
    agentId: dynMeta.agentId,
    algorithm: dynMeta.algorithm,
    expiresAt: dynMeta.expiresAt,
    gatewayId: dynMeta.gatewayId,
    mcpServerId: dynMeta.mcpServerId,
    tokenId: dynMeta.tokenId,
    version: dynMeta.version,
  });
  const dynPlain = {
    v: 1,
    tokenId: dynMeta.tokenId,
    token: 'test_fake_dyn_bearer_777',
    gatewayId: dynMeta.gatewayId,
    mcpServerId: dynMeta.mcpServerId,
    agentId: dynMeta.agentId,
    accountId: dynMeta.accountId,
    allowedTools: ['weather_forecast'],
    expiresAt: dynMeta.expiresAt,
  };
  const dynCipher = crypto.createCipheriv('aes-256-gcm', dynKey, dynIv);
  dynCipher.setAAD(Buffer.from(dynAad, 'utf8'));
  const dynCt = Buffer.concat([dynCipher.update(JSON.stringify(dynPlain), 'utf8'), dynCipher.final()]);
  const dynEnvelope = {
    ...dynMeta,
    ephemeralPublicKeyPem: ephPubPem,
    saltBase64: dynSalt.toString('base64'),
    ivBase64: dynIv.toString('base64'),
    authTagBase64: dynCipher.getAuthTag().toString('base64'),
    ciphertextBase64: dynCt.toString('base64'),
  };

  const tsDynDerived = deriveGatewayEnvelopeKey(
    recipientPrivPem,
    dynEnvelope.ephemeralPublicKeyPem,
    dynEnvelope.saltBase64,
    dynEnvelope.agentId,
    dynEnvelope.tokenId
  ).toString('hex');
  const pyDynDerived = callPython('gateway-derive-key', {
    privateKeyPem: recipientPrivPem,
    ephemeralPublicKeyPem: dynEnvelope.ephemeralPublicKeyPem,
    saltBase64: dynEnvelope.saltBase64,
    agentId: dynEnvelope.agentId,
    tokenId: dynEnvelope.tokenId,
  });
  assert.strictEqual(pyDynDerived.success, true);
  assert.strictEqual(tsDynDerived, dynKey.toString('hex'));
  assert.strictEqual(pyDynDerived.keyHex, tsDynDerived);

  const tsDynPlain = decryptGatewayTokenEnvelope(dynEnvelope, recipientPrivPem, {
    expectedAgentId: dynMeta.agentId,
    expectedAccountId: dynMeta.accountId,
    toolName: 'weather_forecast',
  });
  const pyDynPlain = callPython('gateway-decrypt', {
    envelope: dynEnvelope,
    privateKeyPem: recipientPrivPem,
    expectedAgentId: dynMeta.agentId,
    expectedAccountId: dynMeta.accountId,
    toolName: 'weather_forecast',
  });
  assert.strictEqual(pyDynPlain.success, true);
  assert.strictEqual(pyDynPlain.aadHex, Buffer.from(dynAad, 'utf8').toString('hex'));
  assert.deepStrictEqual(pyDynPlain.plaintext, tsDynPlain);
  assert.deepStrictEqual(tsDynPlain, dynPlain);

  // Cross-language negative rejections must agree in both TS and Python
  const wrongVersionPy = callPython('gateway-decrypt', {
    envelope: { ...activeEnv, version: 1 },
    privateKeyPem: fixture.recipientPrivateKeyPem,
    expectedAgentId: activeEnv.agentId,
    expectedAccountId: activeEnv.accountId,
  });
  assert.strictEqual(wrongVersionPy.success, false);
  assert.strictEqual(wrongVersionPy.code, 'GATEWAY_ENVELOPE_INVALID');

  const wrongAlgPy = callPython('gateway-decrypt', {
    envelope: { ...activeEnv, algorithm: 'ECDH-P256-HKDF-SHA256-AES-256-GCM' },
    privateKeyPem: fixture.recipientPrivateKeyPem,
    expectedAgentId: activeEnv.agentId,
    expectedAccountId: activeEnv.accountId,
  });
  assert.strictEqual(wrongAlgPy.success, false);
  assert.strictEqual(wrongAlgPy.code, 'GATEWAY_ENVELOPE_INVALID');

  const wrongAgentPy = callPython('gateway-decrypt', {
    envelope: activeEnv,
    privateKeyPem: fixture.recipientPrivateKeyPem,
    expectedAgentId: 'AMR-WRONG-AGENT',
    expectedAccountId: activeEnv.accountId,
  });
  assert.strictEqual(wrongAgentPy.success, false);
  assert.strictEqual(wrongAgentPy.code, 'GATEWAY_AGENT_MISMATCH');

  const wrongTokenIdPy = callPython('gateway-decrypt', {
    envelope: activeEnv,
    privateKeyPem: fixture.recipientPrivateKeyPem,
    expectedAgentId: activeEnv.agentId,
    expectedAccountId: activeEnv.accountId,
    expectedTokenId: 'gw_tok_wrong_999',
  });
  assert.strictEqual(wrongTokenIdPy.success, false);
  assert.strictEqual(wrongTokenIdPy.code, 'GATEWAY_TOKEN_ID_MISMATCH');

  const wrongKeyPy = callPython('gateway-decrypt', {
    envelope: activeEnv,
    privateKeyPem: fixture.wrongPrivateKeyPem,
    expectedAgentId: activeEnv.agentId,
    expectedAccountId: activeEnv.accountId,
  });
  assert.strictEqual(wrongKeyPy.success, false);
  assert.strictEqual(wrongKeyPy.code, 'GATEWAY_ENVELOPE_DECRYPTION_FAILED');

  const expiredPy = callPython('gateway-decrypt', {
    envelope: fixture.expired.envelope,
    privateKeyPem: fixture.recipientPrivateKeyPem,
    expectedAgentId: fixture.expired.envelope.agentId,
    expectedAccountId: fixture.expired.envelope.accountId,
  });
  assert.strictEqual(expiredPy.success, false);
  assert.strictEqual(expiredPy.code, 'GATEWAY_TOKEN_EXPIRED');

  const unauthToolPy = callPython('gateway-decrypt', {
    envelope: activeEnv,
    privateKeyPem: fixture.recipientPrivateKeyPem,
    expectedAgentId: activeEnv.agentId,
    expectedAccountId: activeEnv.accountId,
    toolName: 'unauthorized_shell_exec',
  });
  assert.strictEqual(unauthToolPy.success, false);
  assert.strictEqual(unauthToolPy.code, 'GATEWAY_TOOL_UNAUTHORIZED');

  console.log('✓ TS <-> Python MCP Gateway HKDF key derivation, AAD byte equality & envelope decryption verified.');
}

async function runCrossLanguageE2EETest() {
  console.log('--- Starting Cross-Language E2EE Interoperability Test ---');

  runGatewayCrossLanguageInterop();

  if (!isPythonCryptographyAvailable()) {
    console.log('ℹ [Notice] Python "cryptography" package is not installed in the current environment.');
    console.log('Skipping Workflow 1/2 Python subprocess section (MCP Gateway cross-language interop already passed).');
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
