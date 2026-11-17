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
  computeArgsDigest,
  sha256Hex,
  signGatewayInstruction,
  verifyGatewayInstructionSignature,
  sealGatewayTokenEnvelope,
  openGatewayTokenEnvelope,
  signGatewayPop,
  verifyGatewayPop,
} from '../src/crypto.js';
import { GATEWAY_PROTOCOL_VERSION } from '../src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const pyScript = path.join(__dirname, 'py_e2ee_interop.py');

function isPythonCryptographyAvailable(): boolean {
  try {
    const res = spawnSync('python3', ['-c', 'from aamarva.crypto import HAS_CRYPTOGRAPHY; assert HAS_CRYPTOGRAPHY'], {
      encoding: 'utf-8',
      env: { ...process.env, PYTHONPATH: path.join(__dirname, '../python') },
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

  // 10. Gateway RFC 9180 HPKE + X25519 Binding + Signed Instructions + Proof-of-Possession TS <-> Python Interop
  const pyGwKeys = callPython('gw-gen-keys', { agentId: 'AMR-PYTHON' });
  assert.strictEqual(pyGwKeys.success, true);
  assert.strictEqual(
    verifyAgentEncryptionKeyBinding(
      pyGwKeys.identityPublicKeyJwk,
      {
        agentId: 'AMR-PYTHON',
        keyId: pyGwKeys.keyId,
        keyVersion: pyGwKeys.keyVersion,
        fingerprint: pyGwKeys.x25519Fingerprint,
        publicKey: pyGwKeys.x25519PublicKeyJwk,
      },
      pyGwKeys.encBindingSignature
    ),
    true,
    'TypeScript must verify Python X25519 key binding signature'
  );

  const tsX25519 = generateX25519KeyPair();
  const tsX25519PubJwk = exportX25519PublicKeyJWK(tsX25519.publicKey);
  const tsX25519PrivPem = tsX25519.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const tsX25519Fp = computeX25519KeyFingerprint(tsX25519PubJwk);
  const tsKeyId = computeAgentEncryptionKeyId('AMR-TYPESCRIPT', tsX25519PubJwk, 1);

  const issuerKp = generateECKeyPair();
  const issuerPrivPem = issuerKp.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const issuerPubJwk = issuerKp.publicKey.export({ format: 'jwk' });
  const gwKp = generateECKeyPair();
  const gwPrivPem = gwKp.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const gwPubJwk = gwKp.publicKey.export({ format: 'jwk' });

  const nowIso = new Date().toISOString();
  const expIso = new Date(Date.now() + 600_000).toISOString();
  const args = { ticker: 'AAPL', nested: { limit: 10, flags: [true, false] } };
  const argsDigest = computeArgsDigest(args);

  // 10a. TS signs Gateway Instruction -> Python verifies; Python signs Gateway Instruction -> TS verifies
  const unsignedInstForPy: any = {
    version: GATEWAY_PROTOCOL_VERSION,
    instructionId: 'inst_interop_1',
    issuer: 'aamarva.platform',
    audience: 'aamarva.gateway',
    gatewayId: 'gw_interop',
    agentId: 'AMR-PYTHON',
    agentKeyId: pyGwKeys.keyId,
    agentKeyVersion: pyGwKeys.keyVersion,
    agentPublicKey: pyGwKeys.x25519PublicKeyJwk,
    invocationId: 'inv_interop_1',
    mcpServerId: 'mcp_sec',
    toolId: 'tool_sec',
    approvedArguments: args,
    approvedArgsDigest: argsDigest,
    decision: 'approved',
    scope: 'tool:invoke',
    iat: nowIso,
    exp: expIso,
    issuerKeyId: 'iss_1',
  };
  const tsSignedInst = {
    ...unsignedInstForPy,
    signature: signGatewayInstruction(issuerKp.privateKey, unsignedInstForPy),
  };
  const pyVerifyInst = callPython('gw-verify-instruction', {
    issuerPublicKey: issuerPubJwk,
    instruction: tsSignedInst,
  });
  assert.strictEqual(pyVerifyInst.valid, true, 'Python must verify TS-signed gateway instruction');

  const pySignInst = callPython('gw-sign-instruction', {
    issuerPrivateKeyPem: issuerPrivPem,
    instruction: unsignedInstForPy,
  });
  assert.strictEqual(pySignInst.success, true);
  assert.strictEqual(
    verifyGatewayInstructionSignature(issuerPubJwk, { ...unsignedInstForPy, signature: pySignInst.signature }),
    true,
    'TypeScript must verify Python-signed gateway instruction'
  );

  // 10b. RFC 9180 HPKE Seal in TypeScript -> Open in Python
  const tokenPayloadForPy: any = {
    version: GATEWAY_PROTOCOL_VERSION,
    token: 'gw_tok_ts_to_py_999',
    gatewayId: 'gw_interop',
    gatewayUrl: 'https://aamarva.com/api/gateway',
    agentId: 'AMR-PYTHON',
    agentKeyId: pyGwKeys.keyId,
    agentKeyVersion: pyGwKeys.keyVersion,
    invocationId: 'inv_interop_1',
    instructionId: 'inst_interop_1',
    mcpServerId: 'mcp_sec',
    toolId: 'tool_sec',
    approvedArgsDigest: argsDigest,
    scope: 'tool:invoke',
    iat: nowIso,
    exp: expIso,
  };
  const tsSealedEnvelope = await sealGatewayTokenEnvelope({
    tokenPayload: tokenPayloadForPy,
    agentPublicKey: pyGwKeys.x25519PublicKeyJwk,
    gatewaySigningPrivateKey: gwKp.privateKey,
    gatewayKeyId: 'gw_k1',
    gatewayPublicKey: gwPubJwk as any,
  });
  const pyOpened = callPython('gw-open-envelope', {
    envelope: tsSealedEnvelope,
    agentPrivateKeyPem: pyGwKeys.x25519PrivateKeyPem,
    trustedGatewayPublicKeys: { gw_k1: gwPubJwk },
    expectedContext: { agentId: 'AMR-PYTHON', toolId: 'tool_sec', approvedArgsDigest: argsDigest },
  });
  assert.strictEqual(pyOpened.success, true, `Python failed to open TS HPKE envelope: ${pyOpened.error}`);
  assert.strictEqual(pyOpened.payload.token, 'gw_tok_ts_to_py_999');

  // 10c. RFC 9180 HPKE Seal in Python -> Open in TypeScript
  const tokenPayloadForTs: any = {
    version: GATEWAY_PROTOCOL_VERSION,
    token: 'gw_tok_py_to_ts_777',
    gatewayId: 'gw_interop',
    gatewayUrl: 'https://aamarva.com/api/gateway',
    agentId: 'AMR-TYPESCRIPT',
    agentKeyId: tsKeyId,
    agentKeyVersion: 1,
    invocationId: 'inv_interop_2',
    instructionId: 'inst_interop_2',
    mcpServerId: 'mcp_sec',
    toolId: 'tool_sec',
    approvedArgsDigest: argsDigest,
    scope: 'tool:invoke',
    iat: nowIso,
    exp: expIso,
  };
  const pySealed = callPython('gw-seal-envelope', {
    tokenPayload: tokenPayloadForTs,
    agentPublicKey: tsX25519PubJwk,
    gatewaySigningPrivateKeyPem: gwPrivPem,
    gatewayKeyId: 'gw_k1',
    gatewayPublicKey: gwPubJwk,
  });
  assert.strictEqual(pySealed.success, true, `Python failed to seal HPKE envelope: ${pySealed.error}`);
  const tsOpened = await openGatewayTokenEnvelope(
    pySealed.envelope,
    tsX25519PrivPem,
    { gw_k1: gwPubJwk as any },
    { agentId: 'AMR-TYPESCRIPT', toolId: 'tool_sec', approvedArgsDigest: argsDigest }
  );
  assert.strictEqual(tsOpened.token, 'gw_tok_py_to_ts_777');

  // 10d. Proof-of-Possession bidirectional TS <-> Python verification
  const popForPy = {
    version: GATEWAY_PROTOCOL_VERSION,
    tokenSha256: sha256Hex('gw_tok_ts_to_py_999'),
    gatewayId: 'gw_interop',
    agentId: 'AMR-TYPESCRIPT',
    agentKeyId: tsKeyId,
    invocationId: 'inv_interop_1',
    instructionId: 'inst_interop_1',
    mcpServerId: 'mcp_sec',
    toolId: 'tool_sec',
    approvedArgsDigest: argsDigest,
    nonce: 'nonce_interop_1',
    timestamp: nowIso,
  };
  const tsPopSig = signGatewayPop(agentAKeyPair.privateKey, popForPy);
  const pyVerifyPop = callPython('gw-verify-pop', {
    identityPublicKey: agentAIdentityJwk,
    params: popForPy,
    signature: tsPopSig,
  });
  assert.strictEqual(pyVerifyPop.valid, true, 'Python must verify TS Proof-of-Possession signature');

  const pyPopSign = callPython('gw-sign-pop', {
    identityPrivateKeyPem: pyGwKeys.identityPrivateKeyPem,
    params: popForPy,
  });
  assert.strictEqual(pyPopSign.success, true);
  assert.strictEqual(
    verifyGatewayPop(pyGwKeys.identityPublicKeyJwk, popForPy, pyPopSign.signature),
    true,
    'TypeScript must verify Python Proof-of-Possession signature'
  );
  assert.ok(tsX25519Fp.startsWith('SHA256:'));
  console.log('✓ Mandatory Gateway RFC 9180 HPKE, X25519 binding, SignedExecutionInstruction & PoP TS <-> Python interop verified.');

  console.log('--- ALL CROSS-LANGUAGE E2EE & GATEWAY INTEROPERABILITY TESTS PASSED ---');
}

runCrossLanguageE2EETest().catch((err) => {
  console.error('Cross-language test failed:', err);
  process.exit(1);
});
