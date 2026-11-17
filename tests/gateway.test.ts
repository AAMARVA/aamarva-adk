import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  Aamarva,
  AamarvaError,
  FileSystemKeyStore,
  setKeyStore,
  resetLocalIdentityKeyPair,
  resetLocalAgentEncryptionKeys,
  createMockDataStore,
  createMockFetch,
  generateECKeyPair,
  generateX25519KeyPair,
  exportPublicKeyJWK,
  exportX25519PublicKeyJWK,
  getLocalIdentityKeyPair,
  getLocalAgentEncryptionKeyPair,
  computeArgsDigest,
  sha256Hex,
  signGatewayInstruction,
  verifyGatewayInstructionSignature,
  sealGatewayTokenEnvelope,
  openGatewayTokenEnvelope,
  signGatewayPop,
  verifyGatewayPop,
  GATEWAY_PROTOCOL_VERSION,
  GATEWAY_HPKE_KEM,
  GATEWAY_HPKE_KDF,
  GATEWAY_HPKE_AEAD,
  type SignedExecutionInstruction,
  type DecryptedGatewayTokenPayload,
} from '../src/index.js';
import { invokeExternalMcpTool } from '../src/mcp-executor.js';

async function runGatewayTests() {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aamarva-gw-test-'));
  const prevDir = process.env.AAMARVA_KEY_STORE_PATH;
  process.env.AAMARVA_KEY_STORE_PATH = tempDir;
  resetLocalIdentityKeyPair();
  resetLocalAgentEncryptionKeys();
  setKeyStore(new FileSystemKeyStore(tempDir));

  try {
    console.log('--------------------------------------------------');
    console.log('AAMARVA MANDATORY MCP ADAPTER GATEWAY TESTS       ');
    console.log('--------------------------------------------------');

    // 1. Direct external MCP executor is permanently disabled (fail-closed)
    console.log('1. Verifying direct external MCP executor is permanently disabled...');
    await assert.rejects(
      () =>
        invokeExternalMcpTool({
          serverUrl: 'https://external-mcp.example.com/rpc',
          toolId: 'tool_sec_edgar',
          args: { ticker: 'AAPL' },
        }),
      (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_EXECUTION_REQUIRED'
    );
    console.log('✓ Direct external MCP executor fails closed with GATEWAY_EXECUTION_REQUIRED.');

    // 2. RFC 9180 HPKE Base mode seal/open + signed envelope & isolation checks
    console.log('2. Testing RFC 9180 HPKE seal/open, AAD/info binding & key isolation...');
    const agentId = 'AMR-GW-UNIT-1';
    const gwSignKp = generateECKeyPair();
    const gwSignPubJwk = exportPublicKeyJWK(gwSignKp.publicKey);
    const agentXKp = generateX25519KeyPair();
    const agentXPubJwk = exportX25519PublicKeyJWK(agentXKp.publicKey);
    const otherXKp = generateX25519KeyPair();

    const args = { ticker: 'AAPL', nested: { z: 1, a: 2 } };
    const approvedArgsDigest = computeArgsDigest(args);
    const iat = new Date().toISOString();
    const exp = new Date(Date.now() + 300_000).toISOString();

    const tokenPayload: DecryptedGatewayTokenPayload = {
      version: GATEWAY_PROTOCOL_VERSION,
      token: 'gw_tok_rfc9180_secret_token',
      tokenId: 'tok_001',
      gatewayId: 'gw_primary_01',
      gatewayUrl: 'https://aamarva.com/api/gateway',
      agentId,
      agentKeyId: 'x25519_test_v1',
      agentKeyVersion: 1,
      invocationId: 'inv_unit_1',
      instructionId: 'inst_unit_1',
      mcpServerId: 'mcp_srv_sec_edgar',
      toolId: 'tool_sec_edgar',
      approvedArgsDigest,
      scope: 'read:sec_edgar tool:invoke',
      iat,
      exp,
    };

    const envelope = await sealGatewayTokenEnvelope({
      tokenPayload,
      agentPublicKey: agentXPubJwk,
      gatewaySigningPrivateKey: gwSignKp.privateKey,
      gatewayKeyId: 'gw_sig_01',
      gatewayPublicKey: gwSignPubJwk,
    });

    assert.strictEqual(envelope.version, GATEWAY_PROTOCOL_VERSION);
    assert.strictEqual(envelope.suite.kem, GATEWAY_HPKE_KEM);
    assert.strictEqual(envelope.suite.kdf, GATEWAY_HPKE_KDF);
    assert.strictEqual(envelope.suite.aead, GATEWAY_HPKE_AEAD);
    assert.ok(envelope.enc);
    assert.ok(envelope.ciphertext);
    assert.strictEqual(envelope.ciphertext.includes('gw_tok_rfc9180_secret_token'), false);

    // Public key only cannot decrypt
    await assert.rejects(
      () =>
        openGatewayTokenEnvelope(envelope, agentXKp.publicKey, { gw_sig_01: gwSignPubJwk }),
      (err: any) => err?.code === 'TOKEN_DECRYPTION_FAILED'
    );

    // Another agent's X25519 private key cannot decrypt
    await assert.rejects(
      () =>
        openGatewayTokenEnvelope(envelope, otherXKp.privateKey, { gw_sig_01: gwSignPubJwk }),
      (err: any) => err?.code === 'TOKEN_DECRYPTION_FAILED'
    );

    // Untrusted gateway signing key rejected
    const rogueGwKp = generateECKeyPair();
    await assert.rejects(
      () =>
        openGatewayTokenEnvelope(envelope, agentXKp.privateKey, {
          gw_sig_01: exportPublicKeyJWK(rogueGwKp.publicKey),
        }),
      (err: any) => err?.code === 'GATEWAY_SIGNATURE_INVALID'
    );

    // Missing trusted key fails with GATEWAY_UNTRUSTED_KEY
    await assert.rejects(
      () => openGatewayTokenEnvelope(envelope, agentXKp.privateKey, {}),
      (err: any) => err?.code === 'GATEWAY_UNTRUSTED_KEY'
    );

    // Tampered ciphertext fails signature check
    const ctBytes = Buffer.from(envelope.ciphertext, 'base64');
    ctBytes[0] ^= 0xff;
    await assert.rejects(
      () =>
        openGatewayTokenEnvelope(
          { ...envelope, ciphertext: ctBytes.toString('base64') },
          agentXKp.privateKey,
          { gw_sig_01: gwSignPubJwk }
        ),
      (err: any) => err?.code === 'GATEWAY_SIGNATURE_INVALID'
    );

    // Tampered AAD fails
    await assert.rejects(
      () =>
        openGatewayTokenEnvelope(
          { ...envelope, aad: envelope.aad + ':tampered' },
          agentXKp.privateKey,
          { gw_sig_01: gwSignPubJwk }
        ),
      (err: any) => err?.code === 'GATEWAY_SIGNATURE_INVALID'
    );

    // Intended agent decrypts cleanly with context checks
    const decrypted = await openGatewayTokenEnvelope(
      envelope,
      agentXKp.privateKey,
      { gw_sig_01: gwSignPubJwk },
      {
        gatewayId: 'gw_primary_01',
        agentId,
        invocationId: 'inv_unit_1',
        instructionId: 'inst_unit_1',
        mcpServerId: 'mcp_srv_sec_edgar',
        toolId: 'tool_sec_edgar',
        approvedArgsDigest,
      }
    );
    assert.strictEqual(decrypted.token, 'gw_tok_rfc9180_secret_token');
    assert.strictEqual(decrypted.approvedArgsDigest, approvedArgsDigest);
    console.log('✓ RFC 9180 HPKE seal/open, signature trust, and key isolation verified.');

    // 3. Proof-of-Possession signing & verification
    console.log('3. Testing Proof-of-Possession (PoP) signing & wrong-key rejection...');
    const idKp = getLocalIdentityKeyPair(agentId);
    const otherIdKp = generateECKeyPair();
    const popParams = {
      version: GATEWAY_PROTOCOL_VERSION,
      tokenSha256: sha256Hex(decrypted.token),
      gatewayId: decrypted.gatewayId,
      agentId: decrypted.agentId,
      agentKeyId: decrypted.agentKeyId,
      invocationId: decrypted.invocationId,
      instructionId: decrypted.instructionId,
      mcpServerId: decrypted.mcpServerId,
      toolId: decrypted.toolId,
      approvedArgsDigest: decrypted.approvedArgsDigest,
      nonce: 'nonce_pop_test_1',
      timestamp: new Date().toISOString(),
    };
    const popSig = signGatewayPop(idKp.privateKey, popParams);
    assert.strictEqual(verifyGatewayPop(exportPublicKeyJWK(idKp.publicKey), popParams, popSig), true);
    assert.strictEqual(verifyGatewayPop(exportPublicKeyJWK(otherIdKp.publicKey), popParams, popSig), false);
    assert.strictEqual(
      verifyGatewayPop(exportPublicKeyJWK(idKp.publicKey), { ...popParams, nonce: 'tampered' }, popSig),
      false
    );
    console.log('✓ Proof-of-Possession verification and tamper rejection verified.');

    // 4. Full End-to-End Agent Execution Flow through Mandatory Gateway
    console.log('4. Testing full end-to-end FLOOR execution call chain via Mandatory Gateway...');
    const mockStore = createMockDataStore();
    const mockFetch = createMockFetch(mockStore);
    const client = new Aamarva({
      agentId: 'AMR-1111-2222',
      apiKey: 'sk_test_gw',
      fetch: mockFetch,
    });

    await client.login();

    const result = await client.executeFloorTool('tool_sec_edgar', {
      ticker: 'AAPL',
      nested: { b: 2, a: 1 },
    });
    assert.strictEqual(result.status, 'approved');
    assert.strictEqual(result.toolId, 'tool_sec_edgar');
    assert.strictEqual(result.mcpServerId, 'mcp_srv_sec_edgar');
    assert.strictEqual(result.gatewayId, 'gw_primary_01');
    assert.ok(result.result);

    // Proof that external MCP was NEVER called directly by ADK, and ONLY called server-side via gateway
    assert.strictEqual(mockStore.directMcpCalls!.length, 0, 'ADK must make ZERO direct calls to external MCP');
    assert.strictEqual(mockStore.gatewayExecutedMcpCalls!.length, 1);
    assert.strictEqual(mockStore.gatewayExecutedMcpCalls![0].mcpServerId, 'mcp_srv_sec_edgar');
    assert.strictEqual(mockStore.gatewayExecutedMcpCalls![0].usedGatewayCredentials, true);

    // Direct call to /mcp or external MCP URL is actively blocked by gateway/mock boundary
    const directRes = await mockFetch('https://aamarva.com/api/mcp', {
      method: 'POST',
      body: JSON.stringify({ jsonrpc: '2.0', method: 'tools/call', params: { name: 'tool_sec_edgar' } }),
    });
    assert.strictEqual(directRes.status, 403);
    const directBody = await directRes.json();
    assert.strictEqual(directBody.code, 'DIRECT_MCP_FORBIDDEN');
    console.log('✓ Full gateway call chain succeeded with 0 direct MCP calls & 403 direct block.');

    // 5. Atomic single-use enforcement & concurrent double-redemption race
    console.log('5. Testing atomic single-use enforcement & concurrent double-redemption...');
    const gwAuthRes = await client.obtainFloorExecutionAuthorization(
      (await client.createFloorInvocation('tool_sec_edgar', { arguments: { ticker: 'MSFT' } })).invocationId!,
      { arguments: { ticker: 'MSFT' }, toolId: 'tool_sec_edgar' }
    );
    assert.strictEqual((gwAuthRes as any).serverUrl, undefined);
    assert.strictEqual((gwAuthRes as any).auth, undefined);
    assert.strictEqual((gwAuthRes as any).grantToken, undefined);

    const issuedEnv = await client.issueGatewayToken(gwAuthRes.instruction);
    const localKey = getLocalAgentEncryptionKeyPair('AMR-1111-2222', {
      keyId: issuedEnv.agentKeyId,
      keyVersion: issuedEnv.agentKeyVersion,
      createIfMissing: false,
    });
    const gwKeys = await client.getTrustedGatewayKeys();
    const opened = await openGatewayTokenEnvelope(issuedEnv, localKey, gwKeys.gatewayKeys);

    // Concurrent redemption race with same decrypted token
    const raceResults = await Promise.allSettled([
      client.redeemGatewayToken(issuedEnv, opened, { ticker: 'MSFT' }),
      client.redeemGatewayToken(issuedEnv, opened, { ticker: 'MSFT' }),
    ]);
    const fulfilled = raceResults.filter((r) => r.status === 'fulfilled');
    const rejected = raceResults.filter((r) => r.status === 'rejected') as PromiseRejectedResult[];
    assert.strictEqual(fulfilled.length, 1, 'Exactly one concurrent redemption may succeed');
    assert.strictEqual(rejected.length, 1, 'Second concurrent redemption must be rejected');
    assert.ok(
      rejected[0].reason?.code === 'TOKEN_ALREADY_USED' || rejected[0].reason?.statusCode === 409,
      `Expected TOKEN_ALREADY_USED/409, got ${rejected[0].reason?.code}`
    );

    // Subsequent reuse attempt also fails
    await assert.rejects(
      () => client.redeemGatewayToken(issuedEnv, opened, { ticker: 'MSFT' }),
      (err: any) => err?.code === 'TOKEN_ALREADY_USED' || err?.statusCode === 409
    );
    console.log('✓ Atomic single-use token & concurrent race protection verified.');

    // 6. Nonce replay protection on /gateway/mcp
    console.log('6. Testing nonce replay protection...');
    const inv2 = await client.createFloorInvocation('tool_sec_edgar', { arguments: { ticker: 'NVDA' } });
    const auth2 = await client.obtainFloorExecutionAuthorization(inv2.invocationId!, {
      arguments: { ticker: 'NVDA' },
      toolId: 'tool_sec_edgar',
    });
    const env2 = await client.issueGatewayToken(auth2.instruction);
    const dec2 = await openGatewayTokenEnvelope(env2, localKey, gwKeys.gatewayKeys);
    const replayNonce = 'fixed_replay_nonce_12345';
    const tsNow = new Date().toISOString();
    const p2 = getLocalIdentityKeyPair('AMR-1111-2222');
    const pop2 = signGatewayPop(p2.privateKey, {
      version: GATEWAY_PROTOCOL_VERSION,
      tokenSha256: sha256Hex(dec2.token),
      gatewayId: dec2.gatewayId,
      agentId: dec2.agentId,
      agentKeyId: dec2.agentKeyId,
      invocationId: dec2.invocationId,
      instructionId: dec2.instructionId,
      mcpServerId: dec2.mcpServerId,
      toolId: dec2.toolId,
      approvedArgsDigest: dec2.approvedArgsDigest,
      nonce: replayNonce,
      timestamp: tsNow,
    });
    const req2 = {
      version: GATEWAY_PROTOCOL_VERSION,
      token: dec2.token,
      gatewayId: dec2.gatewayId,
      agentId: dec2.agentId,
      agentKeyId: dec2.agentKeyId,
      invocationId: dec2.invocationId,
      instructionId: dec2.instructionId,
      mcpServerId: dec2.mcpServerId,
      toolId: dec2.toolId,
      arguments: { ticker: 'NVDA' },
      approvedArgsDigest: dec2.approvedArgsDigest,
      nonce: replayNonce,
      timestamp: tsNow,
      proofOfPossession: pop2,
    };
    const r2a = await mockFetch('https://aamarva.com/api/gateway/mcp', { method: 'POST', body: JSON.stringify(req2) });
    assert.strictEqual(r2a.status, 200);

    // New token reusing exact same nonce must be rejected as replay
    const inv3 = await client.createFloorInvocation('tool_sec_edgar', { arguments: { ticker: 'GOOG' } });
    const auth3 = await client.obtainFloorExecutionAuthorization(inv3.invocationId!, {
      arguments: { ticker: 'GOOG' },
      toolId: 'tool_sec_edgar',
    });
    const env3 = await client.issueGatewayToken(auth3.instruction);
    const dec3 = await openGatewayTokenEnvelope(env3, localKey, gwKeys.gatewayKeys);
    const pop3 = signGatewayPop(p2.privateKey, {
      version: GATEWAY_PROTOCOL_VERSION,
      tokenSha256: sha256Hex(dec3.token),
      gatewayId: dec3.gatewayId,
      agentId: dec3.agentId,
      agentKeyId: dec3.agentKeyId,
      invocationId: dec3.invocationId,
      instructionId: dec3.instructionId,
      mcpServerId: dec3.mcpServerId,
      toolId: dec3.toolId,
      approvedArgsDigest: dec3.approvedArgsDigest,
      nonce: replayNonce,
      timestamp: tsNow,
    });
    const r3 = await mockFetch('https://aamarva.com/api/gateway/mcp', {
      method: 'POST',
      body: JSON.stringify({
        version: GATEWAY_PROTOCOL_VERSION,
        token: dec3.token,
        gatewayId: dec3.gatewayId,
        agentId: dec3.agentId,
        agentKeyId: dec3.agentKeyId,
        invocationId: dec3.invocationId,
        instructionId: dec3.instructionId,
        mcpServerId: dec3.mcpServerId,
        toolId: dec3.toolId,
        arguments: { ticker: 'GOOG' },
        approvedArgsDigest: dec3.approvedArgsDigest,
        nonce: replayNonce,
        timestamp: tsNow,
        proofOfPossession: pop3,
      }),
    });
    assert.strictEqual(r3.status, 409);
    const r3Json = await r3.json();
    assert.strictEqual(r3Json.code, 'TOKEN_REPLAY_DETECTED');
    console.log('✓ Nonce replay protection verified (409 TOKEN_REPLAY_DETECTED).');

    // 7. Argument digest binding & tampered argument rejection
    console.log('7. Testing argument digest binding & argument tampering rejection...');
    await assert.rejects(
      () => client.redeemGatewayToken(env3, dec3, { ticker: 'TSLA' }),
      (err: any) => err?.code === 'GATEWAY_ARGS_MISMATCH'
    );
    // Forged instruction rejection
    const forgedInstruction: SignedExecutionInstruction = {
      ...auth3.instruction,
      toolId: 'tool_unauthorized_override',
    };
    assert.strictEqual(
      verifyGatewayInstructionSignature(mockStore.trustedGatewayKeys!.issuerPublicJwk, forgedInstruction),
      false
    );
    await assert.rejects(
      () => client.issueGatewayToken(forgedInstruction),
      (err: any) => err?.code === 'GATEWAY_INSTRUCTION_INVALID' || err?.statusCode === 403
    );
    console.log('✓ Argument binding & forged instruction rejection verified.');

    // 8. Expired token rejection
    console.log('8. Testing expired HPKE envelope rejection...');
    const expiredPayload: DecryptedGatewayTokenPayload = {
      ...tokenPayload,
      exp: new Date(Date.now() - 15_000).toISOString(),
    };
    const expiredEnv = await sealGatewayTokenEnvelope({
      tokenPayload: expiredPayload,
      agentPublicKey: agentXPubJwk,
      gatewaySigningPrivateKey: gwSignKp.privateKey,
      gatewayKeyId: 'gw_sig_01',
    });
    await assert.rejects(
      () => openGatewayTokenEnvelope(expiredEnv, agentXKp.privateKey, { gw_sig_01: gwSignPubJwk }),
      (err: any) => err?.code === 'GATEWAY_TOKEN_EXPIRED'
    );
    console.log('✓ Expired token rejection verified.');

    // 9. Credential exposure rejection (FLOOR_CREDENTIAL_EXPOSURE)
    console.log('9. Testing fail-closed credential & direct URL exposure guard...');
    for (const leak of [
      { serverUrl: 'https://external-mcp.evil.internal/rpc' },
      { auth: { type: 'bearer', token: 'secret_leak' } },
      { authConfig: { authType: 'bearer', headerValue: 'Bearer secret_leak' } },
      { grantToken: 'secret_leak' },
      { accessToken: 'secret_leak' },
    ]) {
      const leakyFetch = (async (url: string, init?: any) => {
        if (url.includes('/execute')) {
          const orig = await mockFetch(url, init);
          const origBody = await orig.json();
          return new Response(
            JSON.stringify({
              ...origBody,
              data: { ...origBody.data, ...leak },
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } }
          );
        }
        return mockFetch(url, init);
      }) as typeof fetch;

      const leakyClient = new Aamarva({
        agentId: 'AMR-1111-2222',
        apiKey: 'sk_test_gw',
        fetch: leakyFetch,
      });

      await assert.rejects(
        () => leakyClient.executeFloorTool('tool_sec_edgar', { ticker: 'AAPL' }),
        (err: any) =>
          err?.code === 'FLOOR_CREDENTIAL_EXPOSURE' &&
          !JSON.stringify(err).includes('secret_leak') &&
          !JSON.stringify(err).includes('external-mcp.evil.internal')
      );
    }
    console.log('✓ Fail-closed credential/serverUrl isolation (FLOOR_CREDENTIAL_EXPOSURE) verified.');

    // 10. HITL pending -> approved polling executes strictly via gateway
    console.log('10. Testing HITL approval polling via Mandatory Gateway...');
    const hitlStore = createMockDataStore();
    const hitlFetch = createMockFetch(hitlStore);
    const hitlClient = new Aamarva({
      agentId: 'AMR-1111-2222',
      apiKey: 'sk_hitl',
      fetch: hitlFetch,
    });

    const reqInit = await hitlClient.requestFloorAccess('tool_market_depth', 'Need depth', { pair: 'BTC-USD' });
    assert.strictEqual(reqInit.status, 'pending');
    setTimeout(() => {
      const reqId = reqInit.requestId!;
      hitlStore.floorRequests[reqId].status = 'approved';
      hitlStore.floorRequests[reqId].invocationId = reqId;
      hitlStore.floorInvocations[reqId].status = 'approved';
    }, 60);

    const hitlRes = await hitlClient.executeFloorTool(
      'tool_market_depth',
      { pair: 'BTC-USD' },
      { requestId: reqInit.requestId, waitForApproval: true, pollIntervalMs: 30, pollTimeoutMs: 2000 }
    );
    assert.strictEqual(hitlRes.status, 'approved');
    assert.strictEqual(hitlRes.mcpServerId, 'mcp_srv_market_depth');
    assert.strictEqual(hitlStore.directMcpCalls!.length, 0);
    assert.strictEqual(hitlStore.gatewayExecutedMcpCalls!.length, 1);
    console.log('✓ HITL polling + gateway execution verified.');

    // 11. X25519 gateway key rotation & revocation enforcement
    console.log('11. Testing X25519 gateway key rotation & revocation enforcement...');
    const rotStore = createMockDataStore();
    const rotFetch = createMockFetch(rotStore);
    const rotClient = new Aamarva({
      agentId: 'AMR-1111-2222',
      apiKey: 'sk_rot',
      fetch: rotFetch,
    });
    const firstReg = await rotClient.registerGatewayKey();
    const fetchedGwKey = await rotClient.getGatewayKey();
    assert.strictEqual(fetchedGwKey.keyId, firstReg.keyId);

    const rotated = await rotClient.rotateGatewayKey({ revokePrevious: true });
    assert.notStrictEqual(rotated.keyId, firstReg.keyId);
    assert.strictEqual(rotated.keyVersion, firstReg.keyVersion + 1);

    const afterRotExec = await rotClient.executeFloorTool('tool_sec_edgar', { ticker: 'AMD' });
    assert.strictEqual(afterRotExec.status, 'approved');

    // Revoke active key -> platform & client must reject token issuance/authorization
    await rotClient.revokeGatewayKey();
    const invRevoked = await rotClient.createFloorInvocation('tool_sec_edgar', { arguments: { ticker: 'AMD' } });
    await assert.rejects(
      () =>
        rotClient.obtainFloorExecutionAuthorization(invRevoked.invocationId!, {
          arguments: { ticker: 'AMD' },
          toolId: 'tool_sec_edgar',
        }),
      (err: any) =>
        err?.code === 'AGENT_ENCRYPTION_KEY_REVOKED' ||
        err?.code === 'FLOOR_ACCESS_DENIED' ||
        err?.statusCode === 403
    );
    console.log('✓ X25519 gateway key rotation & revocation enforcement verified.');

    console.log('--------------------------------------------------');
    console.log('ALL MANDATORY MCP ADAPTER GATEWAY TESTS PASSED    ');
    console.log('--------------------------------------------------');
  } finally {
    if (prevDir === undefined) {
      delete process.env.AAMARVA_KEY_STORE_PATH;
    } else {
      process.env.AAMARVA_KEY_STORE_PATH = prevDir;
    }
    resetLocalIdentityKeyPair();
    resetLocalAgentEncryptionKeys();
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

runGatewayTests().catch((err) => {
  console.error('Gateway tests failed:', err);
  process.exit(1);
});
