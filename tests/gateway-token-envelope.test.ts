import assert from 'node:assert';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  Aamarva,
  AamarvaError,
  GATEWAY_ENVELOPE_VERSION,
  GATEWAY_ENVELOPE_PLAINTEXT_VERSION,
  GATEWAY_ENVELOPE_ALGORITHM,
  GATEWAY_HKDF_INFO_PREFIX,
  buildGatewayTokenEnvelopeHkdfInfo,
  createGatewayTokenEnvelopeAad,
  deriveGatewayEnvelopeKey,
  decryptGatewayTokenEnvelope,
  executeGatewayMcpTool,
  normalizeGatewayMcpUrl,
  getKeyStore,
  resetLocalIdentityKeyPair,
} from '../src/index.js';
import type { GatewayTokenEnvelope } from '../src/types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fixturePath = path.join(__dirname, 'fixtures', 'gateway-token-envelope.v1.json');
const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf-8'));

function sealGatewayEnvelopeRaw(options: {
  recipientPublicKeyPem: string;
  agentId: string;
  accountId: string;
  version?: any;
  algorithm?: string;
  tokenId?: string;
  gatewayId?: string;
  mcpServerId?: string;
  expiresAt?: string;
  plaintextOverrides?: Record<string, unknown>;
  aadPrefix?: string;
  token?: string;
  allowedTools?: string[];
}): { envelope: GatewayTokenEnvelope; expectedKeyHex: string; aad: string; plaintext: Record<string, unknown> } {
  const eph = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const ephPubPem = eph.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const recipientPub = crypto.createPublicKey({ key: options.recipientPublicKeyPem, format: 'pem', type: 'spki' });

  const tokenId = options.tokenId || 'gw_tok_raw_001';
  const gatewayId = options.gatewayId || 'gw_prod_01';
  const mcpServerId = options.mcpServerId || 'srv_tools_01';
  const expiresAt = options.expiresAt || new Date(Date.now() + 3600_000).toISOString();

  const meta = {
    version: options.version !== undefined ? options.version : 'AAMARVA-GW-ENV-V1',
    algorithm: options.algorithm || 'P256-HKDF-SHA256-AES-256-GCM',
    tokenId,
    gatewayId,
    mcpServerId,
    agentId: options.agentId,
    accountId: options.accountId,
    expiresAt,
  };

  const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: recipientPub });
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const hkdfInfo = `aamarva-mcp-gateway:token-envelope:v1:${meta.agentId}:${meta.tokenId}`;
  const aesKey = Buffer.from(crypto.hkdfSync('sha256', shared, salt, Buffer.from(hkdfInfo, 'utf8'), 32));
  const rawJsonAad = JSON.stringify({
    accountId: meta.accountId,
    agentId: meta.agentId,
    algorithm: meta.algorithm,
    expiresAt: meta.expiresAt,
    gatewayId: meta.gatewayId,
    mcpServerId: meta.mcpServerId,
    tokenId: meta.tokenId,
    version: meta.version,
  });
  const aad = options.aadPrefix ? `${options.aadPrefix}${rawJsonAad}` : rawJsonAad;

  const plaintextObj: Record<string, unknown> = {
    v: 1,
    tokenId,
    token: options.token || 'test_fake_gw_live_bearer_99887766',
    gatewayId,
    mcpServerId,
    agentId: options.agentId,
    accountId: options.accountId,
    allowedTools: options.allowedTools || ['sec_edgar_search', 'sec_edgar_filing'],
    expiresAt,
    ...(options.plaintextOverrides || {}),
  };

  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([cipher.update(JSON.stringify(plaintextObj), 'utf8'), cipher.final()]);

  return {
    envelope: {
      ...meta,
      ephemeralPublicKeyPem: ephPubPem,
      saltBase64: salt.toString('base64'),
      ivBase64: iv.toString('base64'),
      authTagBase64: cipher.getAuthTag().toString('base64'),
      ciphertextBase64: ct.toString('base64'),
    },
    expectedKeyHex: aesKey.toString('hex'),
    aad,
    plaintext: plaintextObj,
  };
}

function deepFreeze<T>(obj: T): T {
  if (obj && typeof obj === 'object') {
    Object.freeze(obj);
    for (const val of Object.values(obj as Record<string, unknown>)) {
      deepFreeze(val);
    }
  }
  return obj;
}

async function runGatewayTokenEnvelopeTests() {
  console.log('--- Starting MCP Gateway Token Envelope & Execution Tests ---');

  assert.strictEqual(GATEWAY_ENVELOPE_VERSION, 'AAMARVA-GW-ENV-V1');
  assert.strictEqual(GATEWAY_ENVELOPE_PLAINTEXT_VERSION, 1);
  assert.strictEqual(GATEWAY_ENVELOPE_ALGORITHM, 'P256-HKDF-SHA256-AES-256-GCM');
  assert.strictEqual(GATEWAY_HKDF_INFO_PREFIX, 'aamarva-mcp-gateway:token-envelope:v1');

  const activeEnv: GatewayTokenEnvelope = fixture.active.envelope;
  deepFreeze(activeEnv);

  // Case 1, 14, 15: Gateway-generated envelope decrypts in TS + exact HKDF & raw JSON AAD match
  const hkdfInfo = buildGatewayTokenEnvelopeHkdfInfo(activeEnv.agentId, activeEnv.tokenId);
  assert.strictEqual(hkdfInfo, fixture.active.hkdfInfo);
  const aadStr = createGatewayTokenEnvelopeAad(activeEnv);
  assert.strictEqual(aadStr, fixture.active.aadString);
  assert.ok(!aadStr.startsWith('aamarva-mcp-gateway:'), 'AAD must NOT have prefix');

  const derivedKey = deriveGatewayEnvelopeKey(
    fixture.recipientPrivateKeyPem,
    activeEnv.ephemeralPublicKeyPem,
    activeEnv.saltBase64,
    activeEnv.agentId,
    activeEnv.tokenId
  );
  assert.strictEqual(derivedKey.toString('hex'), fixture.active.expectedDerivedKeyHex);

  const decrypted = decryptGatewayTokenEnvelope(activeEnv, fixture.recipientPrivateKeyPem, {
    expectedAgentId: activeEnv.agentId,
    expectedAccountId: activeEnv.accountId,
    expectedTokenId: activeEnv.tokenId,
    expectedGatewayId: activeEnv.gatewayId,
    expectedMcpServerId: activeEnv.mcpServerId,
    toolName: 'sec_edgar_search',
  });
  assert.deepStrictEqual(decrypted, fixture.active.expectedPlaintext);
  console.log('✓ Case 1, 14 & 15: Gateway-generated envelope decrypts; HKDF & raw JSON AAD match.');

  // Case 3: Version mismatch rejected (numeric 1, string "1", or unknown version)
  for (const badVersion of [1, '1', 'AAMARVA-GW-ENV-V2', ''] as any[]) {
    assert.throws(
      () =>
        decryptGatewayTokenEnvelope(
          { ...activeEnv, version: badVersion },
          fixture.recipientPrivateKeyPem,
          { expectedAgentId: activeEnv.agentId, expectedAccountId: activeEnv.accountId }
        ),
      (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_ENVELOPE_INVALID'
    );
  }
  console.log('✓ Case 3: Version mismatch rejected.');

  // Case 4: Algorithm mismatch rejected (including legacy ECDH-P256-HKDF-SHA256-AES-256-GCM)
  for (const badAlg of ['ECDH-P256-HKDF-SHA256-AES-256-GCM', 'AES-256-GCM', '']) {
    assert.throws(
      () =>
        decryptGatewayTokenEnvelope(
          { ...activeEnv, algorithm: badAlg },
          fixture.recipientPrivateKeyPem,
          { expectedAgentId: activeEnv.agentId, expectedAccountId: activeEnv.accountId }
        ),
      (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_ENVELOPE_INVALID'
    );
  }
  console.log('✓ Case 4: Algorithm mismatch rejected.');

  // Case 5: Wrong private key and non-P256 key rejected
  assert.throws(
    () =>
      decryptGatewayTokenEnvelope(activeEnv, fixture.wrongPrivateKeyPem, {
        expectedAgentId: activeEnv.agentId,
        expectedAccountId: activeEnv.accountId,
      }),
    (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_ENVELOPE_DECRYPTION_FAILED'
  );
  const p384Kp = crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
  assert.throws(
    () =>
      decryptGatewayTokenEnvelope(activeEnv, p384Kp.privateKey, {
        expectedAgentId: activeEnv.agentId,
        expectedAccountId: activeEnv.accountId,
      }),
    (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_ENVELOPE_DECRYPTION_FAILED'
  );
  console.log('✓ Case 5: Wrong private key and non-P256 keys rejected.');

  // Case 6: Wrong Agent ID rejected
  assert.throws(
    () =>
      decryptGatewayTokenEnvelope(activeEnv, fixture.recipientPrivateKeyPem, {
        expectedAgentId: 'AMR-OTHER-AGENT',
        expectedAccountId: activeEnv.accountId,
      }),
    (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_AGENT_MISMATCH'
  );
  console.log('✓ Case 6: Wrong Agent ID rejected.');

  // Case 7: Wrong account ID rejected
  assert.throws(
    () =>
      decryptGatewayTokenEnvelope(activeEnv, fixture.recipientPrivateKeyPem, {
        expectedAgentId: activeEnv.agentId,
        expectedAccountId: 'acc_wrong_owner',
      }),
    (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_ACCOUNT_MISMATCH'
  );
  console.log('✓ Case 7: Wrong account ID rejected.');

  // Case 8: Wrong token ID rejected (expectedTokenId mismatch + inner plaintext tokenId mismatch)
  assert.throws(
    () =>
      decryptGatewayTokenEnvelope(activeEnv, fixture.recipientPrivateKeyPem, {
        expectedAgentId: activeEnv.agentId,
        expectedAccountId: activeEnv.accountId,
        expectedTokenId: 'gw_tok_wrong_999',
      }),
    (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_TOKEN_ID_MISMATCH'
  );
  const innerTokenMismatch = sealGatewayEnvelopeRaw({
    recipientPublicKeyPem: fixture.recipientPublicKeyPem,
    agentId: activeEnv.agentId,
    accountId: activeEnv.accountId,
    plaintextOverrides: { tokenId: 'gw_tok_spoofed_inner' },
  });
  assert.throws(
    () =>
      decryptGatewayTokenEnvelope(innerTokenMismatch.envelope, fixture.recipientPrivateKeyPem, {
        expectedAgentId: activeEnv.agentId,
        expectedAccountId: activeEnv.accountId,
      }),
    (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_ENVELOPE_MISMATCH'
  );
  console.log('✓ Case 8: Wrong token ID rejected.');

  // Case 9: AAD metadata tampering (and legacy prefixed AAD) rejected
  for (const [field, badVal] of [
    ['gatewayId', 'gw_tampered_02'],
    ['mcpServerId', 'srv_tampered_02'],
    ['expiresAt', '2036-01-01T00:00:00.000Z'],
    ['tokenId', 'gw_tok_tampered_999'],
  ] as const) {
    assert.throws(
      () =>
        decryptGatewayTokenEnvelope(
          { ...activeEnv, [field]: badVal },
          fixture.recipientPrivateKeyPem,
          { expectedAgentId: activeEnv.agentId, expectedAccountId: activeEnv.accountId }
        ),
      (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_ENVELOPE_DECRYPTION_FAILED',
      `Tampering with AAD field ${field} must fail decryption`
    );
  }
  const legacyPrefixedAadEnv = sealGatewayEnvelopeRaw({
    recipientPublicKeyPem: fixture.recipientPublicKeyPem,
    agentId: activeEnv.agentId,
    accountId: activeEnv.accountId,
    aadPrefix: 'aamarva-mcp-gateway:token-envelope:aad:v1:',
  });
  assert.throws(
    () =>
      decryptGatewayTokenEnvelope(legacyPrefixedAadEnv.envelope, fixture.recipientPrivateKeyPem, {
        expectedAgentId: activeEnv.agentId,
        expectedAccountId: activeEnv.accountId,
      }),
    (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_ENVELOPE_DECRYPTION_FAILED'
  );
  console.log('✓ Case 9: AAD metadata tampering and prefixed AAD rejected.');

  // Case 10: Ciphertext tampering rejected
  const tamperedCt = Buffer.from(activeEnv.ciphertextBase64, 'base64');
  tamperedCt[0] ^= 0xff;
  assert.throws(
    () =>
      decryptGatewayTokenEnvelope(
        { ...activeEnv, ciphertextBase64: tamperedCt.toString('base64') },
        fixture.recipientPrivateKeyPem,
        { expectedAgentId: activeEnv.agentId, expectedAccountId: activeEnv.accountId }
      ),
    (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_ENVELOPE_DECRYPTION_FAILED'
  );
  console.log('✓ Case 10: Ciphertext tampering rejected.');

  // Case 11: Authentication-tag tampering rejected
  const tamperedTag = Buffer.from(activeEnv.authTagBase64, 'base64');
  tamperedTag[0] ^= 0xff;
  assert.throws(
    () =>
      decryptGatewayTokenEnvelope(
        { ...activeEnv, authTagBase64: tamperedTag.toString('base64') },
        fixture.recipientPrivateKeyPem,
        { expectedAgentId: activeEnv.agentId, expectedAccountId: activeEnv.accountId }
      ),
    (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_ENVELOPE_DECRYPTION_FAILED'
  );
  console.log('✓ Case 11: Authentication-tag tampering rejected.');

  // Case 12: Expired token rejected (both fixture.expired and freshly sealed past envelope)
  assert.throws(
    () =>
      decryptGatewayTokenEnvelope(fixture.expired.envelope, fixture.recipientPrivateKeyPem, {
        expectedAgentId: fixture.expired.envelope.agentId,
        expectedAccountId: fixture.expired.envelope.accountId,
      }),
    (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_TOKEN_EXPIRED'
  );
  const pastSealed = sealGatewayEnvelopeRaw({
    recipientPublicKeyPem: fixture.recipientPublicKeyPem,
    agentId: activeEnv.agentId,
    accountId: activeEnv.accountId,
    expiresAt: new Date(Date.now() - 60_000).toISOString(),
  });
  assert.throws(
    () =>
      decryptGatewayTokenEnvelope(pastSealed.envelope, fixture.recipientPrivateKeyPem, {
        expectedAgentId: activeEnv.agentId,
        expectedAccountId: activeEnv.accountId,
      }),
    (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_TOKEN_EXPIRED'
  );
  console.log('✓ Case 12: Expired tokens rejected.');

  // Case 13: Unauthorized tool rejected
  assert.throws(
    () =>
      decryptGatewayTokenEnvelope(activeEnv, fixture.recipientPrivateKeyPem, {
        expectedAgentId: activeEnv.agentId,
        expectedAccountId: activeEnv.accountId,
        toolName: 'exec_shell_command',
      }),
    (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_TOOL_UNAUTHORIZED'
  );
  console.log('✓ Case 13: Unauthorized tool names rejected.');

  // Outer required field validation & plaintext inner checks
  assert.throws(
    () =>
      decryptGatewayTokenEnvelope(
        { ...activeEnv, ephemeralPublicKeyPem: '' },
        fixture.recipientPrivateKeyPem,
        { expectedAgentId: activeEnv.agentId, expectedAccountId: activeEnv.accountId }
      ),
    (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_ENVELOPE_INVALID'
  );
  assert.throws(
    () =>
      decryptGatewayTokenEnvelope(
        { ...activeEnv, saltBase64: 'AAAA' },
        fixture.recipientPrivateKeyPem,
        { expectedAgentId: activeEnv.agentId, expectedAccountId: activeEnv.accountId }
      ),
    (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_ENVELOPE_INVALID'
  );
  const badPlaintextV = sealGatewayEnvelopeRaw({
    recipientPublicKeyPem: fixture.recipientPublicKeyPem,
    agentId: activeEnv.agentId,
    accountId: activeEnv.accountId,
    plaintextOverrides: { v: 2 },
  });
  assert.throws(
    () =>
      decryptGatewayTokenEnvelope(badPlaintextV.envelope, fixture.recipientPrivateKeyPem, {
        expectedAgentId: activeEnv.agentId,
        expectedAccountId: activeEnv.accountId,
      }),
    (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_ENVELOPE_INVALID_PLAINTEXT'
  );
  const emptyToolsPlaintext = sealGatewayEnvelopeRaw({
    recipientPublicKeyPem: fixture.recipientPublicKeyPem,
    agentId: activeEnv.agentId,
    accountId: activeEnv.accountId,
    allowedTools: [],
  });
  assert.throws(
    () =>
      decryptGatewayTokenEnvelope(emptyToolsPlaintext.envelope, fixture.recipientPrivateKeyPem, {
        expectedAgentId: activeEnv.agentId,
        expectedAccountId: activeEnv.accountId,
      }),
    (err: any) => err instanceof AamarvaError && err.code === 'GATEWAY_ENVELOPE_INVALID_PLAINTEXT'
  );

  // URL normalization checks
  assert.strictEqual(normalizeGatewayMcpUrl('https://gw.aamarva.com/v1'), 'https://gw.aamarva.com/v1/mcp');
  assert.strictEqual(normalizeGatewayMcpUrl('https://gw.aamarva.com/mcp/'), 'https://gw.aamarva.com/mcp');
  assert.strictEqual(normalizeGatewayMcpUrl('http://localhost:8787'), 'http://localhost:8787/mcp');
  assert.throws(() => normalizeGatewayMcpUrl('http://remote.example.com/mcp'), /HTTPS is required/i);

  // End-to-end Gateway /mcp invocation via executeGatewayMcpTool & Core-relayed executeFloorTool
  resetLocalIdentityKeyPair();
  getKeyStore().savePrivateKey(fixture.recipientPrivateKeyPem, 'AMR-GW-ALPHA-01');

  let gatewayCalls: Array<{ url: string; auth: string; body: any }> = [];
  const sseFetch: typeof fetch = async (input, init) => {
    const url = String(input);
    const headers = (init?.headers || {}) as Record<string, string>;
    const parsedBody = JSON.parse(String(init?.body || '{}'));
    gatewayCalls.push({
      url,
      auth: headers['Authorization'] || '',
      body: parsedBody,
    });
    const ssePayload = `event: message\ndata: ${JSON.stringify({
      jsonrpc: '2.0',
      id: parsedBody.id,
      result: { content: [{ type: 'text', text: 'SEC 10-K filing retrieved' }] },
    })}\n\n`;
    return new Response(ssePayload, {
      status: 200,
      headers: { 'Content-Type': 'text/event-stream' },
    });
  };

  await assert.rejects(
    () =>
      executeGatewayMcpTool({
        gatewayUrl: 'https://gw.aamarva.com',
        tokenEnvelope: activeEnv,
        toolName: 'forbidden_tool',
        arguments: { ticker: 'AAPL' },
        expectedAgentId: 'AMR-GW-ALPHA-01',
        expectedAccountId: 'acc_fleet_owner_9001',
        fetch: sseFetch,
      }),
    (err: any) => err?.code === 'GATEWAY_TOOL_UNAUTHORIZED'
  );
  assert.strictEqual(gatewayCalls.length, 0);

  const directCall = await executeGatewayMcpTool({
    gatewayUrl: 'https://gw.aamarva.com',
    tokenEnvelope: activeEnv,
    toolName: 'sec_edgar_search',
    arguments: { ticker: 'AAPL' },
    expectedAgentId: 'AMR-GW-ALPHA-01',
    expectedAccountId: 'acc_fleet_owner_9001',
    fetch: sseFetch,
  });
  assert.strictEqual(gatewayCalls.length, 1);
  assert.strictEqual(gatewayCalls[0].url, 'https://gw.aamarva.com/mcp');
  assert.strictEqual(gatewayCalls[0].auth, `Bearer ${fixture.active.expectedPlaintext.token}`);
  assert.strictEqual(gatewayCalls[0].body.method, 'tools/call');
  assert.strictEqual(gatewayCalls[0].body.params.name, 'sec_edgar_search');
  assert.deepStrictEqual(directCall.result, { content: [{ type: 'text', text: 'SEC 10-K filing retrieved' }] });

  gatewayCalls = [];
  const relayedFetch: typeof fetch = async (input, init) => {
    const url = String(input);
    if (url.includes('gw.aamarva.com')) {
      return sseFetch(input, init);
    }
    if (url.endsWith('/auth/login')) {
      return new Response(
        JSON.stringify({
          success: true,
          data: {
            tokens: { accessToken: 'tok_gw_access', refreshToken: 'tok_gw_refresh' },
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }
    if (url.endsWith('/agents/me/e2ee')) {
      return new Response(
        JSON.stringify({ success: true, message: 'E2EE public key registered' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }
    if (url.endsWith('/floor/agent/tools')) {
      return new Response(
        JSON.stringify({
          success: true,
          data: [{ id: 'tool_sec_edgar', name: 'sec_edgar_search', accessStatus: 'authorized' }],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }
    if (url.endsWith('/floor/tools/tool_sec_edgar/invoke')) {
      return new Response(
        JSON.stringify({
          success: true,
          status: 'approved',
          data: {
            invocationId: 'inv_gw_relayed_1',
            toolId: 'tool_sec_edgar',
            status: 'approved',
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }
    if (url.endsWith('/floor/invocations/inv_gw_relayed_1/execute')) {
      return new Response(
        JSON.stringify({
          success: true,
          data: {
            status: 'approved',
            invocationId: 'inv_gw_relayed_1',
            toolId: 'tool_sec_edgar',
            tool: { id: 'tool_sec_edgar', name: 'sec_edgar_search' },
            agentId: 'AMR-GW-ALPHA-01',
            accountId: 'acc_fleet_owner_9001',
            approvedArguments: { ticker: 'MSFT' },
            grant: {
              grantId: 'grant_gw_1',
              status: 'active',
              toolId: 'tool_sec_edgar',
              agentId: 'AMR-GW-ALPHA-01',
              scope: 'read:sec_edgar',
              expiresAt: '2035-01-01T00:00:00.000Z',
            },
            gatewayUrl: 'https://gw.aamarva.com',
            gatewayId: 'gw_prod_us_east_01',
            mcpServerId: 'srv_sec_edgar_01',
            tokenEnvelope: activeEnv,
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }
    throw new Error(`Unexpected URL: ${url}`);
  };

  const client = new Aamarva({
    agentId: 'AMR-GW-ALPHA-01',
    accountId: 'acc_fleet_owner_9001',
    apiKey: 'sk_test_gw',
    fetch: relayedFetch,
  });

  const floorRes = await client.executeFloorTool('tool_sec_edgar', { ticker: 'MSFT' });
  assert.strictEqual(floorRes.status, 'executed');
  assert.strictEqual(floorRes.invocationId, 'inv_gw_relayed_1');
  assert.deepStrictEqual(floorRes.result, { content: [{ type: 'text', text: 'SEC 10-K filing retrieved' }] });
  assert.strictEqual(gatewayCalls.length, 1);
  assert.strictEqual(gatewayCalls[0].auth, `Bearer ${fixture.active.expectedPlaintext.token}`);
  assert.deepStrictEqual(gatewayCalls[0].body.params.arguments, { ticker: 'MSFT' });

  const clientPlain = client.decryptGatewayTokenEnvelope(activeEnv, { toolName: 'sec_edgar_filing' });
  assert.strictEqual(clientPlain.token, fixture.active.expectedPlaintext.token);

  console.log('✓ Core-relayed FLOOR -> Gateway /mcp execution verified.');
  console.log('--- ALL MCP GATEWAY TOKEN ENVELOPE TESTS PASSED ---');
}

runGatewayTokenEnvelopeTests().catch((err) => {
  console.error('MCP Gateway token envelope tests failed:', err);
  process.exit(1);
});
