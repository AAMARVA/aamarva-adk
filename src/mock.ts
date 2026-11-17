/**
 * Offline Mock transport and testing utilities for AAMARVA fleet agent development.
 */

import crypto from 'crypto';
import {
  Agent,
  Connection,
  Cluster,
  ClusterMessage,
  ECJWK,
  FloorTool,
  WatchtowerActivity,
  GATEWAY_PROTOCOL_VERSION,
  type AamarvaIdentityAssertion,
  type DecryptedGatewayTokenPayload,
} from './types.js';
import {
  exportPublicKeyJWK,
  computeKeyFingerprint,
  signIdentityBinding,
  generateECKeyPair,
  canonicalJsonStringify,
  sha256Hex,
  computeArgsDigest,
  signAamarvaIdentityAssertion,
  verifyAamarvaIdentityAssertion,
  sealGatewayTokenEnvelope,
  verifyGatewayPop,
  normalizeAgentId,
} from './crypto.js';

export interface MockDataStore {
  agents: Agent[];
  connections: Connection[];
  messages: Record<string, any[]>;
  e2eeKeys: Record<string, any>;
  clusters: Cluster[];
  clusterMembers: Record<string, string[]>;
  clusterMessages: Record<string, any[]>;
  clusterKeyDistributions?: Record<string, any>;
  floorTools: FloorTool[];
  floorRequests: Record<string, any>;
  floorInvocations: Record<string, any>;
  watchtowerActivities: WatchtowerActivity[];
  trustedGatewayKeys?: {
    gatewayId: string;
    gatewayKeyId: string;
    gatewayUrl: string;
    gatewayPrivateKey: any;
    gatewayPublicJwk: any;
    aamarvaPrivateKey: any;
    aamarvaPublicJwk: any;
    gatewayKeys: Record<string, any>;
  };
  gatewayTokens?: Record<string, any>;
  gatewayUsedNonces?: Record<string, boolean>;
  internalMcpServers?: Record<string, { serverUrl: string; authHeader: string; internalSecret: string }>;
  gatewayExecutedMcpCalls?: Array<{ mcpServerId: string; toolId: string; arguments: any; usedGatewayCredentials: boolean }>;
  directMcpCalls?: Array<{ url: string; method: string; body: any }>;
}

export function createMockDataStore(): MockDataStore {
  return {
    agents: [
      {
        agentId: 'AMR-1111-2222',
        name: 'Financial Analysis Agent',
        bio: 'Specialized in real-time market data, financial research, and telemetry.',
        email: 'finance-agent@example.com',
        status: 'active',
        masterId: 'AMR-0000-MASTER',
      },
      {
        agentId: 'AMR-3333-4444',
        name: 'Code Review & QA Agent',
        bio: 'Automated code auditing, TypeScript validation, and security scanning.',
        email: 'qa-agent@example.com',
        status: 'active',
      },
      {
        agentId: 'AMR-5555-6666',
        name: 'Data Extraction Agent',
        bio: 'ETL pipelines and document parsing.',
        email: 'etl-agent@example.com',
        status: 'active',
      },
    ],
    connections: [
      {
        connectionId: 'conn_mock_123',
        agentId: 'AMR-1111-2222',
        connectedAgentName: 'Financial Analysis Agent',
        status: 'active',
        createdAt: new Date().toISOString(),
      },
    ],
    messages: {
      'conn_mock_123': [],
    },
    e2eeKeys: {},
    clusters: [
      {
        id: 'cluster_987654',
        clusterId: 'cluster_987654',
        name: 'Market Arbitrage Cluster',
        description: 'Consensus on L2 liquidity arbitrage opportunities.',
        ownerUserId: 'usr_abc123',
        ownerAgentId: 'AMR-0000-MASTER',
        epoch: 1,
        keyEpoch: 1,
        rotationStatus: 'NONE',
        membersCount: 3,
        members: ['AMR-1111-2222', 'AMR-5555-6666', 'AMR-0000-MASTER'],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
    ],
    clusterMembers: {
      'cluster_987654': ['AMR-1111-2222', 'AMR-5555-6666', 'AMR-0000-MASTER'],
    },
    clusterMessages: {
      'cluster_987654': [],
    },
    floorTools: [
      {
        id: 'tool_sec_edgar',
        name: 'SEC EDGAR Filings Extractor',
        description: 'Real-time extraction of structured 10-K and 10-Q corporate filings.',
        inputSchema: {
          type: 'object',
          properties: {
            ticker: { type: 'string' },
            form: { type: 'string' },
          },
          required: ['ticker'],
        },
        accessStatus: 'authorized',
        mcpServerId: 'mcp_srv_sec_edgar',
        gatewayId: 'gw_primary_01',
        gatewayUrl: 'https://aamarva.com/api/gateway',
      },
      {
        id: 'tool_market_depth',
        name: 'L2 Market Depth Stream',
        description: 'High-frequency orderbook depth feeds.',
        inputSchema: {
          type: 'object',
          properties: {
            pair: { type: 'string' },
          },
          required: ['pair'],
        },
        accessStatus: 'required',
        mcpServerId: 'mcp_srv_market_depth',
        gatewayId: 'gw_primary_01',
        gatewayUrl: 'https://aamarva.com/api/gateway',
      },
    ],
    floorRequests: {
      'req_tool_001': {
        requestId: 'req_tool_001',
        status: 'pending',
        toolId: 'tool_market_depth',
        reason: 'Autonomous market making',
      },
    },
    floorInvocations: {},
    clusterKeyDistributions: {},
    watchtowerActivities: [
      {
        id: 'act_001',
        type: 'connection.established',
        actorAgentId: 'AMR-1111-2222',
        targetAgentId: 'AMR-3333-4444',
        summary: 'Direct connection channel established with peer',
        timestamp: new Date().toISOString(),
      },
      {
        id: 'act_002',
        type: 'cluster.message_dispatched',
        actorAgentId: 'AMR-1111-2222',
        summary: 'Encrypted message broadcast to cluster_987654',
        timestamp: new Date().toISOString(),
      },
    ],
  };
}

export function createMockFetch(store: MockDataStore = createMockDataStore()): typeof fetch {
  let currentAgentId = store.agents[0]?.agentId || 'AMR-1111-2222';

  store.gatewayTokens = store.gatewayTokens || {};
  store.gatewayUsedNonces = store.gatewayUsedNonces || {};
  store.gatewayExecutedMcpCalls = store.gatewayExecutedMcpCalls || [];
  store.directMcpCalls = store.directMcpCalls || [];
  store.internalMcpServers = store.internalMcpServers || {
    mcp_srv_sec_edgar: {
      serverUrl: 'https://external-sec-mcp.internal.example/rpc',
      authHeader: 'Bearer mcp_secret_credential_never_exposed_to_adk',
      internalSecret: 'gw_internal_secret_sec_edgar',
    },
    mcp_srv_market_depth: {
      serverUrl: 'https://external-depth-mcp.internal.example/rpc',
      authHeader: 'Bearer mcp_secret_depth_never_exposed_to_adk',
      internalSecret: 'gw_internal_secret_depth',
    },
  };

  if (!store.trustedGatewayKeys) {
    const gwKp = generateECKeyPair();
    const aamarvaKp = generateECKeyPair();
    const gwPubJwk = exportPublicKeyJWK(gwKp.publicKey);
    const aamarvaPubJwk = exportPublicKeyJWK(aamarvaKp.publicKey);
    const gatewayId = 'gw_primary_01';
    const gatewayKeyId = 'gw_sig_key_01';
    const gatewayUrl = 'https://aamarva.com/api/gateway';
    store.trustedGatewayKeys = {
      gatewayId,
      gatewayKeyId,
      gatewayUrl,
      gatewayPrivateKey: gwKp.privateKey,
      gatewayPublicJwk: gwPubJwk,
      aamarvaPrivateKey: aamarvaKp.privateKey,
      aamarvaPublicJwk: aamarvaPubJwk,
      gatewayKeys: {
        [gatewayKeyId]: gwPubJwk,
        [gatewayId]: gwPubJwk,
      },
    };
  }
  const gwState = store.trustedGatewayKeys;

  const resolveAgentName = (targetId: string): string => {
    const norm = normalizeAgentId(targetId);
    const found = store.agents.find((a) => normalizeAgentId(a.agentId) === norm);
    return found?.name?.trim() || `Agent ${targetId}`;
  };

  const resolveAgentIdentityPublicKey = (targetId: string): ECJWK | undefined => {
    const norm = normalizeAgentId(targetId);
    const candidates = [
      store.e2eeKeys[targetId],
      store.e2eeKeys[norm],
      store.e2eeKeys[`peer:${targetId}`],
      store.e2eeKeys[`peer:${norm}`],
    ];
    for (const rec of candidates) {
      const candidate = rec?.identityKey || rec?.publicKey || rec?.peerIdentityKey || rec?.peerE2eePublicKey;
      if (
        candidate &&
        typeof candidate === 'object' &&
        candidate.kty === 'EC' &&
        candidate.crv === 'P-256' &&
        typeof candidate.x === 'string' &&
        candidate.x !== 'mock_x' &&
        typeof candidate.y === 'string' &&
        candidate.y !== 'mock_y'
      ) {
        return candidate as ECJWK;
      }
    }
    return undefined;
  };

  // Internal Three-Party Boundary: AAMARVA forwards ONLY the 4-field AamarvaIdentityAssertion
  // to the MCP Gateway, which verifies AAMARVA's signature, mints a short-lived token,
  // HPKE-encrypts it to the agent's P-256 public key, and returns the signed envelope for relay.
  const issueGatewayEnvelopeFromAssertion = async (
    assertion: AamarvaIdentityAssertion,
    ctx: {
      mcpServerId: string;
      toolId: string;
      approvedArgs: Record<string, unknown>;
      approvedArgsDigest: string;
      scope: string | string[];
    }
  ) => {
    if (!verifyAamarvaIdentityAssertion(gwState.aamarvaPublicJwk, assertion)) {
      throw new Error('AAMARVA identity assertion signature verification failed.');
    }
    const normAgent = normalizeAgentId(assertion.agentId);
    const agentName = String(assertion.agentName || '').trim();
    if (!normAgent || !agentName || !assertion.agentPublicKey || assertion.agentPublicKey.crv !== 'P-256') {
      throw new Error('Invalid identity fields supplied to gateway.');
    }

    const rawToken = 'gw_tok_' + crypto.randomBytes(24).toString('base64url');
    const tokenId = 'tokid_' + crypto.randomBytes(8).toString('hex');
    const iat = new Date().toISOString();
    const tokenExp = new Date(Date.now() + 300_000).toISOString();
    const agentPublicKeyFingerprint = computeKeyFingerprint(assertion.agentPublicKey);

    const tokenPayload: DecryptedGatewayTokenPayload = {
      version: GATEWAY_PROTOCOL_VERSION,
      token: rawToken,
      tokenId,
      gatewayId: gwState.gatewayId,
      gatewayUrl: gwState.gatewayUrl,
      agentId: assertion.agentId,
      agentName,
      agentPublicKeyFingerprint,
      mcpServerId: ctx.mcpServerId,
      toolId: ctx.toolId,
      approvedArgsDigest: ctx.approvedArgsDigest,
      scope: ctx.scope,
      iat,
      exp: tokenExp,
    };

    const gatewayEnvelope = await sealGatewayTokenEnvelope({
      tokenPayload,
      agentPublicKey: assertion.agentPublicKey,
      gatewaySigningPrivateKey: gwState.gatewayPrivateKey,
      gatewayKeyId: gwState.gatewayKeyId,
      gatewayPublicKey: gwState.gatewayPublicJwk,
    });

    const tokenHash = sha256Hex(rawToken);
    store.gatewayTokens![tokenHash] = {
      tokenHash,
      tokenId,
      used: false,
      exp: tokenExp,
      gatewayId: gwState.gatewayId,
      agentId: assertion.agentId,
      agentName,
      agentPublicKey: assertion.agentPublicKey,
      agentPublicKeyFingerprint,
      mcpServerId: ctx.mcpServerId,
      toolId: ctx.toolId,
      approvedArgsDigest: ctx.approvedArgsDigest,
      scope: ctx.scope,
    };

    return {
      gatewayEnvelope,
      gatewayId: gwState.gatewayId,
      gatewayUrl: gwState.gatewayUrl,
      expiresAt: tokenExp,
      agentPublicKeyFingerprint,
    };
  };

  const ensurePeerKeyForAgent = (agentId: string) => {
    const existing = store.e2eeKeys[`peer:${agentId}`] || store.e2eeKeys[agentId];
    if (existing) {
      if (existing.peerE2eePublicKey) return existing;
      if (existing.publicKey) {
        return {
          peerE2eePublicKey: existing.publicKey,
          peerKeyFingerprint: existing.fingerprint,
          peerIdentityKey: existing.identityKey || existing.publicKey,
          peerKeySignature: existing.signature,
          peerKeyEpoch: existing.keyEpoch || 1,
          peerAgentId: agentId,
          publicKey: existing.publicKey,
          fingerprint: existing.fingerprint,
          identityKey: existing.identityKey || existing.publicKey,
          signature: existing.signature,
          keyEpoch: existing.keyEpoch || 1,
          agentId,
        };
      }
    }
    const peerKp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const peerJwk = exportPublicKeyJWK(peerKp.publicKey);
    const peerFp = computeKeyFingerprint(peerJwk);
    const peerSig = signIdentityBinding(peerKp.privateKey, agentId, peerFp);
    const record = {
      peerE2eePublicKey: peerJwk,
      peerKeyFingerprint: peerFp,
      peerIdentityKey: peerJwk,
      peerKeySignature: peerSig,
      peerKeyEpoch: 1,
      peerAgentId: agentId,
      publicKey: peerJwk,
      fingerprint: peerFp,
      identityKey: peerJwk,
      signature: peerSig,
      keyEpoch: 1,
      agentId,
    };
    store.e2eeKeys[`peer:${agentId}`] = record;
    return record;
  };

  return (async (input: unknown, init?: RequestInit): Promise<Response> => {
    const urlStr = typeof input === 'string' ? input : (input instanceof URL ? input.toString() : (input as { url?: string })?.url || String(input));
    const url = new URL(urlStr, 'https://aamarva.com');
    const method = (init?.method || 'GET').toUpperCase();
    const pathname = url.pathname.replace('/api', '');

    let targetAgentHeader = '';
    if (init?.headers) {
      if (typeof (init.headers as Headers).get === 'function') {
        targetAgentHeader = (init.headers as Headers).get('x-target-agent-id') || '';
      } else if (Array.isArray(init.headers)) {
        const found = init.headers.find(([k]) => k.toLowerCase() === 'x-target-agent-id');
        if (found) targetAgentHeader = found[1];
      } else {
        for (const [k, v] of Object.entries(init.headers as Record<string, string>)) {
          if (k.toLowerCase() === 'x-target-agent-id') {
            targetAgentHeader = String(v || '');
            break;
          }
        }
      }
    }
    const effectiveAgentId = (currentAgentId || targetAgentHeader || 'AMR-1111-2222').trim();

    let body: Record<string, unknown> | null = null;
    if (init?.body && typeof init.body === 'string') {
      try {
        body = JSON.parse(init.body);
      } catch {
        body = { raw: init.body };
      }
    }

    const json = (status: number, data: unknown) =>
      new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json' },
      });

    // Direct external MCP endpoint access is forbidden; only internal gateway executes external MCP calls
    if (pathname === '/mcp' || (body as any)?.method === 'tools/call' || url.hostname.includes('external-sec-mcp') || url.hostname.includes('external-depth-mcp')) {
      store.directMcpCalls!.push({ url: url.toString(), method, body });
      return json(403, {
        success: false,
        code: 'DIRECT_MCP_FORBIDDEN',
        error: 'Direct external MCP access is forbidden. Requests must traverse the AAMARVA MCP Adapter Gateway.',
      });
    }

    // Health
    if (pathname === '/health' || pathname === '/adk') {
      return json(200, {
        success: true,
        data: {
          adk_version: '1.0.0',
          api_version: 'v1',
          base_url: 'https://aamarva.com/api',
          status: 'ok',
          timestamp: new Date().toISOString(),
        },
      });
    }

    // Auth Register
    if (pathname === '/auth/register' && method === 'POST') {
      const { email, name, bio } = (body || {}) as { email?: string; name?: string; bio?: string };
      const newAgent: Agent = {
        agentId: 'AMR-' + Math.random().toString(36).substring(2, 6).toUpperCase() + '-' + Math.random().toString(36).substring(2, 6).toUpperCase(),
        name: name || 'New Agent',
        email,
        bio,
        status: 'active',
        createdAt: new Date().toISOString(),
      };
      store.agents.push(newAgent);
      return json(201, {
        success: true,
        data: {
          agent: newAgent,
          apiKey: 'sk_amr_mock_' + Math.random().toString(36).substring(2, 12),
          tokens: {
            accessToken: 'mock_access_token_' + Date.now(),
            refreshToken: 'mock_refresh_token_' + Date.now(),
          },
        },
      });
    }

    // Auth Login
    if (pathname === '/auth/login' && method === 'POST') {
      const { agentId, apiKey } = (body || {}) as { agentId?: string; apiKey?: string };
      if (!agentId || !apiKey) {
        return json(401, { success: false, error: 'Invalid credentials' });
      }
      currentAgentId = String(agentId).trim();
      return json(200, {
        success: true,
        data: {
          tokens: {
            accessToken: 'mock_access_token_' + Date.now(),
            refreshToken: 'mock_refresh_token_' + Date.now(),
          },
        },
      });
    }

    // Auth Refresh
    if (pathname === '/auth/refresh' && method === 'POST') {
      return json(200, {
        success: true,
        data: {
          accessToken: 'refreshed_access_token_' + Date.now(),
          refreshToken: 'refreshed_refresh_token_' + Date.now(),
        },
      });
    }

    // Auth Logout
    if (pathname === '/auth/logout' && method === 'POST') {
      return json(200, { success: true, message: 'Logged out successfully' });
    }

    // Auth Check Email
    if (pathname === '/auth/check-email' && method === 'POST') {
      const { email } = (body || {}) as { email?: string };
      const exists = store.agents.some((a) => a.email === email);
      return json(200, { success: true, data: { exists, available: !exists } });
    }

    // Auth Rotate API Key
    if (pathname === '/auth/agent/rotate-api-key' && method === 'POST') {
      return json(200, {
        success: true,
        data: {
          apiKey: 'sk_amr_rotated_' + Math.random().toString(36).substring(2, 12),
          agentId: store.agents[0]?.agentId || 'AMR-1111-2222',
        },
      });
    }

    // Agent Profile: Me
    if (pathname === '/agents/me') {
      if (method === 'GET') {
        const agent = store.agents[0] || { agentId: 'AMR-1111-2222', name: 'Mock Agent' };
        return json(200, { success: true, data: agent });
      }
      if (method === 'PATCH') {
        const hdrs = init?.headers;
        const targetHeader =
          hdrs instanceof Headers
            ? hdrs.get('x-target-agent-id')
            : Array.isArray(hdrs)
            ? hdrs.find(([k]) => k.toLowerCase() === 'x-target-agent-id')?.[1]
            : (hdrs as Record<string, string> | undefined)?.['x-target-agent-id'];
        if (body?.avatar !== undefined && targetHeader) {
          return json(403, { success: false, error: 'Slave accounts cannot update avatar.' });
        }
        const agent = store.agents[0];
        if (agent) {
          if (body?.name !== undefined) agent.name = String(body.name);
          if (body?.bio !== undefined) agent.bio = String(body.bio);
          if (body?.avatar !== undefined) agent.avatar = String(body.avatar);
        }
        return json(200, { success: true, data: agent });
      }
      if (method === 'DELETE') {
        return json(200, { success: true, message: 'Account deleted' });
      }
    }

    // Agents List
    if (pathname === '/agents' && method === 'GET') {
      let result = [...store.agents];
      const q = url.searchParams.get('q');
      if (q) {
        result = result.filter(a => a.name?.toLowerCase().includes(q.toLowerCase()) || a.agentId?.toLowerCase().includes(q.toLowerCase()));
      }
      const page = parseInt(url.searchParams.get('page') || '1', 10);
      const limit = parseInt(url.searchParams.get('limit') || '50', 10);
      return json(200, {
        success: true,
        data: {
          agents: result,
          total: result.length,
          page,
          limit,
        },
      });
    }

    // Register or Get local E2EE key (AAMARVA-managed P-256 identity public key)
    if (pathname === '/agents/me/e2ee') {
      if (method === 'GET') {
        const keyData =
          store.e2eeKeys[effectiveAgentId] ||
          store.e2eeKeys[normalizeAgentId(effectiveAgentId)] ||
          (!targetAgentHeader ? store.e2eeKeys[store.agents[0]?.agentId || 'AMR-1111-2222'] : undefined) || {
            publicKey: { kty: 'EC', crv: 'P-256', x: 'mock_x', y: 'mock_y' },
            fingerprint: 'SHA256:mock_fp_123',
            identityKey: { kty: 'EC', crv: 'P-256', x: 'mock_x', y: 'mock_y' },
            allowRotation: true,
            keyEpoch: 1,
          };
        return json(200, { success: true, data: keyData });
      }
      if (method === 'PUT') {
        const normEff = normalizeAgentId(effectiveAgentId);
        store.e2eeKeys[effectiveAgentId] = body;
        store.e2eeKeys[normEff] = body;
        const peerRec = {
          ...(body || {}),
          peerE2eePublicKey: (body as any)?.publicKey,
          peerKeyFingerprint: (body as any)?.fingerprint,
          peerIdentityKey: (body as any)?.identityKey || (body as any)?.publicKey,
          peerKeySignature: (body as any)?.signature,
          peerKeyEpoch: (body as any)?.keyEpoch || 1,
          peerAgentId: effectiveAgentId,
          agentId: effectiveAgentId,
        };
        store.e2eeKeys[`peer:${effectiveAgentId}`] = peerRec;
        store.e2eeKeys[`peer:${normEff}`] = peerRec;
        return json(200, { success: true, message: 'E2EE key registered' });
      }
    }

    if (pathname === '/gateway/keys' && method === 'GET') {
      return json(200, {
        success: true,
        data: {
          gatewayKeys: gwState.gatewayKeys,
          defaultGatewayId: gwState.gatewayId,
          defaultGatewayUrl: gwState.gatewayUrl,
        },
      });
    }

    // Mandatory MCP Adapter Gateway: Token Redemption & External MCP Execution (POST /gateway/mcp)
    if (pathname === '/gateway/mcp' && method === 'POST') {
      const req = (body || {}) as Record<string, any>;
      if (req.version !== GATEWAY_PROTOCOL_VERSION || typeof req.token !== 'string' || !req.token.trim()) {
        return json(400, { success: false, code: 'TOKEN_INVALID', error: 'Malformed gateway redemption request.' });
      }

      const tokenHash = sha256Hex(req.token.trim());
      const record = store.gatewayTokens![tokenHash];
      if (!record) {
        return json(403, { success: false, code: 'TOKEN_INVALID', error: 'Unknown or invalid gateway token.' });
      }

      // Atomic single-use check BEFORE any async work
      if (record.used) {
        return json(409, { success: false, code: 'TOKEN_ALREADY_USED', error: 'Single-use gateway token has already been redeemed.' });
      }

      const expMs = Date.parse(record.exp);
      if (!record.exp || Number.isNaN(expMs) || expMs <= Date.now()) {
        return json(403, { success: false, code: 'GATEWAY_TOKEN_EXPIRED', error: 'Gateway execution token has expired.' });
      }

      const tsMs = Date.parse(String(req.timestamp || ''));
      if (!req.timestamp || Number.isNaN(tsMs) || Math.abs(Date.now() - tsMs) > 300_000) {
        return json(403, { success: false, code: 'GATEWAY_POP_INVALID', error: 'Redemption timestamp missing or outside replay window.' });
      }

      if (typeof req.nonce !== 'string' || !req.nonce.trim()) {
        return json(400, { success: false, code: 'GATEWAY_POP_INVALID', error: 'Redemption nonce is required.' });
      }
      if (store.gatewayUsedNonces![req.nonce]) {
        return json(409, { success: false, code: 'TOKEN_REPLAY_DETECTED', error: 'Duplicate redemption nonce rejected.' });
      }

      if (
        req.gatewayId !== record.gatewayId ||
        normalizeAgentId(String(req.agentId || '')) !== normalizeAgentId(record.agentId) ||
        req.mcpServerId !== record.mcpServerId ||
        req.toolId !== record.toolId
      ) {
        return json(403, { success: false, code: 'GATEWAY_BINDING_MISMATCH', error: 'Redemption request does not match token authorization bindings.' });
      }

      const reqArgs = req.arguments && typeof req.arguments === 'object' && !Array.isArray(req.arguments) ? req.arguments : null;
      if (!reqArgs || req.approvedArgsDigest !== record.approvedArgsDigest || computeArgsDigest(reqArgs) !== record.approvedArgsDigest) {
        return json(403, { success: false, code: 'GATEWAY_ARGS_MISMATCH', error: 'Redemption arguments do not match approved arguments digest.' });
      }

      const popValid = verifyGatewayPop(
        record.agentPublicKey,
        {
          version: req.version,
          tokenSha256: tokenHash,
          gatewayId: req.gatewayId,
          agentId: req.agentId,
          mcpServerId: req.mcpServerId,
          toolId: req.toolId,
          approvedArgsDigest: req.approvedArgsDigest,
          nonce: req.nonce,
          timestamp: req.timestamp,
        },
        req.proofOfPossession
      );
      if (!popValid) {
        return json(403, { success: false, code: 'GATEWAY_POP_INVALID', error: 'Proof-of-Possession signature verification failed.' });
      }

      // Mark token and nonce spent atomically
      record.used = true;
      store.gatewayUsedNonces![req.nonce] = true;

      // Server-side-only resolution of external MCP server URL and auth credentials (never sent to ADK)
      const mcpBackend = store.internalMcpServers![record.mcpServerId] || {
        serverUrl: 'https://external-mcp.internal.example/rpc',
        authHeader: 'Bearer mcp_secret_credential_never_exposed_to_adk',
        internalSecret: 'gw_internal_default',
      };

      store.gatewayExecutedMcpCalls!.push({
        mcpServerId: record.mcpServerId,
        toolId: record.toolId,
        arguments: JSON.parse(canonicalJsonStringify(reqArgs)),
        usedGatewayCredentials: Boolean(mcpBackend.authHeader && mcpBackend.internalSecret),
      });

      return json(200, {
        success: true,
        data: {
          status: 'approved',
          toolId: record.toolId,
          mcpServerId: record.mcpServerId,
          gatewayId: record.gatewayId,
          result: {
            content: [
              {
                type: 'text',
                text: JSON.stringify({
                  filings: [{ form: '10-K', year: 2026, ticker: reqArgs.ticker || 'AAPL' }],
                }),
              },
            ],
          },
        },
      });
    }

    // Watchtower Activity
    if (pathname === '/watchtower/activity' && method === 'GET') {
      return json(200, { success: true, data: store.watchtowerActivities });
    }

    // Watchtower Stream Ticket
    if (pathname === '/watchtower/stream-ticket' && method === 'POST') {
      return json(200, {
        success: true,
        data: {
          ticket: 'ticket_live_mock_' + Date.now(),
          expiresAt: new Date(Date.now() + 3600000).toISOString(),
        },
      });
    }

    // FLOOR Agent Tools
    if (pathname === '/floor/agent/tools' && method === 'GET') {
      return json(200, { success: true, data: store.floorTools });
    }

    // FLOOR Tool Invoke (Assignment check + HITL gate + AAMARVA->Gateway 4-field assertion relay)
    const floorInvokeMatch = pathname.match(/^\/floor\/tools\/([^/]+)\/invoke$/);
    if (floorInvokeMatch && method === 'POST') {
      const toolId = decodeURIComponent(floorInvokeMatch[1]);
      const tool = store.floorTools.find((t) => t.id === toolId);
      if (!tool) {
        return json(404, {
          success: false,
          error: 'FLOOR_TOOL_NOT_FOUND',
          message: `Tool ${toolId} not found.`,
        });
      }
      const toolStatus = (tool.accessStatus || '').toLowerCase();
      if (['revoked', 'denied', 'rejected'].includes(toolStatus)) {
        return json(403, {
          success: false,
          status: toolStatus,
          error: 'FLOOR_ACCESS_DENIED',
          message: `Access to tool ${toolId} is ${toolStatus}.`,
        });
      }
      const invocationId = 'inv_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6);
      const isApproved = toolStatus === 'authorized' || toolStatus === 'granted' || toolStatus === 'approved';
      const approvedArgs = (body?.arguments && typeof body.arguments === 'object' && !Array.isArray(body.arguments)
        ? body.arguments
        : {}) as Record<string, unknown>;
      const approvedArgsDigest = computeArgsDigest(approvedArgs);
      const mcpServerId = tool.mcpServerId || 'mcp_srv_sec_edgar';
      const agentName = resolveAgentName(effectiveAgentId);
      const scope = 'read:sec_edgar tool:invoke';

      if (!isApproved) {
        // Pending HITL approval: AAMARVA does NOT forward to Gateway or mint tokens
        store.floorInvocations[invocationId] = {
          invocationId,
          toolId,
          agentId: effectiveAgentId,
          agentName,
          mcpServerId,
          status: 'pending',
          arguments: approvedArgs,
          reason: body?.reason,
        };
        store.floorRequests[invocationId] = {
          requestId: invocationId,
          invocationId,
          agentId: effectiveAgentId,
          agentName,
          mcpServerId,
          status: 'pending',
          toolId,
          arguments: approvedArgs,
          approvedArguments: approvedArgs,
          approvedArgsDigest,
          scope,
          reason: body?.reason,
          createdAt: new Date().toISOString(),
        };
        return json(202, {
          success: true,
          status: 'pending',
          data: {
            invocationId,
            requestId: invocationId,
            toolId,
            agentId: effectiveAgentId,
            status: 'pending',
            message: 'Access request submitted for approval.',
          },
        });
      }

      // Tool is already assigned/authorized: AAMARVA looks up agent's P-256 identity key
      const agentPublicKey = resolveAgentIdentityPublicKey(effectiveAgentId);
      if (!agentPublicKey) {
        return json(403, {
          success: false,
          code: 'AGENT_IDENTITY_KEY_UNAVAILABLE',
          error: `Agent ${effectiveAgentId} does not have a registered AAMARVA P-256 identity public key.`,
        });
      }

      const assertionUnsigned = {
        agentPublicKey,
        agentId: effectiveAgentId,
        agentName,
      };
      const assertion: AamarvaIdentityAssertion = {
        ...assertionUnsigned,
        signature: signAamarvaIdentityAssertion(gwState.aamarvaPrivateKey, assertionUnsigned),
      };

      const gwRelay = await issueGatewayEnvelopeFromAssertion(assertion, {
        mcpServerId,
        toolId,
        approvedArgs,
        approvedArgsDigest,
        scope,
      });

      const relayRecord = {
        status: 'approved',
        requestId: invocationId,
        invocationId,
        toolId,
        agentId: effectiveAgentId,
        agentName,
        mcpServerId,
        gatewayId: gwRelay.gatewayId,
        gatewayUrl: gwRelay.gatewayUrl,
        approvedArgsDigest,
        approvedArguments: approvedArgs,
        scope,
        expiresAt: gwRelay.expiresAt,
        verificationInfo: {
          verified: true,
          toolId,
          agentId: effectiveAgentId,
        },
        gatewayEnvelope: gwRelay.gatewayEnvelope,
      };

      store.floorInvocations[invocationId] = {
        ...relayRecord,
        arguments: approvedArgs,
        reason: body?.reason,
      };
      store.floorRequests[invocationId] = {
        ...relayRecord,
        reason: body?.reason,
        createdAt: new Date().toISOString(),
      };

      // Strictly NO external MCP serverUrl and NO external MCP auth/credentials returned!
      return json(200, {
        success: true,
        status: 'approved',
        data: {
          ...relayRecord,
          message: 'Invocation authorized.',
        },
      });
    }

    // FLOOR Request Status (with lazy AAMARVA->Gateway relay when human approves HITL request)
    const floorRequestMatch = pathname.match(/^\/floor\/requests\/([^/]+)$/);
    if (floorRequestMatch && method === 'GET') {
      const reqId = decodeURIComponent(floorRequestMatch[1]);
      const reqData = store.floorRequests[reqId];
      if (!reqData) {
        return json(404, {
          success: false,
          error: 'FLOOR_REQUEST_NOT_FOUND',
          message: `Access request ${reqId} not found.`,
        });
      }

      if (String(reqData.status || '').toLowerCase() === 'approved' && !reqData.gatewayEnvelope) {
        const authorizedAgent = String(reqData.agentId || effectiveAgentId).trim();
        const agentPublicKey = resolveAgentIdentityPublicKey(authorizedAgent);
        if (!agentPublicKey) {
          return json(403, {
            success: false,
            code: 'AGENT_IDENTITY_KEY_UNAVAILABLE',
            error: `Agent ${authorizedAgent} does not have a registered AAMARVA P-256 identity public key.`,
          });
        }
        const tool = store.floorTools.find((t) => t.id === reqData.toolId);
        const mcpServerId = String(reqData.mcpServerId || tool?.mcpServerId || 'mcp_srv_sec_edgar');
        const approvedArgs = (reqData.approvedArguments || reqData.arguments || {}) as Record<string, unknown>;
        const approvedArgsDigest = reqData.approvedArgsDigest || computeArgsDigest(approvedArgs);
        const agentName = String(reqData.agentName || resolveAgentName(authorizedAgent));
        const scope = reqData.scope || 'read:sec_edgar tool:invoke';

        const assertionUnsigned = {
          agentPublicKey,
          agentId: authorizedAgent,
          agentName,
        };
        const assertion: AamarvaIdentityAssertion = {
          ...assertionUnsigned,
          signature: signAamarvaIdentityAssertion(gwState.aamarvaPrivateKey, assertionUnsigned),
        };

        const gwRelay = await issueGatewayEnvelopeFromAssertion(assertion, {
          mcpServerId,
          toolId: reqData.toolId,
          approvedArgs,
          approvedArgsDigest,
          scope,
        });

        reqData.agentId = authorizedAgent;
        reqData.agentName = agentName;
        reqData.mcpServerId = mcpServerId;
        reqData.gatewayId = gwRelay.gatewayId;
        reqData.gatewayUrl = gwRelay.gatewayUrl;
        reqData.approvedArgsDigest = approvedArgsDigest;
        reqData.approvedArguments = approvedArgs;
        reqData.scope = scope;
        reqData.expiresAt = gwRelay.expiresAt;
        reqData.verificationInfo = {
          verified: true,
          toolId: reqData.toolId,
          agentId: authorizedAgent,
        };
        reqData.gatewayEnvelope = gwRelay.gatewayEnvelope;
      }

      return json(200, { success: true, data: reqData });
    }

    // Footprints & Webhook events
    if (pathname === '/agent/footprints' && method === 'GET') {
      return json(200, { success: true, data: [] });
    }
    if (pathname === '/webhooks/events' && method === 'GET') {
      return json(200, { success: true, data: [] });
    }

    // Connections List
    if (pathname === '/connections' && method === 'GET') {
      const pageParam = url.searchParams.get('page');
      const limitParam = url.searchParams.get('limit');
      let result = [...store.connections];
      if (pageParam || limitParam) {
        const page = Math.max(1, parseInt(pageParam || '1', 10) || 1);
        const limit = Math.max(1, parseInt(limitParam || String(result.length || 20), 10) || 20);
        const start = (page - 1) * limit;
        result = result.slice(start, start + limit);
      }
      return json(200, { success: true, data: result });
    }

    // Single Connection details or close
    const connMatch = pathname.match(/^\/connections\/([^/]+)$/);
    if (connMatch) {
      const connectionId = connMatch[1];
      if (method === 'GET') {
        const conn = store.connections.find((c) => c.connectionId === connectionId) || {
          connectionId,
          agentId: 'AMR-1111-2222',
          connectedAgentName: 'Financial Analysis Agent',
          status: 'active',
          createdAt: new Date().toISOString(),
        };
        return json(200, { success: true, data: conn });
      }
      if (method === 'DELETE') {
        store.connections = store.connections.filter((c) => c.connectionId !== connectionId);
        return json(200, { success: true, message: 'Connection dissolved' });
      }
    }

    // Agent Peer Key Lookup Endpoint: GET /connections/peer-key/:agentId
    const agentPeerKeyMatch = pathname.match(/^\/connections\/peer-key\/([^/]+)$/);
    if (agentPeerKeyMatch && method === 'GET') {
      const targetAgentId = decodeURIComponent(agentPeerKeyMatch[1]);
      return json(200, {
        success: true,
        data: ensurePeerKeyForAgent(targetAgentId),
      });
    }

    // Connection Peer Key Endpoint: GET /connections/:connectionId/peer-key
    const peerKeyMatch = pathname.match(/^\/connections\/([^/]+)\/peer-key$/);
    if (peerKeyMatch && method === 'GET') {
      const connectionId = peerKeyMatch[1];
      const conn = store.connections.find((c) => c.connectionId === connectionId);
      const peerAgentId = conn?.agentId || 'AMR-PEER-ECDH';

      if (!store.e2eeKeys[connectionId]) {
        store.e2eeKeys[connectionId] = ensurePeerKeyForAgent(peerAgentId);
      }

      return json(200, {
        success: true,
        data: store.e2eeKeys[connectionId],
      });
    }

    // Connection Messages
    const connMessagesMatch = pathname.match(/^\/connections\/([^/]+)\/messages$/);
    if (connMessagesMatch) {
      const connectionId = connMessagesMatch[1];
      if (method === 'GET') {
        return json(200, { success: true, data: store.messages[connectionId] || [] });
      }
      if (method === 'POST') {
        const newMsg = {
          messageId: 'msg_' + Math.random().toString(36).substring(2, 9),
          connectionId,
          senderAgentId: String(body?.senderAgentId || currentAgentId || 'AMR-1111-2222'),
          ciphertext: body?.ciphertext,
          nonce: body?.nonce,
          version: body?.version || 1,
          keyEpoch: body?.keyEpoch || 1,
          createdAt: new Date().toISOString(),
        };
        if (!store.messages[connectionId]) {
          store.messages[connectionId] = [];
        }
        store.messages[connectionId].push(newMsg);
        return json(201, { success: true, data: newMsg });
      }
    }

    // Clusters
    if (pathname === '/clusters') {
      if (method === 'GET') {
        return json(200, { success: true, data: store.clusters });
      }
      if (method === 'POST') {
        const newCluster: Cluster = {
          id: 'cluster_' + Math.random().toString(36).substring(2, 8),
          clusterId: 'cluster_' + Math.random().toString(36).substring(2, 8),
          name: String(body?.name || 'New Cluster'),
          description: String(body?.description || ''),
          members: Array.isArray(body?.members) ? body.members.map(String) : [],
          createdAt: new Date().toISOString(),
        };
        store.clusters.push(newCluster);
        return json(201, { success: true, data: newCluster });
      }
    }

    // Single Cluster
    const clusterMatch = pathname.match(/^\/clusters\/([^/]+)$/);
    if (clusterMatch) {
      const clusterId = clusterMatch[1];
      if (method === 'GET') {
        const c = store.clusters.find((cl) => cl.id === clusterId || cl.clusterId === clusterId);
        return json(200, { success: true, data: c || { clusterId, name: 'Cluster' } });
      }
      if (method === 'PATCH') {
        const c = store.clusters.find((cl) => cl.id === clusterId || cl.clusterId === clusterId);
        if (c && body?.name) c.name = String(body.name);
        return json(200, { success: true, data: c });
      }
      if (method === 'DELETE') {
        store.clusters = store.clusters.filter((cl) => cl.id !== clusterId && cl.clusterId !== clusterId);
        return json(200, { success: true, message: 'Cluster disbanded' });
      }
    }

    // Public Cluster Members
    const clusterMembersMatch = pathname.match(/^\/clusters\/public\/([^/]+)\/members$/);
    if (clusterMembersMatch && method === 'GET') {
      const clusterId = decodeURIComponent(clusterMembersMatch[1]);
      const cluster = store.clusters.find((cl) => cl.id === clusterId || cl.clusterId === clusterId);
      const memberIds =
        store.clusterMembers[clusterId] ||
        (Array.isArray(cluster?.members) ? cluster!.members.map((m: any) => (typeof m === 'string' ? m : m.agentId)) : []);
      const members = memberIds.map((aid) => {
        const pk = ensurePeerKeyForAgent(aid);
        return {
          agentId: aid,
          role: 'member',
          status: 'active',
          publicKey: pk.publicKey,
          keyFingerprint: pk.fingerprint,
          keyEpoch: pk.keyEpoch || 1,
        };
      });
      return json(200, { success: true, data: members });
    }

    // Rotate Cluster Key
    const clusterRotateMatch = pathname.match(/^\/clusters\/([^/]+)\/rotate-key$/);
    if (clusterRotateMatch && method === 'POST') {
      const clusterId = decodeURIComponent(clusterRotateMatch[1]);
      const cluster = store.clusters.find((cl) => cl.id === clusterId || cl.clusterId === clusterId);
      const nextEpoch = Number(cluster?.epoch || cluster?.keyEpoch || 1) + 1;
      if (cluster) {
        cluster.epoch = nextEpoch;
        cluster.keyEpoch = nextEpoch;
        cluster.rotationStatus = 'NONE';
      }
      return json(200, {
        success: true,
        data: {
          clusterId,
          epoch: nextEpoch,
          keyEpoch: nextEpoch,
          rotationStatus: 'NONE',
          rotatedAt: new Date().toISOString(),
        },
      });
    }

    // Cluster Messages
    const clusterMessagesMatch = pathname.match(/^\/clusters\/([^/]+)\/messages$/);
    if (clusterMessagesMatch) {
      const clusterId = clusterMessagesMatch[1];
      if (method === 'GET') {
        return json(200, { success: true, data: store.clusterMessages[clusterId] || [] });
      }
      if (method === 'POST') {
        const senderAgentId = String(body?.senderAgentId || currentAgentId || 'AMR-1111-2222');
        const keyEpoch = Number(body?.keyEpoch || 1);
        const audienceHash = String(body?.audienceHash || 'ALL');
        if (body?.strictPreflight === true) {
          const distKey = `${clusterId}:${keyEpoch}:${audienceHash}`;
          const sealed = store.clusterKeyDistributions?.[distKey];
          if (sealed) {
            if (sealed.keyFingerprint && body?.keyFingerprint && sealed.keyFingerprint !== body.keyFingerprint) {
              return json(400, {
                success: false,
                code: 'PREFLIGHT_KEY_FINGERPRINT_MISMATCH',
                error: 'Key fingerprint does not match sealed cluster key for this epoch/audience.',
              });
            }
            if (sealed.rosterHash && body?.rosterHash && sealed.rosterHash !== body.rosterHash) {
              return json(409, {
                success: false,
                code: 'ROSTER_HASH_MISMATCH',
                error: 'Roster hash mismatch; cluster membership changed.',
              });
            }
          }
        }

        const msg = {
          messageId: 'msg_cl_' + Date.now(),
          clusterId,
          senderAgentId,
          ciphertext: body?.ciphertext,
          nonce: body?.nonce,
          version: body?.version || 1,
          keyEpoch,
          audienceHash: body?.audienceHash,
          rosterHash: body?.rosterHash,
          keyFingerprint: body?.keyFingerprint,
          signature: body?.signature,
          sequence: body?.sequence,
          recipients: body?.recipients,
          recipientAgentIds: body?.recipientAgentIds,
          createdAt: new Date().toISOString(),
        };
        if (!store.clusterMessages[clusterId]) {
          store.clusterMessages[clusterId] = [];
        }
        store.clusterMessages[clusterId].push(msg);
        return json(201, { success: true, messageId: msg.messageId, data: msg });
      }
    }

    // Cluster Key Distribution
    const clusterKeyDistMatch = pathname.match(/^\/clusters\/([^/]+)\/key-distribution$/);
    if (clusterKeyDistMatch) {
      const clusterId = clusterKeyDistMatch[1];
      if (method === 'POST') {
        store.clusterKeyDistributions = store.clusterKeyDistributions || {};
        const epoch = Number(body?.epoch || 1);
        const audienceHash = String(body?.audienceHash || 'ALL');
        const scopedKey = `${clusterId}:${epoch}:${audienceHash}`;
        const existing = store.clusterKeyDistributions[scopedKey];
        if (
          existing &&
          existing.keyFingerprint &&
          body?.keyFingerprint &&
          existing.keyFingerprint !== body.keyFingerprint
        ) {
          return json(409, {
            success: false,
            code: 'EPOCH_KEY_ALREADY_SEALED',
            error: 'EPOCH_KEY_ALREADY_SEALED',
            message: `Epoch key ${epoch} for scope ${audienceHash} is already sealed.`,
          });
        }
        store.clusterKeyDistributions[scopedKey] = body;
        store.clusterKeyDistributions[clusterId] = body;
        return json(200, {
          success: true,
          data: {
            clusterId,
            epoch,
            audienceHash,
            status: 'distributed',
          },
        });
      }
      if (method === 'GET') {
        const epochStr = url.searchParams.get('epoch');
        const audienceHash = url.searchParams.get('audienceHash');
        const epoch = epochStr ? parseInt(epochStr, 10) : 1;
        const scopedKey = `${clusterId}:${epoch}:${audienceHash || 'ALL'}`;
        const saved = store.clusterKeyDistributions?.[scopedKey];
        if (!saved) {
          return json(404, {
            success: false,
            code: 'CLUSTER_KEY_MISSING',
            error: `No cluster key distribution found for ${clusterId} at epoch ${epoch}.`,
          });
        }
        const pkgs: any[] = Array.isArray(saved?.keyPackages) ? saved.keyPackages : [];
        const matchingPkg =
          pkgs.find((p) => String(p.recipientAgentId || '').toUpperCase() === currentAgentId.toUpperCase()) ||
          pkgs[0];
        return json(200, {
          success: true,
          data: {
            clusterId,
            epoch,
            ...(audienceHash ? { audienceHash } : saved?.audienceHash ? { audienceHash: saved.audienceHash } : {}),
            ...(saved?.rosterHash ? { rosterHash: saved.rosterHash } : {}),
            keyFingerprint: saved?.keyFingerprint || matchingPkg?.keyFingerprint || 'SHA256:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00',
            senderAgentId: saved?.senderAgentId || 'AMR-0000-MASTER',
            recipientAgentId: matchingPkg?.recipientAgentId || currentAgentId || 'AMR-1111-2222',
            wrappingParams: matchingPkg?.wrappingParams || { alg: 'ECDH-ES+A256KW' },
            encryptedKeyPackage: matchingPkg?.encryptedKeyPackage || 'mock_wrapped_group_key_base64',
            nonce: matchingPkg?.nonce || 'mock_nonce_b64',
          },
        });
      }
    }

    return json(404, { success: false, error: `Mock endpoint not found: ${method} ${pathname}` });
  }) as typeof fetch;
}
