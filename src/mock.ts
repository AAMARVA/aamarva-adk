/**
 * Offline Mock transport and testing utilities for AAMARVA fleet agent development.
 * Aligned with canonical AAMARVA Platform Core API endpoints and cryptographic contracts.
 */

import crypto from 'crypto';
import {
  Agent,
  Connection,
  Cluster,
  FloorTool,
  WatchtowerActivity,
} from './types.js';
import {
  exportPublicKeyJWK,
  computeKeyFingerprint,
  signIdentityBinding,
} from './crypto.js';

export interface MockDataStore {
  agents: Agent[];
  connections: Connection[];
  messages: Record<string, any[]>;
  e2eeKeys: Record<string, any>;
  peerKeys: Record<string, any>;
  clusters: Cluster[];
  clusterMembers: Record<string, string[]>;
  clusterMessages: Record<string, any[]>;
  clusterKeyDistributions?: Record<string, any>;
  floorTools: FloorTool[];
  floorRequests: Record<string, any>;
  floorInvocations: Record<string, any>;
  mcpServerUrl?: string;
  watchtowerActivities: WatchtowerActivity[];
  footprints?: any[];
  webhookEvents?: any[];
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
        masterId: 'AMR-0000-MASTER',
      },
      {
        agentId: 'AMR-5555-6666',
        name: 'Data Extraction Agent',
        bio: 'ETL pipelines and document parsing.',
        email: 'etl-agent@example.com',
        status: 'active',
        masterId: 'AMR-0000-MASTER',
      },
    ],
    connections: [
      {
        connectionId: 'conn_mock_123',
        agentId: 'AMR-3333-4444',
        peerAccountId: 'AMR-3333-4444',
        peerAgentId: 'AMR-3333-4444',
        connectedAgentName: 'Code Review & QA Agent',
        status: 'active',
        createdAt: new Date().toISOString(),
      },
    ],
    messages: {
      conn_mock_123: [],
    },
    e2eeKeys: {},
    peerKeys: {},
    clusters: [
      {
        id: 'cluster_987654',
        clusterId: 'cluster_987654',
        name: 'Market Arbitrage Cluster',
        description: 'Consensus on L2 liquidity arbitrage opportunities.',
        ownerUserId: 'usr_abc123',
        ownerAgentId: 'AMR-1111-2222',
        membersCount: 2,
        epoch: 1,
        members: ['AMR-1111-2222', 'AMR-5555-6666'],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
    ],
    clusterMembers: {
      cluster_987654: ['AMR-1111-2222', 'AMR-5555-6666'],
    },
    clusterMessages: {
      cluster_987654: [],
    },
    floorTools: [
      {
        id: 'tool_sec_edgar',
        serverId: 'srv_mock_sec',
        serverName: 'SEC EDGAR MCP Server',
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
        authType: 'bearer',
        authHeaderName: 'Authorization',
        serverUrl: 'https://aamarva.com/api/mcp',
      },
      {
        id: 'tool_market_depth',
        serverId: 'srv_mock_depth',
        serverName: 'Market Depth MCP Server',
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
        authType: 'bearer',
        authHeaderName: 'Authorization',
        serverUrl: 'https://aamarva.com/api/mcp',
      },
    ],
    floorRequests: {
      req_tool_001: {
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
    footprints: [],
    webhookEvents: [],
  };
}

function getHeaderValue(
  headers: RequestInit['headers'],
  name: string
): string | undefined {
  if (!headers) return undefined;
  const target = name.toLowerCase();
  if (typeof Headers !== 'undefined' && headers instanceof Headers) {
    return headers.get(name) ?? undefined;
  }
  if (Array.isArray(headers)) {
    for (const [k, v] of headers) {
      if (String(k).toLowerCase() === target) return String(v);
    }
    return undefined;
  }
  for (const [k, v] of Object.entries(headers as Record<string, unknown>)) {
    if (k.toLowerCase() === target) {
      return Array.isArray(v) ? String(v[0]) : String(v);
    }
  }
  return undefined;
}

function ensurePeerIdentityRecord(store: MockDataStore, peerAgentId: string, connectionId: string) {
  if (!store.peerKeys[peerAgentId]) {
    const ecdhKp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const identityKp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const peerJwk = exportPublicKeyJWK(ecdhKp.publicKey);
    const peerIdentityJwk = exportPublicKeyJWK(identityKp.publicKey);
    const peerFp = computeKeyFingerprint(peerJwk);
    const peerSig = signIdentityBinding(identityKp.privateKey, peerAgentId, peerFp);

    store.peerKeys[peerAgentId] = {
      connectionId,
      peerAccountId: peerAgentId,
      peerAgentId,
      peerE2eePublicKey: peerJwk,
      peerKeyFingerprint: peerFp,
      peerIdentityKey: peerIdentityJwk,
      peerKeySignature: peerSig,
      peerKeyEpoch: 1,
    };
  }
  return store.peerKeys[peerAgentId];
}

export function createMockFetch(store: MockDataStore = createMockDataStore()): typeof fetch {
  const tokenAgents = new Map<string, string>();
  const refreshAgents = new Map<string, string>();

  return (async (input: unknown, init?: RequestInit): Promise<Response> => {
    const urlStr =
      typeof input === 'string'
        ? input
        : input instanceof URL
        ? input.toString()
        : (input as { url?: string })?.url || String(input);
    const url = new URL(urlStr, 'https://aamarva.com');
    const method = (init?.method || 'GET').toUpperCase();
    const pathname = url.pathname.replace(/^\/api/, '');
    const targetAgentHeader = getHeaderValue(init?.headers, 'x-target-agent-id');
    const authHeader = getHeaderValue(init?.headers, 'authorization');
    const bearerToken = authHeader?.replace(/^Bearer\s+/i, '').trim();
    const tokenAgentId = bearerToken ? tokenAgents.get(bearerToken) : undefined;
    const callerAgentId = targetAgentHeader || tokenAgentId || store.agents[0]?.agentId || 'AMR-1111-2222';

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

    // External MCP JSON-RPC handler for simulated FLOOR execution
    if (
      pathname === '/mcp' ||
      (body as any)?.method === 'initialize' ||
      (body as any)?.method === 'notifications/initialized' ||
      (body as any)?.method === 'tools/list' ||
      (body as any)?.method === 'tools/call'
    ) {
      const rpcMethod = (body as any)?.method;
      if (rpcMethod === 'initialize') {
        return json(200, {
          jsonrpc: '2.0',
          id: (body as any)?.id ?? 1,
          result: {
            protocolVersion: '2024-11-05',
            capabilities: { tools: {} },
            serverInfo: { name: 'aamarva-mock-mcp', version: '2.0.0' },
          },
        });
      }
      if (rpcMethod === 'notifications/initialized') {
        return new Response(null, { status: 202 });
      }
      if (rpcMethod === 'tools/list') {
        return json(200, {
          jsonrpc: '2.0',
          id: (body as any)?.id ?? 1,
          result: {
            tools: store.floorTools.map((t) => ({
              name: t.id,
              description: t.description,
              inputSchema: t.inputSchema,
            })),
          },
        });
      }
      const toolArgs = (body as any)?.params?.arguments || {};
      return json(200, {
        jsonrpc: '2.0',
        id: (body as any)?.id || 1,
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                filings: [{ form: '10-K', year: 2026, ticker: toolArgs.ticker || 'AAPL' }],
              }),
            },
          ],
        },
      });
    }

    // ADK Spec Metadata
    if (pathname === '/adk' && method === 'GET') {
      return json(200, {
        success: true,
        data: {
          adk_version: '2.0.0',
          api_version: 'v1',
          base_url: 'https://aamarva.com/api',
          status: 'ok',
          timestamp: new Date().toISOString(),
          adk: { version: '2.0.0', protocol: 'aamarva-fleet' },
          openapi: { openapi: '3.0.0' },
        },
      });
    }

    // Auth Login
    if (pathname === '/auth/login' && method === 'POST') {
      const { agentId, apiKey } = (body || {}) as { agentId?: string; apiKey?: string };
      if (!agentId || !apiKey) {
        return json(401, { success: false, error: 'Invalid credentials' });
      }
      const accessToken = 'mock_access_token_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6);
      const refreshToken = 'mock_refresh_token_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6);
      tokenAgents.set(accessToken, agentId);
      refreshAgents.set(refreshToken, agentId);
      return json(200, {
        success: true,
        data: {
          tokens: {
            accessToken,
            refreshToken,
          },
        },
      });
    }

    // Auth Refresh
    if (pathname === '/auth/refresh' && method === 'POST') {
      const { refreshToken } = (body || {}) as { refreshToken?: string };
      if (!refreshToken) {
        return json(401, { success: false, error: 'Refresh token required' });
      }
      const agentForRefresh = refreshAgents.get(refreshToken) || callerAgentId;
      const newAccess = 'refreshed_access_token_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6);
      const newRefresh = 'refreshed_refresh_token_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6);
      tokenAgents.set(newAccess, agentForRefresh);
      refreshAgents.set(newRefresh, agentForRefresh);
      return json(200, {
        success: true,
        data: {
          tokens: {
            accessToken: newAccess,
            refreshToken: newRefresh,
          },
        },
      });
    }

    // Agent Profile: Me
    if (pathname === '/agents/me') {
      const agent =
        store.agents.find((a) => a.agentId === callerAgentId) ||
        store.agents[0] || {
          agentId: 'AMR-1111-2222',
          name: 'Mock Agent',
          masterId: 'AMR-0000-MASTER',
        };
      if (method === 'GET') {
        return json(200, { success: true, data: agent });
      }
      if (method === 'PATCH') {
        if (body?.name !== undefined) agent.name = String(body.name);
        if (body?.bio !== undefined) agent.bio = String(body.bio);
        return json(200, { success: true, data: agent });
      }
    }

    // Agents List
    if (pathname === '/agents' && method === 'GET') {
      let result = [...store.agents];
      const q = url.searchParams.get('q');
      if (q) {
        result = result.filter(
          (a) =>
            a.name?.toLowerCase().includes(q.toLowerCase()) ||
            a.agentId?.toLowerCase().includes(q.toLowerCase())
        );
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

    // Register or Get own E2EE key
    if (pathname === '/agents/me/e2ee') {
      if (method === 'GET') {
        const keyData = store.e2eeKeys[callerAgentId] || {
          publicKey: { kty: 'EC', crv: 'P-256', x: 'mock_x', y: 'mock_y' },
          fingerprint: 'SHA256:mock_fp_123',
          identityKey: null,
          keyVersion: 1,
          keyEpoch: 1,
        };
        return json(200, { success: true, data: keyData });
      }
      if (method === 'PUT') {
        const existing = store.e2eeKeys[callerAgentId];
        if (
          existing &&
          existing.fingerprint &&
          body?.fingerprint &&
          existing.fingerprint !== body.fingerprint &&
          body?.allowRotation !== true
        ) {
          return json(409, {
            success: false,
            error: 'KEY_ROTATION_NOT_ALLOWED',
            message: 'Public key already registered; set allowRotation: true to rotate.',
          });
        }
        store.e2eeKeys[callerAgentId] = body;
        return json(200, {
          success: true,
          data: {
            fingerprint: body?.fingerprint,
            keyVersion: body?.keyVersion || 1,
            hasIdentityBinding: Boolean(body?.identityKey && body?.signature),
          },
          message: 'E2EE key registered',
        });
      }
    }

    // Get specific agent E2EE key
    const agentE2eeMatch = pathname.match(/^\/agents\/([^/]+)\/e2ee$/);
    if (agentE2eeMatch && method === 'GET') {
      const targetId = decodeURIComponent(agentE2eeMatch[1]);
      if (store.e2eeKeys[targetId]) {
        return json(200, { success: true, data: store.e2eeKeys[targetId] });
      }
      if (store.agents.some((a) => a.agentId === targetId) || targetId.startsWith('AMR-')) {
        const peer = ensurePeerIdentityRecord(store, targetId, `conn_${targetId}`);
        return json(200, {
          success: true,
          data: {
            publicKey: peer.peerE2eePublicKey,
            fingerprint: peer.peerKeyFingerprint,
            identityKey: peer.peerIdentityKey,
            signature: peer.peerKeySignature,
            keyVersion: peer.peerKeyEpoch,
            keyEpoch: peer.peerKeyEpoch,
          },
        });
      }
      return json(404, { success: false, error: 'AGENT_KEY_NOT_FOUND' });
    }

    // Watchtower Activity
    if (pathname === '/watchtower/activity' && method === 'GET') {
      let acts = [...store.watchtowerActivities];
      const before = url.searchParams.get('before');
      if (before) {
        acts = acts.filter((a) => a.timestamp < before);
      }
      const limit = url.searchParams.get('limit') ? parseInt(url.searchParams.get('limit')!, 10) : undefined;
      if (limit && Number.isFinite(limit)) {
        acts = acts.slice(0, limit);
      }
      return json(200, { success: true, data: acts });
    }

    // Watchtower Stream Ticket
    if (pathname === '/watchtower/stream-ticket' && method === 'POST') {
      const ticket = 'ticket_live_mock_' + Date.now();
      const expiresAt = new Date(Date.now() + 3600000).toISOString();
      return json(200, {
        success: true,
        ticket,
        expiresAt,
        data: {
          ticket,
          expiresAt,
        },
      });
    }

    // Watchtower SSE Live Stream
    if (pathname === '/watchtower/stream' && method === 'GET') {
      const ticket = url.searchParams.get('ticket');
      if (!ticket) {
        return json(401, { success: false, error: 'Stream ticket required' });
      }
      const act = store.watchtowerActivities[0] || {
        id: 'evt_stream_1',
        type: 'watchtower.connected',
        timestamp: new Date().toISOString(),
      };
      const ssePayload = `id: ${act.id}\nevent: activity\ndata: ${JSON.stringify(act)}\n\n`;
      return new Response(ssePayload, {
        status: 200,
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
        },
      });
    }

    // FLOOR Agent Tools
    if (pathname === '/floor/agent/tools' && method === 'GET') {
      return json(200, { success: true, data: store.floorTools });
    }

    // FLOOR Tool Governance Policy
    const floorPolicyMatch = pathname.match(/^\/floor\/tools\/([^/]+)\/policy$/);
    if (floorPolicyMatch && method === 'GET') {
      const toolId = decodeURIComponent(floorPolicyMatch[1]);
      const tool = store.floorTools.find((t) => t.id === toolId);
      if (!tool) {
        return json(404, { success: false, error: 'FLOOR_TOOL_NOT_FOUND', message: `Tool ${toolId} not found.` });
      }
      return json(200, {
        success: true,
        data: {
          toolId: tool.id,
          requiresApproval: tool.accessStatus !== 'authorized' && tool.accessStatus !== 'granted',
          accessStatus: tool.accessStatus,
          authType: tool.authType || 'bearer',
        },
      });
    }

    // FLOOR Tool Invoke (Request/Create Invocation)
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
      const invocationId = 'inv_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6);
      const isApproved =
        tool.accessStatus === 'authorized' ||
        tool.accessStatus === 'granted' ||
        tool.accessStatus === 'approved';
      const status = isApproved ? 'approved' : 'pending';
      store.floorInvocations[invocationId] = {
        invocationId,
        toolId,
        status,
        arguments: body?.arguments || {},
        reason: body?.reason,
      };
      store.floorRequests[invocationId] = {
        requestId: invocationId,
        invocationId,
        status,
        toolId,
        reason: body?.reason,
        createdAt: new Date().toISOString(),
      };
      return json(isApproved ? 200 : 202, {
        success: isApproved,
        status,
        requestId: invocationId,
        data: {
          invocationId,
          requestId: invocationId,
          toolId,
          status,
          message: isApproved ? 'Invocation authorized.' : 'Access request submitted for approval.',
        },
      });
    }

    // FLOOR Invocation Execute / Access Authorization
    const floorExecInvocationMatch = pathname.match(/^\/floor\/invocations\/([^/]+)\/(execute|access)$/);
    if (floorExecInvocationMatch && method === 'POST') {
      const invocationId = decodeURIComponent(floorExecInvocationMatch[1]);
      const inv = store.floorInvocations[invocationId] || {
        invocationId,
        toolId: 'tool_sec_edgar',
        status: 'approved',
      };
      if (inv.status !== 'approved') {
        return json(403, {
          success: false,
          status: inv.status,
          error: { message: `Access denied. Invocation status is ${inv.status}.` },
          data: {
            status: inv.status,
            message: `Invocation is ${inv.status}.`,
          },
          message: `Invocation is ${inv.status}.`,
        });
      }
      const tool = store.floorTools.find((t) => t.id === inv.toolId);
      const grantToken = 'mock_mcp_jwt_token';
      const expiresAt = new Date(Date.now() + 3600000).toISOString();
      return json(200, {
        success: true,
        data: {
          status: 'approved',
          invocationId,
          toolId: inv.toolId,
          tool: { id: inv.toolId, name: tool?.name || inv.toolId },
          serverUrl: store.mcpServerUrl || tool?.serverUrl || 'https://aamarva.com/api/mcp',
          authConfig: {
            authType: tool?.authType || 'bearer',
            authHeaderName: tool?.authHeaderName || 'Authorization',
            headerValue: `Bearer ${grantToken}`,
          },
          verificationInfo: {
            verified: true,
            toolId: inv.toolId,
            agentId: callerAgentId,
          },
          grantToken,
          accessToken: grantToken,
          scope: 'tool:invoke',
          expiresAt,
          approvedArguments: inv.arguments || {},
          auth: {
            type: 'bearer',
            token: grantToken,
          },
          grant: {
            grantId: 'grant_' + Date.now(),
            scope: 'tool:invoke',
            expiresAt,
          },
        },
      });
    }

    // FLOOR Request Status
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
      return json(200, { success: true, data: reqData });
    }

    // Footprints & Webhook events
    if (pathname === '/agent/footprints' && method === 'GET') {
      return json(200, { success: true, data: store.footprints || [] });
    }
    if (pathname === '/webhooks/events' && method === 'GET') {
      return json(200, { success: true, data: store.webhookEvents || [] });
    }

    // Connections List
    if (pathname === '/connections' && method === 'GET') {
      return json(200, { success: true, data: store.connections });
    }

    // Canonical Peer Key Endpoint: GET /connections/peer-key/:accountId
    const peerKeyMatch = pathname.match(/^\/connections\/peer-key\/([^/]+)$/);
    if (peerKeyMatch && method === 'GET') {
      const accountId = decodeURIComponent(peerKeyMatch[1]);
      const conn = store.connections.find(
        (c) =>
          c.peerAccountId === accountId ||
          c.peerAgentId === accountId ||
          c.agentId === accountId ||
          c.connectionId === accountId
      );
      const connectionId = conn?.connectionId || `conn_${accountId}`;
      const peerAccountId = conn?.peerAccountId || conn?.peerAgentId || conn?.agentId || accountId;
      const peerRecord = ensurePeerIdentityRecord(store, peerAccountId, connectionId);

      return json(200, {
        success: true,
        data: {
          ...peerRecord,
          connectionId,
        },
      });
    }

    // Canonical Connection Messages: GET / POST /connections/messages/:accountId
    const connMessagesMatch = pathname.match(/^\/connections\/messages\/([^/]+)$/);
    if (connMessagesMatch) {
      const accountId = decodeURIComponent(connMessagesMatch[1]);
      const conn = store.connections.find(
        (c) =>
          c.peerAccountId === accountId ||
          c.peerAgentId === accountId ||
          c.agentId === accountId ||
          c.connectionId === accountId
      );
      const bucketKey = conn?.connectionId || accountId;

      if (method === 'GET') {
        let list = [...(store.messages[bucketKey] || [])];
        const since = url.searchParams.get('since');
        if (since) {
          list = list.filter((m) => String(m.createdAt) > since);
        }
        return json(200, { success: true, data: list });
      }
      if (method === 'POST') {
        if (body?.content !== undefined || body?.message !== undefined) {
          return json(400, {
            success: false,
            error: 'PLAINTEXT_REJECTED',
            message: 'Plaintext fields are forbidden on encrypted message endpoints.',
          });
        }
        const newMsg = {
          messageId: 'msg_' + Math.random().toString(36).substring(2, 9),
          connectionId: bucketKey,
          senderAgentId: callerAgentId,
          ciphertext: body?.ciphertext,
          nonce: body?.nonce,
          version: body?.version || 1,
          keyEpoch: body?.keyEpoch || 1,
          createdAt: new Date().toISOString(),
        };
        if (!store.messages[bucketKey]) {
          store.messages[bucketKey] = [];
        }
        store.messages[bucketKey].push(newMsg);
        return json(201, { success: true, data: newMsg });
      }
    }

    // Clusters List
    if (pathname === '/clusters' && method === 'GET') {
      return json(200, { success: true, data: store.clusters });
    }

    // Single Cluster Details
    const clusterMatch = pathname.match(/^\/clusters\/([^/]+)$/);
    if (clusterMatch && method === 'GET') {
      const clusterId = decodeURIComponent(clusterMatch[1]);
      const c = store.clusters.find((cl) => cl.id === clusterId || cl.clusterId === clusterId);
      if (!c) {
        return json(404, { success: false, error: 'CLUSTER_NOT_FOUND' });
      }
      return json(200, { success: true, data: c });
    }

    // Cluster Messages
    const clusterMessagesMatch = pathname.match(/^\/clusters\/([^/]+)\/messages$/);
    if (clusterMessagesMatch) {
      const clusterId = decodeURIComponent(clusterMessagesMatch[1]);
      if (method === 'GET') {
        let msgs = [...(store.clusterMessages[clusterId] || [])];
        const since = url.searchParams.get('since');
        if (since) {
          msgs = msgs.filter((m) => String(m.createdAt) > since);
        }
        return json(200, { success: true, data: msgs });
      }
      if (method === 'POST') {
        const senderAgentId = String(body?.senderAgentId || callerAgentId);
        const recipientsList = Array.isArray(body?.recipientAgentIds)
          ? body.recipientAgentIds
          : Array.isArray(body?.recipients)
          ? body.recipients
          : [];
        const msg = {
          messageId: 'msg_cl_' + Date.now(),
          clusterId,
          senderAgentId,
          ciphertext: body?.ciphertext,
          nonce: body?.nonce,
          version: body?.version || 2,
          keyEpoch: body?.keyEpoch || 1,
          recipientAgentIds: recipientsList,
          recipients: recipientsList,
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
      const clusterId = decodeURIComponent(clusterKeyDistMatch[1]);
      if (method === 'POST') {
        store.clusterKeyDistributions = store.clusterKeyDistributions || {};
        const epoch = Number(body?.epoch || 1);
        store.clusterKeyDistributions[`${clusterId}:${epoch}`] = body;
        store.clusterKeyDistributions[clusterId] = body;
        return json(200, {
          success: true,
          data: {
            clusterId,
            epoch,
            status: 'distributed',
          },
        });
      }
      if (method === 'GET') {
        const epochStr = url.searchParams.get('epoch');
        const epoch = epochStr ? parseInt(epochStr, 10) : 1;
        const saved =
          store.clusterKeyDistributions?.[`${clusterId}:${epoch}`] ||
          store.clusterKeyDistributions?.[clusterId];
        const dists = Array.isArray(saved?.distributions) ? saved.distributions : [];
        const matchedDist =
          dists.find((d: any) => String(d.recipientAgentId) === callerAgentId) || dists[0];
        const legacyPkg = saved?.keyPackages?.[0];

        if (matchedDist || legacyPkg) {
          return json(200, {
            success: true,
            data: {
              clusterId,
              epoch: saved?.epoch || epoch,
              keyFingerprint: saved?.keyFingerprint || 'SHA256:mock_group_key_fp',
              senderAgentId: saved?.senderAgentId || 'AMR-0000-MASTER',
              recipientAgentId:
                matchedDist?.recipientAgentId || legacyPkg?.recipientAgentId || callerAgentId,
              encryptedKeyPackage:
                matchedDist?.encryptedKeyPackage || legacyPkg?.encryptedKeyPackage,
            },
          });
        }

        return json(200, {
          success: true,
          data: {
            clusterId,
            epoch,
            keyFingerprint: 'SHA256:mock_group_key_fp',
            senderAgentId: 'AMR-0000-MASTER',
            recipientAgentId: callerAgentId,
            wrappingParams: {
              algorithm: 'ECDH-ES+HKDF-256+A256GCM',
              curve: 'P-256',
              hkdfHash: 'SHA-256',
              hkdfSalt: 'aamarva-e2ee-channel-v1',
              hkdfInfo: `aamarva-channel:${clusterId}`,
              aad: `aamarva-cluster-group-key:${clusterId}:${epoch}`,
            },
            encryptedKeyPackage: 'mock_wrapped_group_key_base64',
            nonce: 'mock_nonce_b64',
          },
        });
      }
    }

    return json(404, { success: false, error: `Mock endpoint not found: ${method} ${pathname}` });
  }) as typeof fetch;
}
