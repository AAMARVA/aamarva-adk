/**
 * Offline Mock transport and testing utilities for AAMARVA fleet agent development.
 */

import crypto from 'crypto';
import {
  Agent,
  Connection,
  Cluster,
  ClusterMessage,
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
  clusters: Cluster[];
  clusterMembers: Record<string, string[]>;
  clusterMessages: Record<string, any[]>;
  clusterKeyDistributions?: Record<string, any>;
  floorTools: FloorTool[];
  floorRequests: Record<string, any>;
  floorInvocations: Record<string, any>;
  mcpServerUrl?: string;
  watchtowerActivities: WatchtowerActivity[];
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
        ownerAgentId: 'AMR-1111-2222',
        membersCount: 2,
        members: ['AMR-1111-2222', 'AMR-5555-6666'],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
    ],
    clusterMembers: {
      'cluster_987654': ['AMR-1111-2222', 'AMR-5555-6666'],
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
    const effectiveAgentId = (targetAgentHeader || currentAgentId).trim();

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
    if (pathname === '/mcp' || (body as any)?.method === 'tools/call') {
      const toolName = (body as any)?.params?.name || 'tool_sec_edgar';
      const toolArgs = (body as any)?.params?.arguments || {};
      return json(200, {
        jsonrpc: '2.0',
        id: (body as any)?.id || 1,
        result: {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ filings: [{ form: '10-K', year: 2026, ticker: toolArgs.ticker || 'AAPL' }] }),
            },
          ],
        },
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

    // Register or Get local E2EE key
    if (pathname === '/agents/me/e2ee') {
      if (method === 'GET') {
        const keyData = store.e2eeKeys[currentAgentId] || store.e2eeKeys[store.agents[0]?.agentId || 'AMR-1111-2222'] || {
          publicKey: { kty: 'EC', crv: 'P-256', x: 'mock_x', y: 'mock_y' },
          fingerprint: 'SHA256:mock_fp_123',
          identityKey: { kty: 'EC', crv: 'P-256', x: 'mock_x', y: 'mock_y' },
          allowRotation: true,
          keyEpoch: 1,
        };
        return json(200, { success: true, data: keyData });
      }
      if (method === 'PUT') {
        store.e2eeKeys[currentAgentId] = body;
        store.e2eeKeys[`peer:${currentAgentId}`] = {
          ...(body || {}),
          peerE2eePublicKey: (body as any)?.publicKey,
          peerKeyFingerprint: (body as any)?.fingerprint,
          peerIdentityKey: (body as any)?.identityKey || (body as any)?.publicKey,
          peerKeySignature: (body as any)?.signature,
          peerKeyEpoch: (body as any)?.keyEpoch || 1,
          peerAgentId: currentAgentId,
          agentId: currentAgentId,
        };
        return json(200, { success: true, message: 'E2EE key registered' });
      }
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
      const status = isApproved ? 'approved' : 'pending';
      store.floorInvocations[invocationId] = {
        invocationId,
        toolId,
        agentId: effectiveAgentId,
        status,
        arguments: body?.arguments || {},
        reason: body?.reason,
      };
      store.floorRequests[invocationId] = {
        requestId: invocationId,
        invocationId: isApproved ? invocationId : undefined,
        agentId: effectiveAgentId,
        status,
        toolId,
        reason: body?.reason,
        createdAt: new Date().toISOString(),
      };
      return json(isApproved ? 200 : 202, {
        success: true,
        status,
        data: {
          invocationId,
          requestId: invocationId,
          toolId,
          agentId: effectiveAgentId,
          status,
          message: isApproved ? 'Invocation authorized.' : 'Access request submitted for approval.',
        },
      });
    }

    // FLOOR Invocation Execute Authorization
    const floorExecInvocationMatch = pathname.match(/^\/floor\/invocations\/([^/]+)\/execute$/);
    if (floorExecInvocationMatch && method === 'POST') {
      const invocationId = decodeURIComponent(floorExecInvocationMatch[1]);
      const inv = store.floorInvocations[invocationId];
      if (!inv) {
        return json(404, {
          success: false,
          error: 'FLOOR_INVOCATION_NOT_FOUND',
          message: `Invocation ${invocationId} not found.`,
        });
      }
      if (inv.agentId && inv.agentId.toUpperCase() !== effectiveAgentId.toUpperCase()) {
        return json(403, {
          success: false,
          error: 'FLOOR_ACCESS_DENIED',
          message: `Invocation does not belong to target agent context.`,
        });
      }
      const tool = store.floorTools.find((t) => t.id === inv.toolId);
      if (tool && ['revoked', 'denied', 'rejected'].includes((tool.accessStatus || '').toLowerCase())) {
        return json(403, {
          success: false,
          status: tool.accessStatus,
          error: 'FLOOR_ACCESS_DENIED',
          message: `Tool access has been ${tool.accessStatus}.`,
        });
      }
      if (inv.status !== 'approved') {
        return json(403, {
          success: false,
          status: inv.status,
          data: {
            status: inv.status,
            message: `Invocation is ${inv.status}.`,
          },
          message: `Invocation is ${inv.status}.`,
        });
      }
      const expiresAt = new Date(Date.now() + 3600000).toISOString();
      return json(200, {
        success: true,
        data: {
          status: 'approved',
          invocationId,
          toolId: inv.toolId,
          agentId: inv.agentId || effectiveAgentId,
          serverUrl: store.mcpServerUrl || 'https://aamarva.com/api/mcp',
          auth: {
            type: 'bearer',
            token: 'mock_mcp_jwt_token',
          },
          grant: {
            grantId: 'grant_' + Date.now(),
            agentId: inv.agentId || effectiveAgentId,
            toolId: inv.toolId,
            status: 'active',
            scope: 'read:sec_edgar',
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
        const saved = store.clusterKeyDistributions?.[scopedKey] || store.clusterKeyDistributions?.[clusterId];
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
            keyFingerprint: saved?.keyFingerprint || matchingPkg?.keyFingerprint || 'SHA256:mock_group_key_fp',
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
