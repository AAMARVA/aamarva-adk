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
  return (async (input: unknown, init?: RequestInit): Promise<Response> => {
    const urlStr = typeof input === 'string' ? input : (input instanceof URL ? input.toString() : (input as { url?: string })?.url || String(input));
    const url = new URL(urlStr, 'https://aamarva.com');
    const method = (init?.method || 'GET').toUpperCase();
    const pathname = url.pathname.replace('/api', '');

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
        const agent = store.agents[0];
        if (agent) {
          if (body?.name) agent.name = String(body.name);
          if (body?.bio) agent.bio = String(body.bio);
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
        const agentId = store.agents[0]?.agentId || 'AMR-1111-2222';
        const keyData = store.e2eeKeys[agentId] || {
          publicKey: { kty: 'EC', crv: 'P-256', x: 'mock_x', y: 'mock_y' },
          fingerprint: 'SHA256:mock_fp_123',
          identityKey: { kty: 'EC', crv: 'P-256', x: 'mock_x', y: 'mock_y' },
          keyVersion: 1,
          keyEpoch: 1,
        };
        return json(200, { success: true, data: keyData });
      }
      if (method === 'PUT' || method === 'POST') {
        const agentId = store.agents[0]?.agentId || 'AMR-1111-2222';
        store.e2eeKeys[agentId] = body;
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
      const invocationId = 'inv_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6);
      const isApproved = tool.accessStatus === 'authorized' || tool.accessStatus === 'granted' || tool.accessStatus === 'approved';
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
        status,
        toolId,
        reason: body?.reason,
        createdAt: new Date().toISOString(),
      };
      return json(200, {
        success: true,
        data: {
          invocationId,
          requestId: invocationId,
          toolId,
          status,
          message: isApproved ? 'Invocation authorized.' : 'Access request submitted for approval.',
        },
      });
    }

    // FLOOR Invocation Execute Authorization
    const floorExecInvocationMatch = pathname.match(/^\/floor\/invocations\/([^/]+)\/execute$/);
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
          data: {
            status: inv.status,
            message: `Invocation is ${inv.status}.`,
          },
          message: `Invocation is ${inv.status}.`,
        });
      }
      return json(200, {
        success: true,
        data: {
          status: 'approved',
          invocationId,
          toolId: inv.toolId,
          serverUrl: store.mcpServerUrl || 'https://aamarva.com/api/mcp',
          auth: {
            type: 'bearer',
            token: 'mock_mcp_jwt_token',
          },
          grant: {
            grantId: 'grant_' + Date.now(),
            scope: 'read:sec_edgar',
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
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
      return json(200, { success: true, data: store.connections });
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

    // Peer Key Endpoint
    const peerKeyMatch = pathname.match(/^\/connections\/([^/]+)\/peer-key$/);
    if (peerKeyMatch && method === 'GET') {
      const connectionId = peerKeyMatch[1];
      const conn = store.connections.find((c) => c.connectionId === connectionId);
      const peerAgentId = conn?.agentId || 'AMR-PEER-ECDH';

      if (!store.e2eeKeys[connectionId]) {
        const peerKp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
        const peerJwk = exportPublicKeyJWK(peerKp.publicKey);
        const peerFp = computeKeyFingerprint(peerJwk);
        const peerSig = signIdentityBinding(peerKp.privateKey, peerAgentId, peerFp);
        store.e2eeKeys[connectionId] = {
          peerE2eePublicKey: peerJwk,
          peerKeyFingerprint: peerFp,
          peerIdentityKey: peerJwk,
          peerKeySignature: peerSig,
          peerKeyEpoch: 1,
          peerAgentId,
        };
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
          senderAgentId: 'AMR-1111-2222',
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

    // Cluster Messages
    const clusterMessagesMatch = pathname.match(/^\/clusters\/([^/]+)\/messages$/);
    if (clusterMessagesMatch) {
      const clusterId = clusterMessagesMatch[1];
      if (method === 'GET') {
        return json(200, { success: true, data: store.clusterMessages[clusterId] || [] });
      }
      if (method === 'POST') {
        const senderAgentId = String(body?.senderAgentId || 'AMR-1111-2222');
        const msg = {
          messageId: 'msg_cl_' + Date.now(),
          clusterId,
          senderAgentId,
          ciphertext: body?.ciphertext,
          nonce: body?.nonce,
          version: body?.version || 1,
          keyEpoch: body?.keyEpoch || 1,
          recipients: body?.recipients,
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
        store.clusterKeyDistributions[clusterId] = body;
        return json(200, {
          success: true,
          data: {
            clusterId,
            status: 'distributed',
          },
        });
      }
      if (method === 'GET') {
        const epochStr = url.searchParams.get('epoch');
        const epoch = epochStr ? parseInt(epochStr, 10) : 1;
        const saved = store.clusterKeyDistributions?.[clusterId];
        const keyPackage = saved?.keyPackages?.[0];
        return json(200, {
          success: true,
          data: {
            clusterId,
            epoch,
            keyFingerprint: 'SHA256:mock_group_key_fp',
            senderAgentId: saved?.senderAgentId || 'AMR-0000-MASTER',
            recipientAgentId: keyPackage?.recipientAgentId || 'AMR-1111-2222',
            wrappingParams: keyPackage?.wrappingParams || { alg: 'ECDH-ES+A256KW' },
            encryptedKeyPackage: keyPackage?.encryptedKeyPackage || 'mock_wrapped_group_key_base64',
            nonce: keyPackage?.nonce || 'mock_nonce_b64',
          },
        });
      }
    }

    return json(404, { success: false, error: `Mock endpoint not found: ${method} ${pathname}` });
  }) as typeof fetch;
}
