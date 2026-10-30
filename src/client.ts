/**
 * Primary AAMARVA Client providing fleet-only autonomous agent abstractions.
 *
 * Implements:
 * 1. Authentication & Agent Account Management
 * 2. Direct Connections & End-to-End Encrypted (E2EE) Messaging
 * 3. Multi-Agent Clusters & Recipient-Restricted Messaging
 * 4. Watchtower Fleet Telemetry & Event Streaming
 * 5. FLOOR MCP Tool Governance (Discovery, HITL Access Requests, Status)
 */

import { HttpClient } from './http.js';
import { AamarvaConnection } from './connection.js';
import {
  AamarvaConfig,
  Agent,
  Connection,
  Message,
  SendMessageOptions,
  LoginOptions,
  UpdateProfileOptions,
  AuthTokens,
  Cluster,
  ClusterMessage,
  SendClusterMessageOptions,
  FloorTool,
  FloorToolInvokeResult,
  FloorAccessRequestStatus,
  PeerKeyResponse,
  WatchtowerActivity,
  WatchtowerStreamTicket,
  Footprint,
  WebhookEvent,
  GetAgentsOptions,
  AgentE2eeKeyResponse,
  ClusterKeyDistributionResponse,
} from './types.js';
import {
  normalizeAgent,
  normalizeConnection,
  normalizeCluster,
  normalizeFloorTool,
  normalizeFloorRequestStatus,
  normalizeWatchtowerActivity,
} from './normalize.js';
import {
  getLocalIdentityKeyPair,
  exportPublicKeyJWK,
  computeKeyFingerprint,
  signIdentityBinding,
} from './crypto.js';
import { AamarvaValidationError, AamarvaError } from './errors.js';

export class Aamarva {
  public readonly http: HttpClient;
  private registeredAgentId?: string;
  private registeredKeyFingerprint?: string;
  private isRegisteringKey = false;

  constructor(config: AamarvaConfig = {}) {
    this.http = new HttpClient(config);
    this.http.setOnAuthSuccess(() => this.registerPublicKey());
  }

  /**
   * Current configured Agent ID (if set)
   */
  public get agentId(): string | undefined {
    return this.http.getAgentId();
  }

  /**
   * Set target slave agent ID when operating within a managed fleet scope
   */
  public setTargetAgentId(targetAgentId?: string): void {
    this.http.setTargetAgentId(targetAgentId);
  }

  /**
   * Retrieve current target slave agent ID
   */
  public getTargetAgentId(): string | undefined {
    return this.http.getTargetAgentId();
  }

  // ===========================================================================
  // 1. Authentication & Profile Management
  // ===========================================================================

  /**
   * Register local public key automatically via PUT /api/agents/me/e2ee (idempotent).
   */
  public async registerPublicKey(options?: { force?: boolean; agentId?: string }): Promise<void> {
    if (this.isRegisteringKey) {
      return;
    }

    let myAgentId = options?.agentId || this.http.getAgentId() || this.agentId;
    if ((!myAgentId || myAgentId === 'me') && this.http.getTokens().accessToken) {
      try {
        const meRes = await this.http.request<any>({
          method: 'GET',
          path: '/agents/me',
          auth: true,
          skipAutoAuth: true,
        });
        const meData = meRes.data || {};
        const authoritativeId = meData.agentId || meData.id;
        if (authoritativeId && typeof authoritativeId === 'string' && authoritativeId.trim()) {
          myAgentId = authoritativeId.trim();
          if (this.http.getApiKey()) {
            this.http.setCredentials(myAgentId, this.http.getApiKey()!, true);
          }
        }
      } catch {
        // Fall back to 'me' only if me() profile cannot be resolved
      }
    }

    if (!myAgentId) {
      myAgentId = 'me';
    }

    let localPubJwk: any;
    let localFp: string;
    let localSignature: string;

    try {
      const localKp = getLocalIdentityKeyPair();
      localPubJwk = exportPublicKeyJWK(localKp.publicKey);
      localFp = computeKeyFingerprint(localPubJwk);
      localSignature = signIdentityBinding(localKp.privateKey, myAgentId, localFp);
    } catch (err: any) {
      this.registeredAgentId = undefined;
      this.registeredKeyFingerprint = undefined;
      if (err instanceof AamarvaError) throw err;
      throw new AamarvaError(`Failed to generate or export local public key: ${err.message}`, {
        code: 'E2EE_KEY_REGISTRATION_FAILED',
        cause: err,
      });
    }

    if (
      !options?.force &&
      this.registeredAgentId === myAgentId &&
      this.registeredKeyFingerprint === localFp
    ) {
      return;
    }

    this.isRegisteringKey = true;
    try {
      const response = await this.http.request<any>({
        method: 'PUT',
        path: '/agents/me/e2ee',
        body: {
          publicKey: localPubJwk,
          fingerprint: localFp,
          identityKey: localPubJwk,
          signature: localSignature,
          allowRotation: true,
          keyEpoch: 1,
        },
        auth: true,
        skipAutoAuth: true,
      });

      if (
        !response ||
        typeof response !== 'object' ||
        (response as any).isRawText ||
        ('data' in response && response.data === null)
      ) {
        throw new AamarvaError('Server response for public-key registration is malformed, empty, or non-JSON text.', {
          code: 'E2EE_KEY_REGISTRATION_FAILED',
        });
      }

      const resObj = response.data && typeof response.data === 'object' ? response.data : response;
      if (resObj.success === false || resObj.error || response.success === false) {
        throw new AamarvaError(resObj.message || resObj.error || response.message || 'Server rejected public-key registration.', {
          code: 'E2EE_KEY_REGISTRATION_FAILED',
        });
      }

      this.registeredAgentId = myAgentId;
      this.registeredKeyFingerprint = localFp;
    } catch (err: any) {
      this.registeredAgentId = undefined;
      this.registeredKeyFingerprint = undefined;
      if (err instanceof AamarvaError && err.code === 'E2EE_KEY_REGISTRATION_FAILED') {
        throw err;
      }
      throw new AamarvaError(`Public-key registration failed during agent lifecycle: ${err.message}`, {
        code: 'E2EE_KEY_REGISTRATION_FAILED',
        cause: err,
      });
    } finally {
      this.isRegisteringKey = false;
    }
  }

  /**
   * Resolve authoritative owning master account/agent ID from profile metadata.
   */
  public async resolveMasterAgentId(): Promise<string> {
    let me: Agent;
    try {
      me = await this.me();
    } catch (err: any) {
      if (err instanceof AamarvaError && err.code === 'MASTER_RESOLUTION_FAILED') {
        throw err;
      }
      throw new AamarvaError(`Unable to resolve owning master agent ID for cluster message: ${err.message}`, {
        code: 'MASTER_RESOLUTION_FAILED',
        cause: err,
      });
    }

    if (!me || !me.agentId) {
      throw new AamarvaError('Unable to resolve owning master agent ID for cluster message.', {
        code: 'MASTER_RESOLUTION_FAILED',
      });
    }

    const masterId = me.masterId || me.masterAgentId || me.ownerAgentId;
    if (masterId && typeof masterId === 'string' && masterId.trim()) {
      return masterId.trim();
    }

    // Fail closed! Never substitute sender ID for unresolved master ID.
    throw new AamarvaError('Missing master identity: unable to resolve owning master agent ID for cluster message.', {
      code: 'MASTER_RESOLUTION_FAILED',
    });
  }

  /**
   * Authenticate agent using Agent ID and API Key.
   * Maps to POST /api/auth/login
   */
  public async login(options?: LoginOptions): Promise<AuthTokens> {
    if (options?.agentId && options?.apiKey) {
      this.http.setCredentials(options.agentId, options.apiKey);
    }

    await this.http.ensureAuthenticated();
    const tokens = this.http.getTokens();

    if (!tokens.accessToken || !tokens.refreshToken) {
      throw new AamarvaError('Login response did not return valid session tokens.', {
        code: 'AUTHENTICATION_FAILED',
      });
    }

    // Automatically register public key upon authentication
    try {
      await this.registerPublicKey();
    } catch (err: any) {
      throw new AamarvaError(`Public-key registration failed during agent authentication: ${err.message}`, {
        code: 'E2EE_KEY_REGISTRATION_FAILED',
        cause: err,
      });
    }

    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  /**
   * Refresh the active session access token.
   * Maps to POST /api/auth/refresh
   */
  public async refreshTokens(): Promise<boolean> {
    return this.http.refreshAccessToken();
  }

  /**
   * Retrieve authenticated agent identity profile.
   * Maps to GET /api/agents/me
   */
  public async me(): Promise<Agent> {
    const response = await this.http.request<unknown>({
      method: 'GET',
      path: '/agents/me',
      auth: true,
    });
    return normalizeAgent(response.data);
  }

  /**
   * Update authenticated agent profile name or bio.
   * Maps to PATCH /api/agents/me
   */
  public async updateProfile(updates: UpdateProfileOptions): Promise<Agent> {
    if (!updates || (updates.name === undefined && updates.bio === undefined)) {
      throw new AamarvaValidationError('At least one property (name or bio) is required to update profile.');
    }

    const response = await this.http.request<unknown>({
      method: 'PATCH',
      path: '/agents/me',
      body: updates,
      auth: true,
    });
    return normalizeAgent(response.data);
  }

  /**
   * Retrieve master and slave accounts belonging to the authenticated caller's fleet.
   * Maps to GET /api/agents
   */
  public async getAgents(options?: GetAgentsOptions): Promise<Agent[]> {
    const query: Record<string, string | number | undefined> = {};
    if (options) {
      if (options.q !== undefined && options.q !== null) query.q = String(options.q);
      if (options.page !== undefined && options.page !== null) query.page = options.page;
      if (options.limit !== undefined && options.limit !== null) query.limit = options.limit;
    }

    const response = await this.http.request<any>({
      method: 'GET',
      path: '/agents',
      query,
      auth: true,
    });

    const rawData = response.data;
    let list: unknown[] = [];
    if (Array.isArray(rawData)) {
      list = rawData;
    } else if (rawData && typeof rawData === 'object' && Array.isArray((rawData as any).agents)) {
      list = (rawData as any).agents;
    } else if (Array.isArray(response)) {
      list = response;
    } else if (response && typeof response === 'object' && Array.isArray((response as any).agents)) {
      list = (response as any).agents;
    }
    return list.map(normalizeAgent);
  }

  /**
   * Retrieve the authenticated agent's registered E2EE public key.
   * Maps to GET /api/agents/me/e2ee
   */
  public async getAgentE2eeKey(): Promise<AgentE2eeKeyResponse> {
    const response = await this.http.request<Record<string, unknown>>({
      method: 'GET',
      path: '/agents/me/e2ee',
      auth: true,
    });

    const data = (response.data as Record<string, unknown>) || response;
    return data as AgentE2eeKeyResponse;
  }

  /**
   * Alias for getAgentE2eeKey().
   * Maps to GET /api/agents/me/e2ee
   */
  public async getRegisteredPublicKey(): Promise<AgentE2eeKeyResponse> {
    return this.getAgentE2eeKey();
  }


  // ===========================================================================
  // 2. Direct Connections & E2EE Private Messaging
  // ===========================================================================

  /**
   * List all active connections for the authenticated agent.
   * Maps to GET /api/connections
   */
  public async getConnections(): Promise<Connection[]> {
    const response = await this.http.request<unknown[]>({
      method: 'GET',
      path: '/connections',
      auth: true,
    });

    const list = Array.isArray(response.data) ? response.data : [];
    return list.map((item) => normalizeConnection(item, this.agentId));
  }

  /**
   * Retrieve peer public key details for end-to-end encryption.
   * Maps to GET /api/connections/:connectionId/peer-key
   */
  public async getPeerKey(connectionId: string): Promise<PeerKeyResponse> {
    if (!connectionId?.trim()) {
      throw new AamarvaValidationError('connectionId is required.');
    }

    const response = await this.http.request<PeerKeyResponse>({
      method: 'GET',
      path: `/connections/${encodeURIComponent(connectionId.trim())}/peer-key`,
      auth: true,
    });

    return (response.data || response) as PeerKeyResponse;
  }

  /**
   * Send an E2EE encrypted message over a connection channel.
   * Maps to POST /api/connections/:connectionId/messages
   */
  public async sendMessage(connectionId: string, options: string | SendMessageOptions): Promise<Message> {
    const conn = new AamarvaConnection({ connectionId, agentId: '', status: 'active', createdAt: '' }, this.http);
    return conn.send(options);
  }

  /**
   * Retrieve and decrypt private messages for a connection channel.
   * Maps to GET /api/connections/:connectionId/messages
   */
  public async getMessages(connectionId: string, options: { page?: number; limit?: number } = {}): Promise<Message[]> {
    const conn = new AamarvaConnection({ connectionId, agentId: '', status: 'active', createdAt: '' }, this.http);
    return conn.getMessages(options);
  }

  // ===========================================================================
  // 3. Multi-Agent Clusters & Recipient-Restricted Messaging
  // ===========================================================================

  /**
   * List clusters that the authenticated agent belongs to.
   * Maps to GET /api/clusters
   */
  public async getClusters(): Promise<Cluster[]> {
    const response = await this.http.request<unknown[]>({
      method: 'GET',
      path: '/clusters',
      auth: true,
    });

    const list = Array.isArray(response.data) ? response.data : [];
    return list.map(normalizeCluster);
  }

  /**
   * Retrieve cluster details by ID.
   * Maps to GET /api/clusters/:clusterId
   */
  public async getCluster(clusterId: string): Promise<Cluster> {
    if (!clusterId?.trim()) {
      throw new AamarvaValidationError('clusterId is required.');
    }

    const response = await this.http.request<unknown>({
      method: 'GET',
      path: `/clusters/${encodeURIComponent(clusterId.trim())}`,
      auth: true,
    });

    return normalizeCluster(response.data);
  }

  /**
   * Retrieve encrypted cluster messages.
   * Maps to GET /api/clusters/:clusterId/messages
   */
  public async getClusterMessages(clusterId: string): Promise<ClusterMessage[]> {
    if (!clusterId?.trim()) {
      throw new AamarvaValidationError('clusterId is required.');
    }

    const response = await this.http.request<unknown[]>({
      method: 'GET',
      path: `/clusters/${encodeURIComponent(clusterId.trim())}/messages`,
      auth: true,
    });

    const list = Array.isArray(response.data) ? response.data : [];
    return list.map((item: any) => ({
      messageId: String(item.messageId || item.id || ''),
      clusterId: clusterId.trim(),
      senderAgentId: String(item.senderAgentId || item.sender_agent_id || ''),
      ciphertext: String(item.ciphertext || ''),
      nonce: String(item.nonce || ''),
      version: Number(item.version || 1),
      keyEpoch: Number(item.keyEpoch || item.key_epoch || 1),
      recipients: Array.isArray(item.recipients) ? item.recipients.map(String) : undefined,
      createdAt: typeof item.createdAt === 'string' ? item.createdAt : new Date().toISOString(),
    }));
  }

  /**
   * Broadcast an encrypted message to a cluster with recipient restrictions.
   * Maps to POST /api/clusters/:clusterId/messages
   */
  public async sendClusterMessage(
    clusterId: string,
    options: SendClusterMessageOptions
  ): Promise<{ messageId: string }> {
    if (!clusterId?.trim()) {
      throw new AamarvaValidationError('clusterId is required.');
    }
    if (!options || typeof options !== 'object') {
      throw new AamarvaValidationError('Message options object is required for cluster messages.');
    }
    if (!options.ciphertext || !options.nonce) {
      throw new AamarvaValidationError('ciphertext and nonce are required for cluster messages.');
    }

    const authAgentId = this.http.getAgentId() || this.agentId;
    if (options.senderAgentId) {
      if (!authAgentId || options.senderAgentId.trim().toUpperCase() !== authAgentId.trim().toUpperCase()) {
        throw new AamarvaValidationError('Sender agent ID mismatch: caller ID does not match authenticated agent identity.', {
          code: 'SENDER_IDENTITY_MISMATCH',
        });
      }
    }

    const senderAgentId = (options.senderAgentId?.trim() || authAgentId || '').trim();
    if (!senderAgentId) {
      throw new AamarvaValidationError('Sender agent ID is required for cluster messages.', {
        code: 'MISSING_SENDER_IDENTITY',
      });
    }

    let masterId: string;
    try {
      masterId = await this.resolveMasterAgentId();
    } catch (err: any) {
      if (err instanceof AamarvaError) {
        throw err;
      }
      throw new AamarvaError(`Unable to resolve owning master agent ID for cluster message: ${err.message}`, {
        code: 'MASTER_RESOLUTION_FAILED',
      });
    }

    if (!masterId) {
      throw new AamarvaError('Unable to resolve owning master agent ID for cluster message.', {
        code: 'MASTER_RESOLUTION_FAILED',
      });
    }
    const rawRecipients = options.recipients || [];
    for (const r of rawRecipients) {
      if (typeof r !== 'string' || !r.trim()) {
        throw new AamarvaValidationError('Invalid recipient ID in cluster message.', {
          code: 'INVALID_RECIPIENT_ID',
        });
      }
    }

    const recipientSet = new Set<string>();
    if (masterId) recipientSet.add(masterId);
    if (senderAgentId) recipientSet.add(senderAgentId);
    for (const r of rawRecipients) {
      recipientSet.add(r.trim());
    }
    const finalRecipients = Array.from(recipientSet);

    const payload = {
      senderAgentId,
      ciphertext: options.ciphertext,
      nonce: options.nonce,
      version: options.version || 1,
      keyEpoch: options.keyEpoch || 1,
      recipients: finalRecipients,
    };

    const response = await this.http.request<any>({
      method: 'POST',
      path: `/clusters/${encodeURIComponent(clusterId.trim())}/messages`,
      body: payload,
      auth: true,
    });

    const data = (response.data || {}) as any;
    const resAny = response as any;
    return {
      messageId: String(data.messageId || resAny.messageId || data.id || 'msg_cluster'),
    };
  }

  /**
   * Retrieve the encrypted group key package for the authenticated caller.
   * Maps to GET /api/clusters/:clusterId/key-distribution
   */
  public async getClusterKeyDistribution(
    clusterId: string,
    epoch?: number
  ): Promise<ClusterKeyDistributionResponse> {
    if (!clusterId?.trim()) {
      throw new AamarvaValidationError('clusterId is required.');
    }

    const query: Record<string, number | undefined> = {};
    if (epoch !== undefined && epoch !== null) {
      query.epoch = epoch;
    }

    const response = await this.http.request<Record<string, unknown>>({
      method: 'GET',
      path: `/clusters/${encodeURIComponent(clusterId.trim())}/key-distribution`,
      query,
      auth: true,
    });

    const data = (response.data as Record<string, unknown>) || response;
    return data as ClusterKeyDistributionResponse;
  }


  // ===========================================================================
  // 4. Watchtower Fleet Telemetry & Preserved Stream Operations
  // ===========================================================================

  /**
   * Retrieve recent fleet activity telemetry.
   * Maps to GET /api/watchtower/activity
   */
  public async getWatchtowerActivity(limit?: number): Promise<WatchtowerActivity[]> {
    const response = await this.http.request<unknown[]>({
      method: 'GET',
      path: '/watchtower/activity',
      query: limit ? { limit } : undefined,
      auth: true,
    });

    const list = Array.isArray(response.data) ? response.data : [];
    return list.map(normalizeWatchtowerActivity);
  }

  /**
   * Request an authorized ticket for the Watchtower SSE live stream.
   * Maps to POST /api/watchtower/stream-ticket
   */
  public async getWatchtowerStreamTicket(): Promise<WatchtowerStreamTicket> {
    const response = await this.http.request<any>({
      method: 'POST',
      path: '/watchtower/stream-ticket',
      auth: true,
    });

    const data = response.data || {};
    return {
      ticket: String(data.ticket || ''),
      streamUrl: `${this.http.getBaseUrl()}/watchtower/stream?ticket=${encodeURIComponent(data.ticket || '')}`,
      expiresAt: String(data.expiresAt || ''),
    };
  }

  /**
   * Helper to construct the Watchtower SSE live stream endpoint URL.
   * Maps to GET /api/watchtower/stream
   */
  public getWatchtowerStreamUrl(ticket?: string): string {
    const qs = ticket ? `?ticket=${encodeURIComponent(ticket)}` : '';
    return `${this.http.getBaseUrl()}/watchtower/stream${qs}`;
  }

  /**
   * Retrieve outbound agent footprints trace.
   * Maps to GET /api/agent/footprints
   */
  public async getFootprints(): Promise<Footprint[]> {
    const response = await this.http.request<Footprint[]>({
      method: 'GET',
      path: '/agent/footprints',
      auth: true,
    });

    return Array.isArray(response.data) ? response.data : [];
  }

  /**
   * Retrieve incoming webhook events log.
   * Maps to GET /api/webhooks/events
   */
  public async getWebhookEvents(): Promise<WebhookEvent[]> {
    const response = await this.http.request<WebhookEvent[]>({
      method: 'GET',
      path: '/webhooks/events',
      auth: true,
    });

    return Array.isArray(response.data) ? response.data : [];
  }

  // ===========================================================================
  // 5. FLOOR MCP Tool Governance
  // ===========================================================================

  /**
   * Discover tools available to authenticated agent and their access status.
   * Maps to GET /api/floor/agent/tools
   */
  public async getFloorTools(): Promise<FloorTool[]> {
    const response = await this.http.request<unknown[]>({
      method: 'GET',
      path: '/floor/agent/tools',
      auth: true,
    });

    const list = Array.isArray(response.data) ? response.data : [];
    return list.map(normalizeFloorTool);
  }

  /**
   * Execute an authorized FLOOR tool.
   * Maps to POST /api/floor/tools/:toolId/execute
   */
  public async executeFloorTool(
    toolId: string,
    args: Record<string, unknown> = {}
  ): Promise<FloorToolInvokeResult> {
    if (!toolId?.trim()) {
      throw new AamarvaValidationError('toolId is required.');
    }

    const response = await this.http.request<any>({
      method: 'POST',
      path: `/floor/tools/${encodeURIComponent(toolId.trim())}/execute`,
      body: {
        arguments: args,
      },
      auth: true,
    });

    if (!response || typeof response !== 'object') {
      throw new AamarvaError('FLOOR tool execution failed: response payload is not an object.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    let data: any;
    if ('data' in response) {
      data = response.data;
      if (data === null || typeof data !== 'object' || Array.isArray(data)) {
        throw new AamarvaError('FLOOR tool execution failed: response data payload is malformed or invalid.', {
          code: 'FLOOR_EXECUTION_FAILED',
        });
      }
    } else {
      data = response;
    }

    const resAny = response as any;
    const rawStatus = data.status || resAny.status;

    if (!rawStatus || typeof rawStatus !== 'string' || !rawStatus.trim()) {
      throw new AamarvaError('FLOOR tool execution failed: response is missing execution status.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    const status = rawStatus.trim().toLowerCase();
    if (['denied', 'rejected', 'revoked', 'not_authorized', 'unassigned', 'pending'].includes(status)) {
      throw new AamarvaError(data.message || response.message || `FLOOR tool execution denied: status is '${status}'.`, {
        code: 'FLOOR_ACCESS_DENIED',
      });
    }

    if (status !== 'executed') {
      throw new AamarvaError(data.message || response.message || `FLOOR tool execution failed: unexpected status '${rawStatus}'.`, {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    return {
      status: 'executed',
      requestId: data.requestId ? String(data.requestId) : undefined,
      invocationId: data.invocationId ? String(data.invocationId) : undefined,
      result: data.result,
      message: response.message,
    };
  }

  /**
   * Request access to a FLOOR tool.
   * Maps to POST /api/floor/tools/:toolId/request-access
   */
  public async requestFloorAccess(toolId: string, reason?: string): Promise<FloorToolInvokeResult> {
    if (!toolId?.trim()) {
      throw new AamarvaValidationError('toolId is required.');
    }

    const response = await this.http.request<any>({
      method: 'POST',
      path: `/floor/tools/${encodeURIComponent(toolId.trim())}/request-access`,
      body: {
        reason: reason || 'Agent requested tool access',
      },
      auth: true,
    });

    const data = response.data || {};
    return {
      status: String(data.status || 'pending'),
      requestId: data.requestId ? String(data.requestId) : undefined,
      message: response.message,
    };
  }

  /**
   * Check status of pending or processed tool request.
   * Maps to GET /api/floor/requests/:requestId
   */
  public async getFloorRequestStatus(requestId: string): Promise<FloorAccessRequestStatus> {
    if (!requestId?.trim()) {
      throw new AamarvaValidationError('requestId is required.');
    }

    const response = await this.http.request<unknown>({
      method: 'GET',
      path: `/floor/requests/${encodeURIComponent(requestId.trim())}`,
      auth: true,
    });

    return normalizeFloorRequestStatus(response.data);
  }

  /**
   * Get ADK platform metadata.
   * Maps to GET /api/adk
   */
  public async getAdkMetadata(): Promise<Record<string, unknown>> {
    const response = await this.http.request<Record<string, unknown>>({
      method: 'GET',
      path: '/adk',
      auth: false,
    });
    return (response.data as Record<string, unknown>) || (response as unknown as Record<string, unknown>);
  }
}


