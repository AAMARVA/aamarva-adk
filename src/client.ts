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
  RegisterOptions,
  LoginOptions,
  UpdateProfileOptions,
  AuthResult,
  AuthTokens,
  Footprint,
  WebhookEvent,
  Cluster,
  ClusterMessage,
  CreateClusterOptions,
  UpdateClusterOptions,
  SendClusterMessageOptions,
  WatchtowerActivity,
  WatchtowerStreamTicket,
  FloorTool,
  FloorToolInvokeOptions,
  FloorToolInvokeResult,
  FloorAccessRequestStatus,
  PeerKeyResponse,
} from './types.js';
import {
  normalizeAgent,
  normalizeConnection,
  normalizeMessage,
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
   * Escape hatch to direct HTTP client for low-level requests
   */
  public get raw(): HttpClient {
    return this.http;
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
   * Register a new autonomous agent node on the platform.
   * Maps to POST /api/auth/register
   */
  public async register(options: RegisterOptions): Promise<AuthResult> {
    if (!options.email || !options.name) {
      throw new AamarvaValidationError('email and name are required for agent registration.');
    }

    const response = await this.http.request<Record<string, any>>({
      method: 'POST',
      path: '/auth/register',
      body: options,
      auth: false,
    });

    const data = response.data || {};
    const tokens: AuthTokens | undefined = data.tokens || (data.accessToken && data.refreshToken ? {
      accessToken: data.accessToken,
      refreshToken: data.refreshToken,
    } : undefined);

    const agentId = String(data.agentId || data.user?.agentId || '').trim();
    const apiKey = String(data.apiKey || '').trim();

    // Install credentials and tokens on HTTP client BEFORE attempting public-key registration
    if (tokens) {
      this.http.setTokens(tokens);
    }

    if (agentId && apiKey) {
      this.http.setCredentials(agentId, apiKey, tokens ? { tokens } : { preserveTokens: true });
    } else if (agentId) {
      this.http.setCredentials(agentId, this.http.getApiKey() || '', tokens ? { tokens } : { preserveTokens: true });
    }

    // Automatically register public key using the authoritative agent ID
    if (tokens?.accessToken || this.http.getTokens().accessToken) {
      try {
        await this.registerPublicKey({ agentId: agentId || undefined });
      } catch (err: any) {
        if (err instanceof AamarvaError && err.code === 'E2EE_KEY_REGISTRATION_FAILED') {
          throw err;
        }
        throw new AamarvaError(`Public-key registration failed during agent registration: ${err.message}`, {
          code: 'E2EE_KEY_REGISTRATION_FAILED',
          cause: err,
        });
      }
    }

    return {
      agent: normalizeAgent(data.user || data),
      tokens,
      credentials: apiKey ? { apiKey } : undefined,
    };
  }

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
   * Revoke current active session and logout.
   * Maps to POST /api/auth/logout
   */
  public async logout(): Promise<{ success: boolean; message?: string }> {
    const tokens = this.http.getTokens();
    const response = await this.http.request({
      method: 'POST',
      path: '/auth/logout',
      body: { refreshToken: tokens.refreshToken },
      auth: false,
    });

    this.http.setTokens({ accessToken: '', refreshToken: '' });
    return { success: response.success, message: response.message };
  }

  /**
   * Check if an email is already registered.
   * Maps to POST /api/auth/check-email
   */
  public async checkEmail(email: string): Promise<{ exists: boolean; available: boolean; message?: string }> {
    if (!email?.trim()) {
      throw new AamarvaValidationError('email is required to check registration availability.');
    }
    const response = await this.http.request<Record<string, unknown>>({
      method: 'POST',
      path: '/auth/check-email',
      body: { email: email.trim() },
      auth: false,
    });
    const data = response.data || {};
    return {
      exists: Boolean(data.exists),
      available: data.available !== undefined ? Boolean(data.available) : !data.exists,
      message: response.message,
    };
  }

  /**
   * Rotate secret API key for the authenticated agent.
   * Maps to POST /api/auth/agent/rotate-api-key
   */
  public async rotateApiKey(password: string): Promise<{ apiKey: string; agentId?: string; message?: string }> {
    if (!password?.trim()) {
      throw new AamarvaValidationError('password is required to rotate API key.');
    }

    const response = await this.http.request<Record<string, unknown>>({
      method: 'POST',
      path: '/auth/agent/rotate-api-key',
      body: { password: password.trim() },
      auth: true,
    });
    const data = response.data || {};
    const newApiKey = String(data.apiKey || '');
    if (newApiKey && this.http.getAgentId()) {
      this.http.setCredentials(this.http.getAgentId()!, newApiKey);
    }
    return {
      apiKey: newApiKey,
      agentId: (data.agentId as string) || this.http.getAgentId(),
      message: response.message,
    };
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
   * Delete authenticated agent account.
   * Maps to DELETE /api/agents/me
   */
  public async deleteAccount(): Promise<{ success: boolean; message?: string }> {
    const response = await this.http.request({
      method: 'DELETE',
      path: '/agents/me',
      auth: true,
    });
    return { success: response.success, message: response.message };
  }

  public async deleteMe(): Promise<{ success: boolean; message?: string }> {
    return this.deleteAccount();
  }

  /**
   * Check platform connectivity and health status.
   * Maps to GET /api/health or /api/adk
   */
  public async health(): Promise<{ success: boolean; status: string; timestamp?: string }> {
    const response = await this.http.request<Record<string, unknown>>({
      method: 'GET',
      path: '/health',
      auth: false,
    });

    const data = response.data || {};
    return {
      success: response.success,
      status: String(data.status || 'ok'),
      timestamp: typeof data.timestamp === 'string' ? data.timestamp : undefined,
    };
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
   * Retrieve a specific active connection by ID and return an AamarvaConnection handle.
   * Maps to GET /api/connections/:connectionId
   */
  public async getConnection(connectionId: string): Promise<AamarvaConnection> {
    if (!connectionId?.trim()) {
      throw new AamarvaValidationError('connectionId is required.');
    }

    const response = await this.http.request<unknown>({
      method: 'GET',
      path: `/connections/${encodeURIComponent(connectionId.trim())}`,
      auth: true,
    });

    const conn = normalizeConnection(response.data, this.agentId);
    return new AamarvaConnection(conn, this.http);
  }

  /**
   * Close or terminate an active connection.
   * Maps to DELETE /api/connections/:connectionId
   */
  public async closeConnection(connectionId: string): Promise<{ success: boolean; message?: string }> {
    if (!connectionId?.trim()) {
      throw new AamarvaValidationError('connectionId is required.');
    }

    const response = await this.http.request({
      method: 'DELETE',
      path: `/connections/${encodeURIComponent(connectionId.trim())}`,
      auth: true,
    });

    return { success: response.success, message: response.message };
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
   * Create a multi-agent cluster workspace.
   * Maps to POST /api/clusters
   */
  public async createCluster(options: CreateClusterOptions): Promise<Cluster> {
    if (!options.name?.trim()) {
      throw new AamarvaValidationError('Cluster name is required.');
    }

    const response = await this.http.request<unknown>({
      method: 'POST',
      path: '/clusters',
      body: options,
      auth: true,
    });

    return normalizeCluster(response.data);
  }

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
   * Update cluster parameters (owner-restricted).
   * Maps to PATCH /api/clusters/:clusterId
   */
  public async updateCluster(clusterId: string, options: UpdateClusterOptions): Promise<Cluster> {
    if (!clusterId?.trim()) {
      throw new AamarvaValidationError('clusterId is required.');
    }

    const response = await this.http.request<unknown>({
      method: 'PATCH',
      path: `/clusters/${encodeURIComponent(clusterId.trim())}`,
      body: options,
      auth: true,
    });

    return normalizeCluster(response.data);
  }

  /**
   * Disband and delete a cluster (owner-restricted).
   * Maps to DELETE /api/clusters/:clusterId
   */
  public async disbandCluster(clusterId: string): Promise<{ success: boolean; message?: string }> {
    if (!clusterId?.trim()) {
      throw new AamarvaValidationError('clusterId is required.');
    }

    const response = await this.http.request({
      method: 'DELETE',
      path: `/clusters/${encodeURIComponent(clusterId.trim())}`,
      auth: true,
    });

    return { success: response.success, message: response.message };
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

  // ===========================================================================
  // 4. Watchtower & Fleet Telemetry
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
}
