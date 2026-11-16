/**
 * Primary AAMARVA Client providing fleet-only autonomous agent abstractions.
 *
 * Implements:
 * 1. Authentication, Token Refresh & Agent Identity Management
 * 2. Direct Connections & End-to-End Encrypted (E2EE) Messaging
 * 3. Multi-Agent Clusters, Key Distribution & Recipient-Restricted Messaging
 * 4. Watchtower Fleet Telemetry & Authenticated SSE Event Streaming
 * 5. FLOOR MCP Tool Governance (Discovery, Policy, HITL Access Requests, Grant Redemption & Hardened MCP Execution)
 */

import { HttpClient } from './http.js';
import { AamarvaConnection } from './connection.js';
import {
  AamarvaConfig,
  Agent,
  AgentLifecycleState,
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
  FloorToolPolicy,
  FloorToolInvokeResult,
  FloorAccessRequestStatus,
  FloorExecutionAuthorization,
  PeerKeyResponse,
  WatchtowerActivity,
  WatchtowerStreamTicket,
  WatchtowerStreamEvent,
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
  getLocalIdentitySigningKeyPair,
  getLocalEcdhKeyPair,
  findLocalEcdhKeyPair,
  getLatestLocalEcdhEpoch,
  rotateLocalEcdhKeyPair,
  exportPublicKeyJWK,
  computeKeyFingerprint,
  computeClusterKeyFingerprint,
  computeAudienceHash,
  computeRosterHash,
  signIdentityBinding,
  verifyPeerKey,
  generateClusterKey,
  wrapClusterKeyForRecipient,
  unwrapClusterKey,
  encryptClusterMessagePayload,
  decryptClusterMessagePayload,
} from './crypto.js';
import { invokeExternalMcpTool, McpExecutionAuthConfig } from './mcp-executor.js';
import { AamarvaValidationError, AamarvaError, AamarvaAuthError } from './errors.js';

export class Aamarva {
  public readonly http: HttpClient;
  private lifecycleState: AgentLifecycleState = 'unauthenticated';
  private registeredAgentId?: string;
  private registeredKeyFingerprint?: string;
  private registeredKeyEpoch?: number;
  private isRegisteringKey = false;
  private clusterKeyCache = new Map<string, Buffer>();
  private allowInsecureLocalhostMcpHttp: boolean;

  constructor(config: AamarvaConfig = {}) {
    this.http = new HttpClient(config);
    this.allowInsecureLocalhostMcpHttp = Boolean(config.allowInsecureHttpForLocalhost);
    if (config.accessToken) {
      this.lifecycleState = 'authenticated';
    }
    this.http.setOnAuthSuccess(() => this.registerPublicKey());
    this.http.setOnTargetAgentIdChange(() => {
      this.invalidateTargetScopedState();
    });
  }

  /**
   * Current configured Agent ID (if set)
   */
  public get agentId(): string | undefined {
    return this.http.getAgentId();
  }

  /**
   * Explicit client authentication and E2EE lifecycle state
   */
  public getLifecycleState(): AgentLifecycleState {
    if (this.registeredAgentId && this.registeredKeyFingerprint) {
      return 'e2ee_ready';
    }
    if (this.http.getTokens().accessToken) {
      return this.lifecycleState === 'e2ee_ready' ? 'e2ee_ready' : 'authenticated';
    }
    return this.lifecycleState;
  }

  private invalidateTargetScopedState(): void {
    this.registeredAgentId = undefined;
    this.registeredKeyFingerprint = undefined;
    this.registeredKeyEpoch = undefined;
    this.clusterKeyCache.clear();
    this.lifecycleState = this.http.getTokens().accessToken ? 'authenticated' : 'unauthenticated';
  }

  /**
   * Set target slave agent ID when operating within a managed fleet scope.
   * Immediately clears target-scoped key registrations and cluster key caches to prevent cross-agent contamination.
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
  // 1. Authentication, Identity & Key Management
  // ===========================================================================

  private async resolveEffectiveAgentId(explicitAgentId?: string): Promise<string> {
    const targetId = this.http.getTargetAgentId();
    const candidate = (explicitAgentId || targetId || this.http.getAgentId() || '').trim();
    if (candidate && candidate.toLowerCase() !== 'me') {
      return candidate;
    }

    if (this.http.getTokens().accessToken) {
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
          const resolved = authoritativeId.trim();
          if (!targetId && this.http.getApiKey()) {
            this.http.setCredentials(resolved, this.http.getApiKey()!, true);
          }
          return resolved;
        }
      } catch (err: any) {
        throw new AamarvaError(`Unable to resolve authoritative agent identity for E2EE registration: ${err.message}`, {
          code: 'E2EE_KEY_REGISTRATION_FAILED',
          cause: err,
        });
      }
    }

    throw new AamarvaError('Agent identity could not be resolved for E2EE key registration.', {
      code: 'E2EE_KEY_REGISTRATION_FAILED',
    });
  }

  /**
   * Register local E2EE public key automatically via PUT /api/agents/me/e2ee (idempotent per identity/epoch/fingerprint).
   */
  public async registerPublicKey(options?: { force?: boolean; agentId?: string; allowRotation?: boolean }): Promise<void> {
    if (this.isRegisteringKey) {
      return;
    }

    const myAgentId = await this.resolveEffectiveAgentId(options?.agentId);
    const epoch = getLatestLocalEcdhEpoch(myAgentId);

    let localPubJwk: any;
    let localIdentityJwk: any;
    let localFp: string;
    let localSignature: string;

    try {
      const ecdhKp = getLocalEcdhKeyPair(myAgentId, epoch);
      const identityKp = getLocalIdentitySigningKeyPair(myAgentId);
      localPubJwk = exportPublicKeyJWK(ecdhKp.publicKey);
      localIdentityJwk = exportPublicKeyJWK(identityKp.publicKey);
      localFp = computeKeyFingerprint(localPubJwk);
      localSignature = signIdentityBinding(identityKp.privateKey, myAgentId, localFp);
    } catch (err: any) {
      this.registeredAgentId = undefined;
      this.registeredKeyFingerprint = undefined;
      this.registeredKeyEpoch = undefined;
      if (err instanceof AamarvaError) throw err;
      throw new AamarvaError(`Failed to generate or export local public key: ${err.message}`, {
        code: 'E2EE_KEY_REGISTRATION_FAILED',
        cause: err,
      });
    }

    if (
      !options?.force &&
      !options?.allowRotation &&
      this.registeredAgentId === myAgentId &&
      this.registeredKeyFingerprint === localFp &&
      this.registeredKeyEpoch === epoch
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
          identityKey: localIdentityJwk,
          signature: localSignature,
          allowRotation: Boolean(options?.allowRotation),
          keyVersion: epoch,
          keyEpoch: epoch,
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
      this.registeredKeyEpoch = epoch;
      this.lifecycleState = 'e2ee_ready';
    } catch (err: any) {
      this.registeredAgentId = undefined;
      this.registeredKeyFingerprint = undefined;
      this.registeredKeyEpoch = undefined;
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
   * Rotate the active local ECDH transport keypair to the next positive epoch while retaining historical keys for past message decryption,
   * and register the new key with allowRotation: true bound by the persistent ECDSA identity signing key.
   */
  public async rotateE2eeKey(): Promise<{ keyEpoch: number; fingerprint: string; publicKey: any }> {
    await this.http.ensureAuthenticated();
    const myAgentId = await this.resolveEffectiveAgentId();

    this.isRegisteringKey = true;
    try {
      const rotated = rotateLocalEcdhKeyPair(myAgentId);
      const identityKp = getLocalIdentitySigningKeyPair(myAgentId);
      const localPubJwk = exportPublicKeyJWK(rotated.publicKey);
      const localIdentityJwk = exportPublicKeyJWK(identityKp.publicKey);
      const localFp = computeKeyFingerprint(localPubJwk);
      const localSignature = signIdentityBinding(identityKp.privateKey, myAgentId, localFp);

      const response = await this.http.request<any>({
        method: 'PUT',
        path: '/agents/me/e2ee',
        body: {
          publicKey: localPubJwk,
          fingerprint: localFp,
          identityKey: localIdentityJwk,
          signature: localSignature,
          allowRotation: true,
          keyVersion: rotated.keyEpoch,
          keyEpoch: rotated.keyEpoch,
        },
        auth: true,
        skipAutoAuth: true,
      });

      if (!response || response.success === false) {
        throw new AamarvaError('Server rejected rotated E2EE public key registration.', {
          code: 'E2EE_KEY_REGISTRATION_FAILED',
        });
      }

      this.registeredAgentId = myAgentId;
      this.registeredKeyFingerprint = localFp;
      this.registeredKeyEpoch = rotated.keyEpoch;
      this.clusterKeyCache.clear();
      this.lifecycleState = 'e2ee_ready';

      return {
        keyEpoch: rotated.keyEpoch,
        fingerprint: localFp,
        publicKey: localPubJwk,
      };
    } finally {
      this.isRegisteringKey = false;
    }
  }

  /**
   * Check whether E2EE identity is verified and ready for secure operations.
   */
  public isE2eeReady(): boolean {
    return Boolean(this.registeredAgentId && this.registeredKeyFingerprint);
  }

  /**
   * Verify that the server's registered E2EE key matches our active local ECDH keypair.
   * Fails closed on mismatch (IDENTITY_KEY_MISMATCH).
   */
  public async verifyRegisteredKeyConsistency(): Promise<AgentE2eeKeyResponse> {
    const myAgentId = await this.resolveEffectiveAgentId();
    const latestEpoch = getLatestLocalEcdhEpoch(myAgentId);
    const localEcdhKp = getLocalEcdhKeyPair(myAgentId, latestEpoch);
    const localFp = computeKeyFingerprint(exportPublicKeyJWK(localEcdhKp.publicKey));

    const serverKey = await this.getAgentE2eeKey();
    if (serverKey.fingerprint && serverKey.fingerprint !== localFp) {
      throw new AamarvaError(
        `Server E2EE key fingerprint mismatch: server holds "${serverKey.fingerprint}", local keystore holds "${localFp}".`,
        { code: 'IDENTITY_KEY_MISMATCH' }
      );
    }
    return serverKey;
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
      this.invalidateTargetScopedState();
    }

    await this.http.ensureAuthenticated();
    const tokens = this.http.getTokens();

    if (!tokens.accessToken || !tokens.refreshToken) {
      throw new AamarvaError('Login response did not return valid session tokens.', {
        code: 'AUTHENTICATION_FAILED',
      });
    }

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
   * Retrieve another agent's registered E2EE public key metadata.
   * Maps to GET /api/agents/:agentId/e2ee
   */
  public async getAgentE2eeKeyById(agentId: string): Promise<AgentE2eeKeyResponse> {
    if (!agentId || !agentId.trim()) {
      throw new AamarvaValidationError('agentId is required.');
    }

    const response = await this.http.request<Record<string, unknown>>({
      method: 'GET',
      path: `/agents/${encodeURIComponent(agentId.trim())}/e2ee`,
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

  private async resolveConnectionRecord(
    accountOrConnectionId: string,
    explicitPeerAgentId?: string
  ): Promise<Connection> {
    if (!accountOrConnectionId || !accountOrConnectionId.trim()) {
      throw new AamarvaValidationError('accountId or connectionId is required.');
    }
    const cleanId = accountOrConnectionId.trim();
    if (explicitPeerAgentId && explicitPeerAgentId.trim()) {
      const cleanPeer = explicitPeerAgentId.trim();
      return {
        connectionId: cleanId,
        agentId: cleanPeer,
        peerAccountId: cleanPeer,
        peerAgentId: cleanPeer,
        status: 'active',
        createdAt: '',
      };
    }

    // If caller passed an account ID directly (e.g., AMR-5678), route directly with it,
    // or if caller passed a connectionId (e.g., conn_mock_123), resolve peerAccountId via GET /connections.
    const looksLikeConnectionId = /^(conn|c)[_-]/i.test(cleanId) || !cleanId.toUpperCase().startsWith('AMR-');
    if (looksLikeConnectionId) {
      try {
        const connections = await this.getConnections();
        const match = connections.find(
          (c) =>
            c.connectionId === cleanId ||
            c.peerAccountId === cleanId ||
            c.peerAgentId === cleanId ||
            c.agentId === cleanId
        );
        if (match) {
          return match;
        }
      } catch {
        // Fall back to direct ID routing if connection list fetch fails
      }
    }

    return {
      connectionId: cleanId,
      agentId: cleanId,
      peerAccountId: cleanId,
      peerAgentId: cleanId,
      status: 'active',
      createdAt: '',
    };
  }

  /**
   * Retrieve peer public key details for end-to-end encryption.
   * Maps to GET /api/connections/peer-key/:accountId
   */
  public async getPeerKey(accountOrConnectionId: string): Promise<PeerKeyResponse> {
    const conn = await this.resolveConnectionRecord(accountOrConnectionId);
    const accountId = (conn.peerAccountId || conn.peerAgentId || conn.agentId || conn.connectionId).trim();

    const response = await this.http.request<PeerKeyResponse>({
      method: 'GET',
      path: `/connections/peer-key/${encodeURIComponent(accountId)}`,
      auth: true,
    });

    return (response.data || response) as PeerKeyResponse;
  }

  /**
   * Send an E2EE encrypted message over a connection channel.
   * Maps to POST /api/connections/messages/:accountId
   */
  public async sendMessage(accountOrConnectionId: string, options: string | SendMessageOptions): Promise<Message> {
    const explicitPeer = typeof options === 'object' ? options.peerAgentId : undefined;
    const connRecord = await this.resolveConnectionRecord(accountOrConnectionId, explicitPeer);
    const conn = new AamarvaConnection(connRecord, this.http);
    return conn.send(options);
  }

  /**
   * Retrieve and decrypt private messages for a connection channel.
   * Maps to GET /api/connections/messages/:accountId
   */
  public async getMessages(
    accountOrConnectionId: string,
    options: { page?: number; limit?: number; since?: string; peerAgentId?: string } = {}
  ): Promise<Message[]> {
    const connRecord = await this.resolveConnectionRecord(accountOrConnectionId, options.peerAgentId);
    const conn = new AamarvaConnection(connRecord, this.http);
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
  public async getClusterMessages(
    clusterId: string,
    options: { since?: string; page?: number; limit?: number } = {}
  ): Promise<ClusterMessage[]> {
    if (!clusterId?.trim()) {
      throw new AamarvaValidationError('clusterId is required.');
    }

    const query: Record<string, string | number | undefined> = {};
    if (options.since) query.since = options.since;
    if (options.page !== undefined) query.page = options.page;
    if (options.limit !== undefined) query.limit = options.limit;

    const response = await this.http.request<unknown[]>({
      method: 'GET',
      path: `/clusters/${encodeURIComponent(clusterId.trim())}/messages`,
      query: Object.keys(query).length > 0 ? query : undefined,
      auth: true,
    });

    const list = Array.isArray(response.data) ? response.data : [];
    return list.map((item: any) => {
      const rawRecipients = Array.isArray(item.recipientAgentIds)
        ? item.recipientAgentIds.map(String)
        : Array.isArray(item.recipients)
        ? item.recipients.map(String)
        : undefined;
      return {
        messageId: String(item.messageId || item.id || ''),
        clusterId: clusterId.trim(),
        senderAgentId: String(item.senderAgentId || item.sender_agent_id || ''),
        ciphertext: String(item.ciphertext || ''),
        nonce: String(item.nonce || ''),
        version: Number(item.version !== undefined ? item.version : 2),
        keyEpoch: Number(item.keyEpoch ?? item.key_epoch ?? 1),
        recipients: rawRecipients,
        recipientAgentIds: rawRecipients,
        createdAt: typeof item.createdAt === 'string' ? item.createdAt : new Date().toISOString(),
      };
    });
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

    const rawRecipients = options.recipientAgentIds || options.recipients || [];
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

    const keyEpoch = options.keyEpoch !== undefined ? options.keyEpoch : 1;
    if (!Number.isInteger(keyEpoch) || keyEpoch < 1) {
      throw new AamarvaValidationError('keyEpoch must be a positive integer >= 1.');
    }

    const payload = {
      senderAgentId,
      ciphertext: options.ciphertext,
      nonce: options.nonce,
      version: options.version !== undefined ? options.version : 2,
      keyEpoch,
      recipientAgentIds: finalRecipients,
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
   * Submit key packages to the platform's key-distribution endpoint.
   * Maps to POST /api/clusters/:clusterId/key-distribution
   */
  public async submitClusterKeyDistribution(
    clusterId: string,
    payload: {
      epoch: number;
      senderAgentId?: string;
      keyFingerprint?: string;
      audienceHash?: string;
      rosterHash?: string;
      distributions?: Array<{
        recipientAgentId: string;
        encryptedKeyPackage: string;
      }>;
      keyPackages?: Array<{
        recipientAgentId: string;
        encryptedKeyPackage: string;
        nonce?: string;
        wrappingParams?: Record<string, unknown>;
      }>;
    }
  ): Promise<void> {
    if (!clusterId?.trim()) {
      throw new AamarvaValidationError('clusterId is required.');
    }

    const distributions =
      payload.distributions ||
      (payload.keyPackages || []).map((kp) => ({
        recipientAgentId: kp.recipientAgentId,
        encryptedKeyPackage: kp.encryptedKeyPackage,
      }));

    await this.http.request({
      method: 'POST',
      path: `/clusters/${encodeURIComponent(clusterId.trim())}/key-distribution`,
      body: {
        clusterId: clusterId.trim(),
        epoch: payload.epoch,
        ...(payload.keyFingerprint ? { keyFingerprint: payload.keyFingerprint } : {}),
        ...(payload.audienceHash ? { audienceHash: payload.audienceHash } : {}),
        ...(payload.rosterHash ? { rosterHash: payload.rosterHash } : {}),
        ...(payload.senderAgentId ? { senderAgentId: payload.senderAgentId } : {}),
        distributions,
      },
      auth: true,
    });
  }

  private async resolvePeerEcdhPublicKey(agentId: string): Promise<any | null> {
    // 1. Prefer direct /agents/:agentId/e2ee endpoint
    try {
      const agentKey = await this.getAgentE2eeKeyById(agentId);
      if (agentKey && agentKey.publicKey) {
        if (agentKey.identityKey && agentKey.signature && agentKey.fingerprint) {
          verifyPeerKey(
            agentKey.publicKey,
            agentKey.fingerprint,
            agentId,
            agentKey.signature,
            agentKey.identityKey
          );
        }
        return agentKey.publicKey;
      }
    } catch (err: any) {
      if (err instanceof AamarvaError && err.code === 'PEER_KEY_VERIFICATION_FAILED') {
        throw err;
      }
      // Fall back to connection peer-key lookup
    }

    // 2. Fallback via /connections and /connections/peer-key/:accountId
    try {
      const connections = await this.getConnections();
      const conn = connections.find(
        (c) =>
          (c.peerAccountId || c.peerAgentId || c.agentId).trim().toUpperCase() === agentId.trim().toUpperCase()
      );
      if (conn) {
        const peerKey = await this.getPeerKey(conn.peerAccountId || conn.peerAgentId || conn.agentId);
        if (peerKey && peerKey.peerE2eePublicKey) {
          if (peerKey.peerIdentityKey && peerKey.peerKeySignature && peerKey.peerKeyFingerprint) {
            verifyPeerKey(
              peerKey.peerE2eePublicKey,
              peerKey.peerKeyFingerprint,
              peerKey.peerAgentId || peerKey.peerAccountId || agentId,
              peerKey.peerKeySignature,
              peerKey.peerIdentityKey
            );
          }
          return peerKey.peerE2eePublicKey;
        }
      }
    } catch (err: any) {
      if (err instanceof AamarvaError && err.code === 'PEER_KEY_VERIFICATION_FAILED') {
        throw err;
      }
    }

    return null;
  }

  /**
   * Generate, wrap, and distribute cluster symmetric keys to all authorized recipients using AAMARVA_CLUSTER_KEY_WRAP_V1.
   */
  public async distributeClusterKey(
    clusterId: string,
    options: {
      recipients?: string[];
      epoch?: number;
      recipientPublicKeys?: Record<string, any>;
    } = {}
  ): Promise<{ epoch: number; clusterKey: Buffer; recipients: string[] }> {
    if (!clusterId?.trim()) {
      throw new AamarvaValidationError('clusterId is required.');
    }
    const epoch = options.epoch !== undefined ? options.epoch : 1;
    if (!Number.isInteger(epoch) || epoch < 1) {
      throw new AamarvaValidationError('epoch must be a positive integer >= 1.');
    }

    const effectiveAgentId = await this.resolveEffectiveAgentId();
    const masterId = await this.resolveMasterAgentId();

    let clusterMembers: string[] = [];
    try {
      const cluster = await this.getCluster(clusterId);
      if (Array.isArray(cluster.members) && cluster.members.length > 0) {
        clusterMembers = cluster.members.map(String);
        const memberSetUpper = new Set(clusterMembers.map((m) => m.trim().toUpperCase()));
        if (options.recipients) {
          for (const r of options.recipients) {
            if (r && r.trim() && !memberSetUpper.has(r.trim().toUpperCase())) {
              throw new AamarvaError(
                `Recipient "${r}" is not a verified member of cluster "${clusterId}".`,
                { code: 'CLUSTER_MEMBERSHIP_INVALID' }
              );
            }
          }
        }
      }
    } catch (err: any) {
      if (err instanceof AamarvaError && err.code === 'CLUSTER_MEMBERSHIP_INVALID') {
        throw err;
      }
    }

    const recipientSet = new Set<string>();
    if (masterId) recipientSet.add(masterId);
    if (effectiveAgentId) recipientSet.add(effectiveAgentId);
    if (options.recipients) {
      for (const r of options.recipients) {
        if (r && r.trim()) recipientSet.add(r.trim());
      }
    }
    const finalRecipients = Array.from(recipientSet);
    const rosterMembers = clusterMembers.length > 0 ? clusterMembers : finalRecipients;

    const clusterKey = generateClusterKey();
    const localEpoch = getLatestLocalEcdhEpoch(effectiveAgentId);
    const senderKp = getLocalEcdhKeyPair(effectiveAgentId, localEpoch);

    const distributions: Array<{
      recipientAgentId: string;
      encryptedKeyPackage: string;
    }> = [];

    for (const recipientId of finalRecipients) {
      let recipientPubKey = options.recipientPublicKeys?.[recipientId];
      if (!recipientPubKey) {
        if (recipientId.toUpperCase() === effectiveAgentId.toUpperCase()) {
          recipientPubKey = senderKp.publicKey;
        } else {
          recipientPubKey = await this.resolvePeerEcdhPublicKey(recipientId);
        }
      }

      if (!recipientPubKey) {
        throw new AamarvaError(
          `Recipient "${recipientId}" does not have a registered public key for cluster encryption.`,
          { code: 'RECIPIENT_KEY_MISSING' }
        );
      }

      const wrapped = wrapClusterKeyForRecipient(clusterKey, recipientPubKey, senderKp.privateKey, {
        clusterId: clusterId.trim(),
        epoch,
      });
      distributions.push({
        recipientAgentId: recipientId,
        encryptedKeyPackage: wrapped.encryptedKeyPackage,
      });
    }

    await this.submitClusterKeyDistribution(clusterId, {
      epoch,
      keyFingerprint: computeClusterKeyFingerprint(clusterKey),
      audienceHash: computeAudienceHash(finalRecipients),
      rosterHash: computeRosterHash(rosterMembers),
      senderAgentId: effectiveAgentId,
      distributions,
    });

    this.clusterKeyCache.set(`${clusterId}:${epoch}`, clusterKey);
    return {
      epoch,
      clusterKey,
      recipients: finalRecipients,
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

  /**
   * Retrieve and locally decrypt symmetric cluster key for the given epoch.
   */
  public async getClusterKey(
    clusterId: string,
    epoch = 1,
    options?: { senderPublicKey?: any }
  ): Promise<Buffer> {
    if (!Number.isInteger(epoch) || epoch < 1) {
      throw new AamarvaValidationError('epoch must be a positive integer >= 1.');
    }
    const cacheKey = `${clusterId}:${epoch}`;
    if (this.clusterKeyCache.has(cacheKey)) {
      return this.clusterKeyCache.get(cacheKey)!;
    }

    const dist = await this.getClusterKeyDistribution(clusterId, epoch);
    if (!dist || !dist.encryptedKeyPackage) {
      throw new AamarvaError(`No cluster key package available for cluster "${clusterId}" at epoch ${epoch}.`, {
        code: 'CLUSTER_KEY_MISSING',
      });
    }

    if (dist.epoch !== undefined && Number(dist.epoch) !== epoch) {
      throw new AamarvaError(`Cluster key distribution epoch mismatch: expected ${epoch}, got ${dist.epoch}.`, {
        code: 'CLUSTER_KEY_UNWRAP_FAILED',
      });
    }

    const effectiveAgentId = await this.resolveEffectiveAgentId();
    const latestEpoch = getLatestLocalEcdhEpoch(effectiveAgentId);
    let localKp = getLocalEcdhKeyPair(effectiveAgentId, latestEpoch);

    // If platform specifies recipientKeyFingerprint, locate the matching historical or active local ECDH key
    if (dist.recipientKeyFingerprint) {
      let matched = false;
      for (let e = latestEpoch; e >= 1; e--) {
        const candidate = findLocalEcdhKeyPair(effectiveAgentId, e);
        if (candidate && computeKeyFingerprint(exportPublicKeyJWK(candidate.publicKey)) === dist.recipientKeyFingerprint) {
          localKp = candidate;
          matched = true;
          break;
        }
      }
      if (!matched) {
        throw new AamarvaError(
          `No local ECDH private key matches cluster distribution recipientKeyFingerprint "${dist.recipientKeyFingerprint}".`,
          { code: 'CLUSTER_KEY_UNWRAP_FAILED' }
        );
      }
    }

    let senderPubKey = options?.senderPublicKey || dist.senderPublicKey;
    if (!senderPubKey && dist.senderAgentId) {
      if (dist.senderAgentId.trim().toUpperCase() === effectiveAgentId.toUpperCase()) {
        senderPubKey = localKp.publicKey;
      } else {
        senderPubKey = await this.resolvePeerEcdhPublicKey(dist.senderAgentId);
      }
    }

    const clusterKey = unwrapClusterKey(
      dist.encryptedKeyPackage,
      { expectedClusterId: clusterId.trim(), expectedEpoch: epoch },
      localKp.privateKey,
      senderPubKey
    );

    if (dist.keyFingerprint && computeClusterKeyFingerprint(clusterKey) !== dist.keyFingerprint) {
      throw new AamarvaError('Unwrapped cluster key fingerprint does not match distribution metadata.', {
        code: 'CLUSTER_KEY_UNWRAP_FAILED',
      });
    }

    this.clusterKeyCache.set(cacheKey, clusterKey);
    return clusterKey;
  }

  /**
   * Encrypt and broadcast a cluster message using protocol version 2 and cluster symmetric key.
   */
  public async sendEncryptedClusterMessage(
    clusterId: string,
    plaintext: string,
    options: {
      recipients?: string[];
      recipientAgentIds?: string[];
      epoch?: number;
      recipientPublicKeys?: Record<string, any>;
    } = {}
  ): Promise<{ messageId: string; version: number; keyEpoch: number; recipients: string[] }> {
    const epoch = options.epoch !== undefined ? options.epoch : 1;
    if (!Number.isInteger(epoch) || epoch < 1) {
      throw new AamarvaValidationError('epoch must be a positive integer >= 1.');
    }

    const requestedRecipients = options.recipientAgentIds || options.recipients;

    let clusterKey: Buffer;
    try {
      clusterKey = await this.getClusterKey(clusterId, epoch);
    } catch {
      const dist = await this.distributeClusterKey(clusterId, {
        recipients: requestedRecipients,
        epoch,
        recipientPublicKeys: options.recipientPublicKeys,
      });
      clusterKey = dist.clusterKey;
    }

    const enc = encryptClusterMessagePayload(plaintext, clusterKey, clusterId, epoch);
    const result = await this.sendClusterMessage(clusterId, {
      ciphertext: enc.ciphertext,
      nonce: enc.nonce,
      version: 2,
      keyEpoch: epoch,
      recipientAgentIds: requestedRecipients,
    });

    const masterId = await this.resolveMasterAgentId();
    const senderId = (this.http.getAgentId() || this.agentId || '').trim();
    const allRecipients = Array.from(new Set([masterId, senderId, ...(requestedRecipients || [])]));

    return {
      messageId: result.messageId,
      version: 2,
      keyEpoch: epoch,
      recipients: allRecipients,
    };
  }

  /**
   * Decrypt an encrypted cluster message using the cluster symmetric key.
   */
  public async decryptClusterMessage(
    clusterId: string,
    message: { ciphertext: string; nonce: string; keyEpoch?: number; version?: number },
    options?: { senderPublicKey?: any }
  ): Promise<string> {
    if (!message || typeof message !== 'object') {
      throw new AamarvaValidationError('Cluster message object is required.');
    }
    const epoch = message.keyEpoch;
    if (typeof epoch !== 'number' || !Number.isInteger(epoch) || epoch < 1) {
      throw new AamarvaError(`Missing or invalid keyEpoch on cluster message: ${String(epoch)}`, {
        code: 'CLUSTER_MESSAGE_DECRYPTION_FAILED',
      });
    }
    const version = message.version !== undefined ? message.version : 2;
    const clusterKey = await this.getClusterKey(clusterId, epoch, options);
    return decryptClusterMessagePayload(message.ciphertext, message.nonce, clusterKey, clusterId, epoch, version);
  }

  // ===========================================================================
  // 4. Watchtower Fleet Telemetry & Authenticated SSE Streaming
  // ===========================================================================

  /**
   * Retrieve recent fleet activity telemetry.
   * Maps to GET /api/watchtower/activity
   */
  public async getWatchtowerActivity(
    limit?: number,
    options: { before?: string } = {}
  ): Promise<WatchtowerActivity[]> {
    const query: Record<string, string | number | undefined> = {};
    if (limit !== undefined) query.limit = limit;
    if (options.before) query.before = options.before;

    const response = await this.http.request<unknown[]>({
      method: 'GET',
      path: '/watchtower/activity',
      query: Object.keys(query).length > 0 ? query : undefined,
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

    const data = response.data && typeof response.data === 'object' ? response.data : {};
    const resAny = response as any;
    const ticket = String(resAny.ticket || data.ticket || '');
    const expiresAt = String(resAny.expiresAt || data.expiresAt || '');
    if (!ticket) {
      throw new AamarvaError('Watchtower stream-ticket endpoint did not return a valid ticket.', {
        code: 'WATCHTOWER_TICKET_FAILED',
      });
    }
    return {
      ticket,
      streamUrl: `${this.http.getBaseUrl()}/watchtower/stream?ticket=${encodeURIComponent(ticket)}`,
      expiresAt,
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
   * Stream real-time Watchtower telemetry events over Server-Sent Events (SSE).
   * Handles ticket acquisition, incremental chunk parsing, event deduplication, and bounded backoff reconnect.
   */
  public async *streamWatchtowerEvents(
    options: {
      ticket?: string;
      signal?: AbortSignal;
      maxReconnects?: number;
      deduplicate?: boolean;
    } = {}
  ): AsyncGenerator<WatchtowerStreamEvent, void, unknown> {
    const maxReconnects = options.maxReconnects ?? 5;
    const deduplicate = options.deduplicate !== false;
    const seenIds = new Set<string>();
    let reconnects = 0;
    let currentTicket = options.ticket;
    let lastEventId: string | undefined;

    while (!options.signal?.aborted) {
      try {
        if (!currentTicket) {
          const issued = await this.getWatchtowerStreamTicket();
          currentTicket = issued.ticket;
        }

        const headers: Record<string, string> = {};
        if (lastEventId) {
          headers['Last-Event-ID'] = lastEventId;
        }

        const response = await this.http.openStream(
          '/watchtower/stream',
          { ticket: currentTicket },
          { signal: options.signal, headers, auth: true }
        );

        const body = response.body;
        if (!body) {
          throw new AamarvaError('Watchtower SSE stream response has no readable body.', {
            code: 'WATCHTOWER_STREAM_FAILED',
          });
        }

        const reader = body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        let eventName = 'message';
        let eventId: string | undefined;
        let dataLines: string[] = [];

        const flushEvent = (): WatchtowerStreamEvent | null => {
          if (dataLines.length === 0) {
            eventName = 'message';
            eventId = undefined;
            return null;
          }
          const rawData = dataLines.join('\n');
          dataLines = [];
          let parsed: unknown = rawData;
          try {
            parsed = JSON.parse(rawData);
          } catch {
            // Preserve raw string data when non-JSON
          }
          const ev: WatchtowerStreamEvent = {
            id: eventId,
            event: eventName || 'message',
            data: parsed,
            rawData,
          };
          if (eventId) {
            lastEventId = eventId;
          }
          eventName = 'message';
          eventId = undefined;
          return ev;
        };

        try {
          while (!options.signal?.aborted) {
            const { value, done } = await reader.read();
            if (done) {
              break;
            }
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split(/\r?\n/);
            buffer = lines.pop() ?? '';

            for (const line of lines) {
              if (line === '') {
                const ev = flushEvent();
                if (ev) {
                  reconnects = 0; // Reset backoff once valid event is received
                  if (deduplicate && ev.id) {
                    if (seenIds.has(ev.id)) continue;
                    seenIds.add(ev.id);
                    if (seenIds.size > 1000) {
                      const oldest = seenIds.values().next().value;
                      if (oldest !== undefined) seenIds.delete(oldest);
                    }
                  }
                  yield ev;
                }
                continue;
              }
              if (line.startsWith(':')) {
                continue; // SSE comment / keepalive
              }
              const colonIdx = line.indexOf(':');
              const field = colonIdx === -1 ? line : line.slice(0, colonIdx);
              let val = colonIdx === -1 ? '' : line.slice(colonIdx + 1);
              if (val.startsWith(' ')) val = val.slice(1);

              if (field === 'event') eventName = val;
              else if (field === 'id') eventId = val;
              else if (field === 'data') dataLines.push(val);
            }
          }

          if (!options.signal?.aborted && dataLines.length > 0) {
            const trailing = flushEvent();
            if (trailing && (!deduplicate || !trailing.id || !seenIds.has(trailing.id))) {
              if (trailing.id) seenIds.add(trailing.id);
              yield trailing;
            }
          }
        } finally {
          try {
            reader.releaseLock();
          } catch {
            // Ignore lock release errors
          }
        }

        // Stream closed cleanly; if aborted or maxReconnects === 0 stop
        if (options.signal?.aborted || maxReconnects <= 0) {
          return;
        }
        currentTicket = undefined;
        reconnects++;
        if (reconnects > maxReconnects) {
          return;
        }
      } catch (err: any) {
        if (options.signal?.aborted) {
          return;
        }
        if (err instanceof AamarvaAuthError || err?.statusCode === 401 || err?.statusCode === 403) {
          throw err;
        }
        reconnects++;
        if (reconnects > maxReconnects) {
          throw err;
        }
        currentTicket = undefined;
      }

      const backoffMs = Math.min(Math.pow(2, reconnects) * 250, 5000) + Math.floor(Math.random() * 100);
      await new Promise((resolve) => setTimeout(resolve, backoffMs));
    }
  }

  /**
   * Callback subscription wrapper around streamWatchtowerEvents().
   */
  public subscribeWatchtowerStream(
    onEvent: (event: WatchtowerStreamEvent) => void | Promise<void>,
    options: {
      ticket?: string;
      maxReconnects?: number;
      deduplicate?: boolean;
      onError?: (err: unknown) => void;
    } = {}
  ): { close: () => void; done: Promise<void> } {
    const controller = new AbortController();
    const done = (async () => {
      try {
        for await (const ev of this.streamWatchtowerEvents({
          ticket: options.ticket,
          signal: controller.signal,
          maxReconnects: options.maxReconnects,
          deduplicate: options.deduplicate,
        })) {
          await onEvent(ev);
        }
      } catch (err) {
        if (!controller.signal.aborted && options.onError) {
          options.onError(err);
        } else if (!controller.signal.aborted) {
          throw err;
        }
      }
    })();

    return {
      close: () => controller.abort(),
      done,
    };
  }

  /**
   * Retrieve outbound agent footprints trace.
   * Maps to GET /api/agent/footprints
   */
  public async getFootprints(options: { agentId?: string } = {}): Promise<Footprint[]> {
    const query: Record<string, string | undefined> = {};
    if (options.agentId) query.agentId = options.agentId;

    const response = await this.http.request<Footprint[]>({
      method: 'GET',
      path: '/agent/footprints',
      query: Object.keys(query).length > 0 ? query : undefined,
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
   * Retrieve tool governance policy before submitting an invocation or access request.
   * Maps to GET /api/floor/tools/:toolId/policy
   */
  public async getFloorToolPolicy(toolId: string): Promise<FloorToolPolicy> {
    if (!toolId?.trim()) {
      throw new AamarvaValidationError('toolId is required.');
    }

    const response = await this.http.request<FloorToolPolicy>({
      method: 'GET',
      path: `/floor/tools/${encodeURIComponent(toolId.trim())}/policy`,
      auth: true,
    });

    const data = (response.data && typeof response.data === 'object' ? response.data : response) as FloorToolPolicy;
    return data;
  }

  /**
   * Request / create an invocation or access request for a FLOOR tool.
   * Maps to POST /api/floor/tools/:toolId/invoke
   */
  public async createFloorInvocation(
    toolId: string,
    options: { reason?: string; arguments?: Record<string, unknown>; requestType?: 'access' | 'execute' } = {}
  ): Promise<any> {
    if (!toolId?.trim()) {
      throw new AamarvaValidationError('toolId is required.');
    }

    const body: Record<string, unknown> = {
      reason: options.reason || 'Agent requested tool invocation',
      arguments: options.arguments || {},
    };
    if (options.requestType) {
      body.requestType = options.requestType;
    }

    const response = await this.http.request<any>({
      method: 'POST',
      path: `/floor/tools/${encodeURIComponent(toolId.trim())}/invoke`,
      body,
      auth: true,
    });

    const rawData = response.data;
    const data = (rawData && typeof rawData === 'object' ? rawData : response) || {};
    const resAny = response as any;
    const status = String(data.status || resAny.status || '').trim().toLowerCase();
    const requestId = data.requestId || resAny.requestId || (data.invocationId ? String(data.invocationId) : undefined);
    const invocationId = String(data.invocationId || data.id || requestId || '');

    // Handle HTTP 200 immediate direct result when no invocationId/pending request was created
    const hasImmediateOutput =
      status === 'completed' ||
      status === 'executed' ||
      (response.success === true && !invocationId && status !== 'pending' && status !== 'denied' && status !== 'rejected' && status !== 'approved');

    if (hasImmediateOutput) {
      return {
        invocationId,
        requestId,
        toolId: String(data.toolId || toolId.trim()),
        status: 'executed',
        directResult: data.result !== undefined ? data.result : rawData,
        message: resAny.message || data.message,
      };
    }

    return {
      invocationId,
      requestId: requestId ? String(requestId) : undefined,
      toolId: String(data.toolId || toolId.trim()),
      status: status || 'pending',
      message: resAny.message || data.message,
    };
  }

  /**
   * Poll a FLOOR access request until approved or terminal denial/timeout.
   */
  public async waitForFloorRequestApproval(
    requestId: string,
    options: { intervalMs?: number; timeoutMs?: number } = {}
  ): Promise<FloorAccessRequestStatus> {
    if (!requestId?.trim()) {
      throw new AamarvaValidationError('requestId is required.');
    }

    const intervalMs = Math.max(50, options.intervalMs ?? 1000);
    const timeoutMs = Math.max(intervalMs, options.timeoutMs ?? 30000);
    const deadline = Date.now() + timeoutMs;

    while (true) {
      const status = await this.getFloorRequestStatus(requestId);
      const norm = (status.status || '').trim().toLowerCase();

      if (norm === 'approved' || norm === 'accepted' || norm === 'granted') {
        return status;
      }
      if (['denied', 'rejected', 'revoked', 'expired'].includes(norm)) {
        throw new AamarvaError(`FLOOR request "${requestId}" was not approved (status: ${norm}).`, {
          code: 'FLOOR_ACCESS_DENIED',
        });
      }
      if (Date.now() >= deadline) {
        throw new AamarvaError(`Timed out waiting for FLOOR request "${requestId}" approval.`, {
          code: 'FLOOR_APPROVAL_TIMEOUT',
        });
      }
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
  }

  /**
   * Obtain execution authorization & credentials for an approved FLOOR invocation.
   * Maps to POST /api/floor/invocations/:invocationId/execute (or /access)
   */
  public async obtainFloorExecutionAuthorization(
    invocationId: string,
    options: { arguments?: Record<string, unknown>; reason?: string; useAccessEndpoint?: boolean } = {}
  ): Promise<FloorExecutionAuthorization> {
    if (!invocationId?.trim()) {
      throw new AamarvaValidationError('invocationId is required.');
    }

    const suffix = options.useAccessEndpoint ? 'access' : 'execute';
    const response = await this.http.request<any>({
      method: 'POST',
      path: `/floor/invocations/${encodeURIComponent(invocationId.trim())}/${suffix}`,
      body: {
        arguments: options.arguments || {},
        ...(options.reason ? { reason: options.reason } : {}),
      },
      auth: true,
    });

    if (!response || typeof response !== 'object') {
      throw new AamarvaError('FLOOR authorization failed: response payload is not an object.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    if (response.success === false) {
      const errMsg = typeof response.error === 'string' ? response.error : (response.error?.message || response.message || 'FLOOR authorization was rejected by platform.');
      throw new AamarvaError(errMsg, {
        code: 'FLOOR_ACCESS_DENIED',
      });
    }

    if (response.data === null || typeof response.data !== 'object' || Array.isArray(response.data)) {
      if ('data' in response) {
        throw new AamarvaError('FLOOR authorization failed: malformed response data payload.', {
          code: 'FLOOR_EXECUTION_FAILED',
        });
      }
    }

    const data = (response.data && typeof response.data === 'object' ? response.data : response) as any;
    const rawStatus = (data.status || (response as any).status || '').trim().toLowerCase();

    if (['denied', 'rejected', 'revoked', 'expired', 'unassigned', 'pending'].includes(rawStatus)) {
      throw new AamarvaError(
        data.message || response.message || `FLOOR execution authorization denied: status is '${rawStatus}'.`,
        { code: 'FLOOR_ACCESS_DENIED' }
      );
    }

    const hasVerifiedPlatformGrant =
      data.verificationInfo?.verified === true &&
      data.authConfig &&
      typeof data.authConfig === 'object';

    if (rawStatus !== 'approved' && !(rawStatus === '' && hasVerifiedPlatformGrant)) {
      throw new AamarvaError(
        data.message || response.message || `FLOOR authorization failed: expected status 'approved', got '${rawStatus}'.`,
        { code: 'FLOOR_EXECUTION_FAILED' }
      );
    }

    const returnedInvocationId = String(data.invocationId || invocationId).trim();
    if (returnedInvocationId !== invocationId.trim()) {
      throw new AamarvaError('FLOOR authorization failed: invocation ID mismatch in platform response.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    const serverUrl = data.serverUrl || data.mcpServerUrl || data.server?.url;
    if (!serverUrl || typeof serverUrl !== 'string' || !serverUrl.trim()) {
      throw new AamarvaError('FLOOR authorization failed: valid MCP serverUrl is missing in response.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    // Verify expiration timestamp if present
    const expiresAt = data.expiresAt || data.grant?.expiresAt;
    if (expiresAt && typeof expiresAt === 'string') {
      const expMs = Date.parse(expiresAt);
      if (!Number.isNaN(expMs) && expMs <= Date.now()) {
        throw new AamarvaError('FLOOR execution authorization grant has expired.', {
          code: 'FLOOR_ACCESS_DENIED',
        });
      }
    }

    // Check verificationInfo consistency if provided
    if (data.verificationInfo) {
      if (data.verificationInfo.verified !== true) {
        throw new AamarvaError('FLOOR authorization failed: verificationInfo.verified is not true.', {
          code: 'FLOOR_EXECUTION_FAILED',
        });
      }
      if (data.verificationInfo.toolId && data.toolId && data.verificationInfo.toolId !== data.toolId) {
        throw new AamarvaError('FLOOR authorization failed: verificationInfo.toolId mismatch.', {
          code: 'FLOOR_EXECUTION_FAILED',
        });
      }
      const expectedAgentId = (this.http.getTargetAgentId() || this.http.getAgentId() || '').trim();
      if (
        expectedAgentId &&
        data.verificationInfo.agentId &&
        data.verificationInfo.agentId.trim().toUpperCase() !== expectedAgentId.toUpperCase()
      ) {
        throw new AamarvaError('FLOOR authorization failed: verificationInfo.agentId mismatch.', {
          code: 'FLOOR_ACCESS_DENIED',
        });
      }
    }

    const hasLegacyGrant = Boolean(data.grant && typeof data.grant === 'object');
    if (!hasLegacyGrant && !hasVerifiedPlatformGrant) {
      throw new AamarvaError('FLOOR authorization failed: grant or authConfig details missing in response.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    // Map authConfig or legacy auth into unified McpExecutionAuthConfig and validate credential presence
    let mappedAuth: McpExecutionAuthConfig | undefined;
    if (data.authConfig && typeof data.authConfig === 'object') {
      const ac = data.authConfig;
      const aType = String(ac.authType || 'none').trim().toLowerCase();
      const hdrVal = ac.headerValue ?? data.accessToken ?? data.grantToken;
      if (aType !== 'none' && (!hdrVal || typeof hdrVal !== 'string' || !hdrVal.trim())) {
        throw new AamarvaError(`FLOOR authorization failed: missing credential for authType "${aType}".`, {
          code: 'FLOOR_EXECUTION_FAILED',
        });
      }
      mappedAuth = {
        type: aType,
        authType: aType,
        headerName: ac.authHeaderName,
        authHeaderName: ac.authHeaderName,
        headerValue: hdrVal,
        token: aType === 'bearer' ? hdrVal : undefined,
        apiKey: aType === 'api_key' || aType === 'apikey' ? hdrVal : undefined,
      };
    } else if (data.auth || data.authentication) {
      mappedAuth = data.auth || data.authentication;
    }

    return {
      invocationId: returnedInvocationId,
      toolId: String(data.toolId || ''),
      status: 'approved',
      serverUrl: serverUrl.trim(),
      auth: mappedAuth as any,
      authConfig: data.authConfig,
      verificationInfo: data.verificationInfo,
      grantToken: data.grantToken,
      accessToken: data.accessToken,
      scope: data.scope,
      expiresAt,
      approvedArguments: data.approvedArguments,
      tool: data.tool,
      grant: data.grant,
    };
  }

  /**
   * Execute a FLOOR tool via the platform's zero-trust governance sequence:
   * Discovery -> Access evaluation -> (optional approval polling) -> Execute authorization -> External MCP invocation.
   */
  public async executeFloorTool(
    toolId: string,
    args: Record<string, unknown> = {},
    options: {
      reason?: string;
      invocationId?: string;
      waitForApproval?: boolean;
      approvalTimeoutMs?: number;
      useAccessEndpoint?: boolean;
    } = {}
  ): Promise<FloorToolInvokeResult> {
    if (!toolId?.trim()) {
      throw new AamarvaValidationError('toolId is required.');
    }

    // Step A: Tool discovery
    const tools = await this.getFloorTools();
    const tool = tools.find((t) => t.id === toolId.trim());
    if (!tool) {
      throw new AamarvaError(`Tool "${toolId}" not found in available fleet tools.`, {
        code: 'FLOOR_TOOL_NOT_FOUND',
      });
    }

    // Step B: Access evaluation
    const accessStatus = (tool.accessStatus || '').trim().toLowerCase();
    const hasGrant = ['authorized', 'granted', 'approved'].includes(accessStatus);

    let invocationId = options.invocationId;

    if (!invocationId) {
      const invRes = await this.createFloorInvocation(toolId.trim(), {
        reason: options.reason || (hasGrant ? 'Authorized execution run' : 'Agent requested execution'),
        arguments: args,
      });

      if (invRes.status === 'executed' && invRes.directResult !== undefined) {
        return {
          status: 'executed',
          invocationId: invRes.invocationId || undefined,
          toolId: toolId.trim(),
          result: invRes.directResult,
          serverUrl: tool.serverUrl,
        };
      }

      if (invRes.status === 'pending') {
        if (options.waitForApproval && (invRes.requestId || invRes.invocationId)) {
          const approvedStatus = await this.waitForFloorRequestApproval(
            invRes.requestId || invRes.invocationId,
            { timeoutMs: options.approvalTimeoutMs }
          );
          invocationId = approvedStatus.invocationId || invRes.invocationId;
        } else {
          throw new AamarvaError(
            `Agent is not authorized to execute tool "${toolId}". Access request ${invRes.requestId || invRes.invocationId} is pending human approval.`,
            { code: 'FLOOR_ACCESS_DENIED' }
          );
        }
      } else if (['denied', 'rejected', 'revoked', 'expired'].includes(invRes.status)) {
        throw new AamarvaError(
          `Agent access to tool "${toolId}" was denied (status: ${invRes.status}).`,
          { code: 'FLOOR_ACCESS_DENIED' }
        );
      } else {
        invocationId = invRes.invocationId;
      }
    }

    if (!invocationId) {
      throw new AamarvaError('FLOOR invocation creation failed to return a valid invocationId.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    // Step C & D: Obtain execution authorization & credentials from platform
    const authDetails = await this.obtainFloorExecutionAuthorization(invocationId, {
      arguments: args,
      reason: options.reason,
      useAccessEndpoint: options.useAccessEndpoint,
    });

    if (authDetails.status !== 'approved') {
      throw new AamarvaError(`FLOOR execution denied: status is '${authDetails.status}'.`, {
        code: 'FLOOR_ACCESS_DENIED',
      });
    }

    if (authDetails.toolId && authDetails.toolId.trim() !== toolId.trim()) {
      throw new AamarvaError(
        `FLOOR execution authorization mismatch: authorized tool "${authDetails.toolId}" does not match requested tool "${toolId}".`,
        { code: 'FLOOR_EXECUTION_FAILED' }
      );
    }

    // Step E: Actual MCP tool execution over verified, SSRF-guarded connection
    const execArgs = authDetails.approvedArguments && Object.keys(args).length === 0
      ? authDetails.approvedArguments
      : args;

    const mcpResult = await invokeExternalMcpTool({
      serverUrl: authDetails.serverUrl,
      toolId: toolId.trim(),
      args: execArgs,
      auth: authDetails.auth as McpExecutionAuthConfig,
      inputSchema: tool.inputSchema,
      fetchFn: this.http.getFetch(),
      allowInsecureHttpForLocalhost: this.allowInsecureLocalhostMcpHttp,
    });

    return {
      status: 'approved',
      invocationId,
      toolId: toolId.trim(),
      result: mcpResult,
      serverUrl: authDetails.serverUrl,
    };
  }

  /**
   * Request access to a FLOOR tool.
   * Maps to POST /api/floor/tools/:toolId/invoke
   */
  public async requestFloorAccess(toolId: string, reason?: string): Promise<FloorToolInvokeResult> {
    if (!toolId?.trim()) {
      throw new AamarvaValidationError('toolId is required.');
    }

    try {
      const tools = await this.getFloorTools();
      const existing = tools.find((t) => t.id === toolId.trim());
      if (existing && ['authorized', 'granted', 'approved'].includes((existing.accessStatus || '').toLowerCase())) {
        return {
          status: 'approved',
          toolId: toolId.trim(),
          message: 'Tool access is already granted via persistent access policy.',
        };
      }
    } catch {
      // Fall through to invocation
    }

    const inv = await this.createFloorInvocation(toolId.trim(), {
      reason,
      requestType: 'access',
    });
    return {
      status: inv.status || 'pending',
      requestId: inv.requestId || inv.invocationId,
      invocationId: inv.invocationId,
      toolId: toolId.trim(),
      message: inv.message || 'Access request submitted for approval.',
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
