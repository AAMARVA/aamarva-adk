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
  ClusterMember,
  ClusterMessage,
  SendClusterMessageOptions,
  RotateClusterKeyOptions,
  RotateClusterKeyResponse,
  FloorTool,
  FloorToolInvokeResult,
  FloorAccessRequestStatus,
  ExecuteFloorToolOptions,
  FloorExecutionAuthorization,
  PeerKeyResponse,
  WatchtowerActivity,
  WatchtowerStreamTicket,
  Footprint,
  WebhookEvent,
  GetAgentsOptions,
  GetConnectionsOptions,
  GetClusterKeyDistributionOptions,
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
  normalizeAgentId,
  canonicalMemberSet,
  computeKeyFingerprint,
  computeGroupKeyFingerprint,
  computeRosterHash,
  computeAudienceHash,
  signIdentityBinding,
  verifyPeerKey,
  generateClusterKey,
  wrapClusterKeyForRecipient,
  unwrapClusterKey,
  encryptClusterMessagePayload,
  decryptClusterMessagePayload,
  signClusterMessageV2,
  verifyClusterMessageSignatureV2,
} from './crypto.js';
import { invokeExternalMcpTool } from './mcp-executor.js';
import { AamarvaValidationError, AamarvaError, AamarvaForbiddenError } from './errors.js';

interface CachedClusterKeyEntry {
  key: Buffer;
  keyFingerprint: string;
  rosterHash?: string;
  audienceHash: string;
  epoch: number;
}

export class Aamarva {
  public readonly http: HttpClient;
  private registeredAgentId?: string;
  private registeredKeyFingerprint?: string;
  private isRegisteringKey = false;
  private clusterKeyCache = new Map<string, CachedClusterKeyEntry>();
  private pendingFloorRequests = new Map<string, string>();

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
      const localKp = getLocalIdentityKeyPair(myAgentId);
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
      if (!options?.agentId || this.registeredAgentId === myAgentId) {
        this.registeredAgentId = undefined;
        this.registeredKeyFingerprint = undefined;
      }
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
   * Check whether E2EE identity is verified and ready for secure operations.
   */
  public isE2eeReady(): boolean {
    return Boolean(this.registeredAgentId && this.registeredKeyFingerprint);
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
   * Update authenticated agent profile name, bio, or avatar.
   * Maps to PATCH /api/agents/me
   */
  public async updateProfile(updates: UpdateProfileOptions): Promise<Agent> {
    if (
      !updates ||
      (updates.name === undefined && updates.bio === undefined && updates.avatar === undefined)
    ) {
      throw new AamarvaValidationError(
        'At least one property (name, bio, or avatar) is required to update profile.'
      );
    }

    const body: Record<string, string> = {};
    if (updates.name !== undefined) body.name = updates.name;
    if (updates.bio !== undefined) body.bio = updates.bio;
    if (updates.avatar !== undefined) body.avatar = updates.avatar;

    const response = await this.http.request<unknown>({
      method: 'PATCH',
      path: '/agents/me',
      body,
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
   * List active connections for the authenticated agent.
   * Maps to GET /api/connections
   */
  public async getConnections(options?: GetConnectionsOptions): Promise<Connection[]> {
    const query: Record<string, number | undefined> = {};
    if (options) {
      if (options.page !== undefined && options.page !== null) query.page = options.page;
      if (options.limit !== undefined && options.limit !== null) query.limit = options.limit;
    }

    const response = await this.http.request<unknown[]>({
      method: 'GET',
      path: '/connections',
      query: Object.keys(query).length > 0 ? query : undefined,
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
   * Retrieve peer public key details by target Agent ID (Workflow 1/2 lookup).
   * Maps to GET /api/connections/peer-key/:agentId
   */
  public async getPeerKeyByAgent(agentId: string): Promise<PeerKeyResponse> {
    if (!agentId?.trim()) {
      throw new AamarvaValidationError('agentId is required.');
    }

    const response = await this.http.request<PeerKeyResponse>({
      method: 'GET',
      path: `/connections/peer-key/${encodeURIComponent(agentId.trim())}`,
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
  public async getMessages(
    connectionId: string,
    options: { page?: number; limit?: number; peerAgentId?: string } = {}
  ): Promise<Message[]> {
    const conn = new AamarvaConnection(
      { connectionId, agentId: options.peerAgentId || '', status: 'active', createdAt: '' },
      this.http
    );
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
   * Retrieve cluster members and registered public keys for Workflow 2 roster & wrapping.
   * Maps to GET /api/clusters/public/:clusterId/members
   */
  public async getClusterMembers(clusterId: string): Promise<ClusterMember[]> {
    if (!clusterId?.trim()) {
      throw new AamarvaValidationError('clusterId is required.');
    }

    const response = await this.http.request<any>({
      method: 'GET',
      path: `/clusters/public/${encodeURIComponent(clusterId.trim())}/members`,
      auth: true,
    });

    const raw = response.data;
    let list: any[];
    if (Array.isArray(raw)) {
      list = raw;
    } else if (raw && typeof raw === 'object' && Array.isArray(raw.members)) {
      list = raw.members;
    } else {
      throw new AamarvaError('Malformed cluster members response.', {
        code: 'CLUSTER_MEMBERSHIP_INVALID',
      });
    }

    return list
      .map((item: any): ClusterMember | null => {
        if (typeof item === 'string') {
          const trimmed = item.trim();
          return trimmed ? { agentId: trimmed } : null;
        }
        if (!item || typeof item !== 'object') {
          return null;
        }
        const id = String(item.agentId || item.agent_id || item.id || '').trim();
        if (!id) return null;
        const rawEpoch = item.keyEpoch !== undefined ? item.keyEpoch : item.key_epoch;
        let parsedEpoch: number | undefined;
        if (rawEpoch !== undefined && rawEpoch !== null) {
          if (typeof rawEpoch === 'number' && Number.isInteger(rawEpoch) && rawEpoch >= 1) {
            parsedEpoch = rawEpoch;
          } else if (typeof rawEpoch === 'string' && /^\d+$/.test(rawEpoch.trim())) {
            const p = Number(rawEpoch.trim());
            if (Number.isInteger(p) && p >= 1) parsedEpoch = p;
          }
          if (parsedEpoch === undefined) {
            throw new AamarvaError(`Invalid keyEpoch for cluster member "${id}".`, {
              code: 'CLUSTER_MEMBERSHIP_INVALID',
            });
          }
        }
        return {
          agentId: id,
          name: item.name,
          role: item.role,
          status: item.status,
          publicKey: item.publicKey || item.e2eePublicKey || item.peerE2eePublicKey,
          keyFingerprint: item.keyFingerprint || item.fingerprint || item.peerKeyFingerprint,
          keyEpoch: parsedEpoch,
          identityKey: item.identityKey || item.peerIdentityKey,
          keySignature: item.keySignature || item.signature || item.peerKeySignature,
        };
      })
      .filter((m): m is ClusterMember => m !== null);
  }

  private parsePositiveIntStrict(val: unknown): number | undefined {
    if (typeof val === 'boolean' || val === null || val === undefined) return undefined;
    if (typeof val === 'number') {
      return Number.isInteger(val) && val >= 1 ? val : undefined;
    }
    if (typeof val === 'string' && /^\d+$/.test(val.trim())) {
      const parsed = Number(val.trim());
      return Number.isInteger(parsed) && parsed >= 1 ? parsed : undefined;
    }
    return undefined;
  }

  private assertValidAudienceHash(audienceHash: string): string {
    const trimmed = audienceHash.trim();
    if (trimmed !== 'ALL' && !/^AUD:[0-9A-F]{32}$/.test(trimmed)) {
      throw new AamarvaValidationError('Invalid audienceHash: must be "ALL" or "AUD:<32-HEX>".', {
        code: 'INVALID_AUDIENCE_HASH',
      });
    }
    return trimmed;
  }

  private assertValidRosterHash(rosterHash: string): string {
    const trimmed = rosterHash.trim();
    if (!/^RST:[0-9A-F]{32}$/.test(trimmed)) {
      throw new AamarvaValidationError('Invalid rosterHash: must match "RST:<32-HEX>".', {
        code: 'INVALID_ROSTER_HASH',
      });
    }
    return trimmed;
  }

  private assertValidFingerprint(fp: string, code = 'CLUSTER_KEY_FINGERPRINT_MISMATCH'): string {
    const trimmed = fp.trim();
    if (!/^SHA256:([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(trimmed)) {
      throw new AamarvaValidationError(`Invalid SHA-256 key fingerprint format: ${trimmed}`, { code });
    }
    return trimmed;
  }

  /**
   * Rotate the active group encryption epoch for a cluster.
   * Maps to POST /api/clusters/:clusterId/rotate-key
   */
  public async rotateClusterKey(
    clusterId: string,
    options: RotateClusterKeyOptions = {}
  ): Promise<RotateClusterKeyResponse> {
    if (!clusterId?.trim()) {
      throw new AamarvaValidationError('clusterId is required.');
    }
    const cleanClusterId = clusterId.trim();
    let expectedCurrentEpoch: number | undefined;
    if (options.currentEpoch !== undefined) {
      expectedCurrentEpoch = this.parsePositiveIntStrict(options.currentEpoch);
      if (expectedCurrentEpoch === undefined) {
        throw new AamarvaValidationError('currentEpoch must be a positive integer >= 1.', {
          code: 'CLUSTER_INVALID_EPOCH',
        });
      }
    }

    const response = await this.http.request<any>({
      method: 'POST',
      path: `/clusters/${encodeURIComponent(cleanClusterId)}/rotate-key`,
      body: options || {},
      auth: true,
    });

    const data = response.data && typeof response.data === 'object' ? response.data : null;
    if (!data) {
      throw new AamarvaError('Malformed response from cluster rotate-key endpoint.', {
        code: 'CLUSTER_ROTATION_FAILED',
      });
    }
    if (data.clusterId !== undefined && String(data.clusterId).trim() !== cleanClusterId) {
      throw new AamarvaError('Cluster ID mismatch in rotateClusterKey response.', {
        code: 'CLUSTER_ROTATION_FAILED',
      });
    }

    const rawEpoch = data.epoch !== undefined ? data.epoch : data.keyEpoch;
    const nextEpoch = this.parsePositiveIntStrict(rawEpoch);
    if (nextEpoch === undefined) {
      throw new AamarvaError('Missing or invalid rotated epoch in rotateClusterKey response.', {
        code: 'CLUSTER_ROTATION_FAILED',
      });
    }
    if (data.keyEpoch !== undefined) {
      const parsedKeyEpoch = this.parsePositiveIntStrict(data.keyEpoch);
      if (parsedKeyEpoch === undefined || parsedKeyEpoch !== nextEpoch) {
        throw new AamarvaError('Inconsistent epoch and keyEpoch in rotateClusterKey response.', {
          code: 'CLUSTER_ROTATION_FAILED',
        });
      }
    }
    if (expectedCurrentEpoch !== undefined && nextEpoch <= expectedCurrentEpoch) {
      throw new AamarvaError(
        `Cluster rotation failed to advance epoch monotonically (expected > ${expectedCurrentEpoch}, got ${nextEpoch}).`,
        { code: 'CLUSTER_ROTATION_FAILED' }
      );
    }

    // Evict stale cached cluster keys for previous epochs of this cluster
    for (const key of Array.from(this.clusterKeyCache.keys())) {
      if (key.startsWith(`${cleanClusterId}:`)) {
        const entry = this.clusterKeyCache.get(key);
        if (!entry || entry.epoch < nextEpoch) {
          this.clusterKeyCache.delete(key);
        }
      }
    }

    return {
      clusterId: String(data.clusterId || cleanClusterId),
      epoch: nextEpoch,
      keyEpoch: nextEpoch,
      rotationStatus: data.rotationStatus,
      rotatedAt: data.rotatedAt,
      message: data.message || (response as any).message,
    };
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
      version: this.parsePositiveIntStrict(item.version) ?? 0,
      keyEpoch: this.parsePositiveIntStrict(item.keyEpoch !== undefined ? item.keyEpoch : item.key_epoch) ?? 0,
      audienceHash: item.audienceHash || item.audience_hash,
      rosterHash: item.rosterHash || item.roster_hash,
      keyFingerprint: item.keyFingerprint || item.key_fingerprint,
      signature: item.signature,
      sequence: item.sequence,
      recipients: Array.isArray(item.recipients) ? item.recipients.map(String) : undefined,
      recipientAgentIds: Array.isArray(item.recipientAgentIds) ? item.recipientAgentIds.map(String) : undefined,
      createdAt: typeof item.createdAt === 'string' ? item.createdAt : new Date().toISOString(),
    }));
  }

  private async resolveAuthoritativeClusterContext(
    clusterId: string,
    options: {
      recipients?: string[];
      recipientAgentIds?: string[];
      expectedRosterHash?: string;
      expectedAudienceHash?: string;
      senderAgentId?: string;
    } = {}
  ): Promise<{
    cluster: Cluster;
    clusterEpoch: number;
    clusterMembers: ClusterMember[];
    memberMap: Map<string, ClusterMember>;
    activeRosterIds: string[];
    rosterHash: string;
    audienceHash: string;
    finalRecipients: string[];
    masterId: string;
    senderId: string;
  }> {
    const cleanClusterId = clusterId.trim();
    const authAgentId = (this.http.getAgentId() || this.agentId || '').trim();
    if (!authAgentId) {
      throw new AamarvaValidationError('Sender agent ID is required for cluster operations.', {
        code: 'MISSING_SENDER_IDENTITY',
      });
    }
    if (
      options.senderAgentId &&
      normalizeAgentId(options.senderAgentId) !== normalizeAgentId(authAgentId)
    ) {
      throw new AamarvaValidationError(
        'Sender agent ID mismatch: caller ID does not match authenticated agent identity.',
        { code: 'SENDER_IDENTITY_MISMATCH' }
      );
    }

    const masterId = await this.resolveMasterAgentId();
    if (!masterId) {
      throw new AamarvaError('Unable to resolve owning master agent ID for cluster message.', {
        code: 'MASTER_RESOLUTION_FAILED',
      });
    }

    const cluster = await this.getCluster(cleanClusterId);
    const returnedClusterId = String(cluster.clusterId || cluster.id || '').trim();
    if (returnedClusterId && returnedClusterId !== cleanClusterId) {
      throw new AamarvaError(`Cluster metadata ID mismatch: expected "${cleanClusterId}", got "${returnedClusterId}".`, {
        code: 'CLUSTER_CONTEXT_MISMATCH',
      });
    }

    const clusterEpoch = this.parsePositiveIntStrict(cluster.epoch ?? cluster.keyEpoch);
    if (clusterEpoch === undefined) {
      throw new AamarvaError(`Cluster "${cleanClusterId}" is missing a valid positive integer epoch.`, {
        code: 'CLUSTER_INVALID_EPOCH',
      });
    }

    const clusterMembers = await this.getClusterMembers(cleanClusterId);
    if (!Array.isArray(clusterMembers) || clusterMembers.length === 0) {
      throw new AamarvaError(`Cluster "${cleanClusterId}" has no authoritative members.`, {
        code: 'CLUSTER_MEMBERSHIP_INVALID',
      });
    }

    const memberMap = new Map<string, ClusterMember>();
    for (const member of clusterMembers) {
      const norm = normalizeAgentId(member.agentId);
      if (norm) memberMap.set(norm, member);
    }

    const activeRosterIds = canonicalMemberSet(clusterMembers.map((m) => m.agentId));
    if (!memberMap.has(normalizeAgentId(authAgentId))) {
      throw new AamarvaError(
        `Authenticated agent "${authAgentId}" is not an authoritative member of cluster "${cleanClusterId}".`,
        { code: 'CLUSTER_MEMBERSHIP_INVALID' }
      );
    }
    if (!memberMap.has(normalizeAgentId(masterId))) {
      throw new AamarvaError(
        `Owning master agent "${masterId}" is not an authoritative member of cluster "${cleanClusterId}".`,
        { code: 'CLUSTER_MEMBERSHIP_INVALID' }
      );
    }

    const validateRecipientList = (list?: string[]) => {
      if (!list) return;
      for (const r of list) {
        if (typeof r !== 'string' || !r.trim()) {
          throw new AamarvaValidationError('Invalid recipient ID in cluster message.', {
            code: 'INVALID_RECIPIENT_ID',
          });
        }
        if (!memberMap.has(normalizeAgentId(r))) {
          throw new AamarvaError(
            `Requested recipient "${r.trim()}" is not an authoritative member of cluster "${cleanClusterId}".`,
            { code: 'CLUSTER_MEMBERSHIP_INVALID' }
          );
        }
      }
    };
    validateRecipientList(options.recipients);
    validateRecipientList(options.recipientAgentIds);

    if (options.recipients && options.recipientAgentIds) {
      const a = canonicalMemberSet(options.recipients);
      const b = canonicalMemberSet(options.recipientAgentIds);
      if (a.length !== b.length || a.some((v, idx) => v !== b[idx])) {
        throw new AamarvaValidationError('Conflicting recipients and recipientAgentIds lists.', {
          code: 'CLUSTER_MEMBERSHIP_INVALID',
        });
      }
    }

    const rosterHash = computeRosterHash(activeRosterIds);
    if (cluster.rosterHash && cluster.rosterHash !== rosterHash) {
      throw new AamarvaError(
        `Cluster rosterHash mismatch: metadata has ${cluster.rosterHash}, authoritative members compute ${rosterHash}.`,
        { code: 'ROSTER_HASH_MISMATCH' }
      );
    }
    if (options.expectedRosterHash !== undefined) {
      const cleanExpectedRoster = this.assertValidRosterHash(options.expectedRosterHash);
      if (cleanExpectedRoster !== rosterHash) {
        throw new AamarvaValidationError(
          `Caller rosterHash mismatch: expected ${rosterHash}, got ${cleanExpectedRoster}.`,
          { code: 'ROSTER_HASH_MISMATCH' }
        );
      }
    }

    const requested = options.recipients && options.recipients.length > 0
      ? options.recipients
      : options.recipientAgentIds && options.recipientAgentIds.length > 0
      ? options.recipientAgentIds
      : undefined;

    const recipientSet = new Set<string>();
    const addUnique = (id?: string) => {
      if (!id || !id.trim()) return;
      const norm = normalizeAgentId(id);
      if (!Array.from(recipientSet).some((existing) => normalizeAgentId(existing) === norm)) {
        recipientSet.add(id.trim());
      }
    };

    addUnique(masterId);
    addUnique(authAgentId);
    if (requested && requested.length > 0) {
      for (const r of requested) {
        addUnique(r);
      }
    } else {
      for (const m of clusterMembers) {
        addUnique(m.agentId);
      }
    }
    const finalRecipients = Array.from(recipientSet);
    const audienceHash = computeAudienceHash(finalRecipients, activeRosterIds);

    if (options.expectedAudienceHash !== undefined) {
      const cleanExpectedAud = this.assertValidAudienceHash(options.expectedAudienceHash);
      if (cleanExpectedAud !== audienceHash) {
        throw new AamarvaValidationError(
          `Caller audienceHash mismatch: expected ${audienceHash}, got ${cleanExpectedAud}.`,
          { code: 'AUDIENCE_HASH_MISMATCH' }
        );
      }
    }

    return {
      cluster,
      clusterEpoch,
      clusterMembers,
      memberMap,
      activeRosterIds,
      rosterHash,
      audienceHash,
      finalRecipients,
      masterId,
      senderId: authAgentId,
    };
  }

  private async postVerifiedClusterMessage(
    clusterId: string,
    payload: Record<string, unknown>
  ): Promise<{ messageId: string }> {
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
   * Broadcast an encrypted Workflow 2 message to a cluster with full fail-closed verification.
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

    const version = options.version === undefined ? 2 : options.version;
    if (typeof version !== 'number' || version !== 2) {
      throw new AamarvaValidationError('Cluster messages require protocol version 2.', {
        code: 'INVALID_CLUSTER_MESSAGE_VERSION',
      });
    }

    const keyEpoch = this.parsePositiveIntStrict(options.keyEpoch);
    if (keyEpoch === undefined) {
      throw new AamarvaValidationError('Cluster messages require explicit keyEpoch as an integer >= 1.', {
        code: 'INVALID_CLUSTER_KEY_EPOCH',
      });
    }

    if (
      typeof options.nonce !== 'string' ||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(options.nonce) ||
      options.nonce.length % 4 !== 0
    ) {
      throw new AamarvaValidationError('Cluster message nonce must be a valid Base64-encoded 12-byte string.', {
        code: 'INVALID_CLUSTER_NONCE',
      });
    }
    const decodedNonce = Buffer.from(options.nonce, 'base64');
    if (decodedNonce.toString('base64') !== options.nonce || decodedNonce.length !== 12) {
      throw new AamarvaValidationError('Cluster message nonce must decode from Base64 to exactly 12 bytes.', {
        code: 'INVALID_CLUSTER_NONCE',
      });
    }

    if (options.strictPreflight !== true) {
      throw new AamarvaValidationError('Cluster messages require strictPreflight=true.', {
        code: 'STRICT_PREFLIGHT_REQUIRED',
      });
    }

    if (!options.audienceHash || typeof options.audienceHash !== 'string') {
      throw new AamarvaValidationError('audienceHash is required for Workflow 2 cluster messages.', {
        code: 'INVALID_AUDIENCE_HASH',
      });
    }
    const cleanAudienceHash = this.assertValidAudienceHash(options.audienceHash);

    if (!options.rosterHash || typeof options.rosterHash !== 'string') {
      throw new AamarvaValidationError('rosterHash is required for Workflow 2 cluster messages.', {
        code: 'INVALID_ROSTER_HASH',
      });
    }
    const cleanRosterHash = this.assertValidRosterHash(options.rosterHash);

    if (!options.keyFingerprint || typeof options.keyFingerprint !== 'string') {
      throw new AamarvaValidationError('keyFingerprint is required for Workflow 2 cluster messages.', {
        code: 'CLUSTER_KEY_FINGERPRINT_MISMATCH',
      });
    }
    const cleanKeyFingerprint = this.assertValidFingerprint(options.keyFingerprint);

    if (!options.signature || typeof options.signature !== 'string' || !options.signature.trim()) {
      throw new AamarvaValidationError('ECDSA v2 signature is required for Workflow 2 cluster messages.', {
        code: 'CLUSTER_SIGNATURE_INVALID',
      });
    }
    const sigBuf = Buffer.from(options.signature, 'base64');
    if (sigBuf.length !== 64) {
      throw new AamarvaValidationError('Cluster message signature must be a 64-byte IEEE P1363 Base64 string.', {
        code: 'CLUSTER_SIGNATURE_INVALID',
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

    if (options.recipientAgentIds) {
      for (const r of options.recipientAgentIds) {
        if (typeof r !== 'string' || !r.trim()) {
          throw new AamarvaValidationError('Invalid recipient ID in cluster message.', {
            code: 'INVALID_RECIPIENT_ID',
          });
        }
      }
    }

    const authAgentId = this.http.getAgentId() || this.agentId;
    if (options.senderAgentId) {
      if (!authAgentId || options.senderAgentId.trim().toUpperCase() !== authAgentId.trim().toUpperCase()) {
        throw new AamarvaValidationError('Sender agent ID mismatch: caller ID does not match authenticated agent identity.', {
          code: 'SENDER_IDENTITY_MISMATCH',
        });
      }
    }
    if (!(options.senderAgentId?.trim() || authAgentId || '').trim()) {
      throw new AamarvaValidationError('Sender agent ID is required for cluster messages.', {
        code: 'MISSING_SENDER_IDENTITY',
      });
    }

    const ctx = await this.resolveAuthoritativeClusterContext(clusterId, {
      recipients: options.recipients,
      recipientAgentIds: options.recipientAgentIds,
      expectedRosterHash: cleanRosterHash,
      expectedAudienceHash: cleanAudienceHash,
      senderAgentId: options.senderAgentId,
    });

    if (ctx.cluster.rotationStatus && String(ctx.cluster.rotationStatus).startsWith('ROTATION_REQUIRED')) {
      throw new AamarvaError(`Cluster key rotation required before sending: ${ctx.cluster.rotationStatus}`, {
        code: 'CLUSTER_ROTATION_REQUIRED',
      });
    }
    if (keyEpoch !== ctx.clusterEpoch) {
      throw new AamarvaError(
        `Cluster keyEpoch mismatch: active cluster epoch is ${ctx.clusterEpoch}, got ${keyEpoch}.`,
        { code: 'CLUSTER_INVALID_EPOCH' }
      );
    }

    const senderMember = ctx.memberMap.get(normalizeAgentId(ctx.senderId));
    let senderPubKey: any = senderMember?.publicKey || senderMember?.identityKey;
    if (senderMember?.publicKey && senderMember.keyFingerprint) {
      if (computeKeyFingerprint(exportPublicKeyJWK(senderMember.publicKey)) !== senderMember.keyFingerprint) {
        throw new AamarvaError('Authoritative sender member key fingerprint mismatch.', {
          code: 'CLUSTER_SIGNATURE_INVALID',
        });
      }
    }
    if (!senderPubKey) {
      senderPubKey = exportPublicKeyJWK(getLocalIdentityKeyPair(ctx.senderId, senderMember?.keyEpoch).publicKey);
    }

    const sigOk = verifyClusterMessageSignatureV2(
      senderPubKey,
      {
        clusterId: clusterId.trim(),
        keyEpoch,
        senderAgentId: ctx.senderId,
        audienceHash: ctx.audienceHash,
        rosterHash: ctx.rosterHash,
        sequence: options.sequence ?? '',
        keyFingerprint: cleanKeyFingerprint,
        nonce: options.nonce,
        ciphertext: options.ciphertext,
      },
      options.signature
    );
    if (!sigOk) {
      throw new AamarvaError('Cluster message ECDSA v2 signature verification failed.', {
        code: 'CLUSTER_SIGNATURE_INVALID',
      });
    }

    const payload: Record<string, unknown> = {
      senderAgentId: ctx.senderId,
      ciphertext: options.ciphertext,
      nonce: options.nonce,
      version: 2,
      keyEpoch,
      recipients: ctx.finalRecipients,
      recipientAgentIds: ctx.finalRecipients,
      audienceHash: ctx.audienceHash,
      rosterHash: ctx.rosterHash,
      keyFingerprint: cleanKeyFingerprint,
      signature: options.signature,
      strictPreflight: true,
    };
    if (options.sequence !== undefined) payload.sequence = options.sequence;

    return this.postVerifiedClusterMessage(clusterId, payload);
  }

  /**
   * Submit key packages to the platform's key-distribution endpoint.
   * Maps to POST /api/clusters/:clusterId/key-distribution
   */
  public async submitClusterKeyDistribution(
    clusterId: string,
    payload: {
      epoch: number;
      senderAgentId: string;
      audienceHash?: string;
      rosterHash?: string;
      keyFingerprint?: string;
      keyPackages: Array<{
        recipientAgentId: string;
        encryptedKeyPackage: string | Record<string, unknown>;
        nonce: string;
        keyFingerprint?: string;
        wrappingParams?: Record<string, unknown>;
      }>;
    }
  ): Promise<void> {
    if (!clusterId?.trim()) {
      throw new AamarvaValidationError('clusterId is required.');
    }

    await this.http.request({
      method: 'POST',
      path: `/clusters/${encodeURIComponent(clusterId.trim())}/key-distribution`,
      body: {
        clusterId: clusterId.trim(),
        ...payload,
      },
      auth: true,
    });
  }

  private getClusterCacheKey(clusterId: string, epoch: number, audienceHash: string): string {
    return `${clusterId}:${epoch}:${audienceHash}`;
  }

  private async resolveAuthoritativeMemberKey(
    agentId: string,
    member: ClusterMember,
    explicitKeys?: Record<string, any>
  ): Promise<{ publicKey: any; keyFingerprint?: string; keyEpoch?: number }> {
    const normTarget = normalizeAgentId(agentId);
    let resolvedKey: any = member.publicKey;
    let resolvedFp: string | undefined = member.keyFingerprint;
    let resolvedEpoch: number | undefined = member.keyEpoch;

    if (resolvedKey && member.identityKey && member.keySignature && resolvedFp) {
      verifyPeerKey(resolvedKey, resolvedFp, agentId, member.keySignature, member.identityKey);
    } else if (resolvedKey && resolvedFp) {
      const actualFp = computeKeyFingerprint(exportPublicKeyJWK(resolvedKey));
      if (actualFp !== resolvedFp) {
        throw new AamarvaError(`Cluster member "${agentId}" public key fingerprint mismatch.`, {
          code: 'RECIPIENT_KEY_MISMATCH',
        });
      }
    }

    if (!resolvedKey) {
      const pk = await this.getPeerKeyByAgent(agentId);
      const rawKey = (pk as any).publicKey || pk.peerE2eePublicKey || pk.peerIdentityKey;
      const pkFp = (pk as any).fingerprint || pk.peerKeyFingerprint;
      const pkIdKey = pk.peerIdentityKey || (pk as any).identityKey;
      const pkSig = pk.peerKeySignature || (pk as any).signature;
      if (rawKey) {
        if (pkIdKey && pkSig && pkFp) {
          verifyPeerKey(rawKey, pkFp, agentId, pkSig, pkIdKey);
        } else if (pkFp && computeKeyFingerprint(exportPublicKeyJWK(rawKey)) !== pkFp) {
          throw new AamarvaError(`Peer key fingerprint mismatch for "${agentId}".`, {
            code: 'RECIPIENT_KEY_MISMATCH',
          });
        }
        resolvedKey = rawKey;
        resolvedFp = pkFp || resolvedFp;
        resolvedEpoch = this.parsePositiveIntStrict((pk as any).keyEpoch ?? pk.peerKeyEpoch) ?? resolvedEpoch;
      }
    }

    const direct = explicitKeys?.[agentId] || explicitKeys?.[normTarget];
    if (direct) {
      const directPub = typeof direct === 'object' && direct.publicKey && !direct.kty ? direct.publicKey : direct;
      const directFp = computeKeyFingerprint(exportPublicKeyJWK(directPub));
      if (resolvedKey) {
        const authFp = resolvedFp || computeKeyFingerprint(exportPublicKeyJWK(resolvedKey));
        if (directFp !== authFp) {
          throw new AamarvaError(`Caller-supplied public key for "${agentId}" contradicts authoritative registered key.`, {
            code: 'RECIPIENT_KEY_MISMATCH',
          });
        }
      } else {
        resolvedKey = directPub;
        resolvedFp = directFp;
      }
    }

    if (!resolvedKey) {
      throw new AamarvaError(
        `Recipient "${agentId}" does not have a registered public key for cluster encryption.`,
        { code: 'RECIPIENT_KEY_MISSING' }
      );
    }

    return {
      publicKey: resolvedKey,
      keyFingerprint: resolvedFp,
      keyEpoch: resolvedEpoch,
    };
  }

  /**
   * Generate, wrap, and distribute cluster symmetric keys to all authoritative recipients (Workflow 2).
   */
  public async distributeClusterKey(
    clusterId: string,
    options: {
      recipients?: string[];
      epoch?: number;
      audienceHash?: string;
      rosterHash?: string;
      recipientPublicKeys?: Record<string, any>;
    } = {}
  ): Promise<{
    epoch: number;
    clusterKey: Buffer;
    keyFingerprint: string;
    rosterHash: string;
    audienceHash: string;
    recipients: string[];
  }> {
    if (!clusterId?.trim()) {
      throw new AamarvaValidationError('clusterId is required.');
    }

    if (options.epoch !== undefined) {
      const parsedOptEpoch = this.parsePositiveIntStrict(options.epoch);
      if (parsedOptEpoch === undefined) {
        throw new AamarvaValidationError('Cluster key distribution epoch must be an integer >= 1.', {
          code: 'CLUSTER_INVALID_EPOCH',
        });
      }
    }

    const ctx = await this.resolveAuthoritativeClusterContext(clusterId, {
      recipients: options.recipients,
      expectedRosterHash: options.rosterHash,
      expectedAudienceHash: options.audienceHash,
    });

    if (ctx.cluster.rotationStatus && String(ctx.cluster.rotationStatus).startsWith('ROTATION_REQUIRED')) {
      throw new AamarvaError(`Cluster key rotation required before key distribution: ${ctx.cluster.rotationStatus}`, {
        code: 'CLUSTER_ROTATION_REQUIRED',
      });
    }

    const epoch = ctx.clusterEpoch;
    if (options.epoch !== undefined && options.epoch !== epoch) {
      throw new AamarvaError(
        `Requested key distribution epoch ${options.epoch} does not match authoritative cluster epoch ${epoch}.`,
        { code: 'CLUSTER_INVALID_EPOCH' }
      );
    }

    const authAgentId = ctx.senderId;
    const senderMember = ctx.memberMap.get(normalizeAgentId(authAgentId));
    const senderKp = getLocalIdentityKeyPair(authAgentId, senderMember?.keyEpoch);
    const senderPubJwk = exportPublicKeyJWK(senderKp.publicKey);
    const senderPubFp = computeKeyFingerprint(senderPubJwk);

    // Generate local 256-bit symmetric cluster key
    const clusterKey = generateClusterKey();
    const keyFingerprint = computeGroupKeyFingerprint(clusterKey);

    const keyPackages: Array<{
      recipientAgentId: string;
      encryptedKeyPackage: Record<string, unknown>;
      nonce: string;
      keyFingerprint: string;
      wrappingParams: Record<string, unknown>;
    }> = [];

    for (const recipientId of ctx.finalRecipients) {
      let recipientPubKey: any;
      let recipientKeyFp: string | undefined;
      let recipientKeyEpoch: number | undefined;

      if (
        normalizeAgentId(recipientId) === normalizeAgentId(authAgentId) &&
        !options.recipientPublicKeys?.[recipientId]
      ) {
        recipientPubKey = senderPubJwk;
        recipientKeyFp = senderPubFp;
        recipientKeyEpoch = senderMember?.keyEpoch ?? 1;
      } else {
        const memberRecord = ctx.memberMap.get(normalizeAgentId(recipientId))!;
        const resolved = await this.resolveAuthoritativeMemberKey(
          recipientId,
          memberRecord,
          options.recipientPublicKeys
        );
        recipientPubKey = resolved.publicKey;
        recipientKeyFp = resolved.keyFingerprint;
        recipientKeyEpoch = resolved.keyEpoch;
      }

      const wrapped = wrapClusterKeyForRecipient(clusterKey, recipientPubKey, senderKp.privateKey, {
        clusterId: clusterId.trim(),
        epoch,
        audienceHash: ctx.audienceHash,
        rosterHash: ctx.rosterHash,
        keyFingerprint,
        senderAgentId: authAgentId,
        senderPublicKey: senderPubJwk,
        recipientAgentId: recipientId,
        recipientKeyFingerprint: recipientKeyFp,
        recipientKeyEpoch,
      });

      keyPackages.push({
        recipientAgentId: recipientId,
        encryptedKeyPackage: wrapped.encryptedKeyPackage,
        nonce: wrapped.nonce,
        keyFingerprint,
        wrappingParams: wrapped.wrappingParams,
      });
    }

    await this.submitClusterKeyDistribution(clusterId, {
      epoch,
      audienceHash: ctx.audienceHash,
      rosterHash: ctx.rosterHash,
      keyFingerprint,
      senderAgentId: authAgentId,
      keyPackages,
    });

    this.clusterKeyCache.set(this.getClusterCacheKey(clusterId.trim(), epoch, ctx.audienceHash), {
      key: clusterKey,
      keyFingerprint,
      rosterHash: ctx.rosterHash,
      audienceHash: ctx.audienceHash,
      epoch,
    });

    return {
      epoch,
      clusterKey,
      keyFingerprint,
      rosterHash: ctx.rosterHash,
      audienceHash: ctx.audienceHash,
      recipients: ctx.finalRecipients,
    };
  }

  /**
   * Retrieve the encrypted group key package for the authenticated caller.
   * Maps to GET /api/clusters/:clusterId/key-distribution
   */
  public async getClusterKeyDistribution(
    clusterId: string,
    epochOrOptions?: number | GetClusterKeyDistributionOptions,
    audienceHash?: string
  ): Promise<ClusterKeyDistributionResponse> {
    if (!clusterId?.trim()) {
      throw new AamarvaValidationError('clusterId is required.');
    }

    let resolvedEpoch: number | undefined;
    let resolvedAudienceHash: string | undefined;

    if (typeof epochOrOptions === 'object' && epochOrOptions !== null) {
      resolvedEpoch = epochOrOptions.epoch;
      resolvedAudienceHash = epochOrOptions.audienceHash;
    } else {
      resolvedEpoch = epochOrOptions;
      resolvedAudienceHash = audienceHash;
    }

    const query: Record<string, string | number | undefined> = {};
    if (resolvedEpoch !== undefined && resolvedEpoch !== null) {
      const validEpoch = this.parsePositiveIntStrict(resolvedEpoch);
      if (validEpoch === undefined) {
        throw new AamarvaValidationError('epoch must be a positive integer >= 1.', {
          code: 'CLUSTER_INVALID_EPOCH',
        });
      }
      query.epoch = validEpoch;
    }
    if (
      resolvedAudienceHash !== undefined &&
      resolvedAudienceHash !== null &&
      String(resolvedAudienceHash).trim() !== ''
    ) {
      query.audienceHash = String(resolvedAudienceHash).trim();
    }

    const response = await this.http.request<Record<string, unknown>>({
      method: 'GET',
      path: `/clusters/${encodeURIComponent(clusterId.trim())}/key-distribution`,
      query: Object.keys(query).length > 0 ? query : undefined,
      auth: true,
    });

    const data = (response.data as Record<string, unknown>) || response;
    return data as ClusterKeyDistributionResponse;
  }

  private async getClusterKeyEntry(
    clusterId: string,
    epoch: number,
    options?: { audienceHash?: string; senderPublicKey?: any; expectedKeyFingerprint?: string }
  ): Promise<CachedClusterKeyEntry> {
    if (!clusterId?.trim()) {
      throw new AamarvaValidationError('clusterId is required.');
    }
    const cleanClusterId = clusterId.trim();
    const validEpoch = this.parsePositiveIntStrict(epoch);
    if (validEpoch === undefined) {
      throw new AamarvaValidationError('Valid positive integer epoch is required to retrieve cluster key.', {
        code: 'CLUSTER_INVALID_EPOCH',
      });
    }
    const requestedAudience = this.assertValidAudienceHash(options?.audienceHash || 'ALL');
    const cleanExpectedOptFp = options?.expectedKeyFingerprint
      ? this.assertValidFingerprint(options.expectedKeyFingerprint)
      : undefined;

    const cacheKey = this.getClusterCacheKey(cleanClusterId, validEpoch, requestedAudience);
    const cached = this.clusterKeyCache.get(cacheKey);
    if (cached) {
      if (cleanExpectedOptFp && cached.keyFingerprint !== cleanExpectedOptFp) {
        throw new AamarvaError(
          `Cluster key fingerprint mismatch: expected ${cleanExpectedOptFp}, cached ${cached.keyFingerprint}.`,
          { code: 'CLUSTER_KEY_FINGERPRINT_MISMATCH' }
        );
      }
      return cached;
    }

    const dist = await this.getClusterKeyDistribution(
      cleanClusterId,
      requestedAudience !== 'ALL' ? { epoch: validEpoch, audienceHash: requestedAudience } : validEpoch
    );
    if (!dist || !dist.encryptedKeyPackage) {
      throw new AamarvaError(`No cluster key package available for cluster "${cleanClusterId}" at epoch ${validEpoch}.`, {
        code: 'CLUSTER_KEY_MISSING',
      });
    }

    if (dist.recipientKeyMismatch) {
      throw new AamarvaError(
        `Cluster key unwrapping failed due to recipient key mismatch (expected fingerprint: ${dist.recipientKeyFingerprint || 'unknown'}).`,
        { code: 'RECIPIENT_KEY_MISMATCH' }
      );
    }

    if (dist.clusterId !== undefined && String(dist.clusterId).trim() !== cleanClusterId) {
      throw new AamarvaError('Cluster key distribution clusterId mismatch.', {
        code: 'CLUSTER_KEY_UNWRAP_FAILED',
      });
    }
    if (dist.epoch !== undefined && dist.epoch !== null) {
      const distEpoch = this.parsePositiveIntStrict(dist.epoch);
      if (distEpoch === undefined || distEpoch !== validEpoch) {
        throw new AamarvaError('Cluster key distribution epoch mismatch.', {
          code: 'CLUSTER_KEY_UNWRAP_FAILED',
        });
      }
    }
    if (dist.audienceHash !== undefined && String(dist.audienceHash).trim() !== requestedAudience) {
      throw new AamarvaError('Cluster key distribution audienceHash mismatch.', {
        code: 'CLUSTER_KEY_UNWRAP_FAILED',
      });
    }

    let pkgObj: Record<string, unknown> | undefined;
    if (typeof dist.encryptedKeyPackage === 'object' && dist.encryptedKeyPackage !== null) {
      pkgObj = dist.encryptedKeyPackage as Record<string, unknown>;
    } else if (typeof dist.encryptedKeyPackage === 'string' && dist.encryptedKeyPackage.trim().startsWith('{')) {
      try {
        pkgObj = JSON.parse(dist.encryptedKeyPackage);
      } catch {
        throw new AamarvaError('Malformed JSON in cluster encryptedKeyPackage.', {
          code: 'CLUSTER_KEY_UNWRAP_FAILED',
        });
      }
    }

    const authAgentId = (this.http.getAgentId() || this.agentId || '').trim();
    if (!authAgentId) {
      throw new AamarvaValidationError('Authenticated agent ID is required to unwrap cluster key.');
    }
    if (
      dist.recipientAgentId &&
      normalizeAgentId(String(dist.recipientAgentId)) !== normalizeAgentId(authAgentId)
    ) {
      throw new AamarvaError('Cluster key distribution recipientAgentId mismatch.', {
        code: 'RECIPIENT_KEY_MISMATCH',
      });
    }

    const rawRecipientKeyEpoch =
      dist.recipientKeyEpoch !== undefined ? dist.recipientKeyEpoch : pkgObj?.recipientKeyEpoch;
    let targetPersonalEpoch: number | undefined;
    if (rawRecipientKeyEpoch !== undefined && rawRecipientKeyEpoch !== null) {
      targetPersonalEpoch = this.parsePositiveIntStrict(rawRecipientKeyEpoch);
      if (targetPersonalEpoch === undefined) {
        throw new AamarvaError('Invalid recipientKeyEpoch in cluster key distribution.', {
          code: 'IDENTITY_KEY_INVALID',
        });
      }
    }
    const localKp = getLocalIdentityKeyPair(authAgentId, targetPersonalEpoch);
    if (dist.recipientKeyFingerprint) {
      const localFp = computeKeyFingerprint(exportPublicKeyJWK(localKp.publicKey));
      if (localFp !== dist.recipientKeyFingerprint) {
        throw new AamarvaError(
          `Recipient key fingerprint mismatch: expected ${dist.recipientKeyFingerprint}, local ${localFp}.`,
          { code: 'RECIPIENT_KEY_MISMATCH' }
        );
      }
    }

    const resolvedSenderId = String(dist.senderAgentId || pkgObj?.senderAgentId || '').trim();
    if (!resolvedSenderId) {
      throw new AamarvaError('Cluster key distribution is missing senderAgentId.', {
        code: 'CLUSTER_KEY_UNWRAP_FAILED',
      });
    }

    // Resolve authoritative sender public key (never trust inline key-package senderPublicKey alone)
    let authSenderPubKey: any;
    if (normalizeAgentId(resolvedSenderId) === normalizeAgentId(authAgentId)) {
      const members = await this.getClusterMembers(cleanClusterId);
      const selfMember = members.find((m) => normalizeAgentId(m.agentId) === normalizeAgentId(authAgentId));
      if (!selfMember) {
        throw new AamarvaError(`Key distributor "${resolvedSenderId}" is not an authoritative cluster member.`, {
          code: 'CLUSTER_MEMBERSHIP_INVALID',
        });
      }
      authSenderPubKey = selfMember.publicKey || exportPublicKeyJWK(getLocalIdentityKeyPair(authAgentId, selfMember.keyEpoch).publicKey);
    } else {
      const members = await this.getClusterMembers(cleanClusterId);
      const match = members.find((m) => normalizeAgentId(m.agentId) === normalizeAgentId(resolvedSenderId));
      if (!match) {
        throw new AamarvaError(
          `Cluster key distributor "${resolvedSenderId}" is not an authoritative member of cluster "${cleanClusterId}".`,
          { code: 'CLUSTER_MEMBERSHIP_INVALID' }
        );
      }
      const resolvedMemberMat = await this.resolveAuthoritativeMemberKey(resolvedSenderId, match);
      authSenderPubKey = resolvedMemberMat.publicKey;
    }

    const authSenderFp = computeKeyFingerprint(exportPublicKeyJWK(authSenderPubKey));
    const inlineOrOverrideSenderPub = options?.senderPublicKey || dist.senderPublicKey || pkgObj?.senderPublicKey;
    if (inlineOrOverrideSenderPub) {
      const providedFp = computeKeyFingerprint(exportPublicKeyJWK(inlineOrOverrideSenderPub));
      if (providedFp !== authSenderFp) {
        throw new AamarvaError(
          `Cluster key sender public key does not match authoritative key for "${resolvedSenderId}".`,
          { code: 'CLUSTER_KEY_UNWRAP_FAILED' }
        );
      }
    }

    const distFp = dist.keyFingerprint ? this.assertValidFingerprint(String(dist.keyFingerprint)) : undefined;
    if (cleanExpectedOptFp && distFp && cleanExpectedOptFp !== distFp) {
      throw new AamarvaError(
        `Cluster key fingerprint mismatch: expected ${cleanExpectedOptFp}, distribution has ${distFp}.`,
        { code: 'CLUSTER_KEY_FINGERPRINT_MISMATCH' }
      );
    }
    const resolvedExpectedFp = cleanExpectedOptFp || distFp || (typeof pkgObj?.keyFingerprint === 'string' ? this.assertValidFingerprint(pkgObj.keyFingerprint) : undefined);
    if (!resolvedExpectedFp) {
      throw new AamarvaError('Missing group keyFingerprint in cluster key distribution.', {
        code: 'CLUSTER_KEY_FINGERPRINT_MISMATCH',
      });
    }

    const nonce = String(dist.nonce || (pkgObj?.iv as string) || (dist.wrappingParams as any)?.nonce || '');
    const clusterKey = unwrapClusterKey(dist.encryptedKeyPackage, nonce, localKp.privateKey, authSenderPubKey, {
      clusterId: cleanClusterId,
      epoch: validEpoch,
      audienceHash: requestedAudience,
      expectedKeyFingerprint: resolvedExpectedFp,
      recipientAgentId: authAgentId,
      wrappingParams: dist.wrappingParams as Record<string, unknown> | undefined,
    });

    const entry: CachedClusterKeyEntry = {
      key: clusterKey,
      keyFingerprint: resolvedExpectedFp,
      rosterHash: dist.rosterHash || (typeof pkgObj?.rosterHash === 'string' ? pkgObj.rosterHash : undefined),
      audienceHash: requestedAudience,
      epoch: validEpoch,
    };

    this.clusterKeyCache.set(cacheKey, entry);
    return entry;
  }

  /**
   * Retrieve and locally decrypt symmetric cluster key for the given epoch and audience scope.
   */
  public async getClusterKey(
    clusterId: string,
    epoch?: number,
    options?: { audienceHash?: string; senderPublicKey?: any; expectedKeyFingerprint?: string }
  ): Promise<Buffer> {
    if (epoch === undefined) {
      throw new AamarvaValidationError('epoch is required to retrieve cluster key.', {
        code: 'CLUSTER_INVALID_EPOCH',
      });
    }
    const entry = await this.getClusterKeyEntry(clusterId, epoch, options);
    return entry.key;
  }

  /**
   * Encrypt and broadcast a cluster message using Workflow 2 (protocol v2, audience scoping,
   * ECDSA IEEE P1363 envelope signature, strictPreflight, and 409 epoch race adoption).
   */
  public async sendEncryptedClusterMessage(
    clusterId: string,
    plaintext: string,
    options: {
      recipients?: string[];
      epoch?: number;
      audienceHash?: string;
      rosterHash?: string;
      sequence?: string | number;
      autoRotate?: boolean;
      recipientPublicKeys?: Record<string, any>;
    } = {}
  ): Promise<{
    messageId: string;
    version: number;
    keyEpoch: number;
    audienceHash: string;
    rosterHash: string;
    keyFingerprint: string;
    signature: string;
    recipients: string[];
    ciphertext: string;
    nonce: string;
    senderAgentId: string;
  }> {
    if (!clusterId?.trim()) {
      throw new AamarvaValidationError('clusterId is required.');
    }
    if (typeof plaintext !== 'string' || !plaintext) {
      throw new AamarvaValidationError('Non-empty plaintext string is required.');
    }
    if (options.epoch !== undefined && this.parsePositiveIntStrict(options.epoch) === undefined) {
      throw new AamarvaValidationError('epoch must be a positive integer >= 1.', {
        code: 'CLUSTER_INVALID_EPOCH',
      });
    }

    const preCtx = await this.resolveAuthoritativeClusterContext(clusterId, {
      recipients: options.recipients,
      expectedRosterHash: options.rosterHash,
      expectedAudienceHash: options.audienceHash,
    });

    let epoch = preCtx.clusterEpoch;
    if (preCtx.cluster.rotationStatus && String(preCtx.cluster.rotationStatus).startsWith('ROTATION_REQUIRED')) {
      if (options.autoRotate === false) {
        throw new AamarvaError(`Cluster key rotation required before sending: ${preCtx.cluster.rotationStatus}`, {
          code: 'CLUSTER_ROTATION_REQUIRED',
        });
      }
      const rotated = await this.rotateClusterKey(clusterId, { currentEpoch: epoch });
      epoch = rotated.epoch;
      // Re-verify post-rotation cluster state so rotationStatus & epoch are authoritative
      const postCluster = await this.getCluster(clusterId);
      const postEpoch = this.parsePositiveIntStrict(postCluster.epoch ?? postCluster.keyEpoch);
      if (postEpoch !== undefined && postEpoch !== epoch) {
        throw new AamarvaError(
          `Post-rotation cluster epoch mismatch: rotate returned ${epoch}, cluster reports ${postEpoch}.`,
          { code: 'CLUSTER_ROTATION_FAILED' }
        );
      }
      if (postCluster.rotationStatus && String(postCluster.rotationStatus).startsWith('ROTATION_REQUIRED')) {
        throw new AamarvaError(`Cluster still requires rotation after rotateClusterKey: ${postCluster.rotationStatus}`, {
          code: 'CLUSTER_ROTATION_REQUIRED',
        });
      }
    }

    if (options.epoch !== undefined && options.epoch !== epoch) {
      throw new AamarvaError(
        `Requested epoch ${options.epoch} does not match current authoritative cluster epoch ${epoch}.`,
        { code: 'CLUSTER_INVALID_EPOCH' }
      );
    }

    const cleanClusterId = clusterId.trim();
    const { rosterHash, audienceHash, finalRecipients: allRecipients, senderId, memberMap } = preCtx;

    let clusterKeyEntry: CachedClusterKeyEntry;
    try {
      clusterKeyEntry = await this.getClusterKeyEntry(cleanClusterId, epoch, { audienceHash });
    } catch (getErr: any) {
      const isMissingKey =
        getErr?.code === 'CLUSTER_KEY_MISSING' ||
        getErr?.statusCode === 404 ||
        getErr?.status === 404;
      if (!isMissingKey) {
        throw getErr;
      }

      try {
        const dist = await this.distributeClusterKey(cleanClusterId, {
          recipients: allRecipients,
          epoch,
          audienceHash,
          rosterHash,
          recipientPublicKeys: options.recipientPublicKeys,
        });
        clusterKeyEntry = {
          key: dist.clusterKey,
          keyFingerprint: dist.keyFingerprint,
          rosterHash: dist.rosterHash,
          audienceHash: dist.audienceHash,
          epoch: dist.epoch,
        };
      } catch (distErr: any) {
        const isConflict =
          distErr?.statusCode === 409 ||
          distErr?.code === 'EPOCH_KEY_ALREADY_SEALED' ||
          /EPOCH_KEY_ALREADY_SEALED|ALREADY_SEALED|409/i.test(
            String(distErr?.code || '') + ' ' + String(distErr?.message || '')
          );
        if (isConflict) {
          clusterKeyEntry = await this.getClusterKeyEntry(cleanClusterId, epoch, { audienceHash });
        } else {
          throw distErr;
        }
      }
    }

    const keyFingerprint = clusterKeyEntry.keyFingerprint;
    const enc = encryptClusterMessagePayload(
      plaintext,
      clusterKeyEntry.key,
      cleanClusterId,
      epoch,
      audienceHash,
      senderId
    );

    const senderMember = memberMap.get(normalizeAgentId(senderId));
    const senderKp = getLocalIdentityKeyPair(senderId, senderMember?.keyEpoch);
    const signature = signClusterMessageV2(senderKp.privateKey, {
      clusterId: cleanClusterId,
      keyEpoch: epoch,
      senderAgentId: senderId,
      audienceHash,
      rosterHash,
      sequence: options.sequence ?? '',
      keyFingerprint,
      nonce: enc.nonce,
      ciphertext: enc.ciphertext,
    });

    const result = await this.postVerifiedClusterMessage(cleanClusterId, {
      senderAgentId: senderId,
      ciphertext: enc.ciphertext,
      nonce: enc.nonce,
      version: 2,
      keyEpoch: epoch,
      recipients: allRecipients,
      recipientAgentIds: allRecipients,
      audienceHash,
      rosterHash,
      keyFingerprint,
      signature,
      strictPreflight: true,
      ...(options.sequence !== undefined ? { sequence: options.sequence } : {}),
    });

    return {
      messageId: result.messageId,
      version: 2,
      keyEpoch: epoch,
      audienceHash,
      rosterHash,
      keyFingerprint,
      signature,
      recipients: allRecipients,
      ciphertext: enc.ciphertext,
      nonce: enc.nonce,
      senderAgentId: senderId,
    };
  }

  /**
   * Decrypt an encrypted Workflow 2 cluster message with mandatory signature verification.
   */
  public async decryptClusterMessage(
    clusterId: string,
    message: {
      ciphertext: string;
      nonce: string;
      keyEpoch?: number;
      version?: number;
      audienceHash?: string;
      rosterHash?: string;
      keyFingerprint?: string;
      signature?: string;
      sequence?: string | number;
      senderAgentId?: string;
    },
    options?: { senderPublicKey?: any; verifySignature?: boolean }
  ): Promise<string> {
    if (!clusterId?.trim()) {
      throw new AamarvaValidationError('clusterId is required.');
    }
    const cleanClusterId = clusterId.trim();

    if (options?.verifySignature === false) {
      throw new AamarvaError('Disabling cluster message signature verification is not permitted.', {
        code: 'CLUSTER_SIGNATURE_INVALID',
      });
    }

    if (!message || !message.ciphertext || !message.nonce) {
      throw new AamarvaValidationError('Cluster message ciphertext and nonce are required.', {
        code: 'CLUSTER_MESSAGE_DECRYPTION_FAILED',
      });
    }

    const version = this.parsePositiveIntStrict(message.version);
    if (version !== 2) {
      throw new AamarvaError('Cluster message decryption requires protocol version 2.', {
        code: 'INVALID_CLUSTER_MESSAGE_VERSION',
      });
    }

    const epoch = this.parsePositiveIntStrict(message.keyEpoch);
    if (epoch === undefined) {
      throw new AamarvaError('Cluster message is missing valid positive integer keyEpoch.', {
        code: 'CLUSTER_INVALID_EPOCH',
      });
    }

    if (!message.audienceHash || typeof message.audienceHash !== 'string') {
      throw new AamarvaError('Cluster message is missing audienceHash.', {
        code: 'INVALID_AUDIENCE_HASH',
      });
    }
    const audienceHash = this.assertValidAudienceHash(message.audienceHash);

    if (!message.rosterHash || typeof message.rosterHash !== 'string') {
      throw new AamarvaError('Cluster message is missing rosterHash.', {
        code: 'INVALID_ROSTER_HASH',
      });
    }
    const rosterHash = this.assertValidRosterHash(message.rosterHash);

    if (!message.keyFingerprint || typeof message.keyFingerprint !== 'string') {
      throw new AamarvaError('Cluster message is missing keyFingerprint.', {
        code: 'CLUSTER_KEY_FINGERPRINT_MISMATCH',
      });
    }
    const keyFingerprint = this.assertValidFingerprint(message.keyFingerprint);

    const senderAgentId = String(message.senderAgentId || '').trim();
    if (!senderAgentId) {
      throw new AamarvaError('Cluster message is missing senderAgentId.', {
        code: 'CLUSTER_SIGNATURE_INVALID',
      });
    }

    if (!message.signature || typeof message.signature !== 'string' || !message.signature.trim()) {
      throw new AamarvaError('Cluster message is missing required ECDSA v2 signature.', {
        code: 'CLUSTER_SIGNATURE_INVALID',
      });
    }

    // Authoritative membership & sender key resolution (mandatory)
    const members = await this.getClusterMembers(cleanClusterId);
    const senderMember = members.find((m) => normalizeAgentId(m.agentId) === normalizeAgentId(senderAgentId));
    if (!senderMember) {
      throw new AamarvaError(
        `Message sender "${senderAgentId}" is not an authoritative member of cluster "${cleanClusterId}".`,
        { code: 'CLUSTER_MEMBERSHIP_INVALID' }
      );
    }

    const myAgentId = (this.http.getAgentId() || this.agentId || '').trim();
    let resolvedSenderPub: any;
    if (myAgentId && normalizeAgentId(senderAgentId) === normalizeAgentId(myAgentId) && !senderMember.publicKey) {
      resolvedSenderPub = exportPublicKeyJWK(getLocalIdentityKeyPair(myAgentId, senderMember.keyEpoch).publicKey);
    } else {
      const mat = await this.resolveAuthoritativeMemberKey(senderAgentId, senderMember);
      resolvedSenderPub = mat.publicKey;
    }

    if (options?.senderPublicKey) {
      const authFp = computeKeyFingerprint(exportPublicKeyJWK(resolvedSenderPub));
      const suppliedFp = computeKeyFingerprint(exportPublicKeyJWK(options.senderPublicKey));
      if (suppliedFp !== authFp) {
        throw new AamarvaError(
          `Supplied senderPublicKey contradicts authoritative key for "${senderAgentId}".`,
          { code: 'CLUSTER_SIGNATURE_INVALID' }
        );
      }
    }

    const ok = verifyClusterMessageSignatureV2(
      resolvedSenderPub,
      {
        clusterId: cleanClusterId,
        keyEpoch: epoch,
        senderAgentId,
        audienceHash,
        rosterHash,
        sequence: message.sequence ?? '',
        keyFingerprint,
        nonce: message.nonce,
        ciphertext: message.ciphertext,
      },
      message.signature
    );
    if (!ok) {
      throw new AamarvaError('Cluster message ECDSA signature verification failed.', {
        code: 'CLUSTER_SIGNATURE_INVALID',
      });
    }

    const keyEntry = await this.getClusterKeyEntry(cleanClusterId, epoch, {
      audienceHash,
      expectedKeyFingerprint: keyFingerprint,
    });
    if (keyEntry.rosterHash && keyEntry.rosterHash !== rosterHash) {
      throw new AamarvaError(
        `Cluster message rosterHash mismatch: expected sealed ${keyEntry.rosterHash}, got ${rosterHash}.`,
        { code: 'ROSTER_HASH_MISMATCH' }
      );
    }

    return decryptClusterMessagePayload(
      message.ciphertext,
      message.nonce,
      keyEntry.key,
      cleanClusterId,
      epoch,
      version,
      audienceHash,
      senderAgentId
    );
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

  private getFloorScopeKey(toolId: string): string {
    const authAgent = (this.http.getAgentId() || this.agentId || '').trim().toUpperCase();
    const targetAgent = (this.http.getTargetAgentId() || '').trim().toUpperCase();
    return `${authAgent}::${targetAgent}::${toolId.trim()}`;
  }

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
   * Request / create an invocation for a FLOOR tool.
   * Maps to POST /api/floor/tools/:toolId/invoke
   */
  public async createFloorInvocation(
    toolId: string,
    options: { reason?: string; arguments?: Record<string, unknown> } = {}
  ): Promise<any> {
    if (!toolId?.trim()) {
      throw new AamarvaValidationError('toolId is required.');
    }

    let response: any;
    try {
      response = await this.http.request<any>({
        method: 'POST',
        path: `/floor/tools/${encodeURIComponent(toolId.trim())}/invoke`,
        body: {
          reason: options.reason || 'Agent requested tool invocation',
          arguments: options.arguments || {},
        },
        auth: true,
      });
    } catch (err: any) {
      if (err instanceof AamarvaForbiddenError || err?.statusCode === 403) {
        throw new AamarvaError(`Agent access to tool "${toolId.trim()}" was denied.`, {
          code: 'FLOOR_ACCESS_DENIED',
          statusCode: 403,
        });
      }
      throw err;
    }

    const data = (response?.data && typeof response.data === 'object' ? response.data : response) || {};
    const resAny = (response || {}) as any;
    const status = String(data.status || resAny.status || 'pending').trim().toLowerCase();
    const requestId = data.requestId
      ? String(data.requestId).trim()
      : resAny.requestId
      ? String(resAny.requestId).trim()
      : data.invocationId
      ? String(data.invocationId).trim()
      : undefined;
    const invocationId = String(data.invocationId || data.id || requestId || '').trim();

    if (status === 'pending' && requestId) {
      this.pendingFloorRequests.set(this.getFloorScopeKey(toolId.trim()), requestId);
    }

    return {
      invocationId,
      requestId,
      toolId: String(data.toolId || toolId.trim()).trim(),
      status,
      message: resAny.message || data.message,
    };
  }

  /**
   * Poll a pending FLOOR approval request until a terminal decision is returned.
   * Maps to GET /api/floor/requests/:requestId
   */
  public async waitForFloorApproval(
    requestId: string,
    options: { pollIntervalMs?: number; timeoutMs?: number; toolId?: string } = {}
  ): Promise<FloorAccessRequestStatus> {
    if (!requestId?.trim()) {
      throw new AamarvaValidationError('requestId is required.');
    }

    const reqId = requestId.trim();
    const pollIntervalMs = Math.max(5, options.pollIntervalMs ?? 1000);
    const timeoutMs = Math.max(pollIntervalMs, options.timeoutMs ?? 30000);
    const deadline = Date.now() + timeoutMs;

    while (true) {
      const statusRes = await this.getFloorRequestStatus(reqId);
      const st = (statusRes.status || 'pending').trim().toLowerCase();

      if (st === 'approved') {
        if (!statusRes.invocationId) {
          throw new AamarvaError(
            `FLOOR approval response for request "${reqId}" omitted required invocationId.`,
            { code: 'FLOOR_EXECUTION_FAILED' }
          );
        }
        return statusRes;
      }

      if (['denied', 'rejected', 'revoked', 'expired'].includes(st)) {
        throw new AamarvaError(
          `FLOOR tool access request ${reqId} was ${st}.`,
          {
            code: 'FLOOR_ACCESS_DENIED',
            details: { requestId: reqId, status: st, ...(options.toolId ? { toolId: options.toolId } : {}) },
          }
        );
      }

      if (st !== 'pending') {
        throw new AamarvaError(
          `FLOOR access request ${reqId} returned unexpected status "${st}".`,
          { code: 'FLOOR_EXECUTION_FAILED' }
        );
      }

      if (Date.now() >= deadline) {
        throw new AamarvaError(
          `Agent is not authorized yet. Access request ${reqId} is still pending human approval.`,
          {
            code: 'FLOOR_ACCESS_DENIED',
            details: { requestId: reqId, status: 'pending', ...(options.toolId ? { toolId: options.toolId } : {}) },
          }
        );
      }

      const waitMs = Math.min(pollIntervalMs, Math.max(1, deadline - Date.now()));
      await new Promise((resolve) => setTimeout(resolve, waitMs));
    }
  }

  /**
   * Obtain execution authorization for a FLOOR invocation.
   * Maps to POST /api/floor/invocations/:invocationId/execute
   */
  public async obtainFloorExecutionAuthorization(
    invocationId: string,
    options: {
      arguments?: Record<string, unknown>;
      toolId?: string;
      requiredScope?: string;
      fleetId?: string;
      requireApprovedArguments?: boolean;
    } = {}
  ): Promise<FloorExecutionAuthorization> {
    if (!invocationId?.trim()) {
      throw new AamarvaValidationError('invocationId is required.');
    }

    if (options.arguments !== undefined && !isPlainObject(options.arguments)) {
      throw new AamarvaValidationError('arguments must be a plain object.');
    }

    const expectedInvocationId = invocationId.trim();
    const submittedArgs = options.arguments || {};
    const expectedToolId = options.toolId?.trim() || '';

    let response: any;
    try {
      response = await this.http.request<any>({
        method: 'POST',
        path: `/floor/invocations/${encodeURIComponent(expectedInvocationId)}/execute`,
        body: {
          arguments: submittedArgs,
        },
        auth: true,
      });
    } catch (err: any) {
      if (err instanceof AamarvaForbiddenError || err?.statusCode === 403) {
        throw new AamarvaError('FLOOR execution authorization denied by platform.', {
          code: 'FLOOR_ACCESS_DENIED',
          statusCode: 403,
        });
      }
      throw err;
    }

    if (!isPlainObject(response)) {
      throw new AamarvaError('FLOOR authorization failed: response payload is not an object.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    if (response.success === false) {
      throw new AamarvaError('FLOOR execution authorization was rejected by platform.', {
        code: 'FLOOR_ACCESS_DENIED',
      });
    }

    const data = isPlainObject(response.data) ? (response.data as Record<string, unknown>) : null;
    if (!data) {
      throw new AamarvaError('FLOOR authorization failed: malformed authorization payload.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    // 1. Validate verificationInfo when present (mandatory when grant object is omitted)
    let verificationInfo: Record<string, unknown> | undefined;
    if ('verificationInfo' in data && data.verificationInfo !== undefined) {
      if (!isPlainObject(data.verificationInfo)) {
        throw new AamarvaError('FLOOR authorization failed: malformed verificationInfo object.', {
          code: 'FLOOR_EXECUTION_FAILED',
        });
      }
      verificationInfo = data.verificationInfo;
      if (verificationInfo.verified === false) {
        throw new AamarvaError('FLOOR authorization failed: verificationInfo.verified is false.', {
          code: 'FLOOR_ACCESS_DENIED',
        });
      }
      if (verificationInfo.verified !== true) {
        throw new AamarvaError('FLOOR authorization failed: verificationInfo.verified must be true.', {
          code: 'FLOOR_EXECUTION_FAILED',
        });
      }
      if ('invocationId' in verificationInfo && verificationInfo.invocationId !== undefined) {
        if (typeof verificationInfo.invocationId !== 'string' || verificationInfo.invocationId.trim() !== expectedInvocationId) {
          throw new AamarvaError('FLOOR authorization failed: verificationInfo.invocationId does not match invocation.', {
            code: 'FLOOR_EXECUTION_FAILED',
          });
        }
      }
    }

    // 2. Validate grantToken / accessToken (documented in docs/endpoints.md)
    let validGrantToken = '';
    if ('grantToken' in data && data.grantToken !== undefined) {
      if (typeof data.grantToken !== 'string' || !data.grantToken.trim()) {
        throw new AamarvaError('FLOOR authorization failed: grantToken is malformed or empty.', {
          code: 'FLOOR_EXECUTION_FAILED',
        });
      }
      validGrantToken = data.grantToken.trim();
    }
    let validAccessToken = '';
    if ('accessToken' in data && data.accessToken !== undefined) {
      if (typeof data.accessToken !== 'string' || !data.accessToken.trim()) {
        throw new AamarvaError('FLOOR authorization failed: accessToken is malformed or empty.', {
          code: 'FLOOR_EXECUTION_FAILED',
        });
      }
      validAccessToken = data.accessToken.trim();
    }
    const hasDocGrantProof = Boolean(verificationInfo?.verified === true && (validGrantToken || validAccessToken));

    // 3. Reconcile top-level execution status across grant-based and docs/endpoints.md contracts
    const rawStatus = String(data.status || (response as any).status || '').trim().toLowerCase();
    if (rawStatus) {
      if (['denied', 'rejected', 'revoked', 'expired', 'unassigned', 'pending'].includes(rawStatus)) {
        throw new AamarvaError(
          `FLOOR execution authorization denied: status is '${rawStatus}'.`,
          { code: 'FLOOR_ACCESS_DENIED' }
        );
      }
      if (rawStatus !== 'approved') {
        throw new AamarvaError(
          `FLOOR authorization failed: expected status 'approved', got '${rawStatus}'.`,
          { code: 'FLOOR_EXECUTION_FAILED' }
        );
      }
    } else if (!(response.success === true && hasDocGrantProof)) {
      throw new AamarvaError(
        `FLOOR authorization failed: expected status 'approved', got ''.`,
        { code: 'FLOOR_EXECUTION_FAILED' }
      );
    }

    // 4. Invocation ID binding
    const returnedInvocationId = typeof data.invocationId === 'string' ? data.invocationId.trim() : '';
    if (!returnedInvocationId || returnedInvocationId !== expectedInvocationId) {
      throw new AamarvaError('FLOOR authorization failed: invocation ID missing or mismatched in platform response.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    // 5. Grant validation (no implicit grant.status fallback; supports documented grantToken+verificationInfo contract)
    let grant: Record<string, unknown> | undefined;
    if ('grant' in data && data.grant !== undefined) {
      if (!isPlainObject(data.grant) || Object.keys(data.grant).length === 0) {
        throw new AamarvaError('FLOOR authorization failed: grant details missing or empty in response.', {
          code: 'FLOOR_EXECUTION_FAILED',
        });
      }
      grant = data.grant;
      if (grant.revoked === true || Boolean(grant.revokedAt)) {
        throw new AamarvaError('FLOOR authorization denied: grant has been revoked.', {
          code: 'FLOOR_ACCESS_DENIED',
        });
      }
      const grantStatus = typeof grant.status === 'string' ? grant.status.trim().toLowerCase() : '';
      if (grantStatus && ['denied', 'rejected', 'revoked', 'expired', 'inactive', 'pending'].includes(grantStatus)) {
        throw new AamarvaError(`FLOOR authorization denied: grant status is '${grantStatus}'.`, {
          code: 'FLOOR_ACCESS_DENIED',
        });
      }
      if (!grantStatus || !['authorized', 'granted', 'approved', 'active'].includes(grantStatus)) {
        throw new AamarvaError(`FLOOR authorization denied: grant status is missing or inactive ('${grantStatus}').`, {
          code: 'FLOOR_ACCESS_DENIED',
        });
      }
      if ('invocationId' in grant && grant.invocationId !== undefined) {
        if (typeof grant.invocationId !== 'string' || grant.invocationId.trim() !== expectedInvocationId) {
          throw new AamarvaError('FLOOR authorization failed: grant.invocationId does not match invocation.', {
            code: 'FLOOR_EXECUTION_FAILED',
          });
        }
      }
    } else if (!hasDocGrantProof) {
      throw new AamarvaError('FLOOR authorization failed: grant details missing in response.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    // 6. Strict invocation-to-tool binding across all tool ID fields
    if ('tool' in data && data.tool !== undefined && !isPlainObject(data.tool)) {
      throw new AamarvaError('FLOOR authorization failed: malformed tool object in response.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }
    const toolObj = isPlainObject(data.tool) ? data.tool : undefined;
    const toolIdCandidates: string[] = [];
    const readRequiredStringField = (obj: Record<string, unknown> | undefined, field: string, label: string): string | undefined => {
      if (!obj || !(field in obj) || obj[field] === undefined) return undefined;
      if (typeof obj[field] !== 'string' || !obj[field].trim()) {
        throw new AamarvaError(`FLOOR authorization failed: malformed ${label} in platform response.`, {
          code: 'FLOOR_EXECUTION_FAILED',
        });
      }
      return obj[field].trim();
    };

    const topToolId = readRequiredStringField(data, 'toolId', 'toolId');
    const nestedToolId = readRequiredStringField(toolObj, 'id', 'tool.id');
    const grantToolId = readRequiredStringField(grant, 'toolId', 'grant.toolId');
    const verifiedToolId = readRequiredStringField(verificationInfo, 'toolId', 'verificationInfo.toolId');

    for (const candidate of [topToolId, nestedToolId, grantToolId, verifiedToolId]) {
      if (candidate) toolIdCandidates.push(candidate);
    }

    const returnedToolId = topToolId || nestedToolId || '';
    if (!returnedToolId) {
      throw new AamarvaError('FLOOR authorization failed: authorized toolId is missing in platform response.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }
    if (toolIdCandidates.some((tid) => tid !== returnedToolId) || (expectedToolId && returnedToolId !== expectedToolId)) {
      throw new AamarvaError('FLOOR authorization failed: authorized toolId mismatch across authorization payload.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    // 7. MCP server URL validation
    const serverUrl =
      data.serverUrl !== undefined
        ? data.serverUrl
        : data.mcpServerUrl !== undefined
        ? data.mcpServerUrl
        : isPlainObject(data.server)
        ? data.server.url
        : undefined;
    if (!serverUrl || typeof serverUrl !== 'string' || !serverUrl.trim()) {
      throw new AamarvaError('FLOOR authorization failed: valid MCP serverUrl is missing in response.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }
    let parsedServerUrl: URL;
    try {
      parsedServerUrl = new URL(serverUrl.trim());
    } catch {
      throw new AamarvaError('FLOOR authorization failed: malformed MCP serverUrl in response.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }
    if (parsedServerUrl.protocol !== 'http:' && parsedServerUrl.protocol !== 'https:') {
      throw new AamarvaError('FLOOR authorization failed: unsupported MCP serverUrl protocol.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    // 8. Validate authorized MCP credentials before any connection
    const rawAuth =
      data.auth !== undefined
        ? data.auth
        : data.authentication !== undefined
        ? data.authentication
        : data.authConfig;
    if (rawAuth !== undefined && !isPlainObject(rawAuth)) {
      throw new AamarvaError('FLOOR authorization failed: malformed MCP auth configuration in response.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }
    let resolvedAuth: Record<string, unknown> | undefined;
    if (isPlainObject(rawAuth) && hasValidMcpAuthConfig(rawAuth)) {
      resolvedAuth = rawAuth;
    } else if (validGrantToken || validAccessToken) {
      resolvedAuth = { type: 'bearer', token: validGrantToken || validAccessToken };
    } else {
      throw new AamarvaError('FLOOR authorization failed: authorized MCP credentials missing or invalid.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    // 9. Validate every present expiration timestamp
    const topExpires = validateIsoExpiration(data.expiresAt, 'expiresAt' in data && data.expiresAt !== undefined);
    const grantExpires = validateIsoExpiration(
      grant?.expiresAt,
      Boolean(grant && 'expiresAt' in grant && grant.expiresAt !== undefined)
    );
    const resolvedExpiresAt = grantExpires || topExpires;

    // 10. Validate grant scope when present (or required)
    const scopeSources: string[][] = [];
    let resolvedScope: string | string[] | undefined;
    for (const [container, label] of [
      [data, 'data.scope'],
      [grant, 'grant.scope'],
      [verificationInfo, 'verificationInfo.scope'],
    ] as const) {
      if (container && 'scope' in container && container.scope !== undefined) {
        const tokens = parseAndValidateScopeTokens(container.scope, label);
        scopeSources.push(tokens);
        if (resolvedScope === undefined) {
          resolvedScope = container.scope as string | string[];
        }
      }
    }
    if (scopeSources.length > 1) {
      const baseSet = JSON.stringify([...new Set(scopeSources[0])].sort());
      for (let i = 1; i < scopeSources.length; i++) {
        if (JSON.stringify([...new Set(scopeSources[i])].sort()) !== baseSet) {
          throw new AamarvaError('FLOOR authorization denied: conflicting scopes across authorization response.', {
            code: 'FLOOR_ACCESS_DENIED',
          });
        }
      }
    }
    const reqScope = options.requiredScope?.trim();
    if (reqScope) {
      const grantedSet = new Set(scopeSources.flat());
      if (grantedSet.size === 0 || (!grantedSet.has(reqScope) && !grantedSet.has('*') && !grantedSet.has('tool:*'))) {
        throw new AamarvaError(`FLOOR authorization denied: required scope '${reqScope}' is not granted.`, {
          code: 'FLOOR_ACCESS_DENIED',
        });
      }
    }

    // 11. Strengthened agent identity, target-agent scoping, and fleet-context validation
    const authAgentId = (this.http.getAgentId() || this.agentId || '').trim();
    const targetAgentId = (this.http.getTargetAgentId() || '').trim();
    const expectedAgentId = targetAgentId || authAgentId;

    const returnedAgentFields: string[] = [];
    for (const [obj, field, label] of [
      [data, 'agentId', 'data.agentId'],
      [grant, 'agentId', 'grant.agentId'],
      [verificationInfo, 'agentId', 'verificationInfo.agentId'],
      [data, 'targetAgentId', 'data.targetAgentId'],
      [grant, 'targetAgentId', 'grant.targetAgentId'],
      [verificationInfo, 'targetAgentId', 'verificationInfo.targetAgentId'],
    ] as const) {
      const val = readRequiredStringField(obj, field, label);
      if (val) returnedAgentFields.push(val);
    }

    if (expectedAgentId) {
      if (returnedAgentFields.length === 0) {
        throw new AamarvaError('FLOOR authorization failed: authorized agent identity missing in platform response.', {
          code: 'FLOOR_EXECUTION_FAILED',
        });
      }
      const expectedUpper = expectedAgentId.toUpperCase();
      for (const returnedId of returnedAgentFields) {
        if (returnedId.toUpperCase() !== expectedUpper) {
          throw new AamarvaError('FLOOR authorization failed: agent fleet context mismatch in authorization response.', {
            code: 'FLOOR_EXECUTION_FAILED',
          });
        }
      }
    } else if (returnedAgentFields.length > 1) {
      const firstUpper = returnedAgentFields[0].toUpperCase();
      if (returnedAgentFields.some((id) => id.toUpperCase() !== firstUpper)) {
        throw new AamarvaError('FLOOR authorization failed: conflicting agent identities in authorization response.', {
          code: 'FLOOR_EXECUTION_FAILED',
        });
      }
    }

    const fleetIds: string[] = [];
    for (const [obj, label] of [
      [data, 'data.fleetId'],
      [grant, 'grant.fleetId'],
      [verificationInfo, 'verificationInfo.fleetId'],
    ] as const) {
      const fid = readRequiredStringField(obj, 'fleetId', label);
      if (fid) fleetIds.push(fid);
    }
    const expectedFleetId = options.fleetId?.trim() || '';
    if (expectedFleetId && (fleetIds.length === 0 || fleetIds.some((f) => f.toUpperCase() !== expectedFleetId.toUpperCase()))) {
      throw new AamarvaError('FLOOR authorization failed: fleet context mismatch in authorization response.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }
    if (fleetIds.length > 1 && fleetIds.some((f) => f.toUpperCase() !== fleetIds[0].toUpperCase())) {
      throw new AamarvaError('FLOOR authorization failed: conflicting fleet identifiers in authorization response.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    const masterIds: string[] = [];
    for (const [obj, label] of [
      [data, 'data.masterId'],
      [grant, 'grant.masterId'],
      [verificationInfo, 'verificationInfo.masterId'],
    ] as const) {
      const mid = readRequiredStringField(obj, 'masterId', label);
      if (mid) masterIds.push(mid);
    }
    if (masterIds.length > 1 && masterIds.some((m) => m.toUpperCase() !== masterIds[0].toUpperCase())) {
      throw new AamarvaError('FLOOR authorization failed: conflicting master agent identifiers in authorization response.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    const returnedAgentId = returnedAgentFields[0] || '';

    // 12. Strict invocation-to-arguments binding
    let dataApprovedArgs: Record<string, unknown> | undefined;
    if ('approvedArguments' in data && data.approvedArguments !== undefined) {
      if (!isPlainObject(data.approvedArguments)) {
        throw new AamarvaError('FLOOR authorization failed: malformed approvedArguments in response.', {
          code: 'FLOOR_EXECUTION_FAILED',
        });
      }
      dataApprovedArgs = data.approvedArguments;
    }

    let grantApprovedArgs: Record<string, unknown> | undefined;
    if (grant && 'approvedArguments' in grant && grant.approvedArguments !== undefined) {
      if (!isPlainObject(grant.approvedArguments)) {
        throw new AamarvaError('FLOOR authorization failed: malformed grant.approvedArguments in response.', {
          code: 'FLOOR_EXECUTION_FAILED',
        });
      }
      grantApprovedArgs = grant.approvedArguments;
    }

    if (dataApprovedArgs && grantApprovedArgs) {
      if (canonicalJsonStringify(dataApprovedArgs) !== canonicalJsonStringify(grantApprovedArgs)) {
        throw new AamarvaError('FLOOR authorization failed: conflicting approvedArguments in authorization response.', {
          code: 'FLOOR_EXECUTION_FAILED',
        });
      }
    }

    const approvedArgs = dataApprovedArgs ?? grantApprovedArgs;
    if (options.requireApprovedArguments && !approvedArgs) {
      throw new AamarvaError('FLOOR authorization failed: approvedArguments missing in authorization response.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }
    if (approvedArgs) {
      if (canonicalJsonStringify(approvedArgs) !== canonicalJsonStringify(submittedArgs)) {
        throw new AamarvaError('FLOOR authorization failed: execution arguments do not match approved arguments.', {
          code: 'FLOOR_EXECUTION_FAILED',
        });
      }
    }

    return {
      invocationId: returnedInvocationId,
      toolId: returnedToolId,
      status: 'approved',
      serverUrl: parsedServerUrl.toString(),
      ...(returnedAgentId ? { agentId: returnedAgentId } : {}),
      ...(resolvedScope !== undefined ? { scope: resolvedScope } : {}),
      ...(resolvedExpiresAt ? { expiresAt: resolvedExpiresAt } : {}),
      ...(approvedArgs ? { approvedArguments: approvedArgs } : {}),
      auth: resolvedAuth,
      ...(grant ? { grant } : {}),
    };
  }

  /**
   * Execute a FLOOR tool via the platform's 5-stage zero-trust governance sequence:
   * Discovery -> Access evaluation -> Approval status/polling -> Execute authorization -> External MCP invocation.
   */
  public async executeFloorTool(
    toolId: string,
    args: Record<string, unknown> = {},
    options: ExecuteFloorToolOptions = {}
  ): Promise<FloorToolInvokeResult> {
    if (!toolId?.trim()) {
      throw new AamarvaValidationError('toolId is required.');
    }
    if (args !== undefined && !isPlainObject(args)) {
      throw new AamarvaValidationError('arguments must be a plain object.');
    }

    const cleanToolId = toolId.trim();
    const scopeKey = this.getFloorScopeKey(cleanToolId);
    const shouldWait = Boolean(
      options.waitForApproval || (options.pollTimeoutMs !== undefined && options.pollTimeoutMs > 0)
    );
    const expectedAgentId = (this.http.getTargetAgentId() || this.http.getAgentId() || this.agentId || '').trim();

    // Stage 1: Tool discovery (informational only; never authorizes execution)
    const tools = await this.getFloorTools();
    const tool = tools.find((t) => t.id === cleanToolId);
    if (!tool) {
      throw new AamarvaError(`Tool "${cleanToolId}" not found in available fleet tools.`, {
        code: 'FLOOR_TOOL_NOT_FOUND',
      });
    }

    const accessStatus = (tool.accessStatus || '').trim().toLowerCase();
    let invocationId = options.invocationId?.trim() || undefined;

    if (!invocationId && ['revoked', 'denied', 'rejected', 'expired'].includes(accessStatus)) {
      this.pendingFloorRequests.delete(scopeKey);
      throw new AamarvaError(
        `Agent access to tool "${cleanToolId}" is ${accessStatus}.`,
        { code: 'FLOOR_ACCESS_DENIED' }
      );
    }

    const assertRequestBinding = (statusRes: FloorAccessRequestStatus) => {
      if (statusRes.toolId && statusRes.toolId.trim() !== cleanToolId) {
        throw new AamarvaError(
          `FLOOR request status toolId "${statusRes.toolId}" does not match requested tool "${cleanToolId}".`,
          { code: 'FLOOR_EXECUTION_FAILED' }
        );
      }
      if (expectedAgentId && statusRes.agentId && statusRes.agentId.trim().toUpperCase() !== expectedAgentId.toUpperCase()) {
        throw new AamarvaError(
          'FLOOR request status agentId does not match target agent context.',
          { code: 'FLOOR_EXECUTION_FAILED' }
        );
      }
    };

    // Stage 2 & 3: Access evaluation, reuse existing pending request, and optional HITL polling
    if (!invocationId) {
      const existingRequestId =
        options.requestId?.trim() ||
        tool.requestId?.trim() ||
        this.pendingFloorRequests.get(scopeKey);

      if (existingRequestId) {
        if (shouldWait) {
          const approvedStatus = await this.waitForFloorApproval(existingRequestId, {
            pollIntervalMs: options.pollIntervalMs,
            timeoutMs: options.pollTimeoutMs,
            toolId: cleanToolId,
          });
          assertRequestBinding(approvedStatus);
          this.pendingFloorRequests.delete(scopeKey);
          invocationId = approvedStatus.invocationId;
        } else {
          const statusRes = await this.getFloorRequestStatus(existingRequestId);
          const reqStatus = (statusRes.status || 'pending').trim().toLowerCase();
          if (reqStatus === 'approved') {
            assertRequestBinding(statusRes);
            this.pendingFloorRequests.delete(scopeKey);
            if (!statusRes.invocationId) {
              throw new AamarvaError(
                `FLOOR approval for request "${existingRequestId}" omitted invocationId.`,
                { code: 'FLOOR_EXECUTION_FAILED' }
              );
            }
            invocationId = statusRes.invocationId;
          } else if (reqStatus === 'pending') {
            throw new AamarvaError(
              `Agent is not authorized to execute tool "${cleanToolId}". Access request ${existingRequestId} is pending human approval.`,
              {
                code: 'FLOOR_ACCESS_DENIED',
                details: { requestId: existingRequestId, status: 'pending', toolId: cleanToolId },
              }
            );
          } else if (['denied', 'rejected', 'revoked', 'expired'].includes(reqStatus)) {
            this.pendingFloorRequests.delete(scopeKey);
            throw new AamarvaError(
              `Agent access to tool "${cleanToolId}" was ${reqStatus}.`,
              {
                code: 'FLOOR_ACCESS_DENIED',
                details: { requestId: existingRequestId, status: reqStatus, toolId: cleanToolId },
              }
            );
          } else {
            throw new AamarvaError(
              `FLOOR access request ${existingRequestId} returned unexpected status "${reqStatus}".`,
              { code: 'FLOOR_EXECUTION_FAILED' }
            );
          }
        }
      } else {
        const hasGrant = ['authorized', 'granted', 'approved'].includes(accessStatus);
        const invRes = await this.createFloorInvocation(cleanToolId, {
          reason: options.reason || (hasGrant ? 'Authorized execution run' : 'Agent requested execution'),
          arguments: args,
        });

        if (invRes.toolId && String(invRes.toolId).trim() !== cleanToolId) {
          throw new AamarvaError(
            `FLOOR invocation toolId "${invRes.toolId}" does not match requested tool "${cleanToolId}".`,
            { code: 'FLOOR_EXECUTION_FAILED' }
          );
        }

        if (invRes.status === 'pending') {
          const reqId = invRes.requestId || invRes.invocationId;
          if (reqId) {
            this.pendingFloorRequests.set(scopeKey, reqId);
          }
          if (shouldWait && reqId) {
            const approvedStatus = await this.waitForFloorApproval(reqId, {
              pollIntervalMs: options.pollIntervalMs,
              timeoutMs: options.pollTimeoutMs,
              toolId: cleanToolId,
            });
            assertRequestBinding(approvedStatus);
            this.pendingFloorRequests.delete(scopeKey);
            invocationId = approvedStatus.invocationId;
          } else {
            throw new AamarvaError(
              `Agent is not authorized to execute tool "${cleanToolId}". Access request ${reqId} is pending human approval.`,
              {
                code: 'FLOOR_ACCESS_DENIED',
                details: { requestId: reqId, status: 'pending', toolId: cleanToolId },
              }
            );
          }
        } else if (['denied', 'rejected', 'revoked', 'expired'].includes(invRes.status)) {
          throw new AamarvaError(
            `Agent access to tool "${cleanToolId}" was denied (status: ${invRes.status}).`,
            { code: 'FLOOR_ACCESS_DENIED' }
          );
        } else if (!['approved', 'authorized', 'granted'].includes(invRes.status)) {
          throw new AamarvaError(
            `FLOOR invocation creation returned unexpected status "${invRes.status}".`,
            { code: 'FLOOR_EXECUTION_FAILED' }
          );
        } else {
          invocationId = invRes.invocationId;
        }
      }
    }

    if (!invocationId) {
      throw new AamarvaError('FLOOR invocation creation failed to return a valid invocationId.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    // Stage 4: Mandatory execution authorization gate before any MCP connection
    const authDetails = await this.obtainFloorExecutionAuthorization(invocationId, {
      arguments: args,
      toolId: cleanToolId,
      requiredScope: options.requiredScope,
      fleetId: options.fleetId,
      requireApprovedArguments: options.requireApprovedArguments,
    });

    if (authDetails.status !== 'approved') {
      throw new AamarvaError(`FLOOR execution denied: status is '${authDetails.status}'.`, {
        code: 'FLOOR_ACCESS_DENIED',
      });
    }

    if (authDetails.toolId.trim() !== cleanToolId) {
      throw new AamarvaError(
        `FLOOR execution authorization mismatch: authorized tool "${authDetails.toolId}" does not match requested tool "${cleanToolId}".`,
        { code: 'FLOOR_EXECUTION_FAILED' }
      );
    }

    const authorizedArgs = authDetails.approvedArguments ? { ...authDetails.approvedArguments } : { ...(args || {}) };

    // Stage 5: External MCP tool execution over verified connection
    const mcpResult = await invokeExternalMcpTool({
      serverUrl: authDetails.serverUrl,
      toolId: cleanToolId,
      args: authorizedArgs,
      auth: authDetails.auth,
      inputSchema: tool.inputSchema,
      fetchFn: this.http.getFetch(),
    });

    return {
      status: 'approved',
      invocationId,
      toolId: cleanToolId,
      result: mcpResult,
      serverUrl: authDetails.serverUrl,
    };
  }

  /**
   * Request access to a FLOOR tool without executing it.
   * Reuses an existing pending request when already pending.
   * Maps to POST /api/floor/tools/:toolId/invoke
   */
  public async requestFloorAccess(
    toolId: string,
    reason?: string,
    args?: Record<string, unknown>
  ): Promise<FloorToolInvokeResult> {
    if (!toolId?.trim()) {
      throw new AamarvaValidationError('toolId is required.');
    }

    const cleanToolId = toolId.trim();
    const scopeKey = this.getFloorScopeKey(cleanToolId);

    try {
      const tools = await this.getFloorTools();
      const existing = tools.find((t) => t.id === cleanToolId);
      if (existing && ['authorized', 'granted', 'approved'].includes((existing.accessStatus || '').toLowerCase())) {
        return {
          status: 'approved',
          toolId: cleanToolId,
          message: 'Tool access is already granted via persistent access policy.',
        };
      }
      const existingReqId = existing?.requestId?.trim() || this.pendingFloorRequests.get(scopeKey);
      if (existingReqId) {
        const statusRes = await this.getFloorRequestStatus(existingReqId);
        const st = (statusRes.status || 'pending').toLowerCase();
        if (st === 'pending') {
          return {
            status: 'pending',
            requestId: existingReqId,
            toolId: cleanToolId,
            message: 'Access request is already pending approval.',
          };
        }
        this.pendingFloorRequests.delete(scopeKey);
        if (st === 'approved') {
          return {
            status: 'approved',
            requestId: existingReqId,
            invocationId: statusRes.invocationId,
            toolId: cleanToolId,
            message: 'Access request has been approved.',
          };
        }
      }
    } catch {
      // Fall through to invocation submission
    }

    const inv = await this.createFloorInvocation(cleanToolId, { reason, arguments: args });
    const reqId = inv.requestId || inv.invocationId;
    if (inv.status === 'pending' && reqId) {
      this.pendingFloorRequests.set(scopeKey, reqId);
    }
    return {
      status: inv.status || 'pending',
      requestId: reqId,
      invocationId: inv.invocationId,
      toolId: cleanToolId,
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

    const data = (response && typeof response === 'object' && 'data' in response ? response.data : response) ?? {};
    return normalizeFloorRequestStatus(data);
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

function isPlainObject(val: unknown): val is Record<string, unknown> {
  return typeof val === 'object' && val !== null && !Array.isArray(val);
}

function hasValidMcpAuthConfig(auth: Record<string, unknown>): boolean {
  const authType = String(auth.type || auth.authType || '').trim().toLowerCase();
  const headerName = String(auth.headerName || auth.authHeaderName || '').trim();
  if (typeof auth.token === 'string' && auth.token.trim().length > 0) return true;
  if (typeof auth.apiKey === 'string' && auth.apiKey.trim().length > 0) return true;
  if (typeof auth.headerValue === 'string' && auth.headerValue.trim().length > 0) {
    if (headerName.length > 0 || authType === 'bearer' || authType === 'apikey') return true;
  }
  if (isPlainObject(auth.headers)) {
    for (const [k, v] of Object.entries(auth.headers)) {
      if (k.trim().length > 0 && typeof v === 'string' && v.trim().length > 0) {
        return true;
      }
    }
  }
  return false;
}

function validateIsoExpiration(rawValue: unknown, isPresent: boolean): string | undefined {
  if (!isPresent) return undefined;
  if (typeof rawValue !== 'string' || !rawValue.trim()) {
    throw new AamarvaError('FLOOR authorization denied: malformed grant expiration timestamp.', {
      code: 'FLOOR_ACCESS_DENIED',
    });
  }
  const trimmed = rawValue.trim();
  if (!/^\d{4}-\d{2}-\d{2}/.test(trimmed)) {
    throw new AamarvaError('FLOOR authorization denied: malformed grant expiration timestamp.', {
      code: 'FLOOR_ACCESS_DENIED',
    });
  }
  const expiresMs = Date.parse(trimmed);
  if (Number.isNaN(expiresMs)) {
    throw new AamarvaError('FLOOR authorization denied: malformed grant expiration timestamp.', {
      code: 'FLOOR_ACCESS_DENIED',
    });
  }
  if (expiresMs <= Date.now()) {
    throw new AamarvaError('FLOOR authorization denied: execution grant has expired.', {
      code: 'FLOOR_ACCESS_DENIED',
    });
  }
  return trimmed;
}

function parseAndValidateScopeTokens(rawScope: unknown, label: string): string[] {
  const deniedScopeTokens = new Set(['none', 'denied', 'revoked', 'expired', 'invalid', 'unauthorized']);
  let tokens: string[] = [];
  if (typeof rawScope === 'string') {
    const trimmed = rawScope.trim();
    if (!trimmed) {
      throw new AamarvaError(`FLOOR authorization denied: ${label} is empty.`, {
        code: 'FLOOR_ACCESS_DENIED',
      });
    }
    tokens = trimmed.split(/[\s,]+/).filter(Boolean);
  } else if (Array.isArray(rawScope)) {
    if (rawScope.length === 0) {
      throw new AamarvaError(`FLOOR authorization denied: ${label} is empty.`, {
        code: 'FLOOR_ACCESS_DENIED',
      });
    }
    for (const item of rawScope) {
      if (typeof item !== 'string' || !item.trim()) {
        throw new AamarvaError(`FLOOR authorization denied: ${label} contains invalid entry.`, {
          code: 'FLOOR_ACCESS_DENIED',
        });
      }
      tokens.push(...item.trim().split(/[\s,]+/).filter(Boolean));
    }
  } else {
    throw new AamarvaError(`FLOOR authorization denied: ${label} is invalid.`, {
      code: 'FLOOR_ACCESS_DENIED',
    });
  }

  if (tokens.length === 0 || tokens.some((t) => deniedScopeTokens.has(t.toLowerCase()))) {
    throw new AamarvaError(`FLOOR authorization denied: ${label} is not permitted for execution.`, {
      code: 'FLOOR_ACCESS_DENIED',
    });
  }
  return tokens;
}

function canonicalJsonStringify(obj: unknown): string {
  if (obj === null || typeof obj !== 'object') {
    if (typeof obj === 'number' && Object.is(obj, -0)) {
      return '0';
    }
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map((item) => (item === undefined ? 'null' : canonicalJsonStringify(item))).join(',') + ']';
  }
  const record = obj as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const entries: string[] = [];
  for (const k of keys) {
    const val = record[k];
    if (val !== undefined) {
      entries.push(`${JSON.stringify(k)}:${canonicalJsonStringify(val)}`);
    }
  }
  return `{${entries.join(',')}}`;
}



