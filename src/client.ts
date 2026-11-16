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
    const list: any[] = Array.isArray(raw)
      ? raw
      : raw && typeof raw === 'object' && Array.isArray(raw.members)
      ? raw.members
      : [];

    return list
      .map((item: any): ClusterMember | null => {
        if (typeof item === 'string') {
          return { agentId: item.trim() };
        }
        if (!item || typeof item !== 'object') {
          return null;
        }
        const id = String(item.agentId || item.agent_id || item.id || '').trim();
        if (!id) return null;
        return {
          agentId: id,
          name: item.name,
          role: item.role,
          status: item.status,
          publicKey: item.publicKey || item.e2eePublicKey || item.peerE2eePublicKey,
          keyFingerprint: item.keyFingerprint || item.fingerprint || item.peerKeyFingerprint,
          keyEpoch:
            item.keyEpoch !== undefined
              ? Number(item.keyEpoch)
              : item.key_epoch !== undefined
              ? Number(item.key_epoch)
              : undefined,
          identityKey: item.identityKey || item.peerIdentityKey,
          keySignature: item.keySignature || item.signature || item.peerKeySignature,
        };
      })
      .filter((m): m is ClusterMember => m !== null);
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

    const response = await this.http.request<any>({
      method: 'POST',
      path: `/clusters/${encodeURIComponent(clusterId.trim())}/rotate-key`,
      body: options || {},
      auth: true,
    });

    const data = (response.data && typeof response.data === 'object' ? response.data : response) || {};
    const nextEpoch = Number(data.epoch ?? data.keyEpoch ?? 1);
    return {
      clusterId: String(data.clusterId || clusterId.trim()),
      epoch: nextEpoch,
      keyEpoch: Number(data.keyEpoch ?? nextEpoch),
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
      version: Number(item.version || 1),
      keyEpoch: Number(item.keyEpoch || item.key_epoch || 1),
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

  /**
   * Broadcast an encrypted message to a cluster with recipient restrictions & Workflow 2 metadata.
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

    const keyEpoch = options.keyEpoch === undefined ? 1 : options.keyEpoch;
    if (typeof keyEpoch !== 'number' || !Number.isInteger(keyEpoch) || keyEpoch < 1) {
      throw new AamarvaValidationError('Cluster messages require keyEpoch to be an integer >= 1.', {
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

    const recipientSet = new Set<string>();
    if (masterId) recipientSet.add(masterId);
    if (senderAgentId) recipientSet.add(senderAgentId);
    for (const r of rawRecipients) {
      recipientSet.add(r.trim());
    }
    if (options.recipientAgentIds) {
      for (const r of options.recipientAgentIds) {
        recipientSet.add(r.trim());
      }
    }
    const finalRecipients = Array.from(recipientSet);

    const payload: Record<string, unknown> = {
      senderAgentId,
      ciphertext: options.ciphertext,
      nonce: options.nonce,
      version,
      keyEpoch,
      recipients: finalRecipients,
    };
    if (options.audienceHash !== undefined) payload.audienceHash = options.audienceHash;
    if (options.rosterHash !== undefined) payload.rosterHash = options.rosterHash;
    if (options.keyFingerprint !== undefined) payload.keyFingerprint = options.keyFingerprint;
    if (options.signature !== undefined) payload.signature = options.signature;
    if (options.strictPreflight !== undefined) payload.strictPreflight = options.strictPreflight;
    if (options.sequence !== undefined) payload.sequence = options.sequence;
    if (options.recipientAgentIds !== undefined) payload.recipientAgentIds = options.recipientAgentIds;

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

  private getClusterCacheKey(clusterId: string, epoch = 1, audienceHash = 'ALL'): string {
    return `${clusterId}:${epoch}:${audienceHash || 'ALL'}`;
  }

  private async resolveRecipientKeyMaterial(
    agentId: string,
    clusterMembers: ClusterMember[],
    explicitKeys?: Record<string, any>
  ): Promise<{ publicKey: any; keyFingerprint?: string; keyEpoch?: number } | null> {
    const normTarget = normalizeAgentId(agentId);
    const direct = explicitKeys?.[agentId] || explicitKeys?.[normTarget];
    if (direct) {
      if (typeof direct === 'object' && direct.publicKey && !direct.kty) {
        return {
          publicKey: direct.publicKey,
          keyFingerprint: direct.keyFingerprint || direct.fingerprint,
          keyEpoch: direct.keyEpoch,
        };
      }
      return { publicKey: direct };
    }

    const fromRoster = clusterMembers.find((m) => normalizeAgentId(m.agentId) === normTarget);
    if (fromRoster?.publicKey) {
      return {
        publicKey: fromRoster.publicKey,
        keyFingerprint: fromRoster.keyFingerprint,
        keyEpoch: fromRoster.keyEpoch,
      };
    }

    try {
      const pk = await this.getPeerKeyByAgent(agentId);
      const rawKey = (pk as any).publicKey || pk.peerE2eePublicKey || pk.peerIdentityKey;
      if (rawKey) {
        return {
          publicKey: rawKey,
          keyFingerprint: (pk as any).fingerprint || pk.peerKeyFingerprint,
          keyEpoch: (pk as any).keyEpoch ?? pk.peerKeyEpoch,
        };
      }
    } catch {
      // Fallback to direct connection lookup below
    }

    try {
      const connections = await this.getConnections();
      const conn = connections.find(
        (c) => normalizeAgentId(c.peerAgentId || c.agentId) === normTarget
      );
      if (conn) {
        const peerKey = await this.getPeerKey(conn.connectionId);
        const rawKey = peerKey.peerE2eePublicKey || peerKey.peerIdentityKey;
        if (rawKey) {
          return {
            publicKey: rawKey,
            keyFingerprint: peerKey.peerKeyFingerprint,
            keyEpoch: peerKey.peerKeyEpoch,
          };
        }
      }
    } catch {
      // connection lookup failed
    }

    return null;
  }

  /**
   * Generate, wrap, and distribute cluster symmetric keys to all required recipients (Workflow 2).
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
    const epoch = options.epoch || 1;
    const authAgentId = (this.http.getAgentId() || this.agentId || '').trim();
    if (!authAgentId) {
      throw new AamarvaValidationError('Sender agent ID is required for cluster key distribution.');
    }

    const masterId = await this.resolveMasterAgentId();

    let clusterMembers: ClusterMember[] = [];
    try {
      clusterMembers = await this.getClusterMembers(clusterId);
    } catch {
      try {
        const cl = await this.getCluster(clusterId);
        if (Array.isArray(cl.members)) {
          clusterMembers = cl.members.map((m: any) =>
            typeof m === 'string' ? { agentId: m } : m
          );
        }
      } catch {
        // Fallback when cluster details endpoint is unavailable in minimal mocks
      }
    }

    const activeRosterIds = canonicalMemberSet([
      masterId,
      authAgentId,
      ...clusterMembers.map((m) => m.agentId),
      ...(options.recipients || []),
    ]);

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
    if (options.recipients && options.recipients.length > 0) {
      for (const r of options.recipients) {
        addUnique(r);
      }
    } else {
      for (const m of clusterMembers) {
        addUnique(m.agentId);
      }
    }
    const finalRecipients = Array.from(recipientSet);

    const rosterHash = options.rosterHash || computeRosterHash(activeRosterIds);
    const audienceHash =
      options.audienceHash || computeAudienceHash(finalRecipients, activeRosterIds);

    // Generate local 256-bit symmetric cluster key
    const clusterKey = generateClusterKey();
    const keyFingerprint = computeGroupKeyFingerprint(clusterKey);
    const senderKp = getLocalIdentityKeyPair(authAgentId, epoch > 1 ? epoch : undefined);
    const senderPubJwk = exportPublicKeyJWK(senderKp.publicKey);
    const senderPubFp = computeKeyFingerprint(senderPubJwk);

    const keyPackages: Array<{
      recipientAgentId: string;
      encryptedKeyPackage: Record<string, unknown>;
      nonce: string;
      keyFingerprint: string;
      wrappingParams: Record<string, unknown>;
    }> = [];

    for (const recipientId of finalRecipients) {
      let recipientPubKey: any;
      let recipientKeyFp: string | undefined;
      let recipientKeyEpoch: number | undefined;

      if (normalizeAgentId(recipientId) === normalizeAgentId(authAgentId) && !options.recipientPublicKeys?.[recipientId]) {
        recipientPubKey = senderPubJwk;
        recipientKeyFp = senderPubFp;
        recipientKeyEpoch = epoch;
      } else {
        const resolved = await this.resolveRecipientKeyMaterial(
          recipientId,
          clusterMembers,
          options.recipientPublicKeys
        );
        if (resolved) {
          recipientPubKey = resolved.publicKey;
          recipientKeyFp = resolved.keyFingerprint;
          recipientKeyEpoch = resolved.keyEpoch;
        }
      }

      if (!recipientPubKey) {
        throw new AamarvaError(
          `Recipient "${recipientId}" does not have a registered public key for cluster encryption.`,
          { code: 'RECIPIENT_KEY_MISSING' }
        );
      }

      const wrapped = wrapClusterKeyForRecipient(clusterKey, recipientPubKey, senderKp.privateKey, {
        clusterId,
        epoch,
        audienceHash,
        rosterHash,
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

    // Submit key packages via platform endpoint
    await this.submitClusterKeyDistribution(clusterId, {
      epoch,
      audienceHash,
      rosterHash,
      keyFingerprint,
      senderAgentId: authAgentId,
      keyPackages,
    });

    this.clusterKeyCache.set(this.getClusterCacheKey(clusterId, epoch, audienceHash), {
      key: clusterKey,
      keyFingerprint,
      rosterHash,
      audienceHash,
      epoch,
    });

    return {
      epoch,
      clusterKey,
      keyFingerprint,
      rosterHash,
      audienceHash,
      recipients: finalRecipients,
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
      query.epoch = resolvedEpoch;
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
    epoch = 1,
    options?: { audienceHash?: string; senderPublicKey?: any; expectedKeyFingerprint?: string }
  ): Promise<CachedClusterKeyEntry> {
    const requestedAudience = options?.audienceHash || 'ALL';
    const cacheKey = this.getClusterCacheKey(clusterId, epoch, requestedAudience);
    const cached = this.clusterKeyCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    const dist = await this.getClusterKeyDistribution(
      clusterId,
      options?.audienceHash ? { epoch, audienceHash: options.audienceHash } : epoch
    );
    if (!dist || !dist.encryptedKeyPackage) {
      throw new AamarvaError(`No cluster key package available for cluster "${clusterId}" at epoch ${epoch}.`, {
        code: 'CLUSTER_KEY_MISSING',
      });
    }

    let pkgObj: Record<string, unknown> | undefined;
    if (typeof dist.encryptedKeyPackage === 'object' && dist.encryptedKeyPackage !== null) {
      pkgObj = dist.encryptedKeyPackage as Record<string, unknown>;
    } else if (typeof dist.encryptedKeyPackage === 'string' && dist.encryptedKeyPackage.trim().startsWith('{')) {
      try {
        pkgObj = JSON.parse(dist.encryptedKeyPackage);
      } catch {
        pkgObj = undefined;
      }
    }

    const authAgentId = (this.http.getAgentId() || this.agentId || 'me').trim();
    const targetEpoch = dist.recipientKeyEpoch !== undefined ? Number(dist.recipientKeyEpoch) : undefined;
    const localKp = getLocalIdentityKeyPair(
      authAgentId,
      targetEpoch !== undefined ? targetEpoch : epoch > 1 ? epoch : undefined
    );

    let senderPubKey =
      options?.senderPublicKey || dist.senderPublicKey || (pkgObj?.senderPublicKey as any);
    const resolvedSenderId = dist.senderAgentId || (pkgObj?.senderAgentId as string | undefined);

    if (!senderPubKey && resolvedSenderId) {
      if (normalizeAgentId(resolvedSenderId) === normalizeAgentId(authAgentId)) {
        senderPubKey = localKp.publicKey;
      } else {
        try {
          const members = await this.getClusterMembers(clusterId);
          const match = members.find((m) => normalizeAgentId(m.agentId) === normalizeAgentId(resolvedSenderId));
          if (match?.publicKey) {
            senderPubKey = match.publicKey;
          }
        } catch {
          // fallback
        }
        if (!senderPubKey) {
          try {
            const pk = await this.getPeerKeyByAgent(resolvedSenderId);
            senderPubKey = (pk as any).publicKey || pk.peerE2eePublicKey || pk.peerIdentityKey;
          } catch {
            // fallback
          }
        }
        if (!senderPubKey) {
          try {
            const conns = await this.getConnections();
            const conn = conns.find((c) => normalizeAgentId(c.peerAgentId) === normalizeAgentId(resolvedSenderId));
            if (conn) {
              const pk = await this.getPeerKey(conn.connectionId);
              senderPubKey = pk.peerE2eePublicKey || pk.peerIdentityKey;
            }
          } catch {
            // fallback
          }
        }
      }
    }

    if (!senderPubKey) {
      throw new AamarvaError(
        `Unable to unwrap cluster key: missing sender public key for "${resolvedSenderId || 'unknown'}".`,
        { code: 'CLUSTER_KEY_UNWRAP_FAILED' }
      );
    }

    const resolvedAudience = String(dist.audienceHash || pkgObj?.audienceHash || requestedAudience || 'ALL');
    const resolvedExpectedFp =
      options?.expectedKeyFingerprint ||
      dist.keyFingerprint ||
      (typeof pkgObj?.keyFingerprint === 'string' ? pkgObj.keyFingerprint : undefined);
    const nonce = String(dist.nonce || (pkgObj?.iv as string) || (dist.wrappingParams as any)?.nonce || '');

    let clusterKey: Buffer;
    try {
      clusterKey = unwrapClusterKey(dist.encryptedKeyPackage, nonce, localKp.privateKey, senderPubKey, {
        clusterId,
        epoch,
        audienceHash: resolvedAudience,
        expectedKeyFingerprint: resolvedExpectedFp,
      });
    } catch (err: any) {
      if (dist.recipientKeyMismatch) {
        throw new AamarvaError(
          `Cluster key unwrapping failed due to recipient key mismatch (expected fingerprint: ${dist.recipientKeyFingerprint || 'unknown'}).`,
          { code: 'RECIPIENT_KEY_MISMATCH', cause: err }
        );
      }
      throw err;
    }

    const entry: CachedClusterKeyEntry = {
      key: clusterKey,
      keyFingerprint: resolvedExpectedFp || computeGroupKeyFingerprint(clusterKey),
      rosterHash: dist.rosterHash || (typeof pkgObj?.rosterHash === 'string' ? pkgObj.rosterHash : undefined),
      audienceHash: resolvedAudience,
      epoch,
    };

    this.clusterKeyCache.set(this.getClusterCacheKey(clusterId, epoch, resolvedAudience), entry);
    return entry;
  }

  /**
   * Retrieve and locally decrypt symmetric cluster key for the given epoch and audience scope.
   */
  public async getClusterKey(
    clusterId: string,
    epoch = 1,
    options?: { audienceHash?: string; senderPublicKey?: any; expectedKeyFingerprint?: string }
  ): Promise<Buffer> {
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
    let cluster: Cluster | undefined;
    try {
      cluster = await this.getCluster(clusterId);
    } catch {
      cluster = undefined;
    }

    let epoch = options.epoch || cluster?.epoch || cluster?.keyEpoch || 1;

    if (cluster?.rotationStatus && String(cluster.rotationStatus).startsWith('ROTATION_REQUIRED')) {
      if (options.autoRotate === false) {
        throw new AamarvaError(`Cluster key rotation required before sending: ${cluster.rotationStatus}`, {
          code: 'CLUSTER_ROTATION_REQUIRED',
        });
      }
      const rotated = await this.rotateClusterKey(clusterId, { currentEpoch: epoch });
      epoch = rotated.epoch || epoch + 1;
    }

    let clusterMembers: ClusterMember[] = [];
    try {
      clusterMembers = await this.getClusterMembers(clusterId);
    } catch {
      if (Array.isArray(cluster?.members)) {
        clusterMembers = cluster.members.map((m: any) => (typeof m === 'string' ? { agentId: m } : m));
      }
    }

    const masterId = await this.resolveMasterAgentId();
    const senderId = (this.http.getAgentId() || this.agentId || '').trim();

    const activeRosterIds = canonicalMemberSet([
      masterId,
      senderId,
      ...clusterMembers.map((m) => m.agentId),
      ...(options.recipients || []),
    ]);

    const targetedRaw =
      options.recipients && options.recipients.length > 0
        ? [masterId, senderId, ...options.recipients]
        : activeRosterIds;
    const recipientSet = new Set<string>();
    for (const r of targetedRaw) {
      if (r && r.trim()) {
        const norm = normalizeAgentId(r);
        if (!Array.from(recipientSet).some((existing) => normalizeAgentId(existing) === norm)) {
          recipientSet.add(r.trim());
        }
      }
    }
    const allRecipients = Array.from(recipientSet);

    const rosterHash = options.rosterHash || cluster?.rosterHash || computeRosterHash(activeRosterIds);
    const audienceHash =
      options.audienceHash || computeAudienceHash(allRecipients, activeRosterIds);

    let clusterKeyEntry: CachedClusterKeyEntry;
    try {
      clusterKeyEntry = await this.getClusterKeyEntry(clusterId, epoch, { audienceHash });
    } catch {
      try {
        const dist = await this.distributeClusterKey(clusterId, {
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
          /EPOCH_KEY_ALREADY_SEALED|ALREADY_SEALED|409/i.test(
            String(distErr?.code || '') + ' ' + String(distErr?.message || '')
          );
        if (isConflict) {
          clusterKeyEntry = await this.getClusterKeyEntry(clusterId, epoch, { audienceHash });
        } else {
          throw distErr;
        }
      }
    }

    const keyFingerprint =
      clusterKeyEntry.keyFingerprint || computeGroupKeyFingerprint(clusterKeyEntry.key);
    const enc = encryptClusterMessagePayload(
      plaintext,
      clusterKeyEntry.key,
      clusterId,
      epoch,
      audienceHash,
      senderId
    );

    const senderKp = getLocalIdentityKeyPair(senderId || 'me', epoch > 1 ? epoch : undefined);
    const signature = signClusterMessageV2(senderKp.privateKey, {
      clusterId,
      keyEpoch: epoch,
      senderAgentId: senderId,
      audienceHash,
      rosterHash,
      sequence: options.sequence ?? '',
      keyFingerprint,
      nonce: enc.nonce,
      ciphertext: enc.ciphertext,
    });

    const result = await this.sendClusterMessage(clusterId, {
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
   * Decrypt an encrypted cluster message using the cluster symmetric key (Workflow 2).
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
    const epoch = message.keyEpoch || 1;
    const version = message.version !== undefined ? message.version : 2;
    const audienceHash = message.audienceHash || 'ALL';
    const shouldVerify =
      options?.verifySignature === true ||
      (options?.verifySignature !== false && Boolean(options?.senderPublicKey && message.signature));

    let resolvedSenderPub = options?.senderPublicKey;
    if (shouldVerify && message.signature && message.rosterHash && message.keyFingerprint) {
      if (!resolvedSenderPub && message.senderAgentId) {
        const myAgentId = (this.http.getAgentId() || this.agentId || '').trim();
        if (myAgentId && normalizeAgentId(message.senderAgentId) === normalizeAgentId(myAgentId)) {
          resolvedSenderPub = exportPublicKeyJWK(getLocalIdentityKeyPair(myAgentId, epoch > 1 ? epoch : undefined).publicKey);
        } else {
          try {
            const members = await this.getClusterMembers(clusterId);
            const match = members.find((m) => normalizeAgentId(m.agentId) === normalizeAgentId(message.senderAgentId));
            resolvedSenderPub = match?.publicKey || match?.identityKey;
          } catch {
            // fallback below
          }
          if (!resolvedSenderPub) {
            try {
              const pk = await this.getPeerKeyByAgent(message.senderAgentId);
              resolvedSenderPub = pk.publicKey;
            } catch {
              // fallback handled below
            }
          }
        }
      }
      if (!resolvedSenderPub) {
        throw new AamarvaError('Unable to verify cluster message signature: sender public key unavailable.', {
          code: 'CLUSTER_SIGNATURE_INVALID',
        });
      }
      const ok = verifyClusterMessageSignatureV2(
        resolvedSenderPub,
        {
          clusterId,
          keyEpoch: epoch,
          senderAgentId: message.senderAgentId || '',
          audienceHash,
          rosterHash: message.rosterHash,
          sequence: message.sequence ?? '',
          keyFingerprint: message.keyFingerprint,
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
    }

    const clusterKey = await this.getClusterKey(clusterId, epoch, {
      audienceHash,
      senderPublicKey: resolvedSenderPub || options?.senderPublicKey,
      expectedKeyFingerprint: message.keyFingerprint,
    });
    return decryptClusterMessagePayload(
      message.ciphertext,
      message.nonce,
      clusterKey,
      clusterId,
      epoch,
      version,
      audienceHash,
      message.senderAgentId
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
    options: { arguments?: Record<string, unknown> } = {}
  ): Promise<FloorExecutionAuthorization> {
    if (!invocationId?.trim()) {
      throw new AamarvaValidationError('invocationId is required.');
    }

    const expectedInvocationId = invocationId.trim();
    const submittedArgs = options.arguments || {};

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

    if (!response || typeof response !== 'object') {
      throw new AamarvaError('FLOOR authorization failed: response payload is not an object.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    if (response.success === false) {
      throw new AamarvaError('FLOOR execution authorization was rejected by platform.', {
        code: 'FLOOR_ACCESS_DENIED',
      });
    }

    const data = response.data && typeof response.data === 'object' ? (response.data as any) : null;
    if (!data || Array.isArray(data)) {
      throw new AamarvaError('FLOOR authorization failed: malformed authorization payload.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    const rawStatus = String(data.status || (response as any).status || '').trim().toLowerCase();

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

    const returnedInvocationId = typeof data.invocationId === 'string' ? data.invocationId.trim() : '';
    if (!returnedInvocationId || returnedInvocationId !== expectedInvocationId) {
      throw new AamarvaError('FLOOR authorization failed: invocation ID missing or mismatched in platform response.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    const returnedToolId =
      typeof data.toolId === 'string' && data.toolId.trim()
        ? data.toolId.trim()
        : data.tool && typeof data.tool.id === 'string' && data.tool.id.trim()
        ? data.tool.id.trim()
        : '';
    if (!returnedToolId) {
      throw new AamarvaError('FLOOR authorization failed: authorized toolId is missing in platform response.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    const serverUrl = data.serverUrl || data.mcpServerUrl || data.server?.url;
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

    if (!data.grant || typeof data.grant !== 'object' || Array.isArray(data.grant)) {
      throw new AamarvaError('FLOOR authorization failed: grant details missing in response.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    const grantStatus = typeof data.grant.status === 'string' ? data.grant.status.trim().toLowerCase() : '';
    if (grantStatus && ['denied', 'rejected', 'revoked', 'expired', 'inactive'].includes(grantStatus)) {
      throw new AamarvaError(`FLOOR authorization denied: grant status is '${grantStatus}'.`, {
        code: 'FLOOR_ACCESS_DENIED',
      });
    }

    const expiresAtRaw = data.grant.expiresAt || data.expiresAt;
    if (typeof expiresAtRaw === 'string' && expiresAtRaw.trim()) {
      const expiresMs = Date.parse(expiresAtRaw.trim());
      if (Number.isNaN(expiresMs) || expiresMs <= Date.now()) {
        throw new AamarvaError('FLOOR authorization denied: execution grant has expired.', {
          code: 'FLOOR_ACCESS_DENIED',
        });
      }
    }

    const expectedAgentId = (this.http.getTargetAgentId() || this.http.getAgentId() || this.agentId || '').trim();
    const returnedAgentId = String(
      data.agentId || data.grant.agentId || data.verificationInfo?.agentId || ''
    ).trim();
    if (expectedAgentId && returnedAgentId && returnedAgentId.toUpperCase() !== expectedAgentId.toUpperCase()) {
      throw new AamarvaError('FLOOR authorization failed: agent fleet context mismatch in authorization response.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }

    const approvedArgs =
      data.approvedArguments && typeof data.approvedArguments === 'object' && !Array.isArray(data.approvedArguments)
        ? (data.approvedArguments as Record<string, unknown>)
        : data.grant.approvedArguments && typeof data.grant.approvedArguments === 'object' && !Array.isArray(data.grant.approvedArguments)
        ? (data.grant.approvedArguments as Record<string, unknown>)
        : undefined;
    if (approvedArgs) {
      if (JSON.stringify(approvedArgs) !== JSON.stringify(submittedArgs)) {
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
      ...(typeof expiresAtRaw === 'string' ? { expiresAt: expiresAtRaw } : {}),
      ...(approvedArgs ? { approvedArguments: approvedArgs } : {}),
      auth: data.auth || data.authentication || data.authConfig,
      grant: data.grant,
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

    const cleanToolId = toolId.trim();
    const scopeKey = this.getFloorScopeKey(cleanToolId);
    const shouldWait = Boolean(
      options.waitForApproval || (options.pollTimeoutMs !== undefined && options.pollTimeoutMs > 0)
    );

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
          this.pendingFloorRequests.delete(scopeKey);
          invocationId = approvedStatus.invocationId;
        } else {
          const statusRes = await this.getFloorRequestStatus(existingRequestId);
          const reqStatus = (statusRes.status || 'pending').trim().toLowerCase();
          if (reqStatus === 'approved') {
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
    const authDetails = await this.obtainFloorExecutionAuthorization(invocationId, { arguments: args });

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

    // Stage 5: External MCP tool execution over verified connection
    const mcpResult = await invokeExternalMcpTool({
      serverUrl: authDetails.serverUrl,
      toolId: cleanToolId,
      args,
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


