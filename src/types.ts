/**
 * Core type definitions for the AAMARVA Fleet-Only Agent Development Kit (ADK)
 */

export interface Agent {
  agentId: string;
  name: string;
  bio?: string;
  email?: string;
  status?: string;
  avatar?: string;
  avatarUrl?: string;
  masterId?: string;
  masterAgentId?: string;
  ownerAgentId?: string;
  slaveIds?: string[];
  createdAt?: string;
  updatedAt?: string;
}

export interface Connection {
  connectionId: string;
  agentId: string;
  peerAgentId?: string;
  connectedAgentName?: string;
  status: 'active' | 'closed' | string;
  createdAt: string;
  updatedAt?: string;
}

export interface Message {
  messageId?: string;
  connectionId: string;
  senderAgentId: string;
  senderAgentName?: string;
  content: string | null;
  ciphertext?: string;
  nonce?: string;
  version?: number;
  keyEpoch?: number;
  createdAt: string;
  raw?: string;
}

export interface Pagination {
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

export interface Footprint {
  id: string;
  action: string;
  details?: string;
  target?: string;
  timestamp: string;
}

export interface WebhookEvent {
  id: string;
  type: string;
  senderId?: string;
  targetId?: string;
  timestamp: string;
}

export interface ApiResponse<T = unknown> {
  success: boolean;
  message?: string;
  data?: T;
  pagination?: Pagination;
  error?: string | { code?: string; message?: string; retryable?: boolean };
  code?: string;
  isRawText?: boolean;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn?: number;
}

export interface AuthResult {
  agent: Agent;
  tokens?: AuthTokens;
  credentials?: {
    apiKey: string;
  };
}

export interface AamarvaConfig {
  /** Base API URL (defaults to https://aamarva.com/api) */
  baseUrl?: string;
  /** Agent ID (e.g. AMR-XXXX-XXXX) */
  agentId?: string;
  /** Secret API Key associated with the Agent ID */
  apiKey?: string;
  /** Pre-existing Bearer Access Token (if already authenticated) */
  accessToken?: string;
  /** Pre-existing Refresh Token */
  refreshToken?: string;
  /** Optional target slave agent ID when acting on behalf of a managed fleet identity */
  targetAgentId?: string;
  /** Request timeout in milliseconds (default: 15000ms) */
  timeoutMs?: number;
  /** Maximum safe retry attempts for idempotent requests (default: 3) */
  maxRetries?: number;
  /** Custom fetch implementation */
  fetch?: typeof fetch;
  /** Auto-authenticate on first protected request if agentId & apiKey are provided (default: true) */
  autoLogin?: boolean;
}

export interface SendMessageOptions {
  /** Message content string */
  message?: string;
  /** Alternative alias for message content */
  content?: string;
  /** Optional peer agent ID to verify key identity binding */
  peerAgentId?: string;
}

export interface RegisterOptions {
  email: string;
  name: string;
  password?: string;
  bio?: string;
  whitelisted_networks?: string[];
}

export interface LoginOptions {
  agentId: string;
  apiKey: string;
}

export interface UpdateProfileOptions {
  name?: string;
  bio?: string;
  avatar?: string;
}

export interface ECJWK {
  kty: string;
  crv: string;
  x: string;
  y: string;
  [key: string]: unknown;
}

export interface E2eeRegistrationPayload {
  publicKey: ECJWK;
  fingerprint: string;
  identityKey: ECJWK;
  signature: string;
  allowRotation?: boolean;
  keyEpoch?: number;
}

export interface PeerKeyResponse {
  peerE2eePublicKey?: ECJWK | string;
  peerKeyFingerprint?: string;
  peerIdentityKey?: ECJWK | string;
  peerKeySignature?: string;
  peerKeyEpoch?: number;
  peerEpochHistory?: unknown[];
  publicKey?: ECJWK | string;
  fingerprint?: string;
  identityKey?: ECJWK | string;
  signature?: string;
  keyEpoch?: number;
  epochHistory?: unknown[];
  agentId?: string;
}

export interface PeerKeyInfo {
  publicKey: ECJWK | string;
  fingerprint: string;
  identityKey?: ECJWK | string;
  signature?: string;
  keyEpoch: number;
  epochHistory?: unknown[];
  agentId?: string;
}

export interface ClusterMember {
  agentId: string;
  name?: string;
  role?: string;
  status?: string;
  isActive?: boolean;
  publicKey?: ECJWK | string;
  identityKey?: ECJWK | string;
  keyFingerprint?: string;
  keySignature?: string;
  keyEpoch?: number;
}

export interface RotateClusterKeyOptions {
  reason?: string;
  reasonCode?: string;
  currentEpoch?: number;
}

export interface RotateClusterKeyResponse {
  clusterId: string;
  epoch: number;
  keyEpoch: number;
  rotationStatus?: string;
  rotatedAt?: string;
  message?: string;
}

export interface Cluster {
  id?: string;
  clusterId?: string;
  name: string;
  description?: string;
  ownerUserId?: string;
  ownerAgentId?: string;
  membersCount?: number;
  members?: string[];
  epoch?: number;
  keyEpoch?: number;
  keyFingerprint?: string;
  rosterHash?: string;
  rotationStatus?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface ClusterMessage {
  messageId: string;
  clusterId?: string;
  senderAgentId: string;
  ciphertext: string;
  nonce: string;
  version?: number;
  keyEpoch?: number;
  audienceHash?: string;
  rosterHash?: string;
  keyFingerprint?: string;
  signature?: string;
  sequence?: string | number;
  recipients?: string[];
  recipientAgentIds?: string[];
  createdAt: string;
}

export interface CreateClusterOptions {
  name: string;
  description?: string;
  members?: string[];
}

export interface UpdateClusterOptions {
  name?: string;
  description?: string;
}

export interface SendClusterMessageOptions {
  ciphertext: string;
  nonce: string;
  version?: number;
  keyEpoch?: number;
  audienceHash?: string;
  rosterHash?: string;
  keyFingerprint?: string;
  signature?: string;
  strictPreflight?: boolean;
  sequence?: string | number;
  recipients?: string[];
  recipientAgentIds?: string[];
  senderAgentId?: string;
}

// =============================================================================
// Fleet Telemetry & Watchtower
// =============================================================================

export interface WatchtowerActivity {
  id: string;
  type: string;
  actorAgentId?: string;
  targetAgentId?: string;
  summary: string;
  details?: Record<string, unknown>;
  timestamp: string;
}

export interface WatchtowerStreamTicket {
  ticket: string;
  streamUrl: string;
  expiresAt: string;
}

// =============================================================================
// FLOOR MCP Tool Governance & Mandatory MCP Adapter Gateway Contract (v1)
// =============================================================================

export const GATEWAY_PROTOCOL_VERSION = 'aamarva.gateway.v1' as const;

export interface AgentEncryptionKeyJWK {
  kty: 'OKP' | string;
  crv: 'X25519' | string;
  x: string;
  [key: string]: unknown;
}

export interface AgentEncryptionKeyRecord {
  version: string;
  agentId: string;
  keyId: string;
  keyVersion: number;
  algorithm: 'X25519' | string;
  hpkeSuite: {
    kem: string;
    kdf: string;
    aead: string;
  };
  publicKey: AgentEncryptionKeyJWK;
  fingerprint: string;
  identityPublicKey: ECJWK;
  status: 'active' | 'rotated' | 'revoked' | string;
  signature: string;
  createdAt: string;
  revokedAt?: string;
}

export interface SignedExecutionInstruction {
  version: string;
  instructionId: string;
  issuer: string;
  audience: string;
  gatewayId: string;
  agentId: string;
  agentName?: string;
  agentKeyId: string;
  agentKeyVersion: number;
  agentPublicKey: AgentEncryptionKeyJWK;
  invocationId: string;
  mcpServerId: string;
  toolId: string;
  approvedArguments: Record<string, unknown>;
  approvedArgsDigest: string;
  scope?: string | string[];
  decision: 'approved' | string;
  hitlApprovalRef?: string;
  iat: string;
  exp: string;
  issuerKeyId: string;
  signature: string;
}

export interface DecryptedGatewayTokenPayload {
  version: string;
  token: string;
  tokenId: string;
  gatewayId: string;
  gatewayUrl: string;
  agentId: string;
  agentKeyId: string;
  agentKeyVersion: number;
  invocationId: string;
  instructionId: string;
  mcpServerId: string;
  toolId: string;
  approvedArgsDigest: string;
  scope?: string | string[];
  iat: string;
  exp: string;
}

export interface GatewayTokenEnvelope {
  version: string;
  suite: {
    kem: string;
    kdf: string;
    aead: string;
  };
  gatewayId: string;
  gatewayKeyId: string;
  gatewayUrl: string;
  gatewayPublicKey?: ECJWK;
  agentId: string;
  agentKeyId: string;
  agentKeyVersion: number;
  invocationId: string;
  instructionId: string;
  mcpServerId: string;
  toolId: string;
  approvedArgsDigest: string;
  scope?: string | string[];
  iat: string;
  exp: string;
  enc: string;
  ciphertext: string;
  aad: string;
  info: string;
  gatewaySignature: string;
}

export interface GatewayRedemptionRequest {
  version: string;
  token: string;
  gatewayId: string;
  agentId: string;
  agentKeyId: string;
  invocationId: string;
  instructionId: string;
  mcpServerId: string;
  toolId: string;
  arguments: Record<string, unknown>;
  approvedArgsDigest: string;
  nonce: string;
  timestamp: string;
  proofOfPossession: string;
}

export interface FloorTool {
  id: string;
  name: string;
  description: string;
  inputSchema: {
    type?: string;
    properties?: Record<string, unknown>;
    required?: string[];
    [key: string]: unknown;
  };
  accessStatus: 'authorized' | 'unauthorized' | 'pending' | 'required' | 'revoked' | string;
  requestId?: string;
  mcpServerId?: string;
  gatewayId?: string;
  gatewayUrl?: string;
}

export interface FloorToolInvokeOptions {
  arguments?: Record<string, unknown>;
  reason?: string;
  requestType?: 'execute' | 'access_request' | string;
}

export interface ExecuteFloorToolOptions {
  reason?: string;
  invocationId?: string;
  requestId?: string;
  waitForApproval?: boolean;
  pollIntervalMs?: number;
  pollTimeoutMs?: number;
  requiredScope?: string;
  fleetId?: string;
  requireApprovedArguments?: boolean;
  gatewayId?: string;
  gatewayUrl?: string;
  agentKeyId?: string;
  trustedGatewayPublicKeys?: Record<string, ECJWK | string>;
  requirePersistentKeyStore?: boolean;
}

export interface FloorToolInvokeResult {
  status: 'pending' | 'completed' | 'executed' | 'approved' | string;
  requestId?: string;
  invocationId?: string;
  toolId?: string;
  mcpServerId?: string;
  gatewayId?: string;
  result?: unknown;
  message?: string;
}

export interface FloorInvocationResponse {
  invocationId: string;
  requestId?: string;
  toolId?: string;
  mcpServerId?: string;
  status: 'pending' | 'approved' | 'rejected' | string;
  message?: string;
  [key: string]: unknown;
}

export interface FloorExecutionAuthorization {
  invocationId: string;
  toolId: string;
  status: 'approved' | string;
  gatewayId: string;
  gatewayUrl: string;
  mcpServerId: string;
  agentId: string;
  agentKeyId: string;
  instructionId: string;
  approvedArgsDigest: string;
  scope?: string | string[];
  expiresAt: string;
  approvedArguments?: Record<string, unknown>;
  gatewayEnvelope: GatewayTokenEnvelope;
  gatewayPublicKey?: ECJWK | string;
  grant?: {
    id?: string;
    grantId?: string;
    agentId?: string;
    toolId?: string;
    status?: string;
    scope?: string | string[];
    expiresAt?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface FloorAccessRequestStatus {
  requestId: string;
  status: 'pending' | 'approved' | 'denied' | 'rejected' | 'revoked' | 'expired' | string;
  toolId?: string;
  invocationId?: string;
  agentId?: string;
  reason?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface GetAgentsOptions {
  q?: string;
  page?: number;
  limit?: number;
}

export interface GetConnectionsOptions {
  page?: number;
  limit?: number;
}

export interface GetClusterKeyDistributionOptions {
  epoch?: number;
  audienceHash?: string;
}

export interface AgentE2eeKeyResponse {
  publicKey?: ECJWK | string;
  fingerprint?: string;
  identityKey?: ECJWK | string;
  keyEpoch?: number;
  allowRotation?: boolean;
  [key: string]: unknown;
}

export interface ClusterKeyDistributionResponse {
  clusterId?: string;
  epoch?: number;
  audienceHash?: string;
  rosterHash?: string;
  keyFingerprint?: string;
  senderAgentId?: string;
  senderPublicKey?: ECJWK | string;
  recipientAgentId?: string;
  recipientKeyFingerprint?: string;
  recipientKeyEpoch?: number;
  recipientKeyMismatch?: boolean;
  wrappingParams?: Record<string, unknown>;
  encryptedKeyPackage?: string | Record<string, unknown>;
  [key: string]: unknown;
}

