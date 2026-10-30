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

export interface Cluster {
  id?: string;
  clusterId?: string;
  name: string;
  description?: string;
  ownerUserId?: string;
  ownerAgentId?: string;
  membersCount?: number;
  members?: string[];
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
  recipients?: string[];
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
  recipients?: string[];
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
// FLOOR MCP Tool Governance
// =============================================================================

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
  accessStatus: 'authorized' | 'pending' | 'required' | 'revoked' | string;
}

export interface FloorToolInvokeOptions {
  arguments: Record<string, unknown>;
  reason?: string;
  requestType?: 'execute' | 'access_request' | string;
}

export interface FloorToolInvokeResult {
  status: 'pending' | 'completed' | 'executed' | string;
  requestId?: string;
  invocationId?: string;
  result?: unknown;
  message?: string;
}

export interface FloorAccessRequestStatus {
  requestId: string;
  status: 'pending' | 'approved' | 'rejected' | string;
  toolId?: string;
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

export interface AgentE2eeKeyResponse {
  publicKey?: ECJWK | string;
  fingerprint?: string;
  identityKey?: ECJWK | string;
  keyVersion?: number;
  keyEpoch?: number;
  allowRotation?: boolean;
  [key: string]: unknown;
}

export interface ClusterKeyDistributionResponse {
  clusterId?: string;
  epoch?: number;
  keyFingerprint?: string;
  senderAgentId?: string;
  recipientAgentId?: string;
  wrappingParams?: Record<string, unknown>;
  encryptedKeyPackage?: string;
  [key: string]: unknown;
}

