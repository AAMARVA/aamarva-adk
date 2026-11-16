/**
 * Core type definitions for the AAMARVA Fleet-Only Agent Development Kit (ADK)
 */

export type AgentLifecycleState =
  | 'unauthenticated'
  | 'authenticated'
  | 'effective_identity_resolved'
  | 'local_keys_loaded'
  | 'keys_registered'
  | 'verified'
  | 'e2ee_ready';

export interface Agent {
  agentId: string;
  name: string;
  bio?: string;
  email?: string;
  status?: string;
  avatar?: string;
  avatarUrl?: string;
  role?: string;
  isMaster?: boolean;
  isSlave?: boolean;
  verificationStatus?: string;
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
  peerAccountId?: string;
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
  agentId?: string;
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
  ticket?: string;
  expiresAt?: string;
  streamUrl?: string;
  status?: string;
  requestId?: string;
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
  /** Explicit opt-in to allow insecure http:// MCP server URLs on localhost/127.0.0.1/::1 (default: false) */
  allowInsecureHttpForLocalhost?: boolean;
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
  keyVersion?: number;
  keyEpoch?: number;
}

export interface PeerEpochKeyEntry {
  keyEpoch?: number;
  keyVersion?: number;
  epoch?: number;
  publicKey?: ECJWK | string;
  e2eePublicKey?: ECJWK | string;
  peerE2eePublicKey?: ECJWK | string;
  fingerprint?: string;
  keyFingerprint?: string;
  peerKeyFingerprint?: string;
  signature?: string;
  keySignature?: string;
  peerKeySignature?: string;
  identityKey?: ECJWK | string;
  peerIdentityKey?: ECJWK | string;
  [key: string]: unknown;
}

export interface PeerKeyResponse {
  connectionId?: string;
  peerAccountId?: string;
  peerAgentId?: string;
  peerE2eePublicKey?: ECJWK | string;
  peerKeyFingerprint?: string;
  peerIdentityKey?: ECJWK | string;
  peerKeySignature?: string;
  peerKeyEpoch?: number;
  peerEpochHistory?: PeerEpochKeyEntry[];
  peerEpochKeys?: PeerEpochKeyEntry[] | Record<string, PeerEpochKeyEntry>;
  publicKey?: ECJWK | string;
  fingerprint?: string;
  identityKey?: ECJWK | string;
  signature?: string;
  keyEpoch?: number;
  keyVersion?: number;
  epochHistory?: PeerEpochKeyEntry[];
  agentId?: string;
  [key: string]: unknown;
}

export interface PeerKeyInfo {
  publicKey: ECJWK | string;
  fingerprint: string;
  identityKey?: ECJWK | string;
  signature?: string;
  keyEpoch: number;
  epochHistory?: PeerEpochKeyEntry[];
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
  epoch?: number;
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
  actorAgentName?: string;
  targetAgentId?: string;
  category?: string;
  outcome?: string;
  summary: string;
  details?: Record<string, unknown>;
  timestamp: string;
}

export interface WatchtowerStreamTicket {
  ticket: string;
  streamUrl: string;
  expiresAt: string;
}

export interface WatchtowerStreamEvent {
  id?: string;
  event: string;
  data: unknown;
  rawData?: string;
  raw?: string;
}

// =============================================================================
// FLOOR MCP Tool Governance
// =============================================================================

export interface FloorTool {
  id: string;
  name: string;
  description: string;
  serverId?: string;
  serverName?: string;
  serverUrl?: string;
  authType?: string;
  authHeaderName?: string;
  inputSchema: {
    type?: string;
    properties?: Record<string, unknown>;
    required?: string[];
    [key: string]: unknown;
  };
  accessStatus: 'authorized' | 'granted' | 'hitl' | 'pending' | 'required' | 'unassigned' | 'revoked' | string;
}

export interface FloorToolPolicy {
  toolId: string;
  accessStatus?: string;
  policy?: string;
  requiresApproval?: boolean;
  serverId?: string;
  serverUrl?: string;
  authType?: string;
  [key: string]: unknown;
}

export interface FloorToolInvokeOptions {
  arguments: Record<string, unknown>;
  reason?: string;
  requestType?: 'execute' | 'access' | 'access_request' | string;
}

export interface FloorToolInvokeResult {
  status: 'pending' | 'accepted' | 'completed' | 'executed' | 'approved' | string;
  requestId?: string;
  invocationId?: string;
  toolId?: string;
  result?: unknown;
  message?: string;
  serverUrl?: string;
}

export interface FloorInvocationResponse {
  invocationId: string;
  requestId?: string;
  toolId?: string;
  status: 'pending' | 'accepted' | 'approved' | 'rejected' | 'denied' | string;
  result?: unknown;
  message?: string;
  [key: string]: unknown;
}

export interface FloorAuthConfig {
  authType?: 'none' | 'bearer' | 'api_key' | 'apiKey' | 'custom_header' | 'header' | string;
  type?: string;
  authHeaderName?: string;
  headerName?: string;
  headerValue?: string;
  token?: string;
  apiKey?: string;
  headers?: Record<string, string>;
  [key: string]: unknown;
}

export interface FloorExecutionAuthorization {
  invocationId: string;
  toolId: string;
  status: 'approved' | string;
  serverUrl: string;
  authConfig?: FloorAuthConfig;
  auth?: FloorAuthConfig;
  verificationInfo?: {
    verified?: boolean;
    toolId?: string;
    agentId?: string;
    [key: string]: unknown;
  };
  grantToken?: string;
  accessToken?: string;
  scope?: string;
  expiresAt?: string;
  approvedArguments?: Record<string, unknown>;
  tool?: { id?: string; name?: string; [key: string]: unknown };
  grant?: {
    id?: string;
    grantId?: string;
    agentId?: string;
    toolId?: string;
    status?: string;
    expiresAt?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface FloorAccessRequestStatus {
  requestId: string;
  status: 'pending' | 'accepted' | 'approved' | 'rejected' | 'denied' | 'revoked' | 'expired' | string;
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

export interface AgentE2eeKeyResponse {
  agentId?: string;
  publicKey?: ECJWK | string;
  fingerprint?: string;
  identityKey?: ECJWK | string;
  signature?: string;
  hasIdentityBinding?: boolean;
  keyVersion?: number;
  keyEpoch?: number;
  allowRotation?: boolean;
  epochHistory?: PeerEpochKeyEntry[];
  [key: string]: unknown;
}

export interface ClusterKeyDistributionResponse {
  clusterId?: string;
  epoch?: number;
  keyFingerprint?: string;
  senderAgentId?: string;
  senderPublicKey?: ECJWK | string;
  recipientAgentId?: string;
  recipientKeyFingerprint?: string;
  wrappingParams?: Record<string, unknown>;
  encryptedKeyPackage?: string;
  nonce?: string;
  [key: string]: unknown;
}
