/**
 * AAMARVA Agent Development Kit (ADK)
 * Fleet-Only Sovereign Agent Infrastructure SDK
 */

export { Aamarva } from './client.js';
export { AamarvaConnection } from './connection.js';
export { HttpClient } from './http.js';
export { AamarvaMcpServer, createAamarvaMcpServer, type McpToolDefinition } from './integrations/mcp.js';
export {
  AamarvaError,
  AamarvaAuthError,
  AamarvaForbiddenError,
  AamarvaNotFoundError,
  AamarvaConflictError,
  AamarvaRateLimitError,
  AamarvaValidationError,
  AamarvaTimeoutError,
  AamarvaNetworkError,
  AamarvaServerError,
  normalizeError,
} from './errors.js';
export {
  normalizeAgent,
  normalizeConnection,
  normalizeMessage,
  normalizeCluster,
  normalizeFloorTool,
  normalizeFloorRequestStatus,
  normalizeWatchtowerActivity,
} from './normalize.js';


export { createMockFetch, createMockDataStore } from './mock.js';
export { runCli } from './cli.js';
export type {
  EncryptedEnvelope,
  KeyStore,
  ClusterSigningPayloadParams,
  WrapClusterKeyOptions,
  UnwrapClusterKeyOptions,
} from './crypto.js';
export {
  WORKFLOW_HKDF_SALT,
  InMemoryKeyStore,
  FileSystemKeyStore,
  setKeyStore,
  getKeyStore,
  resetLocalIdentityKeyPair,
  generateECKeyPair,
  getLocalIdentityKeyPair,
  getLocalPublicKeyPem,
  exportPublicKeyJWK,
  importPublicKey,
  normalizeAgentId,
  canonicalMemberSet,
  computeKeyFingerprint,
  computeGroupKeyFingerprint,
  computeRosterHash,
  computeAudienceHash,
  createIdentityBindingString,
  signIdentityBinding,
  verifyIdentityBinding,
  verifyPeerKey,
  deriveConnectionAesKey,
  createDirectMessageAadV1,
  encryptMessageWithKeys,
  decryptMessageWithKeys,
  generateClusterKey,
  createClusterWrapAadV2,
  createClusterMessageAadV2,
  createClusterSigningPayloadV2,
  signClusterMessageV2,
  verifyClusterMessageSignatureV2,
  wrapClusterKeyForRecipient,
  unwrapClusterKey,
  encryptClusterMessagePayload,
  decryptClusterMessagePayload,
} from './crypto.js';
export * from './types.js';
