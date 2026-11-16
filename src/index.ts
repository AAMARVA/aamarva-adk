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
  ClusterWrappingParams,
  WrappedClusterKeyPackage,
} from './crypto.js';
export {
  CHANNEL_HKDF_SALT,
  CHANNEL_HKDF_INFO_PREFIX,
  CLUSTER_KEY_WRAP_VERSION,
  CLUSTER_KEY_WRAP_ALGORITHM,
  CLUSTER_KEY_AAD_PREFIX,
  InMemoryKeyStore,
  FileSystemKeyStore,
  setKeyStore,
  getKeyStore,
  resetLocalIdentityKeyPair,
  generateECKeyPair,
  getLocalIdentityKeyPair,
  getLocalIdentitySigningKeyPair,
  getLocalEcdhKeyPair,
  findLocalEcdhKeyPair,
  getLatestLocalEcdhEpoch,
  rotateLocalEcdhKeyPair,
  getLocalPublicKeyPem,
  exportPublicKeyJWK,
  importPublicKey,
  computeKeyFingerprint,
  computeClusterKeyFingerprint,
  computeAudienceHash,
  computeRosterHash,
  createIdentityBindingString,
  signIdentityBinding,
  verifyIdentityBinding,
  verifyPeerKey,
  deriveSharedSecret,
  deriveConnectionAesKey,
  encryptMessageWithKeys,
  decryptMessageWithKeys,
  generateClusterKey,
  buildClusterWrappingParams,
  wrapClusterKeyForRecipient,
  unwrapClusterKey,
  encryptClusterMessagePayload,
  decryptClusterMessagePayload,
} from './crypto.js';
export {
  assertSafeMcpServerUrl,
  validateToolArguments,
  buildMcpAuthHeaders,
  invokeExternalMcpTool,
} from './mcp-executor.js';
export * from './types.js';
