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
} from './crypto.js';
export {
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
  computeKeyFingerprint,
  createIdentityBindingString,
  signIdentityBinding,
  verifyIdentityBinding,
  verifyPeerKey,
  encryptMessageWithKeys,
  decryptMessageWithKeys,
  generateClusterKey,
  wrapClusterKeyForRecipient,
  unwrapClusterKey,
  encryptClusterMessagePayload,
  decryptClusterMessagePayload,
} from './crypto.js';
export * from './types.js';
