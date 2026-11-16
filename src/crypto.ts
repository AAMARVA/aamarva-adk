/**
 * Local End-to-End Encryption (E2EE) Module for AAMARVA ADK.
 * Architecture:
 * - Identity Keypair (ECDSA P-256): Signs agent key bindings (AAMARVA-KEY-BINDING:v1:<AGENT_ID>:<FINGERPRINT>)
 * - Transport Keypair (ECDH P-256, Epoch-scoped): Derives shared secrets per epoch
 * - Channel Key Derivation: HKDF-SHA256 (salt="aamarva-e2ee-channel-v1", info="aamarva-channel:<contextId>") -> AES-256-GCM
 * - Cluster Key Wrapping: AAMARVA_CLUSTER_KEY_WRAP_V1 (ECDH-ES+HKDF-256+A256GCM)
 */
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { AamarvaError } from './errors.js';
import type { ECJWK } from './types.js';

export type { ECJWK };

export const CHANNEL_HKDF_SALT = 'aamarva-e2ee-channel-v1';
export const CHANNEL_HKDF_INFO_PREFIX = 'aamarva-channel:';
export const CLUSTER_KEY_WRAP_VERSION = 'AAMARVA_CLUSTER_KEY_WRAP_V1';
export const CLUSTER_KEY_WRAP_ALGORITHM = 'ECDH-ES+HKDF-256+A256GCM';
export const CLUSTER_KEY_AAD_PREFIX = 'aamarva-cluster-group-key:';

export interface EncryptedEnvelope {
  ciphertext: string;
  nonce: string;
  version: number;
  keyEpoch: number;
}

export interface ClusterWrappingParams {
  algorithm: string;
  curve: string;
  hkdfHash: string;
  hkdfSalt: string;
  hkdfInfo: string;
  aad: string;
}

export interface WrappedClusterKeyPackage {
  version: string;
  clusterId: string;
  epoch: number;
  iv: string;
  ciphertext: string;
  senderPublicKey: ECJWK;
  wrappingParams: ClusterWrappingParams;
}

/**
 * KeyStore abstraction for managing local agent private keys.
 * Implementations must ensure private keys are securely kept and never leaked.
 */
export interface KeyStore {
  /**
   * Retrieve the PEM-encoded private key for an agent identity or key slot.
   * Returns null if no key has been stored yet.
   */
  loadPrivateKey(identityId?: string): string | null;

  /**
   * Persist the PEM-encoded private key for an agent identity or key slot.
   * Private key material must never be transmitted or logged.
   */
  savePrivateKey(privateKeyPem: string, identityId?: string, options?: { overwrite?: boolean }): void;

  /**
   * Optional list of stored key slot IDs for epoch discovery.
   */
  listKeyIds?(): string[];
}

function sanitizeKeySlotId(rawId: string): string {
  if (!rawId || typeof rawId !== 'string') {
    throw new AamarvaError('Key identifier must be a non-empty string.', { code: 'IDENTITY_KEY_INVALID' });
  }
  const trimmed = rawId.trim();
  if (!trimmed || trimmed === '.' || trimmed === '..' || trimmed.includes('/') || trimmed.includes('\\') || trimmed.includes('\0') || trimmed.includes('..')) {
    throw new AamarvaError(`Unsafe key identifier rejected: "${rawId}".`, { code: 'IDENTITY_KEY_INVALID' });
  }
  const safe = trimmed.replace(/[^A-Za-z0-9._:-]/g, '_');
  if (!safe || safe === '.' || safe === '..') {
    throw new AamarvaError(`Invalid key identifier: "${rawId}".`, { code: 'IDENTITY_KEY_INVALID' });
  }
  return safe;
}

function validatePositiveEpoch(epoch: unknown, code = 'MESSAGE_INVALID_ENVELOPE'): number {
  if (typeof epoch !== 'number' || !Number.isInteger(epoch) || epoch < 1) {
    throw new AamarvaError(`Invalid keyEpoch "${String(epoch)}": must be a positive integer >= 1.`, { code });
  }
  return epoch;
}

function decodeStrictBase64(value: unknown, fieldName: string, errorCode: string): Buffer {
  if (typeof value !== 'string' || !value.trim()) {
    throw new AamarvaError(`Missing or empty base64 field "${fieldName}".`, { code: errorCode });
  }
  const trimmed = value.trim();
  if (trimmed.length % 4 === 1 || !/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) {
    throw new AamarvaError(`Malformed base64 encoding for "${fieldName}".`, { code: errorCode });
  }
  const buf = Buffer.from(trimmed, 'base64');
  if (buf.length === 0) {
    throw new AamarvaError(`Empty decoded buffer for "${fieldName}".`, { code: errorCode });
  }
  return buf;
}

/**
 * In-memory KeyStore for ephemeral testing or explicit opt-in.
 */
export class InMemoryKeyStore implements KeyStore {
  private keys = new Map<string, string>();

  public loadPrivateKey(identityId = 'default'): string | null {
    const safeId = sanitizeKeySlotId(identityId);
    return this.keys.get(safeId) || null;
  }

  public savePrivateKey(privateKeyPem: string, identityId = 'default', options?: { overwrite?: boolean }): void {
    const safeId = sanitizeKeySlotId(identityId);
    if (this.keys.has(safeId) && !options?.overwrite) {
      return;
    }
    this.keys.set(safeId, privateKeyPem);
  }

  public listKeyIds(): string[] {
    return Array.from(this.keys.keys());
  }
}

/**
 * FileSystemKeyStore persists private keys atomically to disk with POSIX permissions (0600 files, 0700 directory).
 * Configurable with a custom directory path or AAMARVA_KEY_STORE_PATH env.
 */
export class FileSystemKeyStore implements KeyStore {
  private baseDir: string;

  constructor(baseDir?: string) {
    this.baseDir = baseDir || process.env.AAMARVA_KEY_STORE_PATH || path.join(os.homedir(), '.aamarva', 'keys');
  }

  private resolveKeyPath(identityId: string): string {
    const safeId = sanitizeKeySlotId(identityId);
    const resolvedBase = path.resolve(this.baseDir);
    const resolvedTarget = path.resolve(resolvedBase, `${safeId}.pem`);
    if (!resolvedTarget.startsWith(resolvedBase + path.sep)) {
      throw new AamarvaError('Resolved key path escapes keystore base directory.', { code: 'IDENTITY_KEY_INVALID' });
    }
    return resolvedTarget;
  }

  public loadPrivateKey(identityId = 'default'): string | null {
    if (!this.baseDir) return null;
    const keyPath = this.resolveKeyPath(identityId);
    if (!fs.existsSync(keyPath)) {
      return null;
    }
    const stat = fs.lstatSync(keyPath);
    if (stat.isSymbolicLink() || !stat.isFile()) {
      throw new AamarvaError('Refusing to load private key from non-regular file or symlink.', {
        code: 'IDENTITY_KEY_INVALID',
      });
    }
    const content = fs.readFileSync(keyPath, 'utf8');
    if (!content.trim()) {
      throw new AamarvaError('Stored private key file is empty or corrupt.', {
        code: 'IDENTITY_KEY_INVALID',
      });
    }
    return content;
  }

  public savePrivateKey(privateKeyPem: string, identityId = 'default', options?: { overwrite?: boolean }): void {
    if (!privateKeyPem || typeof privateKeyPem !== 'string' || !privateKeyPem.trim()) {
      throw new AamarvaError('Cannot persist empty private key.', { code: 'IDENTITY_KEY_INVALID' });
    }
    if (!this.baseDir) return;
    if (!fs.existsSync(this.baseDir)) {
      fs.mkdirSync(this.baseDir, { recursive: true, mode: 0o700 });
    } else {
      try {
        fs.chmodSync(this.baseDir, 0o700);
      } catch {
        // Ignore on platforms without POSIX chmod
      }
    }
    const keyPath = this.resolveKeyPath(identityId);
    if (fs.existsSync(keyPath) && !options?.overwrite) {
      return;
    }
    const tmpPath = path.join(
      path.resolve(this.baseDir),
      `.tmp-${process.pid}-${crypto.randomBytes(8).toString('hex')}.pem`
    );
    try {
      fs.writeFileSync(tmpPath, privateKeyPem, { mode: 0o600, flag: 'wx' });
      try {
        fs.chmodSync(tmpPath, 0o600);
      } catch {
        // Ignore on non-POSIX
      }
      fs.renameSync(tmpPath, keyPath);
      try {
        fs.chmodSync(keyPath, 0o600);
      } catch {
        // Ignore on non-POSIX
      }
    } catch (err) {
      try {
        if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
      } catch {
        // ignore cleanup errors
      }
      throw err;
    }
  }

  public listKeyIds(): string[] {
    if (!this.baseDir || !fs.existsSync(this.baseDir)) return [];
    return fs
      .readdirSync(this.baseDir)
      .filter((f) => f.endsWith('.pem') && !f.startsWith('.tmp-'))
      .map((f) => f.slice(0, -4));
  }
}

let activeKeyStore: KeyStore = new FileSystemKeyStore();
const identityKeyCache = new Map<string, any>();

export function setKeyStore(store: KeyStore): void {
  activeKeyStore = store;
  identityKeyCache.clear();
}

export function getKeyStore(): KeyStore {
  return activeKeyStore;
}

export function resetLocalIdentityKeyPair(): void {
  identityKeyCache.clear();
  activeKeyStore = new FileSystemKeyStore();
}

export function generateECKeyPair(): { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject } {
  return crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
}

function validatePrivateECP256Key(privKey: crypto.KeyObject): void {
  if (privKey.asymmetricKeyType !== 'ec') {
    throw new AamarvaError('Stored private key must be an elliptic curve (EC) key.', {
      code: 'IDENTITY_KEY_INVALID',
    });
  }
  const details = privKey.asymmetricKeyDetails;
  if (details?.namedCurve && details.namedCurve !== 'prime256v1') {
    throw new AamarvaError(`Unsupported curve for stored key: ${details.namedCurve}. Only prime256v1 (P-256) is supported.`, {
      code: 'IDENTITY_KEY_INVALID',
    });
  }
}

function loadOrCreateKeyPairInSlot(slotId: string, allowGenerate = true): { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject } {
  const cached = identityKeyCache.get(slotId);
  if (cached) {
    return cached;
  }

  let storedPem: string | null;
  try {
    storedPem = activeKeyStore.loadPrivateKey(slotId);
  } catch (err: any) {
    if (err instanceof AamarvaError) throw err;
    throw new AamarvaError(`Failed to read key from keystore: ${err.message}`, {
      code: 'IDENTITY_KEY_INVALID',
      cause: err,
    });
  }

  if (typeof storedPem === 'string' && storedPem.trim()) {
    try {
      const privateKey = crypto.createPrivateKey({ key: storedPem, format: 'pem', type: 'pkcs8' });
      validatePrivateECP256Key(privateKey);
      const publicKey = crypto.createPublicKey(privateKey);
      const kp = { privateKey, publicKey };
      identityKeyCache.set(slotId, kp);
      return kp;
    } catch (err: any) {
      if (err instanceof AamarvaError) throw err;
      throw new AamarvaError('Failed to load stored key: key is corrupt or invalid format.', {
        code: 'IDENTITY_KEY_INVALID',
        cause: err,
      });
    }
  }

  if (!allowGenerate) {
    throw new AamarvaError(`Missing stored key for slot "${slotId}".`, {
      code: 'IDENTITY_KEY_MISSING',
    });
  }

  const kp = generateECKeyPair();
  identityKeyCache.set(slotId, kp);
  const privPem = kp.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  activeKeyStore.savePrivateKey(privPem, slotId);
  return kp;
}

function loadKeyPairFromSlotIfExists(slotId: string): { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject } | null {
  const cached = identityKeyCache.get(slotId);
  if (cached) {
    return cached;
  }
  const storedPem = activeKeyStore.loadPrivateKey(slotId);
  if (typeof storedPem === 'string' && storedPem.trim()) {
    return loadOrCreateKeyPairInSlot(slotId, false);
  }
  return null;
}

/**
 * Retrieve or generate the persistent ECDSA P-256 identity signing keypair for an agent.
 * Separate from the ECDH key-agreement keypair.
 */
export function getLocalIdentitySigningKeyPair(agentId: string): { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject } {
  if (!agentId || typeof agentId !== 'string' || !agentId.trim()) {
    throw new AamarvaError('agentId is required for identity signing key.', { code: 'IDENTITY_KEY_INVALID' });
  }
  const normalizedId = agentId.trim();
  const slotId = `${normalizedId}__identity`;
  return loadOrCreateKeyPairInSlot(slotId, true);
}

/**
 * Retrieve or generate an epoch-scoped ECDH P-256 keypair for an agent.
 */
export function getLocalEcdhKeyPair(
  agentId: string,
  keyEpoch = 1
): { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject; keyEpoch: number } {
  if (!agentId || typeof agentId !== 'string' || !agentId.trim()) {
    throw new AamarvaError('agentId is required for ECDH keypair.', { code: 'IDENTITY_KEY_INVALID' });
  }
  const epoch = validatePositiveEpoch(keyEpoch, 'IDENTITY_KEY_INVALID');
  const normalizedId = agentId.trim();
  const slotId = `${normalizedId}__ecdh_e${epoch}`;

  // Check if an explicit epoch key exists; if epoch === 1 and only legacy raw slot exists, preserve it without silent overwrite
  const existing = loadKeyPairFromSlotIfExists(slotId);
  if (existing) {
    return { ...existing, keyEpoch: epoch };
  }
  if (epoch === 1) {
    const legacyExisting = loadKeyPairFromSlotIfExists(normalizedId);
    if (legacyExisting) {
      return { ...legacyExisting, keyEpoch: 1 };
    }
  }

  const kp = loadOrCreateKeyPairInSlot(slotId, true);
  return { ...kp, keyEpoch: epoch };
}

/**
 * Look up a stored local ECDH keypair for a specific historical epoch without creating one.
 */
export function findLocalEcdhKeyPair(
  agentId: string,
  keyEpoch: number
): { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject; keyEpoch: number } | null {
  if (!agentId || typeof agentId !== 'string' || !agentId.trim()) {
    return null;
  }
  const epoch = validatePositiveEpoch(keyEpoch, 'IDENTITY_KEY_INVALID');
  const normalizedId = agentId.trim();
  const slotId = `${normalizedId}__ecdh_e${epoch}`;
  const kp = loadKeyPairFromSlotIfExists(slotId);
  if (kp) {
    return { ...kp, keyEpoch: epoch };
  }
  if (epoch === 1) {
    const legacy = loadKeyPairFromSlotIfExists(normalizedId);
    if (legacy) {
      return { ...legacy, keyEpoch: 1 };
    }
  }
  return null;
}

/**
 * Discover the highest locally persisted ECDH key epoch for an agent (defaults to 1 if none yet).
 */
export function getLatestLocalEcdhEpoch(agentId: string): number {
  if (!agentId || typeof agentId !== 'string' || !agentId.trim()) {
    return 1;
  }
  const safePrefix = `${sanitizeKeySlotId(agentId.trim())}__ecdh_e`;
  let maxEpoch = 0;

  if (typeof activeKeyStore.listKeyIds === 'function') {
    for (const id of activeKeyStore.listKeyIds()) {
      if (id.startsWith(safePrefix)) {
        const suffix = id.slice(safePrefix.length);
        const parsed = Number(suffix);
        if (Number.isInteger(parsed) && parsed >= 1 && parsed > maxEpoch) {
          maxEpoch = parsed;
        }
      }
    }
  }

  for (const key of identityKeyCache.keys()) {
    if (key.startsWith(safePrefix)) {
      const parsed = Number(key.slice(safePrefix.length));
      if (Number.isInteger(parsed) && parsed >= 1 && parsed > maxEpoch) {
        maxEpoch = parsed;
      }
    }
  }

  return maxEpoch >= 1 ? maxEpoch : 1;
}

/**
 * Generate and store a fresh ECDH keypair for key rotation at nextEpoch.
 */
export function rotateLocalEcdhKeyPair(
  agentId: string,
  nextEpoch?: number
): { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject; keyEpoch: number } {
  if (!agentId || typeof agentId !== 'string' || !agentId.trim()) {
    throw new AamarvaError('agentId is required for ECDH key rotation.', { code: 'IDENTITY_KEY_INVALID' });
  }
  const currentLatest = getLatestLocalEcdhEpoch(agentId);
  const targetEpoch = nextEpoch !== undefined ? validatePositiveEpoch(nextEpoch, 'IDENTITY_KEY_INVALID') : currentLatest + 1;
  const normalizedId = agentId.trim();
  const slotId = `${normalizedId}__ecdh_e${targetEpoch}`;

  if (loadKeyPairFromSlotIfExists(slotId)) {
    throw new AamarvaError(`ECDH key for epoch ${targetEpoch} already exists; refusing to overwrite existing epoch key.`, {
      code: 'IDENTITY_KEY_INVALID',
    });
  }

  const kp = generateECKeyPair();
  identityKeyCache.set(slotId, kp);
  const privPem = kp.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  activeKeyStore.savePrivateKey(privPem, slotId);
  return { ...kp, keyEpoch: targetEpoch };
}

/**
 * Backwards-compatible accessor returning the active local ECDH keypair for an identity.
 * Uses KeyStore slot directly when invoked without epoch awareness.
 */
export function getLocalIdentityKeyPair(identityId = 'default'): any {
  const safeId = sanitizeKeySlotId(identityId);
  const existingLegacy = loadKeyPairFromSlotIfExists(safeId);
  if (existingLegacy) {
    return existingLegacy;
  }
  const latestEpoch = getLatestLocalEcdhEpoch(identityId);
  if (latestEpoch > 1 || loadKeyPairFromSlotIfExists(`${safeId}__ecdh_e1`)) {
    return getLocalEcdhKeyPair(identityId, latestEpoch);
  }
  return loadOrCreateKeyPairInSlot(safeId, true);
}

export function getLocalPublicKeyPem(identityId = 'default'): string {
  const kp = getLocalIdentityKeyPair(identityId);
  return kp.publicKey.export({ type: 'spki', format: 'pem' }).toString();
}

/**
 * Export a P-256 EC public key in standard JWK representation.
 */
export function exportPublicKeyJWK(keyOrKp?: any): ECJWK {
  let pubKey: crypto.KeyObject;
  if (!keyOrKp) {
    pubKey = getLocalIdentityKeyPair().publicKey;
  } else if (keyOrKp.publicKey) {
    pubKey = keyOrKp.publicKey;
  } else if (typeof keyOrKp.export === 'function') {
    pubKey = keyOrKp;
  } else if (typeof keyOrKp === 'string') {
    pubKey = importPublicKey(keyOrKp);
  } else if (typeof keyOrKp === 'object' && keyOrKp.kty === 'EC' && keyOrKp.crv === 'P-256' && keyOrKp.x && keyOrKp.y) {
    const imported = importPublicKey(keyOrKp);
    const jwk = imported.export({ format: 'jwk' });
    return {
      kty: 'EC',
      crv: 'P-256',
      x: jwk.x!,
      y: jwk.y!,
    };
  } else {
    throw new AamarvaError('Invalid key object provided for JWK export.', { code: 'INVALID_PEER_KEY' });
  }

  validateECP256Key(pubKey);
  const jwk = pubKey.export({ format: 'jwk' });
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
    throw new AamarvaError('Exported key is not a valid P-256 EC JWK.', { code: 'INVALID_PEER_KEY' });
  }

  return {
    kty: 'EC',
    crv: 'P-256',
    x: jwk.x,
    y: jwk.y,
  };
}

function validateECP256Key(pubKey: crypto.KeyObject): void {
  if (pubKey.asymmetricKeyType !== 'ec') {
    throw new AamarvaError('Public key must be an elliptic curve (EC) key.', { code: 'PEER_KEY_VERIFICATION_FAILED' });
  }
  const details = pubKey.asymmetricKeyDetails;
  if (details?.namedCurve && details.namedCurve !== 'prime256v1') {
    throw new AamarvaError(`Unsupported curve: ${details.namedCurve}. Only prime256v1 (P-256) is supported.`, {
      code: 'PEER_KEY_VERIFICATION_FAILED',
    });
  }
}

/**
 * Import a P-256 EC public key from JWK object, JSON string, or PEM string into a KeyObject.
 */
export function importPublicKey(key: ECJWK | string | crypto.KeyObject | any): crypto.KeyObject {
  if (!key) {
    throw new AamarvaError('Missing public key.', { code: 'PEER_KEY_UNAVAILABLE' });
  }
  if (typeof key.export === 'function') {
    validateECP256Key(key);
    return key;
  }
  if (typeof key === 'string') {
    const trimmed = key.trim();
    if (!trimmed) {
      throw new AamarvaError('Empty public key provided.', { code: 'PEER_KEY_UNAVAILABLE' });
    }
    if (trimmed.startsWith('{')) {
      try {
        const parsed = JSON.parse(trimmed);
        return importPublicKey(parsed);
      } catch (err: any) {
        if (err instanceof AamarvaError) throw err;
        throw new AamarvaError(`Failed to parse JWK string: ${err.message}`, { code: 'INVALID_PEER_KEY', cause: err });
      }
    }
    try {
      const pub = crypto.createPublicKey({ key: trimmed, format: 'pem', type: 'spki' });
      validateECP256Key(pub);
      return pub;
    } catch (err: any) {
      if (err instanceof AamarvaError) throw err;
      throw new AamarvaError(`Invalid peer public key: ${err.message}`, { code: 'INVALID_PEER_KEY', cause: err });
    }
  }
  if (typeof key === 'object' && key !== null) {
    const kty = key.kty;
    const crv = key.crv;
    if (!kty || !crv) {
      throw new AamarvaError('Invalid key object: missing kty or crv properties.', { code: 'INVALID_PEER_KEY' });
    }
    if (kty !== 'EC') {
      throw new AamarvaError(`Invalid key type: ${kty}. Expected 'EC'.`, { code: 'INVALID_PEER_KEY' });
    }
    if (crv !== 'P-256') {
      throw new AamarvaError(`Unsupported curve: ${crv}. Only P-256 is supported.`, { code: 'INVALID_PEER_KEY' });
    }
    if (!key.x || !key.y || typeof key.x !== 'string' || typeof key.y !== 'string') {
      throw new AamarvaError('Malformed JWK: missing or invalid x/y coordinate parameters.', { code: 'INVALID_PEER_KEY' });
    }
    try {
      const pub = crypto.createPublicKey({
        key: { kty: 'EC', crv: 'P-256', x: key.x, y: key.y },
        format: 'jwk',
      });
      validateECP256Key(pub);
      return pub;
    } catch (err: any) {
      if (err instanceof AamarvaError) throw err;
      throw new AamarvaError(`Failed to import EC JWK: ${err.message}`, { code: 'INVALID_PEER_KEY', cause: err });
    }
  }
  throw new AamarvaError('Invalid public key format provided.', { code: 'INVALID_PEER_KEY' });
}

/**
 * Exact fingerprint calculation: SHA-256 hash of canonical P-256 JWK.
 */
export function computeKeyFingerprint(key: ECJWK | string | crypto.KeyObject | any): string {
  try {
    const pubKey = importPublicKey(key);
    const jwk = pubKey.export({ format: 'jwk' });
    const canonicalJwk = JSON.stringify({
      crv: 'P-256',
      kty: 'EC',
      x: jwk.x,
      y: jwk.y,
    });
    const hash = crypto.createHash('sha256').update(canonicalJwk, 'utf8').digest('hex').toUpperCase();
    return 'SHA256:' + hash.match(/.{1,2}/g)!.join(':');
  } catch (err: any) {
    if (err instanceof AamarvaError) throw err;
    throw new AamarvaError(`Failed to compute key fingerprint: ${err.message}`, {
      code: 'PEER_KEY_VERIFICATION_FAILED',
      cause: err,
    });
  }
}

export function computeClusterKeyFingerprint(clusterKey: Buffer): string {
  if (!Buffer.isBuffer(clusterKey) || clusterKey.length !== 32) {
    throw new AamarvaError('Cluster key must be a 32-byte buffer.', { code: 'CLUSTER_KEY_INVALID' });
  }
  const hash = crypto.createHash('sha256').update(clusterKey).digest('hex').toUpperCase();
  return 'SHA256:' + hash.match(/.{1,2}/g)!.join(':');
}

export function computeAudienceHash(agentIds: string[]): string {
  const normalized = Array.from(
    new Set(
      agentIds
        .filter((id) => typeof id === 'string' && id.trim().length > 0)
        .map((id) => id.trim().toUpperCase())
    )
  ).sort();
  return crypto.createHash('sha256').update(JSON.stringify(normalized), 'utf8').digest('hex');
}

export function computeRosterHash(memberIds: string[]): string {
  return computeAudienceHash(memberIds);
}

/**
 * Construct the canonical identity binding string expected by AAMARVA:
 * AAMARVA-KEY-BINDING:v1:<AGENT_ID>:<FINGERPRINT>
 */
export function createIdentityBindingString(agentId: string, fingerprint: string): string {
  if (!agentId || typeof agentId !== 'string' || !agentId.trim()) {
    throw new AamarvaError('agentId is required for identity key binding.', { code: 'IDENTITY_KEY_INVALID' });
  }
  if (!fingerprint || typeof fingerprint !== 'string' || !fingerprint.trim()) {
    throw new AamarvaError('fingerprint is required for identity key binding.', { code: 'IDENTITY_KEY_INVALID' });
  }
  return `AAMARVA-KEY-BINDING:v1:${agentId.trim().toUpperCase()}:${fingerprint.trim()}`;
}

/**
 * Sign the identity binding string using ECDSA SHA-256 with the agent's private identity key.
 */
export function signIdentityBinding(privateKeyPemOrKey: any, agentId: string, fingerprint: string): string {
  const bindingString = createIdentityBindingString(agentId, fingerprint);
  try {
    const privKey = typeof privateKeyPemOrKey === 'string'
      ? crypto.createPrivateKey({ key: privateKeyPemOrKey, format: 'pem', type: 'pkcs8' })
      : (privateKeyPemOrKey.privateKey || privateKeyPemOrKey);
    validatePrivateECP256Key(privKey);
    const sig = crypto.sign('SHA256', Buffer.from(bindingString, 'utf8'), privKey);
    return sig.toString('base64');
  } catch (err: any) {
    if (err instanceof AamarvaError) throw err;
    throw new AamarvaError(`Failed to sign identity binding: ${err.message}`, {
      code: 'IDENTITY_KEY_INVALID',
      cause: err,
    });
  }
}

/**
 * Verify an identity binding signature against the binding string with the identity public key.
 */
export function verifyIdentityBinding(
  identityKey: ECJWK | string | crypto.KeyObject | any,
  agentId: string,
  fingerprint: string,
  signatureBase64: string
): boolean {
  if (!signatureBase64 || typeof signatureBase64 !== 'string') {
    return false;
  }
  const bindingString = createIdentityBindingString(agentId, fingerprint);
  try {
    const pubKey = importPublicKey(identityKey);
    const sigBuf = decodeStrictBase64(signatureBase64, 'signature', 'PEER_KEY_VERIFICATION_FAILED');
    return crypto.verify('SHA256', Buffer.from(bindingString, 'utf8'), pubKey, sigBuf);
  } catch {
    return false;
  }
}

/**
 * Strict verification of peer public key, fingerprint, and identity signature binding.
 */
export function verifyPeerKey(
  peerKey: ECJWK | string | crypto.KeyObject | any,
  expectedFingerprint: string | undefined,
  peerAgentId: string | undefined,
  signature: string | undefined,
  identityKey: ECJWK | string | crypto.KeyObject | any
): void {
  if (!peerKey) {
    throw new AamarvaError('Invalid or missing peer public key.', {
      code: 'PEER_KEY_UNAVAILABLE',
    });
  }
  if (typeof peerKey === 'string' && !peerKey.trim()) {
    throw new AamarvaError('Invalid or missing peer public key.', {
      code: 'PEER_KEY_UNAVAILABLE',
    });
  }

  if (!expectedFingerprint) {
    throw new AamarvaError('Missing expected peer fingerprint.', {
      code: 'PEER_KEY_VERIFICATION_FAILED',
    });
  }

  if (!peerAgentId) {
    throw new AamarvaError('Missing peer agent ID.', {
      code: 'PEER_KEY_VERIFICATION_FAILED',
    });
  }

  if (!signature) {
    throw new AamarvaError('Missing peer key signature.', {
      code: 'PEER_KEY_VERIFICATION_FAILED',
    });
  }

  if (!identityKey) {
    throw new AamarvaError('Missing peer identity key.', {
      code: 'PEER_KEY_VERIFICATION_FAILED',
    });
  }

  let pubKey: crypto.KeyObject;
  try {
    pubKey = importPublicKey(peerKey);
  } catch (err: any) {
    if (err instanceof AamarvaError && err.code === 'PEER_KEY_UNAVAILABLE') throw err;
    throw new AamarvaError(`Peer key verification failed: ${err.message}`, {
      code: 'PEER_KEY_VERIFICATION_FAILED',
      cause: err,
    });
  }

  const computedFp = computeKeyFingerprint(pubKey);
  if (computedFp !== expectedFingerprint) {
    throw new AamarvaError('Peer key fingerprint verification failed (mismatch).', {
      code: 'PEER_KEY_VERIFICATION_FAILED',
    });
  }

  try {
    importPublicKey(identityKey);
  } catch (err: any) {
    throw new AamarvaError(`Peer identity key verification failed: ${err.message}`, {
      code: 'PEER_KEY_VERIFICATION_FAILED',
      cause: err,
    });
  }

  const isValid = verifyIdentityBinding(identityKey, peerAgentId, computedFp, signature);
  if (!isValid) {
    throw new AamarvaError('Peer key identity signature verification failed.', {
      code: 'PEER_KEY_VERIFICATION_FAILED',
    });
  }
}

export function deriveSharedSecret(localPrivateKeyPemOrKey: any, peerKey: ECJWK | string | crypto.KeyObject | any): Buffer {
  try {
    const peerPub = importPublicKey(peerKey);
    const localPriv = typeof localPrivateKeyPemOrKey === 'string'
      ? crypto.createPrivateKey({ key: localPrivateKeyPemOrKey, format: 'pem', type: 'pkcs8' })
      : (localPrivateKeyPemOrKey.privateKey || localPrivateKeyPemOrKey);
    validatePrivateECP256Key(localPriv);

    return crypto.diffieHellman({
      privateKey: localPriv,
      publicKey: peerPub,
    });
  } catch (err: any) {
    if (err instanceof AamarvaError) throw err;
    throw new AamarvaError(`Failed to perform ECDH shared secret derivation: ${err.message}`, {
      code: 'MESSAGE_ENCRYPTION_FAILED',
      cause: err,
    });
  }
}

/**
 * Authoritative Platform HKDF-SHA256 channel key derivation:
 * - Hash: SHA-256
 * - Salt: "aamarva-e2ee-channel-v1"
 * - Info: "aamarva-channel:<connectionId>"
 * - Length: 32 bytes (AES-256-GCM)
 */
export function deriveConnectionAesKey(sharedSecret: Buffer, connectionId: string): Buffer {
  if (!connectionId || typeof connectionId !== 'string' || !connectionId.trim()) {
    throw new AamarvaError('Connection ID is required for key derivation.', { code: 'MESSAGE_ENCRYPTION_FAILED' });
  }
  const canonicalId = connectionId.trim();
  try {
    const derived = crypto.hkdfSync(
      'sha256',
      sharedSecret,
      Buffer.from(CHANNEL_HKDF_SALT, 'utf8'),
      Buffer.from(`${CHANNEL_HKDF_INFO_PREFIX}${canonicalId}`, 'utf8'),
      32
    );
    return Buffer.from(derived);
  } catch (err: any) {
    throw new AamarvaError(`Failed to derive AES key via HKDF: ${err.message}`, {
      code: 'MESSAGE_ENCRYPTION_FAILED',
      cause: err,
    });
  }
}

export function encryptMessageWithKeys(
  plaintext: string,
  connectionId: string,
  localPrivateKey: any,
  peerKey: ECJWK | string | crypto.KeyObject | any,
  expectedFingerprint: string | undefined,
  peerAgentId: string | undefined,
  peerSignature: string | undefined,
  peerIdentityKey: ECJWK | string | crypto.KeyObject | any,
  keyEpoch: number = 1
): EncryptedEnvelope {
  if (typeof plaintext !== 'string') {
    throw new AamarvaError('Message payload must be a string.', { code: 'MESSAGE_ENCRYPTION_FAILED' });
  }
  const validatedEpoch = validatePositiveEpoch(keyEpoch, 'MESSAGE_ENCRYPTION_FAILED');
  verifyPeerKey(peerKey, expectedFingerprint, peerAgentId, peerSignature, peerIdentityKey);
  const sharedSecret = deriveSharedSecret(localPrivateKey, peerKey);
  const aesKey = deriveConnectionAesKey(sharedSecret, connectionId);

  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, nonce);
  cipher.setAAD(Buffer.from(connectionId.trim(), 'utf8'));
  const encryptedBuf = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const combined = Buffer.concat([encryptedBuf, authTag]);

  return {
    ciphertext: combined.toString('base64'),
    nonce: nonce.toString('base64'),
    version: 1,
    keyEpoch: validatedEpoch,
  };
}

export function decryptMessageWithKeys(
  envelope: { ciphertext?: string; nonce?: string; version?: number; keyEpoch?: number },
  connectionId: string,
  localPrivateKey: any,
  peerKey: ECJWK | string | crypto.KeyObject | any,
  expectedFingerprint: string | undefined,
  peerAgentId: string | undefined,
  peerSignature: string | undefined,
  peerIdentityKey: ECJWK | string | crypto.KeyObject | any
): string {
  if (!envelope || typeof envelope !== 'object' || !envelope.ciphertext || !envelope.nonce) {
    throw new AamarvaError('Invalid encrypted message envelope: missing ciphertext or nonce.', {
      code: 'MESSAGE_INVALID_ENVELOPE',
    });
  }
  if (envelope.version !== undefined && envelope.version !== 1) {
    throw new AamarvaError(`Unsupported direct message envelope version: ${String(envelope.version)}.`, {
      code: 'MESSAGE_INVALID_ENVELOPE',
    });
  }
  if (envelope.keyEpoch !== undefined) {
    validatePositiveEpoch(envelope.keyEpoch, 'MESSAGE_INVALID_ENVELOPE');
  }

  const nonce = decodeStrictBase64(envelope.nonce, 'nonce', 'MESSAGE_INVALID_ENVELOPE');
  if (nonce.length !== 12) {
    throw new AamarvaError(`Invalid AES-GCM nonce length: expected 12 bytes, got ${nonce.length}.`, {
      code: 'MESSAGE_INVALID_ENVELOPE',
    });
  }
  const combined = decodeStrictBase64(envelope.ciphertext, 'ciphertext', 'MESSAGE_INVALID_ENVELOPE');
  if (combined.length < 16) {
    throw new AamarvaError('Ciphertext is too short or malformed (missing auth tag).', {
      code: 'MESSAGE_INVALID_ENVELOPE',
    });
  }

  verifyPeerKey(peerKey, expectedFingerprint, peerAgentId, peerSignature, peerIdentityKey);

  try {
    const sharedSecret = deriveSharedSecret(localPrivateKey, peerKey);
    const aesKey = deriveConnectionAesKey(sharedSecret, connectionId);

    const authTag = combined.subarray(combined.length - 16);
    const ciphertextBuf = combined.subarray(0, combined.length - 16);

    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, nonce);
    decipher.setAAD(Buffer.from(connectionId.trim(), 'utf8'));
    decipher.setAuthTag(authTag);

    const decryptedBuf = Buffer.concat([decipher.update(ciphertextBuf), decipher.final()]);
    return decryptedBuf.toString('utf8');
  } catch (err: any) {
    if (err instanceof AamarvaError) {
      throw err;
    }
    throw new AamarvaError(`Failed to decrypt message locally: ${err.message}`, {
      code: 'MESSAGE_DECRYPTION_FAILED',
      cause: err,
    });
  }
}

export function encryptMessage(plaintext: string, connectionId: string, agentIdA?: string, agentIdB?: string): EncryptedEnvelope {
  throw new AamarvaError('Use connection.send() or client.sendMessage() with E2EE key exchange.', {
    code: 'MESSAGE_ENCRYPTION_FAILED',
  });
}

export function decryptMessage(envelope: any, connectionId: string, agentIdA?: string, agentIdB?: string): string {
  throw new AamarvaError('Use connection.getMessages() with E2EE key exchange.', {
    code: 'MESSAGE_DECRYPTION_FAILED',
  });
}

/**
 * Cluster Key Distribution and Encryption (AAMARVA_CLUSTER_KEY_WRAP_V1)
 */
export function generateClusterKey(): Buffer {
  return crypto.randomBytes(32);
}

export function buildClusterWrappingParams(clusterId: string, epoch: number): ClusterWrappingParams {
  if (!clusterId || typeof clusterId !== 'string' || !clusterId.trim()) {
    throw new AamarvaError('clusterId is required for cluster key wrapping.', { code: 'CLUSTER_KEY_INVALID' });
  }
  const cleanId = clusterId.trim();
  const validEpoch = validatePositiveEpoch(epoch, 'CLUSTER_KEY_INVALID');
  return {
    algorithm: CLUSTER_KEY_WRAP_ALGORITHM,
    curve: 'P-256',
    hkdfHash: 'SHA-256',
    hkdfSalt: CHANNEL_HKDF_SALT,
    hkdfInfo: `${CHANNEL_HKDF_INFO_PREFIX}${cleanId}`,
    aad: `${CLUSTER_KEY_AAD_PREFIX}${cleanId}:${validEpoch}`,
  };
}

export function wrapClusterKeyForRecipient(
  clusterKey: Buffer,
  recipientPublicKeyPemOrJwk: any,
  senderPrivateKey: any,
  options: { clusterId?: string; epoch?: number } = {}
): { encryptedKeyPackage: string; nonce: string; wrappingParams: ClusterWrappingParams } {
  if (!Buffer.isBuffer(clusterKey) || clusterKey.length !== 32) {
    throw new AamarvaError('Cluster key must be a 32-byte buffer.', { code: 'CLUSTER_KEY_INVALID' });
  }
  const clusterId = (options.clusterId || '').trim();
  if (!clusterId) {
    throw new AamarvaError('clusterId is required to wrap a cluster key under AAMARVA_CLUSTER_KEY_WRAP_V1.', {
      code: 'CLUSTER_KEY_INVALID',
    });
  }
  const epoch = validatePositiveEpoch(options.epoch, 'CLUSTER_KEY_INVALID');

  const recipientKey = typeof recipientPublicKeyPemOrJwk === 'string'
    ? importPublicKey(recipientPublicKeyPemOrJwk)
    : (recipientPublicKeyPemOrJwk?.publicKey ? recipientPublicKeyPemOrJwk.publicKey : importPublicKey(recipientPublicKeyPemOrJwk));

  const senderPrivObj = typeof senderPrivateKey === 'string'
    ? crypto.createPrivateKey({ key: senderPrivateKey, format: 'pem', type: 'pkcs8' })
    : (senderPrivateKey?.privateKey || senderPrivateKey);
  validatePrivateECP256Key(senderPrivObj);

  const senderPubKeyObj = crypto.createPublicKey(senderPrivObj);
  const senderPublicKeyJwk = exportPublicKeyJWK(senderPubKeyObj);
  const wrappingParams = buildClusterWrappingParams(clusterId, epoch);

  const sharedSecret = deriveSharedSecret(senderPrivObj, recipientKey);
  const wrapKey = Buffer.from(
    crypto.hkdfSync(
      'sha256',
      sharedSecret,
      Buffer.from(wrappingParams.hkdfSalt, 'utf8'),
      Buffer.from(wrappingParams.hkdfInfo, 'utf8'),
      32
    )
  );
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv('aes-256-gcm', wrapKey, iv);
  cipher.setAAD(Buffer.from(wrappingParams.aad, 'utf8'));
  const encryptedBuf = Buffer.concat([cipher.update(clusterKey), cipher.final(), cipher.getAuthTag()]);

  const ivB64 = iv.toString('base64');
  const ciphertextB64 = encryptedBuf.toString('base64');

  const keyPackage: WrappedClusterKeyPackage = {
    version: CLUSTER_KEY_WRAP_VERSION,
    clusterId,
    epoch,
    iv: ivB64,
    ciphertext: ciphertextB64,
    senderPublicKey: senderPublicKeyJwk,
    wrappingParams,
  };

  return {
    encryptedKeyPackage: JSON.stringify(keyPackage),
    nonce: ivB64,
    wrappingParams,
  };
}

export function unwrapClusterKey(
  encryptedKeyPackageInput: string | WrappedClusterKeyPackage,
  nonceOrOptions: string | { expectedClusterId?: string; expectedEpoch?: number } | undefined,
  recipientPrivateKey: any,
  senderPublicKeyPemOrJwk?: any
): Buffer {
  let pkg: WrappedClusterKeyPackage;
  if (typeof encryptedKeyPackageInput === 'string') {
    const trimmed = encryptedKeyPackageInput.trim();
    if (!trimmed.startsWith('{')) {
      throw new AamarvaError('Cluster key package must be a valid AAMARVA_CLUSTER_KEY_WRAP_V1 JSON package.', {
        code: 'CLUSTER_KEY_UNWRAP_FAILED',
      });
    }
    try {
      pkg = JSON.parse(trimmed);
    } catch (err: any) {
      throw new AamarvaError(`Failed to parse wrapped cluster key package: ${err.message}`, {
        code: 'CLUSTER_KEY_UNWRAP_FAILED',
        cause: err,
      });
    }
  } else if (encryptedKeyPackageInput && typeof encryptedKeyPackageInput === 'object') {
    pkg = encryptedKeyPackageInput;
  } else {
    throw new AamarvaError('Missing wrapped cluster key package.', { code: 'CLUSTER_KEY_UNWRAP_FAILED' });
  }

  if (pkg.version !== CLUSTER_KEY_WRAP_VERSION) {
    throw new AamarvaError(`Unsupported cluster key wrap version: ${String(pkg.version)}.`, {
      code: 'CLUSTER_KEY_UNWRAP_FAILED',
    });
  }
  if (!pkg.clusterId || typeof pkg.clusterId !== 'string' || !pkg.clusterId.trim()) {
    throw new AamarvaError('Wrapped cluster key package is missing clusterId.', { code: 'CLUSTER_KEY_UNWRAP_FAILED' });
  }
  const epoch = validatePositiveEpoch(pkg.epoch, 'CLUSTER_KEY_UNWRAP_FAILED');
  const expectedOpts = (typeof nonceOrOptions === 'object' && nonceOrOptions !== null) ? nonceOrOptions : {};
  if (expectedOpts.expectedClusterId && pkg.clusterId.trim() !== expectedOpts.expectedClusterId.trim()) {
    throw new AamarvaError('Wrapped cluster key package clusterId mismatch.', { code: 'CLUSTER_KEY_UNWRAP_FAILED' });
  }
  if (expectedOpts.expectedEpoch !== undefined && epoch !== expectedOpts.expectedEpoch) {
    throw new AamarvaError('Wrapped cluster key package epoch mismatch.', { code: 'CLUSTER_KEY_UNWRAP_FAILED' });
  }

  const expectedParams = buildClusterWrappingParams(pkg.clusterId, epoch);
  const wp = pkg.wrappingParams;
  if (
    !wp ||
    wp.algorithm !== expectedParams.algorithm ||
    wp.curve !== expectedParams.curve ||
    wp.hkdfHash !== expectedParams.hkdfHash ||
    wp.hkdfSalt !== expectedParams.hkdfSalt ||
    wp.hkdfInfo !== expectedParams.hkdfInfo ||
    wp.aad !== expectedParams.aad
  ) {
    throw new AamarvaError('Wrapped cluster key package wrappingParams failed validation.', {
      code: 'CLUSTER_KEY_UNWRAP_FAILED',
    });
  }

  const resolvedSenderInput = senderPublicKeyPemOrJwk || pkg.senderPublicKey;
  if (!resolvedSenderInput) {
    throw new AamarvaError('Missing sender public key for cluster key unwrap.', { code: 'CLUSTER_KEY_UNWRAP_FAILED' });
  }
  const senderKey = typeof resolvedSenderInput === 'string'
    ? importPublicKey(resolvedSenderInput)
    : (resolvedSenderInput?.publicKey ? resolvedSenderInput.publicKey : importPublicKey(resolvedSenderInput));

  if (senderPublicKeyPemOrJwk && pkg.senderPublicKey) {
    const passedFp = computeKeyFingerprint(senderKey);
    const pkgFp = computeKeyFingerprint(pkg.senderPublicKey);
    if (passedFp !== pkgFp) {
      throw new AamarvaError('Sender public key in cluster key package does not match verified sender key.', {
        code: 'CLUSTER_KEY_UNWRAP_FAILED',
      });
    }
  }

  const iv = decodeStrictBase64(pkg.iv, 'iv', 'CLUSTER_KEY_UNWRAP_FAILED');
  if (iv.length !== 12) {
    throw new AamarvaError(`Invalid cluster key wrap IV length: expected 12 bytes, got ${iv.length}.`, {
      code: 'CLUSTER_KEY_UNWRAP_FAILED',
    });
  }
  const combined = decodeStrictBase64(pkg.ciphertext, 'ciphertext', 'CLUSTER_KEY_UNWRAP_FAILED');
  if (combined.length < 16) {
    throw new AamarvaError('Cluster key package ciphertext is too short or malformed.', {
      code: 'CLUSTER_KEY_UNWRAP_FAILED',
    });
  }

  try {
    const sharedSecret = deriveSharedSecret(recipientPrivateKey, senderKey);
    const wrapKey = Buffer.from(
      crypto.hkdfSync(
        'sha256',
        sharedSecret,
        Buffer.from(expectedParams.hkdfSalt, 'utf8'),
        Buffer.from(expectedParams.hkdfInfo, 'utf8'),
        32
      )
    );

    const authTag = combined.subarray(combined.length - 16);
    const ciphertextBuf = combined.subarray(0, combined.length - 16);

    const decipher = crypto.createDecipheriv('aes-256-gcm', wrapKey, iv);
    decipher.setAAD(Buffer.from(expectedParams.aad, 'utf8'));
    decipher.setAuthTag(authTag);
    const unwrapped = Buffer.concat([decipher.update(ciphertextBuf), decipher.final()]);
    if (unwrapped.length !== 32) {
      throw new AamarvaError('Unwrapped cluster key has invalid length (expected 32 bytes).', {
        code: 'CLUSTER_KEY_UNWRAP_FAILED',
      });
    }
    return unwrapped;
  } catch (err: any) {
    if (err instanceof AamarvaError) throw err;
    throw new AamarvaError(`Failed to unwrap cluster key: ${err.message}`, {
      code: 'CLUSTER_KEY_UNWRAP_FAILED',
      cause: err,
    });
  }
}

export function encryptClusterMessagePayload(
  plaintext: string,
  clusterKey: Buffer,
  clusterId: string,
  epoch: number
): { ciphertext: string; nonce: string; version: number; keyEpoch: number } {
  if (typeof plaintext !== 'string') {
    throw new AamarvaError('Cluster message plaintext must be a string.', { code: 'MESSAGE_ENCRYPTION_FAILED' });
  }
  if (!Buffer.isBuffer(clusterKey) || clusterKey.length !== 32) {
    throw new AamarvaError('Cluster key must be a 32-byte buffer.', { code: 'CLUSTER_KEY_INVALID' });
  }
  if (!clusterId || typeof clusterId !== 'string' || !clusterId.trim()) {
    throw new AamarvaError('clusterId is required for cluster message encryption.', { code: 'MESSAGE_ENCRYPTION_FAILED' });
  }
  const validEpoch = validatePositiveEpoch(epoch, 'MESSAGE_ENCRYPTION_FAILED');

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', clusterKey, iv);
  cipher.setAAD(Buffer.from(`${clusterId.trim()}:${validEpoch}:v2`, 'utf8'));

  const ciphertextBuf = Buffer.concat([
    cipher.update(Buffer.from(plaintext, 'utf8')),
    cipher.final(),
    cipher.getAuthTag(),
  ]);

  return {
    ciphertext: ciphertextBuf.toString('base64'),
    nonce: iv.toString('base64'),
    version: 2,
    keyEpoch: validEpoch,
  };
}

export function decryptClusterMessagePayload(
  ciphertextBase64: string,
  nonceBase64: string,
  clusterKey: Buffer,
  clusterId: string,
  epoch: number,
  version = 2
): string {
  if (!Buffer.isBuffer(clusterKey) || clusterKey.length !== 32) {
    throw new AamarvaError('Cluster key must be a 32-byte buffer.', { code: 'CLUSTER_MESSAGE_DECRYPTION_FAILED' });
  }
  if (!clusterId || typeof clusterId !== 'string' || !clusterId.trim()) {
    throw new AamarvaError('clusterId is required for cluster message decryption.', { code: 'CLUSTER_MESSAGE_DECRYPTION_FAILED' });
  }
  const validEpoch = validatePositiveEpoch(epoch, 'CLUSTER_MESSAGE_DECRYPTION_FAILED');
  if (version !== 2) {
    throw new AamarvaError(`Unsupported cluster message version: ${String(version)}. Expected v2.`, {
      code: 'CLUSTER_MESSAGE_DECRYPTION_FAILED',
    });
  }

  const iv = decodeStrictBase64(nonceBase64, 'nonce', 'CLUSTER_MESSAGE_DECRYPTION_FAILED');
  if (iv.length !== 12) {
    throw new AamarvaError(`Invalid AES-GCM nonce length: expected 12 bytes, got ${iv.length}.`, {
      code: 'CLUSTER_MESSAGE_DECRYPTION_FAILED',
    });
  }
  const combined = decodeStrictBase64(ciphertextBase64, 'ciphertext', 'CLUSTER_MESSAGE_DECRYPTION_FAILED');
  if (combined.length < 16) {
    throw new AamarvaError('Cluster ciphertext is too short or malformed.', {
      code: 'CLUSTER_MESSAGE_DECRYPTION_FAILED',
    });
  }

  try {
    const authTag = combined.subarray(combined.length - 16);
    const ciphertextBuf = combined.subarray(0, combined.length - 16);

    const decipher = crypto.createDecipheriv('aes-256-gcm', clusterKey, iv);
    decipher.setAAD(Buffer.from(`${clusterId.trim()}:${validEpoch}:v${version}`, 'utf8'));
    decipher.setAuthTag(authTag);

    return Buffer.concat([decipher.update(ciphertextBuf), decipher.final()]).toString('utf8');
  } catch (err: any) {
    if (err instanceof AamarvaError) throw err;
    throw new AamarvaError(`Failed to decrypt cluster message: ${err.message}`, {
      code: 'CLUSTER_MESSAGE_DECRYPTION_FAILED',
      cause: err,
    });
  }
}
