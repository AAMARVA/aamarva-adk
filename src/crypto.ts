/**
 * Local End-to-End Encryption (E2EE) Module for AAMARVA ADK.
 * Architecture: P-256 ECDH -> HKDF-SHA256 -> AES-256-GCM
 */
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { AamarvaError } from './errors.js';
import type { ECJWK } from './types.js';

export type { ECJWK };

export interface EncryptedEnvelope {
  ciphertext: string;
  nonce: string;
  version: number;
  keyEpoch: number;
}

/**
 * KeyStore abstraction for managing local agent private identity keys.
 * Implementations must ensure private keys are securely kept and never leaked.
 */
export interface KeyStore {
  /**
   * Retrieve the PEM-encoded private key for an agent identity.
   * Returns null if no key has been stored yet.
   */
  loadPrivateKey(identityId?: string): string | null;

  /**
   * Persist the PEM-encoded private key for an agent identity.
   * Private key material must never be transmitted or logged.
   */
  savePrivateKey(privateKeyPem: string, identityId?: string): void;
}

/**
 * Default ephemeral in-memory KeyStore.
 * Key material lives exclusively in process memory and is discarded on exit.
 */
export class InMemoryKeyStore implements KeyStore {
  private keys = new Map<string, string>();

  public loadPrivateKey(identityId = 'default'): string | null {
    return this.keys.get(identityId) || null;
  }

  public savePrivateKey(privateKeyPem: string, identityId = 'default'): void {
    if (this.keys.has(identityId)) {
      return;
    }
    this.keys.set(identityId, privateKeyPem);
  }
}

/**
 * FileSystemKeyStore stores identity keys with restricted POSIX permissions (0600).
 * Configurable with a custom directory path or AAMARVA_KEY_STORE_PATH env.
 */
export class FileSystemKeyStore implements KeyStore {
  private baseDir: string;

  constructor(baseDir?: string) {
    this.baseDir = baseDir || process.env.AAMARVA_KEY_STORE_PATH || path.join(os.homedir(), '.aamarva', 'keys');
  }

  public loadPrivateKey(identityId = 'default'): string | null {
    if (!this.baseDir) return null;
    const keyPath = path.join(this.baseDir, `${identityId}.pem`);
    if (fs.existsSync(keyPath)) {
      return fs.readFileSync(keyPath, 'utf8');
    }
    return null;
  }

  public savePrivateKey(privateKeyPem: string, identityId = 'default'): void {
    if (!this.baseDir) return;
    if (!fs.existsSync(this.baseDir)) {
      fs.mkdirSync(this.baseDir, { recursive: true, mode: 0o700 });
    }
    const keyPath = path.join(this.baseDir, `${identityId}.pem`);
    if (fs.existsSync(keyPath)) {
      return;
    }
    fs.writeFileSync(keyPath, privateKeyPem, { mode: 0o600 });
  }
}

let activeKeyStore: KeyStore = new InMemoryKeyStore();
const identityKeyCache = new Map<string, any>();

export function setKeyStore(store: KeyStore): void {
  activeKeyStore = store;
}

export function getKeyStore(): KeyStore {
  return activeKeyStore;
}

export function resetLocalIdentityKeyPair(): void {
  identityKeyCache.clear();
  activeKeyStore = new InMemoryKeyStore();
}

export function generateECKeyPair(): any {
  return crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
}

export function getLocalIdentityKeyPair(identityId = 'default', epoch?: number): any {
  const effectiveId = epoch !== undefined && epoch !== null ? `${identityId}_epoch_${epoch}` : identityId;
  const cached = identityKeyCache.get(effectiveId);
  if (cached) {
    return cached;
  }

  const storedPem = activeKeyStore.loadPrivateKey(effectiveId);
  if (typeof storedPem === 'string' && storedPem.trim()) {
    try {
      const privateKey = crypto.createPrivateKey({ key: storedPem, format: 'pem', type: 'pkcs8' });
      const publicKey = crypto.createPublicKey(privateKey);
      const kp: any = { privateKey, publicKey };
      identityKeyCache.set(effectiveId, kp);
      return kp;
    } catch (err: any) {
      throw new AamarvaError('Failed to load stored identity key: key is corrupt or invalid format.', {
        code: 'IDENTITY_KEY_INVALID',
        cause: err,
      });
    }
  }

  if (epoch !== undefined && epoch !== null) {
    // Fallback to active key for this identity when historical epoch archive is unavailable
    return getLocalIdentityKeyPair(identityId);
  }

  const kp = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });
  identityKeyCache.set(identityId, kp);
  const privPem = kp.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  activeKeyStore.savePrivateKey(privPem, identityId);
  return kp;
}

export function getLocalPublicKeyPem(identityId = 'default', epoch?: number): string {
  const kp = getLocalIdentityKeyPair(identityId, epoch);
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
    return {
      kty: 'EC',
      crv: 'P-256',
      x: String(keyOrKp.x),
      y: String(keyOrKp.y),
    };
  } else {
    throw new AamarvaError('Invalid key object provided for JWK export.', { code: 'INVALID_PEER_KEY' });
  }

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
 * Normalize an AAMARVA Agent ID cleanly (trim, strip leading '@', uppercase).
 */
export function normalizeAgentId(agentId?: string | null): string {
  return String(agentId || '').trim().replace(/^@+/, '').trim().toUpperCase();
}

/**
 * Deduplicate, normalize, and lexicographically sort agent IDs.
 */
export function canonicalMemberSet(agentIds: Iterable<string>): string[] {
  const set = new Set<string>();
  for (const id of agentIds) {
    const norm = normalizeAgentId(id);
    if (norm) set.add(norm);
  }
  return Array.from(set).sort();
}

/**
 * Exact fingerprint calculation: SHA-256 hash of canonical P-256 JWK.
 */
export function computeKeyFingerprint(key: ECJWK | string | crypto.KeyObject | any): string {
  try {
    const pubKey = importPublicKey(key);
    const jwk = pubKey.export({ format: 'jwk' });
    const canonicalJwk = JSON.stringify({
      crv: "P-256",
      kty: "EC",
      x: jwk.x,
      y: jwk.y
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

/**
 * Compute full SHA-256 fingerprint of raw 32-byte AES cluster group key.
 * Format: SHA256:AA:BB:CC:...
 */
export function computeGroupKeyFingerprint(rawKey: Buffer | Uint8Array): string {
  const hash = crypto.createHash('sha256').update(rawKey).digest('hex').toUpperCase();
  return 'SHA256:' + hash.match(/.{1,2}/g)!.join(':');
}

/**
 * Compute canonical cluster roster hash: RST:<32-HEX>
 */
export function computeRosterHash(activeIds: Iterable<string>): string {
  const canonical = canonicalMemberSet(activeIds);
  const hash = crypto.createHash('sha256').update(canonical.join(','), 'utf8').digest('hex').toUpperCase();
  return `RST:${hash.slice(0, 32)}`;
}

/**
 * Compute subgroup audience scope hash: 'ALL' or 'AUD:<32-HEX>'
 */
export function computeAudienceHash(recipientIds: Iterable<string>, allActiveIds: Iterable<string>): string {
  const canonRec = canonicalMemberSet(recipientIds);
  const canonAll = canonicalMemberSet(allActiveIds);
  if (canonRec.length === 0) {
    return 'ALL';
  }
  if (canonAll.length > 0) {
    const recSet = new Set(canonRec);
    if (canonAll.every((id) => recSet.has(id))) {
      return 'ALL';
    }
  }
  const hash = crypto.createHash('sha256').update(canonRec.join(','), 'utf8').digest('hex').toUpperCase();
  return `AUD:${hash.slice(0, 32)}`;
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
  return `AAMARVA-KEY-BINDING:v1:${normalizeAgentId(agentId)}:${fingerprint.trim()}`;
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
    const sig = crypto.sign('SHA256', Buffer.from(bindingString, 'utf8'), privKey);
    return sig.toString('base64');
  } catch (err: any) {
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
    const sigBuf = Buffer.from(signatureBase64, 'base64');
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

export const WORKFLOW_HKDF_SALT = 'aamarva-e2ee-channel-v1';

/**
 * Derive 32-byte AES-GCM key via HKDF-SHA256 using Workflow 1 parameters:
 * Salt: "aamarva-e2ee-channel-v1", Info: "aamarva-channel:<connectionId>"
 */
export function deriveConnectionAesKey(sharedSecret: Buffer, connectionId: string): Buffer {
  if (!connectionId) {
    throw new AamarvaError('Connection ID is required for key derivation.', { code: 'MESSAGE_ENCRYPTION_FAILED' });
  }
  try {
    const derived = crypto.hkdfSync(
      'sha256',
      sharedSecret,
      Buffer.from(WORKFLOW_HKDF_SALT, 'utf8'),
      Buffer.from(`aamarva-channel:${connectionId}`, 'utf8'),
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

/**
 * Canonical Workflow 1 direct message AAD string:
 * AAMARVA:E2EE:v1:<connectionId>:<NORMALIZED_SENDER_AGENT_ID>
 */
export function createDirectMessageAadV1(connectionId: string, senderAgentId?: string): string {
  const normSender = normalizeAgentId(senderAgentId) || 'AGENT';
  return `AAMARVA:E2EE:v1:${connectionId}:${normSender}`;
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
  keyEpoch: number = 1,
  senderAgentId?: string
): EncryptedEnvelope {
  if (typeof plaintext !== 'string') {
    throw new AamarvaError('Message payload must be a string.', { code: 'MESSAGE_ENCRYPTION_FAILED' });
  }
  verifyPeerKey(peerKey, expectedFingerprint, peerAgentId, peerSignature, peerIdentityKey);
  const sharedSecret = deriveSharedSecret(localPrivateKey, peerKey);
  const aesKey = deriveConnectionAesKey(sharedSecret, connectionId);

  const nonce = crypto.randomBytes(12);
  const aad = createDirectMessageAadV1(connectionId, senderAgentId);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, nonce);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const encryptedBuf = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const combined = Buffer.concat([encryptedBuf, authTag]);

  return {
    ciphertext: combined.toString('base64'),
    nonce: nonce.toString('base64'),
    version: 1,
    keyEpoch: Number(keyEpoch) || 1,
  };
}

export function decryptMessageWithKeys(
  envelope: { ciphertext?: string; nonce?: string; version?: number; keyEpoch?: number; senderAgentId?: string },
  connectionId: string,
  localPrivateKey: any,
  peerKey: ECJWK | string | crypto.KeyObject | any,
  expectedFingerprint: string | undefined,
  peerAgentId: string | undefined,
  peerSignature: string | undefined,
  peerIdentityKey: ECJWK | string | crypto.KeyObject | any,
  senderAgentId?: string
): string {
  if (!envelope || !envelope.ciphertext || !envelope.nonce) {
    throw new AamarvaError('Invalid encrypted message envelope: missing ciphertext or nonce.', {
      code: 'MESSAGE_INVALID_ENVELOPE',
    });
  }
  verifyPeerKey(peerKey, expectedFingerprint, peerAgentId, peerSignature, peerIdentityKey);

  try {
    const sharedSecret = deriveSharedSecret(localPrivateKey, peerKey);
    const aesKey = deriveConnectionAesKey(sharedSecret, connectionId);

    const nonce = Buffer.from(envelope.nonce, 'base64');
    const combined = Buffer.from(envelope.ciphertext, 'base64');

    if (combined.length < 16) {
      throw new AamarvaError('Ciphertext is too short or malformed (missing auth tag).', {
        code: 'MESSAGE_INVALID_ENVELOPE',
      });
    }

    const authTag = combined.subarray(combined.length - 16);
    const ciphertextBuf = combined.subarray(0, combined.length - 16);

    const resolvedSender = senderAgentId !== undefined ? senderAgentId : envelope.senderAgentId;
    const aad = createDirectMessageAadV1(connectionId, resolvedSender);

    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, nonce);
    decipher.setAAD(Buffer.from(aad, 'utf8'));
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
  throw new AamarvaError('Use connection.send() or client.send_message() with E2EE key exchange.', {
    code: 'MESSAGE_ENCRYPTION_FAILED',
  });
}

export function decryptMessage(envelope: any, connectionId: string, agentIdA?: string, agentIdB?: string): string {
  throw new AamarvaError('Use connection.getMessages() with E2EE key exchange.', {
    code: 'MESSAGE_DECRYPTION_FAILED',
  });
}

/**
 * Workflow 2: Cluster Group Key Distribution, Wrapping, AAD & ECDSA Signing
 */
export function generateClusterKey(): Buffer {
  return crypto.randomBytes(32);
}

export function createClusterWrapAadV2(clusterId: string, epoch = 1, audienceHash = 'ALL'): string {
  const scope = audienceHash && audienceHash !== 'ALL' ? `:${audienceHash}` : '';
  return `aamarva-cluster-group-key:${clusterId}:${epoch}${scope}`;
}

export function createClusterMessageAadV2(
  clusterId: string,
  senderAgentId?: string,
  epoch = 1,
  audienceHash = 'ALL'
): string {
  const normSender = normalizeAgentId(senderAgentId) || 'AGENT';
  const scope = audienceHash && audienceHash !== 'ALL' ? `:${audienceHash}` : '';
  return `AAMARVA:E2EE:v2:${clusterId}:${normSender}:${epoch}${scope}`;
}

export interface ClusterSigningPayloadParams {
  clusterId: string;
  keyEpoch: number;
  senderAgentId: string;
  audienceHash?: string;
  rosterHash: string;
  sequence?: string | number | null;
  keyFingerprint: string;
  nonce: string;
  ciphertext: string;
}

export function createClusterSigningPayloadV2(params: ClusterSigningPayloadParams): string {
  return [
    'AAMARVA:CLUSTER_MSG:v2',
    params.clusterId.trim(),
    String(params.keyEpoch),
    normalizeAgentId(params.senderAgentId),
    params.audienceHash || 'ALL',
    params.rosterHash,
    params.sequence === undefined || params.sequence === null ? '' : String(params.sequence),
    params.keyFingerprint,
    params.nonce,
    params.ciphertext,
  ].join('|');
}

/**
 * Sign a Workflow 2 cluster message envelope with ECDSA P-256 SHA-256
 * producing an IEEE P1363 (64-byte r || s) Base64 signature compatible with WebCrypto subtle.sign.
 */
export function signClusterMessageV2(privateKeyPemOrKey: any, params: ClusterSigningPayloadParams): string {
  const payload = createClusterSigningPayloadV2(params);
  try {
    const privKey = typeof privateKeyPemOrKey === 'string'
      ? crypto.createPrivateKey({ key: privateKeyPemOrKey, format: 'pem', type: 'pkcs8' })
      : (privateKeyPemOrKey.privateKey || privateKeyPemOrKey);
    const sig = crypto.sign('SHA256', Buffer.from(payload, 'utf8'), {
      key: privKey,
      dsaEncoding: 'ieee-p1363',
    });
    return sig.toString('base64');
  } catch (err: any) {
    throw new AamarvaError(`Failed to sign cluster message: ${err.message}`, {
      code: 'CLUSTER_MESSAGE_SIGN_FAILED',
      cause: err,
    });
  }
}

export function verifyClusterMessageSignatureV2(
  senderPublicKey: ECJWK | string | crypto.KeyObject | any,
  params: ClusterSigningPayloadParams,
  signatureBase64: string
): boolean {
  if (!signatureBase64 || typeof signatureBase64 !== 'string') {
    return false;
  }
  const payload = createClusterSigningPayloadV2(params);
  try {
    const pubKey = importPublicKey(senderPublicKey);
    const sigBuf = Buffer.from(signatureBase64, 'base64');
    if (sigBuf.length === 64) {
      return crypto.verify(
        'SHA256',
        Buffer.from(payload, 'utf8'),
        { key: pubKey, dsaEncoding: 'ieee-p1363' },
        sigBuf
      );
    }
    return crypto.verify('SHA256', Buffer.from(payload, 'utf8'), pubKey, sigBuf);
  } catch {
    return false;
  }
}

export interface WrapClusterKeyOptions {
  clusterId?: string;
  epoch?: number;
  audienceHash?: string;
  rosterHash?: string;
  keyFingerprint?: string;
  senderAgentId?: string;
  senderPublicKey?: ECJWK;
  recipientAgentId?: string;
  recipientKeyFingerprint?: string;
  recipientKeyEpoch?: number;
}

export function wrapClusterKeyForRecipient(
  clusterKey: Buffer,
  recipientPublicKeyPemOrJwk: any,
  senderPrivateKey: any,
  options: WrapClusterKeyOptions = {}
): {
  encryptedKeyPackage: Record<string, unknown>;
  nonce: string;
  ciphertext: string;
  keyFingerprint: string;
  aad: string;
  wrappingParams: Record<string, unknown>;
} {
  const clusterId = options.clusterId || 'default';
  const epoch = options.epoch || 1;
  const audienceHash = options.audienceHash || 'ALL';
  const hkdfSalt = WORKFLOW_HKDF_SALT;
  const hkdfInfo = `aamarva-channel:${clusterId}`;
  const wrapAad = createClusterWrapAadV2(clusterId, epoch, audienceHash);
  const keyFingerprint = options.keyFingerprint || computeGroupKeyFingerprint(clusterKey);

  const recipientKey = typeof recipientPublicKeyPemOrJwk === 'string'
    ? importPublicKey(recipientPublicKeyPemOrJwk)
    : (recipientPublicKeyPemOrJwk?.publicKey ? recipientPublicKeyPemOrJwk.publicKey : importPublicKey(recipientPublicKeyPemOrJwk));

  const sharedSecret = deriveSharedSecret(senderPrivateKey, recipientKey);
  const wrapKey = crypto.hkdfSync(
    'sha256',
    sharedSecret,
    Buffer.from(hkdfSalt, 'utf8'),
    Buffer.from(hkdfInfo, 'utf8'),
    32
  );
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(wrapKey), iv);
  cipher.setAAD(Buffer.from(wrapAad, 'utf8'));
  const encryptedBuf = Buffer.concat([cipher.update(clusterKey), cipher.final(), cipher.getAuthTag()]);
  const ctB64 = encryptedBuf.toString('base64');
  const ivB64 = iv.toString('base64');

  const senderPubJwk =
    options.senderPublicKey ||
    (senderPrivateKey?.publicKey ? exportPublicKeyJWK(senderPrivateKey.publicKey) : undefined);

  const packageObj: Record<string, unknown> = {
    iv: ivB64,
    key: ctB64,
    epoch,
    clusterId,
    audienceHash,
    ...(options.rosterHash ? { rosterHash: options.rosterHash } : {}),
    keyFingerprint,
    ...(options.senderAgentId ? { senderAgentId: options.senderAgentId } : {}),
    ...(senderPubJwk ? { senderPublicKey: senderPubJwk } : {}),
    ...(options.recipientAgentId ? { recipientAgentId: options.recipientAgentId } : {}),
    ...(options.recipientKeyFingerprint ? { recipientKeyFingerprint: options.recipientKeyFingerprint } : {}),
    ...(options.recipientKeyEpoch !== undefined ? { recipientKeyEpoch: options.recipientKeyEpoch } : {}),
    aad: wrapAad,
    hkdfSalt,
    hkdfInfo,
  };

  return {
    encryptedKeyPackage: packageObj,
    nonce: ivB64,
    ciphertext: ctB64,
    keyFingerprint,
    aad: wrapAad,
    wrappingParams: {
      algorithm: 'ECDH-ES+HKDF-256+A256GCM',
      alg: 'ECDH-ES+A256GCM',
      curve: 'P-256',
      hkdfHash: 'SHA-256',
      hkdfSalt,
      hkdfInfo,
      aad: wrapAad,
    },
  };
}

export interface UnwrapClusterKeyOptions {
  clusterId?: string;
  epoch?: number;
  audienceHash?: string;
  expectedKeyFingerprint?: string;
  aad?: string;
  hkdfSalt?: string;
  hkdfInfo?: string;
}

export function unwrapClusterKey(
  encryptedKeyPackage: string | Record<string, unknown>,
  nonceBase64: string,
  recipientPrivateKey: any,
  senderPublicKeyPemOrJwk: any,
  options: UnwrapClusterKeyOptions = {}
): Buffer {
  let pkgObj: Record<string, unknown> | null = null;
  if (encryptedKeyPackage && typeof encryptedKeyPackage === 'object') {
    pkgObj = encryptedKeyPackage;
  } else if (typeof encryptedKeyPackage === 'string' && encryptedKeyPackage.trim().startsWith('{')) {
    try {
      pkgObj = JSON.parse(encryptedKeyPackage);
    } catch {
      pkgObj = null;
    }
  }

  const ctB64 = String(pkgObj?.key || pkgObj?.ciphertext || (typeof encryptedKeyPackage === 'string' ? encryptedKeyPackage : ''));
  const ivB64 = String(pkgObj?.iv || nonceBase64 || '');

  if (!ctB64 || !ivB64) {
    throw new AamarvaError('Cluster key package is missing ciphertext or iv/nonce.', {
      code: 'CLUSTER_KEY_UNWRAP_FAILED',
    });
  }

  const clusterId = String(pkgObj?.clusterId || options.clusterId || 'default');
  const epoch = Number(pkgObj?.epoch || options.epoch || 1);
  const audienceHash = String(pkgObj?.audienceHash || options.audienceHash || 'ALL');
  const hkdfSalt = String(pkgObj?.hkdfSalt || options.hkdfSalt || WORKFLOW_HKDF_SALT);
  const hkdfInfo = String(pkgObj?.hkdfInfo || options.hkdfInfo || `aamarva-channel:${clusterId}`);
  const wrapAad = String(pkgObj?.aad || options.aad || createClusterWrapAadV2(clusterId, epoch, audienceHash));

  const senderKey = typeof senderPublicKeyPemOrJwk === 'string'
    ? importPublicKey(senderPublicKeyPemOrJwk)
    : (senderPublicKeyPemOrJwk?.publicKey ? senderPublicKeyPemOrJwk.publicKey : importPublicKey(senderPublicKeyPemOrJwk));

  const sharedSecret = deriveSharedSecret(recipientPrivateKey, senderKey);
  const wrapKey = crypto.hkdfSync(
    'sha256',
    sharedSecret,
    Buffer.from(hkdfSalt, 'utf8'),
    Buffer.from(hkdfInfo, 'utf8'),
    32
  );
  const iv = Buffer.from(ivB64, 'base64');
  const combined = Buffer.from(ctB64, 'base64');

  if (combined.length < 16) {
    throw new AamarvaError('Cluster key package is too short or malformed.', {
      code: 'CLUSTER_KEY_UNWRAP_FAILED',
    });
  }

  const authTag = combined.subarray(combined.length - 16);
  const ciphertextBuf = combined.subarray(0, combined.length - 16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(wrapKey), iv);
  if (wrapAad) {
    decipher.setAAD(Buffer.from(wrapAad, 'utf8'));
  }
  decipher.setAuthTag(authTag);

  let rawKey: Buffer;
  try {
    rawKey = Buffer.concat([decipher.update(ciphertextBuf), decipher.final()]);
  } catch (err: any) {
    throw new AamarvaError(`Failed to unwrap cluster key: ${err.message}`, {
      code: 'CLUSTER_KEY_UNWRAP_FAILED',
      cause: err,
    });
  }

  const expectedFp = options.expectedKeyFingerprint || (typeof pkgObj?.keyFingerprint === 'string' ? pkgObj.keyFingerprint : undefined);
  if (expectedFp && /^SHA256:([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(expectedFp)) {
    const actualFp = computeGroupKeyFingerprint(rawKey);
    if (actualFp !== expectedFp) {
      throw new AamarvaError(
        `Cluster group key fingerprint mismatch: expected ${expectedFp}, got ${actualFp}.`,
        { code: 'CLUSTER_KEY_FINGERPRINT_MISMATCH' }
      );
    }
  }

  return rawKey;
}

export function encryptClusterMessagePayload(
  plaintext: string,
  clusterKey: Buffer,
  clusterId: string,
  epoch = 1,
  audienceHash = 'ALL',
  senderAgentId?: string
): { ciphertext: string; nonce: string; version: number; keyEpoch: number; audienceHash: string } {
  const iv = crypto.randomBytes(12);
  const aad = createClusterMessageAadV2(clusterId, senderAgentId, epoch, audienceHash);
  const cipher = crypto.createCipheriv('aes-256-gcm', clusterKey, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));

  const ciphertextBuf = Buffer.concat([
    cipher.update(Buffer.from(plaintext, 'utf8')),
    cipher.final(),
    cipher.getAuthTag(),
  ]);

  return {
    ciphertext: ciphertextBuf.toString('base64'),
    nonce: iv.toString('base64'),
    version: 2,
    keyEpoch: epoch,
    audienceHash: audienceHash || 'ALL',
  };
}

export function decryptClusterMessagePayload(
  ciphertextBase64: string,
  nonceBase64: string,
  clusterKey: Buffer,
  clusterId: string,
  epoch = 1,
  version = 2,
  audienceHash = 'ALL',
  senderAgentId?: string
): string {
  const iv = Buffer.from(nonceBase64, 'base64');
  const combined = Buffer.from(ciphertextBase64, 'base64');

  if (combined.length < 16) {
    throw new AamarvaError('Cluster ciphertext is too short or malformed.', {
      code: 'CLUSTER_MESSAGE_DECRYPTION_FAILED',
    });
  }

  const authTag = combined.subarray(combined.length - 16);
  const ciphertextBuf = combined.subarray(0, combined.length - 16);
  const aad = createClusterMessageAadV2(clusterId, senderAgentId, epoch, audienceHash);

  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', clusterKey, iv);
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(authTag);

    return Buffer.concat([decipher.update(ciphertextBuf), decipher.final()]).toString('utf8');
  } catch (err: any) {
    throw new AamarvaError(`Failed to decrypt cluster message: ${err.message}`, {
      code: 'CLUSTER_MESSAGE_DECRYPTION_FAILED',
      cause: err,
    });
  }
}


