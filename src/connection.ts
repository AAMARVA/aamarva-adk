/**
 * Active Connection Channel abstraction for peer-to-peer E2EE messaging.
 * Routes through /connections/peer-key/:accountId and /connections/messages/:accountId
 * while binding HKDF and AES-256-GCM AAD to the canonical connectionId.
 */

import { HttpClient } from './http.js';
import { Connection, Message, PeerEpochKeyEntry, SendMessageOptions } from './types.js';
import { normalizeMessage } from './normalize.js';
import { AamarvaValidationError, AamarvaError } from './errors.js';
import {
  getLocalIdentitySigningKeyPair,
  getLocalEcdhKeyPair,
  findLocalEcdhKeyPair,
  getLatestLocalEcdhEpoch,
  exportPublicKeyJWK,
  computeKeyFingerprint,
  signIdentityBinding,
  verifyPeerKey,
  encryptMessageWithKeys,
  decryptMessageWithKeys,
  EncryptedEnvelope,
} from './crypto.js';

export class AamarvaConnection {
  public readonly connectionId: string;
  public readonly agentId: string;
  public readonly peerAccountId?: string;
  public readonly peerAgentId?: string;
  public readonly status: string;
  public readonly createdAt?: string;
  public readonly connectedAgentName?: string;
  public readonly updatedAt?: string;
  private http: HttpClient;

  constructor(connection: Connection, http: HttpClient) {
    if (!connection.connectionId && !connection.peerAccountId && !connection.peerAgentId && !connection.agentId) {
      throw new AamarvaValidationError('A valid connectionId or peerAccountId is required to construct an AamarvaConnection.');
    }
    this.connectionId = connection.connectionId || connection.peerAccountId || connection.peerAgentId || connection.agentId;
    this.peerAccountId = connection.peerAccountId || connection.peerAgentId || connection.agentId || undefined;
    this.peerAgentId = connection.peerAgentId || connection.peerAccountId || connection.agentId || undefined;
    this.agentId = connection.agentId || connection.peerAccountId || connection.peerAgentId || '';
    this.status = connection.status || 'active';
    this.createdAt = connection.createdAt;
    this.connectedAgentName = connection.connectedAgentName;
    this.updatedAt = connection.updatedAt;
    this.http = http;
  }

  private async resolveMyAgentId(): Promise<string> {
    const httpAny = this.http as any;
    const targetId = typeof httpAny?.getTargetAgentId === 'function' ? httpAny.getTargetAgentId() : undefined;
    const baseId = typeof httpAny?.getAgentId === 'function' ? httpAny.getAgentId() : httpAny?.agentId;
    const configured = (targetId || baseId || '').trim();
    if (configured) {
      return configured;
    }

    try {
      const meRes = await this.http.request<any>({
        method: 'GET',
        path: '/agents/me',
        auth: true,
        skipAutoAuth: true,
      });
      const meData = meRes.data || {};
      const resolved = String(meData.agentId || meData.id || '').trim();
      if (resolved) {
        return resolved;
      }
    } catch {
      // handled below
    }

    throw new AamarvaError('Authenticated agent identity could not be resolved for E2EE operation.', {
      code: 'E2EE_KEY_REGISTRATION_FAILED',
    });
  }

  private resolveAccountId(explicitPeerId?: string): string {
    const candidate = (explicitPeerId || this.peerAccountId || this.peerAgentId || this.agentId || '').trim();
    if (candidate) {
      return candidate;
    }
    throw new AamarvaValidationError('Peer accountId is required for direct connection messaging.');
  }

  private async fetchAndVerifyPeerKeys(accountId: string, expectedPeerAgentId?: string): Promise<{
    canonicalConnectionId: string;
    rawPeerKey: any;
    peerFp: string | undefined;
    peerIdentityKey: any;
    peerSignature: string | undefined;
    peerEpoch: number;
    actualPeerAgentId: string;
    peerEpochHistory: PeerEpochKeyEntry[];
  }> {
    const encodedAccount = encodeURIComponent(accountId);
    const peerRes = await this.http.request<any>({
      method: 'GET',
      path: `/connections/peer-key/${encodedAccount}`,
      auth: true,
    });
    const peerData = peerRes.data || peerRes || {};
    const rawPeerKey = peerData.peerE2eePublicKey;
    const peerFp = peerData.peerKeyFingerprint;
    const peerIdentityKey = peerData.peerIdentityKey;
    const peerSignature = peerData.peerKeySignature;
    const rawPeerEpoch = peerData.peerKeyEpoch ?? peerData.peerKeyVersion;
    if (rawPeerEpoch !== undefined && (!Number.isInteger(Number(rawPeerEpoch)) || Number(rawPeerEpoch) < 1)) {
      throw new AamarvaError('Invalid peer key epoch returned by server.', {
        code: 'PEER_KEY_VERIFICATION_FAILED',
      });
    }
    const peerEpoch = rawPeerEpoch !== undefined ? Number(rawPeerEpoch) : 1;
    const actualPeerAgentId = peerData.peerAgentId || peerData.peerAccountId;
    const canonicalConnectionId =
      typeof peerData.connectionId === 'string' && peerData.connectionId.trim()
        ? peerData.connectionId.trim()
        : this.connectionId;

    if (!rawPeerKey) {
      throw new AamarvaError('Peer public key unavailable for connection.', {
        code: 'PEER_KEY_UNAVAILABLE',
      });
    }

    if (!actualPeerAgentId || typeof actualPeerAgentId !== 'string' || !actualPeerAgentId.trim()) {
      throw new AamarvaError('Missing peerAgentId in peer key response.', {
        code: 'PEER_KEY_VERIFICATION_FAILED',
      });
    }

    const expected = (expectedPeerAgentId || accountId || '').trim();
    if (expected && actualPeerAgentId.trim().toUpperCase() !== expected.toUpperCase()) {
      throw new AamarvaError('Peer identity mismatch for public key binding.', {
        code: 'PEER_KEY_VERIFICATION_FAILED',
      });
    }

    if (!peerIdentityKey || !peerSignature) {
      throw new AamarvaError('Missing peer identity binding material.', {
        code: 'PEER_KEY_VERIFICATION_FAILED',
      });
    }

    verifyPeerKey(rawPeerKey, peerFp, actualPeerAgentId, peerSignature, peerIdentityKey);

    const rawHistory = Array.isArray(peerData.peerEpochHistory)
      ? peerData.peerEpochHistory
      : Array.isArray(peerData.peerEpochKeys)
      ? peerData.peerEpochKeys
      : [];

    return {
      canonicalConnectionId,
      rawPeerKey,
      peerFp,
      peerIdentityKey,
      peerSignature,
      peerEpoch,
      actualPeerAgentId: actualPeerAgentId.trim(),
      peerEpochHistory: rawHistory,
    };
  }

  /**
   * Send an encrypted private message to the connected peer agent using E2EE.
   */
  public async send(options: string | SendMessageOptions): Promise<Message> {
    const content = (typeof options === 'string' ? options : options.message || options.content || '').trim();
    if (!content) {
      throw new AamarvaValidationError('Message content cannot be empty.', {
        hint: 'Provide a non-empty string for the message payload.',
      });
    }

    const explicitPeer = typeof options === 'object' ? options.peerAgentId : undefined;
    const accountId = this.resolveAccountId(explicitPeer);
    const myAgentId = await this.resolveMyAgentId();

    const localEpoch = getLatestLocalEcdhEpoch(myAgentId);
    const localEcdhKp = getLocalEcdhKeyPair(myAgentId, localEpoch);
    const localIdentityKp = getLocalIdentitySigningKeyPair(myAgentId);

    const localPubJwk = exportPublicKeyJWK(localEcdhKp.publicKey);
    const localIdentityJwk = exportPublicKeyJWK(localIdentityKp.publicKey);
    const localFp = computeKeyFingerprint(localPubJwk);
    const localSignature = signIdentityBinding(localIdentityKp.privateKey, myAgentId, localFp);

    // 1. Register local E2EE public key using PUT /api/agents/me/e2ee (fail closed on rejection)
    try {
      await this.http.request({
        method: 'PUT',
        path: '/agents/me/e2ee',
        body: {
          publicKey: localPubJwk,
          fingerprint: localFp,
          identityKey: localIdentityJwk,
          signature: localSignature,
          allowRotation: false,
          keyVersion: localEpoch,
          keyEpoch: localEpoch,
        },
        auth: true,
      });
    } catch (err: any) {
      throw new AamarvaError(`E2EE key registration failed: ${err.message}`, {
        code: 'E2EE_KEY_REGISTRATION_FAILED',
        cause: err,
      });
    }

    // 2. Fetch and verify peer public key
    let peerInfo;
    try {
      peerInfo = await this.fetchAndVerifyPeerKeys(accountId, explicitPeer);
    } catch (err: any) {
      if (err instanceof AamarvaError) throw err;
      throw new AamarvaError(`Failed to fetch peer public key: ${err.message}`, {
        code: 'PEER_KEY_VERIFICATION_FAILED',
        cause: err,
      });
    }

    const envelope = encryptMessageWithKeys(
      content,
      peerInfo.canonicalConnectionId,
      localEcdhKp.privateKey,
      peerInfo.rawPeerKey,
      peerInfo.peerFp,
      peerInfo.actualPeerAgentId,
      peerInfo.peerSignature,
      peerInfo.peerIdentityKey,
      peerInfo.peerEpoch
    );

    const encodedAccount = encodeURIComponent(accountId);
    const response = await this.http.request<unknown>({
      method: 'POST',
      path: `/connections/messages/${encodedAccount}`,
      body: envelope,
      auth: true,
    });

    const msg = normalizeMessage(response.data, peerInfo.canonicalConnectionId);
    msg.content = content;
    return msg;
  }

  /**
   * Retrieve normalized and decrypted message list for this connection channel.
   */
  public async getMessages(options: { page?: number; limit?: number; since?: string } = {}): Promise<Message[]> {
    const accountId = this.resolveAccountId();

    let peerInfo;
    try {
      peerInfo = await this.fetchAndVerifyPeerKeys(accountId);
    } catch (err: any) {
      if (err instanceof AamarvaError) throw err;
      throw new AamarvaError(`Failed to fetch peer public key for decryption: ${err.message}`, {
        code: 'PEER_KEY_VERIFICATION_FAILED',
        cause: err,
      });
    }

    const query: Record<string, string | number | undefined> = {
      page: options.page || 1,
      limit: options.limit || 50,
    };
    if (options.since) {
      query.since = options.since;
    }

    const encodedAccount = encodeURIComponent(accountId);
    const response = await this.http.request<unknown[]>({
      method: 'GET',
      path: `/connections/messages/${encodedAccount}`,
      query,
      auth: true,
    });

    const rawList = Array.isArray(response.data) ? response.data : [];
    const myAgentId = await this.resolveMyAgentId();
    const activeLocalEpoch = getLatestLocalEcdhEpoch(myAgentId);
    const activeLocalKp = getLocalEcdhKeyPair(myAgentId, activeLocalEpoch);

    return rawList.map((item) => {
      const msg = normalizeMessage(item, peerInfo.canonicalConnectionId);
      if (msg.ciphertext && msg.nonce) {
        const msgEpoch = msg.keyEpoch;
        if (typeof msgEpoch !== 'number' || !Number.isInteger(msgEpoch) || msgEpoch < 1) {
          throw new AamarvaError('Invalid keyEpoch on encrypted direct message.', {
            code: 'MESSAGE_INVALID_ENVELOPE',
          });
        }

        // Resolve peer key for msgEpoch if peer history contains an entry
        let selectedPeerKey = peerInfo.rawPeerKey;
        let selectedPeerFp = peerInfo.peerFp;
        let selectedPeerIdentityKey = peerInfo.peerIdentityKey;
        let selectedPeerSignature = peerInfo.peerSignature;

        const histEntry = peerInfo.peerEpochHistory.find((e) => Number(e.keyEpoch) === msgEpoch);
        if (histEntry) {
          selectedPeerKey = histEntry.publicKey;
          selectedPeerFp = histEntry.fingerprint || peerInfo.peerFp;
          selectedPeerIdentityKey = histEntry.identityKey || peerInfo.peerIdentityKey;
          selectedPeerSignature = histEntry.signature || peerInfo.peerSignature;
          verifyPeerKey(
            selectedPeerKey,
            selectedPeerFp,
            peerInfo.actualPeerAgentId,
            selectedPeerSignature,
            selectedPeerIdentityKey
          );
        }

        // Resolve local ECDH key for msgEpoch if we rotated across epochs
        const localEpochKp = findLocalEcdhKeyPair(myAgentId, msgEpoch);
        const primaryLocalKp = localEpochKp || (msgEpoch === 1 || activeLocalEpoch === 1 ? activeLocalKp : null);

        if (!primaryLocalKp) {
          throw new AamarvaError(
            `Missing local ECDH private key for epoch ${msgEpoch}. Cannot decrypt message.`,
            { code: 'MESSAGE_DECRYPTION_FAILED' }
          );
        }

        const envelopePayload = {
          ciphertext: msg.ciphertext,
          nonce: msg.nonce,
          version: msg.version,
          keyEpoch: msgEpoch,
        };

        try {
          msg.content = decryptMessageWithKeys(
            envelopePayload,
            peerInfo.canonicalConnectionId,
            primaryLocalKp.privateKey,
            selectedPeerKey,
            selectedPeerFp,
            peerInfo.actualPeerAgentId,
            selectedPeerSignature,
            selectedPeerIdentityKey
          );
        } catch (err: any) {
          // If sender rotated their epoch key (or tagged msg with peer epoch), also check active local key with historical/current verified peer key
          if (localEpochKp && localEpochKp !== activeLocalKp) {
            try {
              msg.content = decryptMessageWithKeys(
                envelopePayload,
                peerInfo.canonicalConnectionId,
                activeLocalKp.privateKey,
                selectedPeerKey,
                selectedPeerFp,
                peerInfo.actualPeerAgentId,
                selectedPeerSignature,
                selectedPeerIdentityKey
              );
              return msg;
            } catch {
              // throw original error below
            }
          }
          if (err instanceof AamarvaError) throw err;
          throw new AamarvaError(`Failed to decrypt incoming message: ${err.message}`, {
            code: 'MESSAGE_DECRYPTION_FAILED',
            cause: err,
          });
        }
      }
      return msg;
    });
  }

  /**
   * Alias for getMessages
   */
  public async messages(options: { page?: number; limit?: number; since?: string } = {}): Promise<Message[]> {
    return this.getMessages(options);
  }

  /**
   * Retrieve raw encrypted transport message envelopes directly from the backend.
   */
  public async getEncryptedMessages(options: { page?: number; limit?: number; since?: string } = {}): Promise<EncryptedEnvelope[]> {
    const accountId = this.resolveAccountId();
    const query: Record<string, string | number | undefined> = {
      page: options.page || 1,
      limit: options.limit || 50,
    };
    if (options.since) {
      query.since = options.since;
    }

    const encodedAccount = encodeURIComponent(accountId);
    const response = await this.http.request<unknown[]>({
      method: 'GET',
      path: `/connections/messages/${encodedAccount}`,
      query,
      auth: true,
    });

    const rawList = Array.isArray(response.data) ? response.data : [];
    return rawList.map((item: any) => {
      const version = Number(item.version ?? 1);
      const rawEpoch = item.keyEpoch ?? item.key_epoch ?? item.keyVersion ?? 1;
      const keyEpoch = Number(rawEpoch);
      if (!Number.isInteger(keyEpoch) || keyEpoch < 1) {
        throw new AamarvaError(`Invalid keyEpoch "${String(rawEpoch)}" in message envelope.`, {
          code: 'MESSAGE_INVALID_ENVELOPE',
        });
      }
      return {
        ciphertext: String(item.ciphertext || ''),
        nonce: String(item.nonce || ''),
        version,
        keyEpoch,
      };
    });
  }
}
