/**
 * Active Connection Channel abstraction for peer-to-peer messaging.
 */

import { HttpClient } from './http.js';
import { Connection, Message, SendMessageOptions } from './types.js';
import { normalizeMessage } from './normalize.js';
import { AamarvaValidationError, AamarvaError } from './errors.js';
import {
  getLocalIdentityKeyPair,
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
  public readonly status: string;
  public readonly createdAt?: string;
  private http: HttpClient;

  constructor(connection: Connection, http: HttpClient) {
    if (!connection.connectionId) {
      throw new AamarvaValidationError('A valid connectionId is required to construct an AamarvaConnection.');
    }
    this.connectionId = connection.connectionId;
    this.agentId = connection.agentId;
    this.status = connection.status || 'active';
    this.createdAt = connection.createdAt;
    this.http = http;
  }

  private resolveMyAgentId(): string {
    const httpAny = this.http as any;
    const fromGetter = typeof httpAny?.getAgentId === 'function' ? httpAny.getAgentId() : undefined;
    const fromProp = typeof httpAny?.agentId === 'string' ? httpAny.agentId : undefined;
    return (fromGetter || fromProp || 'me').trim() || 'me';
  }

  private async fetchVerifiedPeerKey(expectedPeerAgentId?: string): Promise<{
    rawPeerKey: any;
    peerFp: string | undefined;
    peerEpoch: number;
    peerIdentityKey: any;
    peerSignature: string | undefined;
    actualPeerAgentId: string;
  }> {
    let peerRes: any;
    try {
      peerRes = await this.http.request<any>({
        method: 'GET',
        path: `/connections/${encodeURIComponent(this.connectionId)}/peer-key`,
        auth: true,
      });
    } catch (primaryErr: any) {
      const targetId = (expectedPeerAgentId || this.agentId || '').trim();
      const statusCode = primaryErr?.statusCode ?? primaryErr?.status;
      if (targetId && (statusCode === 404 || primaryErr?.code === 'NOT_FOUND')) {
        peerRes = await this.http.request<any>({
          method: 'GET',
          path: `/connections/peer-key/${encodeURIComponent(targetId)}`,
          auth: true,
        });
      } else {
        throw primaryErr;
      }
    }

    const peerData = peerRes.data || peerRes || {};
    if (peerData.connectionId && String(peerData.connectionId).trim() !== this.connectionId.trim()) {
      throw new AamarvaError('Connection ID mismatch in peer key response.', {
        code: 'PEER_KEY_VERIFICATION_FAILED',
      });
    }
    const rawPeerKey = peerData.peerE2eePublicKey || peerData.e2eePublicKey || peerData.publicKey;
    const peerFp = peerData.peerKeyFingerprint || peerData.keyFingerprint || peerData.fingerprint;
    const peerIdentityKey = peerData.peerIdentityKey || peerData.identityKey;
    const peerSignature = peerData.peerKeySignature || peerData.signature;
    const rawPeerEpoch = peerData.peerKeyEpoch !== undefined ? peerData.peerKeyEpoch : peerData.keyEpoch;
    let peerEpoch: number | undefined;
    if (typeof rawPeerEpoch === 'number' && Number.isInteger(rawPeerEpoch) && rawPeerEpoch >= 1) {
      peerEpoch = rawPeerEpoch;
    } else if (typeof rawPeerEpoch === 'string' && /^\d+$/.test(rawPeerEpoch.trim())) {
      const parsed = Number(rawPeerEpoch.trim());
      if (Number.isInteger(parsed) && parsed >= 1) peerEpoch = parsed;
    }
    if (peerEpoch === undefined) {
      throw new AamarvaError('Missing or invalid peerKeyEpoch in peer key response.', {
        code: 'PEER_KEY_VERIFICATION_FAILED',
      });
    }
    const actualPeerAgentId = peerData.peerAgentId || peerData.agentId;

    if (!rawPeerKey) {
      throw new AamarvaError('Peer public key unavailable for connection.', {
        code: 'PEER_KEY_UNAVAILABLE',
      });
    }

    if (!actualPeerAgentId) {
      throw new AamarvaError('Missing peerAgentId in peer key response.', {
        code: 'PEER_KEY_VERIFICATION_FAILED',
      });
    }
    if (expectedPeerAgentId && actualPeerAgentId.trim().toUpperCase() !== expectedPeerAgentId.trim().toUpperCase()) {
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

    return {
      rawPeerKey,
      peerFp,
      peerEpoch,
      peerIdentityKey,
      peerSignature,
      actualPeerAgentId,
    };
  }

  /**
   * Send an encrypted private message to the connected peer agent using E2EE
   * @param options Message string or object with message/content property
   */
  public async send(options: string | SendMessageOptions): Promise<Message> {
    const content = (typeof options === 'string' ? options : options.message || options.content || '').trim();
    if (!content) {
      throw new AamarvaValidationError('Message content cannot be empty.', {
        hint: 'Provide a non-empty string for the message payload.',
      });
    }

    const myAgentId = this.resolveMyAgentId();
    const localKp = getLocalIdentityKeyPair(myAgentId);
    const localPubJwk = exportPublicKeyJWK(localKp.publicKey);
    const localFp = computeKeyFingerprint(localPubJwk);
    const localSignature = signIdentityBinding(localKp.privateKey, myAgentId, localFp);

    // 1. Register local E2EE public key using PUT /api/agents/me/e2ee
    try {
      await this.http.request({
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
      });
    } catch (err: any) {
      throw new AamarvaError(`E2EE key registration failed: ${err.message}`, {
        code: 'E2EE_KEY_REGISTRATION_FAILED',
        cause: err,
      });
    }

    // 2. Fetch and verify peer public key
    const expectedPeerAgentId = (typeof options === 'object' && options.peerAgentId) || this.agentId;
    let peerInfo;
    try {
      peerInfo = await this.fetchVerifiedPeerKey(expectedPeerAgentId);
    } catch (err: any) {
      if (err instanceof AamarvaError) throw err;
      throw new AamarvaError(`Failed to fetch peer public key: ${err.message}`, {
        code: 'PEER_KEY_VERIFICATION_FAILED',
        cause: err,
      });
    }

    const envelope = encryptMessageWithKeys(
      content,
      this.connectionId,
      localKp.privateKey,
      peerInfo.rawPeerKey,
      peerInfo.peerFp,
      peerInfo.actualPeerAgentId,
      peerInfo.peerSignature,
      peerInfo.peerIdentityKey,
      peerInfo.peerEpoch,
      myAgentId
    );

    const response = await this.http.request<unknown>({
      method: 'POST',
      path: `/connections/${encodeURIComponent(this.connectionId)}/messages`,
      body: envelope,
      auth: true,
    });

    const msg = normalizeMessage(response.data, this.connectionId);
    msg.content = content;
    return msg;
  }

  /**
   * Retrieve normalized and decrypted message list for this connection channel
   */
  public async getMessages(options: { page?: number; limit?: number; peerAgentId?: string } = {}): Promise<Message[]> {
    let peerInfo;
    try {
      peerInfo = await this.fetchVerifiedPeerKey(options.peerAgentId || this.agentId);
    } catch (err: any) {
      if (err instanceof AamarvaError) throw err;
      throw new AamarvaError(`Failed to fetch peer public key for decryption: ${err.message}`, {
        code: 'PEER_KEY_VERIFICATION_FAILED',
        cause: err,
      });
    }

    const response = await this.http.request<unknown[]>({
      method: 'GET',
      path: `/connections/${encodeURIComponent(this.connectionId)}/messages`,
      query: {
        page: options.page || 1,
        limit: options.limit || 50,
      },
      auth: true,
    });

    const rawList = Array.isArray(response.data) ? response.data : [];
    const myAgentId = this.resolveMyAgentId();

    return rawList.map((item) => {
      const msg = normalizeMessage(item, this.connectionId);
      if (msg.connectionId && msg.connectionId.trim() !== this.connectionId.trim()) {
        throw new AamarvaError('Connection ID mismatch in encrypted message envelope.', {
          code: 'MESSAGE_INVALID_ENVELOPE',
        });
      }
      if (msg.ciphertext && msg.nonce) {
        try {
          const localKp = getLocalIdentityKeyPair(myAgentId, msg.keyEpoch);
          msg.content = decryptMessageWithKeys(
            {
              ciphertext: msg.ciphertext,
              nonce: msg.nonce,
              version: msg.version,
              keyEpoch: msg.keyEpoch,
              senderAgentId: msg.senderAgentId,
            },
            this.connectionId,
            localKp.privateKey,
            peerInfo.rawPeerKey,
            peerInfo.peerFp,
            peerInfo.actualPeerAgentId,
            peerInfo.peerSignature,
            peerInfo.peerIdentityKey,
            msg.senderAgentId || peerInfo.actualPeerAgentId
          );
        } catch (err: any) {
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
  public async messages(options: { page?: number; limit?: number; peerAgentId?: string } = {}): Promise<Message[]> {
    return this.getMessages(options);
  }

  /**
   * Retrieve raw encrypted transport message envelopes directly from the backend
   */
  public async getEncryptedMessages(options: { page?: number; limit?: number } = {}): Promise<EncryptedEnvelope[]> {
    const response = await this.http.request<unknown[]>({
      method: 'GET',
      path: `/connections/${encodeURIComponent(this.connectionId)}/messages`,
      query: {
        page: options.page || 1,
        limit: options.limit || 50,
      },
      auth: true,
    });

    const rawList = Array.isArray(response.data) ? response.data : [];
    return rawList.map((item: any) => {
      const msg = normalizeMessage(item, this.connectionId);
      return {
        ciphertext: msg.ciphertext!,
        nonce: msg.nonce!,
        version: msg.version!,
        keyEpoch: msg.keyEpoch!,
      };
    });
  }
}

