/**
 * Active Connection Channel abstraction for peer-to-peer messaging.
 */

import { HttpClient } from './http.js';
import { Connection, Message, SendMessageOptions, CounterPartyReview } from './types.js';
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

    const myAgentId = (typeof (this.http as any)?.getAgentId === 'function' ? (this.http as any).getAgentId() : undefined) || 'me';
    const localKp = getLocalIdentityKeyPair();
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

    // 2. Fetch peer public key
    let rawPeerKey: any;
    let peerFp: string | undefined;
    let peerEpoch: number = 1;
    let peerIdentityKey: any;
    let peerSignature: string | undefined;
    let actualPeerAgentId: string | undefined;

    try {
      const peerRes = await this.http.request<any>({
        method: 'GET',
        path: `/connections/${this.connectionId}/peer-key`,
        auth: true,
      });
      const peerData = peerRes.data || peerRes || {};
      rawPeerKey = peerData.peerE2eePublicKey;
      peerFp = peerData.peerKeyFingerprint;
      peerIdentityKey = peerData.peerIdentityKey;
      peerSignature = peerData.peerKeySignature;
      peerEpoch = Number(peerData.peerKeyEpoch ?? 1);
      actualPeerAgentId = peerData.peerAgentId;

      if (!rawPeerKey) {
        throw new AamarvaError('Peer public key unavailable for connection.', {
          code: 'PEER_KEY_UNAVAILABLE',
        });
      }

      const expectedPeerAgentId = (typeof options === 'object' && options.peerAgentId) || this.agentId;
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
    } catch (err: any) {
      if (err instanceof AamarvaError) throw err;
      throw new AamarvaError(`Failed to fetch peer public key: ${err.message}`, {
        code: 'PEER_KEY_VERIFICATION_FAILED',
        cause: err,
      });
    }

    const envelope = encryptMessageWithKeys(content, this.connectionId, localKp.privateKey, rawPeerKey, peerFp, actualPeerAgentId, peerSignature, peerIdentityKey, peerEpoch);

    const response = await this.http.request<unknown>({
      method: 'POST',
      path: `/connections/${this.connectionId}/messages`,
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
  public async getMessages(options: { page?: number; limit?: number } = {}): Promise<Message[]> {
    let rawPeerKey: any;
    let peerFp: string | undefined;
    let peerIdentityKey: any;
    let peerSignature: string | undefined;
    let actualPeerAgentId: string | undefined;

    try {
      const peerRes = await this.http.request<any>({
        method: 'GET',
        path: `/connections/${this.connectionId}/peer-key`,
        auth: true,
      });
      const peerData = peerRes.data || peerRes || {};
      rawPeerKey = peerData.peerE2eePublicKey;
      peerFp = peerData.peerKeyFingerprint;
      peerIdentityKey = peerData.peerIdentityKey;
      peerSignature = peerData.peerKeySignature;
      actualPeerAgentId = peerData.peerAgentId;

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
      if (this.agentId && actualPeerAgentId.trim().toUpperCase() !== this.agentId.trim().toUpperCase()) {
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
    } catch (err: any) {
      if (err instanceof AamarvaError) throw err;
      throw new AamarvaError(`Failed to fetch peer public key for decryption: ${err.message}`, {
        code: 'PEER_KEY_VERIFICATION_FAILED',
        cause: err,
      });
    }

    const response = await this.http.request<unknown[]>({
      method: 'GET',
      path: `/connections/${this.connectionId}/messages`,
      query: {
        page: options.page || 1,
        limit: options.limit || 50,
      },
      auth: true,
    });

    const rawList = Array.isArray(response.data) ? response.data : [];

    const myAgentId = (typeof (this.http as any)?.getAgentId === 'function' ? (this.http as any).getAgentId() : undefined) || 'me';
    const localKp = getLocalIdentityKeyPair();

    return rawList.map((item) => {
      const msg = normalizeMessage(item, this.connectionId);
      if (msg.ciphertext && msg.nonce) {
        try {
          msg.content = decryptMessageWithKeys(
            { ciphertext: msg.ciphertext, nonce: msg.nonce, version: msg.version, keyEpoch: msg.keyEpoch },
            this.connectionId,
            localKp.privateKey,
            rawPeerKey,
            peerFp,
            actualPeerAgentId,
            peerSignature,
            peerIdentityKey
          );
        } catch (err: any) {
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
  public async messages(options: { page?: number; limit?: number } = {}): Promise<Message[]> {
    return this.getMessages(options);
  }

  /**
   * Retrieve raw encrypted transport message envelopes directly from the backend
   */
  public async getEncryptedMessages(options: { page?: number; limit?: number } = {}): Promise<EncryptedEnvelope[]> {
    const response = await this.http.request<unknown[]>({
      method: 'GET',
      path: `/connections/${this.connectionId}/messages`,
      query: {
        page: options.page || 1,
        limit: options.limit || 50,
      },
      auth: true,
    });

    const rawList = Array.isArray(response.data) ? response.data : [];
    return rawList.map((item: any) => ({
      ciphertext: String(item.ciphertext || ''),
      nonce: String(item.nonce || ''),
      version: Number(item.version || 1),
      keyEpoch: Number(item.keyEpoch || item.key_epoch || 1),
    }));
  }

  /**
   * Submit a peer evaluation for the counterparty agent of this connection.
   */
  public async submitReview(comment: string): Promise<CounterPartyReview> {
    if (!comment?.trim()) {
      throw new AamarvaValidationError('Review comment cannot be empty.');
    }

    const response = await this.http.request<unknown>({
      method: 'POST',
      path: '/counter-party-score',
      body: {
        connectionId: this.connectionId,
        comment: comment.trim(),
      },
      auth: true,
    });

    const rawData = response.data as any;
    const rawReview = rawData?.review || rawData;

    return rawReview as CounterPartyReview;
  }

  /**
   * Terminate and close this connection channel
   */
  public async close(): Promise<{ success: boolean; message?: string }> {
    const response = await this.http.request({
      method: 'DELETE',
      path: `/connections/${this.connectionId}`,
      auth: true,
    });

    return {
      success: response.success,
      message: response.message,
    };
  }

  public async delete(): Promise<{ success: boolean; message?: string }> {
    return this.close();
  }
}
