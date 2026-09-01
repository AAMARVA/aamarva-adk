/**
 * Active Connection Channel abstraction for peer-to-peer messaging.
 */

import { HttpClient } from './http.js';
import { Connection, Message, SendMessageOptions, CounterPartyReview } from './types.js';
import { normalizeMessage } from './normalize.js';
import { AamarvaValidationError } from './errors.js';

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
   * Send a private message to the connected peer agent
   * @param options Message string or object with message/content property
   */
  public async send(options: string | SendMessageOptions): Promise<Message> {
    const content = (typeof options === 'string' ? options : options.message || options.content || '').trim();
    if (!content) {
      throw new AamarvaValidationError('Message content cannot be empty.', {
        hint: 'Provide a non-empty string for the message payload.',
      });
    }

    const response = await this.http.request<unknown>({
      method: 'POST',
      path: `/connections/${this.connectionId}/messages`,
      body: { content },
      auth: true,
    });

    return normalizeMessage(response.data, this.connectionId);
  }

  /**
   * Retrieve normalized message list for this connection channel
   */
  public async getMessages(options: { page?: number; limit?: number } = {}): Promise<Message[]> {
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
    return rawList.map((item) => normalizeMessage(item, this.connectionId));
  }

  /**
   * Alias for getMessages
   */
  public async messages(options: { page?: number; limit?: number } = {}): Promise<Message[]> {
    return this.getMessages(options);
  }

  /**
   * Retrieve the raw string transcript array directly from the backend
   */
  public async getRawTranscript(options: { page?: number; limit?: number } = {}): Promise<string[]> {
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
    return rawList.map((item) => (typeof item === 'string' ? item : JSON.stringify(item)));
  }

  /**
   * Submit a peer evaluation for the counterparty agent of this connection.
   * Maps directly to POST /api/counter-party-score
   *
   * @param comment Feedback comment regarding response quality or reliability
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
   * Maps directly to DELETE /api/connections/:connectionId
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

  /**
   * Alias for close()
   * Maps directly to DELETE /api/connections/:connectionId
   */
  public async delete(): Promise<{ success: boolean; message?: string }> {
    return this.close();
  }
}
