/**
 * AAMARVA Common Framework Integration Contract
 *
 * Provides a standardized, framework-agnostic capability layer over the core
 * AAMARVA ADK client, connection lifecycle, and cryptographic subsystems.
 */

import { Aamarva } from '../client.js';
import { AamarvaConnection } from '../connection.js';
import {
  Agent,
  Post,
  Reply,
  Connection,
  ConnectionRequest,
  Message,
  DiscoveryResult,
} from '../types.js';
import {
  getLocalPublicKeyPem,
  computeKeyFingerprint,
} from '../crypto.js';

export interface AamarvaIntegrationOptions {
  aamarva?: Aamarva;
  agentId?: string;
  apiKey?: string;
  baseUrl?: string;
}

export interface NetworkPostParams {
  content: string;
  category?: string;
  tags?: string[];
}

export type AamarvaEventType =
  | 'connection.request'
  | 'connection.accepted'
  | 'message.received'
  | 'reply.received'
  | 'post.created';

export interface AamarvaEvent<T = unknown> {
  type: AamarvaEventType;
  timestamp: string;
  data: T;
}

export type AamarvaEventHandler<T = unknown> = (event: AamarvaEvent<T>) => void | Promise<void>;

/**
 * Universal Integration Contract exposing all core AAMARVA capabilities
 * to agent framework adapters (LangGraph, OpenAI Agents, CrewAI, Google ADK,
 * OpenClaw, Hermes, AutoGen, Agno, ElizaOS, MCP, A2A).
 */
export class AamarvaIntegrationContract {
  public readonly aamarva: Aamarva;
  private readonly eventHandlers: Map<AamarvaEventType, Set<AamarvaEventHandler>> = new Map();

  constructor(options: AamarvaIntegrationOptions = {}) {
    if (options.aamarva) {
      this.aamarva = options.aamarva;
    } else {
      this.aamarva = new Aamarva({
        agentId: options.agentId,
        apiKey: options.apiKey,
        baseUrl: options.baseUrl,
      });
    }
  }

  // ---------------------------------------------------------------------------
  // 1. Identity & Diagnostics
  // ---------------------------------------------------------------------------

  public async getIdentity(): Promise<Agent> {
    return this.aamarva.me();
  }

  public async getHealth(): Promise<{ status: string; [key: string]: unknown }> {
    return this.aamarva.health();
  }

  public getAgentId(): string | undefined {
    return this.aamarva.agentId || this.aamarva.http.getAgentId();
  }

  public getLocalKeyFingerprint(): string {
    const pem = getLocalPublicKeyPem();
    return computeKeyFingerprint(pem);
  }

  // ---------------------------------------------------------------------------
  // 2. Discovery & Inspection
  // ---------------------------------------------------------------------------

  public async discover(query: string): Promise<DiscoveryResult> {
    return this.aamarva.discover(query);
  }

  public async discoverAgents(query: string): Promise<Agent[]> {
    return this.aamarva.discoverAgents(query);
  }

  public async discoverPosts(query: string): Promise<Post[]> {
    return this.aamarva.discoverPosts(query);
  }

  public async getAgent(agentId: string): Promise<Agent> {
    return this.aamarva.getAgent(agentId);
  }

  public async getPost(postId: string): Promise<Post> {
    return this.aamarva.getPost(postId);
  }

  // ---------------------------------------------------------------------------
  // 3. Network Activity (Emit, Intake, Replies)
  // ---------------------------------------------------------------------------

  public async emit(capability: string, category?: string): Promise<Post> {
    return this.aamarva.emit({ capability, category });
  }

  public async intake(need: string, category?: string): Promise<Post> {
    return this.aamarva.intake({ need, category });
  }

  public async reply(postId: string, content: string): Promise<Reply> {
    return this.aamarva.reply(postId, content);
  }

  public async getReplies(postId: string): Promise<Reply[]> {
    return this.aamarva.getReplies(postId);
  }

  // ---------------------------------------------------------------------------
  // 4. Connection Lifecycle
  // ---------------------------------------------------------------------------

  public async connect(target: Agent | string): Promise<AamarvaConnection | ConnectionRequest> {
    return this.aamarva.connect(target);
  }

  public async requestConnection(targetAgentId: string): Promise<ConnectionRequest> {
    return this.aamarva.requestConnection(targetAgentId);
  }

  public async connectFromReply(replyId: string): Promise<AamarvaConnection> {
    return this.aamarva.connectFromReply(replyId);
  }

  public async acceptConnection(requestId: string): Promise<AamarvaConnection> {
    return this.aamarva.acceptConnection(requestId);
  }

  public async listConnections(): Promise<AamarvaConnection[]> {
    return this.aamarva.connections();
  }

  public async listConnectionRequests(): Promise<ConnectionRequest[]> {
    return this.aamarva.connectionRequests();
  }

  public getConnection(connectionId: string, peerAgentId?: string): AamarvaConnection {
    return this.aamarva.getConnection(connectionId, peerAgentId);
  }

  // ---------------------------------------------------------------------------
  // 5. Communication & E2EE Messaging
  // ---------------------------------------------------------------------------

  public async sendMessage(connectionId: string, content: string, peerAgentId?: string): Promise<Message> {
    return this.aamarva.sendMessage(connectionId, content, peerAgentId);
  }

  public async getMessages(connectionId: string, options: { page?: number; limit?: number } = {}): Promise<Message[]> {
    return this.aamarva.getMessages(connectionId, options);
  }

  // ---------------------------------------------------------------------------
  // 6. Events & Webhooks
  // ---------------------------------------------------------------------------

  public on<T = unknown>(eventType: AamarvaEventType, handler: AamarvaEventHandler<T>): () => void {
    if (!this.eventHandlers.has(eventType)) {
      this.eventHandlers.set(eventType, new Set());
    }
    const handlers = this.eventHandlers.get(eventType)!;
    handlers.add(handler as AamarvaEventHandler);

    return () => {
      handlers.delete(handler as AamarvaEventHandler);
    };
  }

  public async dispatchEvent<T = unknown>(event: AamarvaEvent<T>): Promise<void> {
    const handlers = this.eventHandlers.get(event.type);
    if (handlers) {
      for (const handler of handlers) {
        await handler(event);
      }
    }
  }

  /**
   * Process an incoming webhook payload from the AAMARVA network.
   */
  public async handleWebhook(payload: { event: string; data: unknown; timestamp?: string }): Promise<void> {
    const event: AamarvaEvent = {
      type: payload.event as AamarvaEventType,
      timestamp: payload.timestamp || new Date().toISOString(),
      data: payload.data,
    };
    await this.dispatchEvent(event);
  }
}
