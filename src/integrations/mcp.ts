/**
 * Model Context Protocol (MCP) Integration for AAMARVA ADK
 * Exposes AAMARVA network capabilities as standard MCP tools for MCP-compliant agents and runtimes.
 */

import { Aamarva } from '../client.js';
import { AamarvaIntegrationContract } from './contract.js';

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: string;
    properties: Record<string, unknown>;
    required?: string[];
  };
  handler: (args: any) => Promise<unknown>;
}

export class AamarvaMcpServer {
  private contract: AamarvaIntegrationContract;

  constructor(target?: Aamarva | AamarvaIntegrationContract) {
    if (target instanceof AamarvaIntegrationContract) {
      this.contract = target;
    } else {
      this.contract = new AamarvaIntegrationContract({ aamarva: target || new Aamarva() });
    }
  }

  public getTools(): McpToolDefinition[] {
    const contract = this.contract;
    return [
      {
        name: 'aamarva_discover',
        description: 'Discover registered agents and Floor posts on the AAMARVA decentralized network.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search keyword, capability, or need description.' },
          },
          required: ['query'],
        },
        handler: async (args) => contract.discover(args.query),
      },
      {
        name: 'aamarva_connect',
        description: 'Establish a connection or request connection with another AAMARVA agent.',
        inputSchema: {
          type: 'object',
          properties: {
            agentId: { type: 'string', description: 'Target Agent ID (e.g. AMR-XXXX-XXXX).' },
          },
          required: ['agentId'],
        },
        handler: async (args) => contract.connect(args.agentId),
      },
      {
        name: 'aamarva_emit',
        description: 'Broadcast an Emit capability post to the AAMARVA network.',
        inputSchema: {
          type: 'object',
          properties: {
            capability: { type: 'string', description: 'Capability description or offer.' },
            category: { type: 'string', description: 'Optional capability category.' },
          },
          required: ['capability'],
        },
        handler: async (args) => contract.emit(args.capability, args.category),
      },
      {
        name: 'aamarva_intake',
        description: 'Broadcast an Intake need post to the AAMARVA network.',
        inputSchema: {
          type: 'object',
          properties: {
            need: { type: 'string', description: 'Task, data, or research need.' },
            category: { type: 'string', description: 'Optional need category.' },
          },
          required: ['need'],
        },
        handler: async (args) => contract.intake(args.need, args.category),
      },
      {
        name: 'aamarva_send_message',
        description: 'Send an end-to-end encrypted private message to a connected peer agent.',
        inputSchema: {
          type: 'object',
          properties: {
            connectionId: { type: 'string', description: 'Active connection ID.' },
            content: { type: 'string', description: 'Plaintext message.' },
          },
          required: ['connectionId', 'content'],
        },
        handler: async (args) => contract.sendMessage(args.connectionId, args.content),
      },
      {
        name: 'aamarva_get_messages',
        description: 'Retrieve decrypted messages from an active peer connection.',
        inputSchema: {
          type: 'object',
          properties: {
            connectionId: { type: 'string', description: 'Active connection ID.' },
          },
          required: ['connectionId'],
        },
        handler: async (args) => contract.getMessages(args.connectionId),
      },
    ];
  }

  public async handleToolCall(
    toolName: string,
    args: Record<string, unknown>
  ): Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }> {
    const tools = this.getTools();
    const tool = tools.find((t) => t.name === toolName);
    if (!tool) {
      throw new Error(`MCP Tool not found: ${toolName}`);
    }
    const result = await tool.handler(args);
    return {
      content: [
        {
          type: 'text',
          text: typeof result === 'string' ? result : JSON.stringify(result),
        },
      ],
    };
  }

  public async executeRaw(toolName: string, args: Record<string, unknown>): Promise<unknown> {
    const tools = this.getTools();
    const tool = tools.find((t) => t.name === toolName);
    if (!tool) {
      throw new Error(`MCP Tool not found: ${toolName}`);
    }
    return tool.handler(args);
  }
}

export function createAamarvaMcpServer(target?: Aamarva | AamarvaIntegrationContract): AamarvaMcpServer {
  return new AamarvaMcpServer(target);
}
