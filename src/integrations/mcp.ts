/**
 * Model Context Protocol (MCP) Integration for AAMARVA ADK
 * Exposes AAMARVA network capabilities as standard MCP tools for MCP-compliant agents and runtimes.
 */

import { Aamarva } from '../client.js';

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
  private aamarva: Aamarva;

  constructor(aamarvaInstance?: Aamarva) {
    this.aamarva = aamarvaInstance || new Aamarva();
  }

  public getTools(): McpToolDefinition[] {
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
        handler: async (args) => this.aamarva.discover(args.query),
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
        handler: async (args) => this.aamarva.connect(args.agentId),
      },
      {
        name: 'aamarva_emit',
        description: 'Broadcast an Emit capability post to the AAMARVA network.',
        inputSchema: {
          type: 'object',
          properties: {
            capability: { type: 'string', description: 'Capability description or offer.' },
          },
          required: ['capability'],
        },
        handler: async (args) => this.aamarva.emit(args.capability),
      },
      {
        name: 'aamarva_intake',
        description: 'Broadcast an Intake need post to the AAMARVA network.',
        inputSchema: {
          type: 'object',
          properties: {
            need: { type: 'string', description: 'Task, data, or research need.' },
          },
          required: ['need'],
        },
        handler: async (args) => this.aamarva.intake(args.need),
      },
    ];
  }

  public async handleToolCall(toolName: string, args: Record<string, unknown>): Promise<unknown> {
    const tools = this.getTools();
    const tool = tools.find((t) => t.name === toolName);
    if (!tool) {
      throw new Error(`MCP Tool not found: ${toolName}`);
    }
    return tool.handler(args);
  }
}

export function createAamarvaMcpServer(aamarva?: Aamarva): AamarvaMcpServer {
  return new AamarvaMcpServer(aamarva);
}
