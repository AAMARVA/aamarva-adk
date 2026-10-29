/**
 * Model Context Protocol (MCP) Integration for AAMARVA ADK
 *
 * Exposes AAMARVA fleet capabilities and FLOOR MCP tool governance:
 * 1. List tools and access status
 * 2. Request human-in-the-loop tool access approval
 * 3. Check tool request status
 * 4. Execute authorized tools protected by server-side authorization
 * 5. Secure fleet direct messaging and cluster communications
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
  public readonly aamarva: Aamarva;

  constructor(client?: Aamarva) {
    this.aamarva = client || new Aamarva();
  }

  public getTools(): McpToolDefinition[] {
    const client = this.aamarva;

    return [
      {
        name: 'aamarva_floor_list_tools',
        description: 'Discover available FLOOR tools, schemas, and caller access status.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
        handler: async () => client.getFloorTools(),
      },
      {
        name: 'aamarva_floor_request_access',
        description: 'Request human-in-the-loop (HITL) approval for a tool without executing it.',
        inputSchema: {
          type: 'object',
          properties: {
            toolId: { type: 'string', description: 'Identifier of the tool to request access for.' },
            reason: { type: 'string', description: 'Business justification for requesting access.' },
          },
          required: ['toolId'],
        },
        handler: async (args: { toolId: string; reason?: string }) =>
          client.requestFloorAccess(args.toolId, args.reason),
      },
      {
        name: 'aamarva_floor_check_status',
        description: 'Check the status of a pending or processed tool access request.',
        inputSchema: {
          type: 'object',
          properties: {
            requestId: { type: 'string', description: 'The tool access request ID.' },
          },
          required: ['requestId'],
        },
        handler: async (args: { requestId: string }) => client.getFloorRequestStatus(args.requestId),
      },
      {
        name: 'aamarva_floor_execute_tool',
        description: 'Execute an authorized FLOOR tool with arguments.',
        inputSchema: {
          type: 'object',
          properties: {
            toolId: { type: 'string', description: 'Identifier of the tool to execute.' },
            arguments: { type: 'object', description: 'Input arguments conforming to tool schema.' },
          },
          required: ['toolId', 'arguments'],
        },
        handler: async (args: { toolId: string; arguments: Record<string, any> }) =>
          client.executeFloorTool(args.toolId, args.arguments),
      },
      {
        name: 'aamarva_send_message',
        description: 'Send an end-to-end encrypted private message to an authorized connected peer agent.',
        inputSchema: {
          type: 'object',
          properties: {
            connectionId: { type: 'string', description: 'Active connection channel ID.' },
            content: { type: 'string', description: 'Plaintext message to encrypt and send.' },
          },
          required: ['connectionId', 'content'],
        },
        handler: async (args: { connectionId: string; content: string }) =>
          client.sendMessage(args.connectionId, args.content),
      },
      {
        name: 'aamarva_get_messages',
        description: 'Retrieve and decrypt private messages from an active peer connection.',
        inputSchema: {
          type: 'object',
          properties: {
            connectionId: { type: 'string', description: 'Active connection channel ID.' },
          },
          required: ['connectionId'],
        },
        handler: async (args: { connectionId: string }) => client.getMessages(args.connectionId),
      },
      {
        name: 'aamarva_cluster_send_message',
        description: 'Send an encrypted message to a cluster with recipient restrictions.',
        inputSchema: {
          type: 'object',
          properties: {
            clusterId: { type: 'string', description: 'Target cluster ID.' },
            ciphertext: { type: 'string', description: 'Encrypted ciphertext payload.' },
            nonce: { type: 'string', description: 'Cryptographic nonce IV.' },
            recipients: {
              type: 'array',
              items: { type: 'string' },
              description: 'Optional authorized recipient agent IDs.',
            },
          },
          required: ['clusterId', 'ciphertext', 'nonce'],
        },
        handler: async (args: { clusterId: string; ciphertext: string; nonce: string; recipients?: string[] }) =>
          client.sendClusterMessage(args.clusterId, {
            ciphertext: args.ciphertext,
            nonce: args.nonce,
            recipients: args.recipients,
          }),
      },
      {
        name: 'aamarva_watchtower_activity',
        description: 'Retrieve recent fleet telemetry and private activity snapshot.',
        inputSchema: {
          type: 'object',
          properties: {
            limit: { type: 'number', description: 'Maximum number of activity events to return.' },
          },
        },
        handler: async (args: { limit?: number }) => client.getWatchtowerActivity(args.limit),
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

export function createAamarvaMcpServer(client?: Aamarva): AamarvaMcpServer {
  return new AamarvaMcpServer(client);
}
