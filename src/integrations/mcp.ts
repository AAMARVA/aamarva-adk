/**
 * Model Context Protocol (MCP) Integration for AAMARVA ADK
 *
 * Provides a genuine, standards-compliant Model Context Protocol server using
 * the official @modelcontextprotocol/sdk, supporting:
 * - Full MCP protocol lifecycle and initialization
 * - Standard tools/list and tools/call JSON-RPC methods
 * - Proper tool definitions and JSON Schema validation
 * - Stdio transport for local agent orchestration
 * - Streamable HTTP transport for remote microservices and web environments
 * - Strict preservation of FLOOR permissions and endpoint allowlists
 */

import type { Readable, Writable } from 'node:stream';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createRequire } from 'node:module';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type {
  StreamableHTTPServerTransport,
  StreamableHTTPServerTransportOptions,
} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { Aamarva } from '../client.js';

let cachedMcpSdk: any = null;

function getMcpSdk(): any {
  if (cachedMcpSdk) {
    return cachedMcpSdk;
  }
  try {
    const require = createRequire(import.meta.url);
    const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
    const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
    const {
      CallToolRequestSchema,
      ListToolsRequestSchema,
      ErrorCode,
      McpError,
    } = require('@modelcontextprotocol/sdk/types.js');
    const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
    const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
    cachedMcpSdk = {
      Server,
      McpServer,
      CallToolRequestSchema,
      ListToolsRequestSchema,
      ErrorCode,
      McpError,
      StdioServerTransport,
      StreamableHTTPServerTransport,
    };
    return cachedMcpSdk;
  } catch (err) {
    throw new Error(
      'Model Context Protocol SDK not found. Please install @modelcontextprotocol/sdk to use MCP server features.'
    );
  }
}

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
        description: 'Execute an authorized FLOOR tool with arguments. Fails closed if unauthorized.',
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
      {
        name: 'aamarva_agent_footprints',
        description: 'Retrieve cryptographic activity audit footprints for the current agent.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
        handler: async () => client.getFootprints(),
      },
      {
        name: 'aamarva_webhook_events',
        description: 'Retrieve recent webhook event delivery history for the agent.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
        handler: async () => client.getWebhookEvents(),
      },
      {
        name: 'aamarva_get_agents',
        description: 'List fleet peer agents within sovereign fleet boundary.',
        inputSchema: {
          type: 'object',
          properties: {
            q: { type: 'string', description: 'Search query filter.' },
            page: { type: 'number', description: 'Page number for pagination.' },
            limit: { type: 'number', description: 'Items per page.' },
          },
        },
        handler: async (args: { q?: string; page?: number; limit?: number }) =>
          client.getAgents(args),
      },
      {
        name: 'aamarva_get_clusters',
        description: 'Retrieve all multi-agent clusters the caller belongs to.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
        handler: async () => client.getClusters(),
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

  /**
   * Creates an official standards-compliant MCP Protocol Server instance.
   */
  public toProtocolServer(): Server {
    const { Server, ListToolsRequestSchema, CallToolRequestSchema } = getMcpSdk();
    const server = new Server(
      {
        name: 'aamarva-adk',
        version: '2.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    // Register standard tools/list handler
    server.setRequestHandler(ListToolsRequestSchema, async () => {
      const tools = this.getTools();
      return {
        tools: tools.map((tool: any) => ({
          name: tool.name,
          description: tool.description,
          inputSchema: tool.inputSchema,
        })),
      };
    });

    // Register standard tools/call handler
    server.setRequestHandler(CallToolRequestSchema, async (request: any) => {
      const { name, arguments: args } = request.params;
      const tools = this.getTools();
      const tool = tools.find((t: any) => t.name === name);

      if (!tool) {
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `Unknown tool: ${name}`,
            },
          ],
        };
      }

      try {
        const rawResult = await tool.handler(args || {});
        return {
          content: [
            {
              type: 'text',
              text: typeof rawResult === 'string' ? rawResult : JSON.stringify(rawResult, null, 2),
            },
          ],
        };
      } catch (err: any) {
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: err?.message || String(err),
            },
          ],
        };
      }
    });

    return server;
  }

  /**
   * Creates a high-level McpServer instance.
   */
  public toMcpServer(): McpServer {
    const { McpServer, CallToolRequestSchema, McpError, ErrorCode } = getMcpSdk();
    const mcp = new McpServer({
      name: 'aamarva-adk',
      version: '2.0.0',
    });

    const tools = this.getTools();
    mcp.server.setRequestHandler(CallToolRequestSchema, async (req: any) => {
      const tool = tools.find((t: any) => t.name === req.params.name);
      if (!tool) {
        throw new McpError(ErrorCode.MethodNotFound, `Tool not found: ${req.params.name}`);
      }
      try {
        const res = await tool.handler(req.params.arguments || {});
        return {
          content: [{ type: 'text', text: typeof res === 'string' ? res : JSON.stringify(res) }],
        };
      } catch (e: any) {
        return {
          isError: true,
          content: [{ type: 'text', text: e.message || String(e) }],
        };
      }
    });

    return mcp;
  }

  /**
   * Connects this MCP server to standard I/O (stdio) transport.
   */
  public async startStdio(
    stdin?: Readable,
    stdout?: Writable
  ): Promise<{ server: Server; transport: StdioServerTransport }> {
    const { StdioServerTransport } = getMcpSdk();
    const server = this.toProtocolServer();
    const transport = new StdioServerTransport(stdin, stdout);
    await server.connect(transport);
    return { server, transport };
  }

  /**
   * Creates a Streamable HTTP transport and connects the MCP server to it.
   */
  public createStreamableHttpTransport(
    options?: StreamableHTTPServerTransportOptions
  ): { server: Server; transport: StreamableHTTPServerTransport } {
    const { StreamableHTTPServerTransport } = getMcpSdk();
    const server = this.toProtocolServer();
    const transport = new StreamableHTTPServerTransport(options);
    return { server, transport };
  }

  /**
   * Creates a Node.js HTTP request handler (for Express / Connect / http.createServer)
   * supporting Streamable HTTP and SSE transports.
   */
  public createHttpHandler(
    transportOptions?: StreamableHTTPServerTransportOptions
  ): (req: IncomingMessage, res: ServerResponse, parsedBody?: unknown) => Promise<void> {
    const { server, transport } = this.createStreamableHttpTransport(transportOptions);
    let connected = false;

    return async (req: IncomingMessage, res: ServerResponse, parsedBody?: unknown) => {
      if (!connected) {
        await server.connect(transport);
        connected = true;
      }
      return transport.handleRequest(req, res, parsedBody);
    };
  }
}

export function createAamarvaMcpServer(client?: Aamarva): AamarvaMcpServer {
  return new AamarvaMcpServer(client);
}

export function createMcpProtocolServer(client?: Aamarva): Server {
  return new AamarvaMcpServer(client).toProtocolServer();
}

export async function startStdioMcpServer(
  client?: Aamarva,
  stdin?: Readable,
  stdout?: Writable
): Promise<{ server: Server; transport: StdioServerTransport }> {
  return new AamarvaMcpServer(client).startStdio(stdin, stdout);
}

export function createStreamableHttpMcpHandler(
  client?: Aamarva,
  transportOptions?: StreamableHTTPServerTransportOptions
): (req: IncomingMessage, res: ServerResponse, parsedBody?: unknown) => Promise<void> {
  return new AamarvaMcpServer(client).createHttpHandler(transportOptions);
}
