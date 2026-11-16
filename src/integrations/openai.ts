/**
 * OpenAI Agents & Function Calling Integration for AAMARVA ADK
 *
 * Exposes AAMARVA sovereign fleet tools conforming to the OpenAI Chat Completions
 * and OpenAI Agents SDK tool specifications.
 */

import { Aamarva } from '../client.js';

/**
 * Returns the array of OpenAI-compatible function calling tool definitions.
 */
export function getOpenAIToolDefinitions(): any[] {
  return [
    {
      type: 'function',
      function: {
        name: 'aamarva_floor_list_tools',
        description: 'Discover available FLOOR tools, input schemas, and caller access status.',
        parameters: { type: 'object', properties: {}, additionalProperties: false },
      },
    },
    {
      type: 'function',
      function: {
        name: 'aamarva_floor_request_access',
        description: 'Request human-in-the-loop (HITL) approval for an AAMARVA FLOOR tool.',
        parameters: {
          type: 'object',
          properties: {
            toolId: { type: 'string', description: 'Identifier of the tool to request access for.' },
            reason: { type: 'string', description: 'Business justification for access request.' },
          },
          required: ['toolId'],
          additionalProperties: false,
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'aamarva_floor_check_status',
        description: 'Check the status of a pending or processed FLOOR tool access request.',
        parameters: {
          type: 'object',
          properties: {
            requestId: { type: 'string', description: 'The tool access request ID.' },
          },
          required: ['requestId'],
          additionalProperties: false,
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'aamarva_floor_execute_tool',
        description: 'Execute an authorized AAMARVA FLOOR tool with input arguments.',
        parameters: {
          type: 'object',
          properties: {
            toolId: { type: 'string', description: 'Identifier of the tool to execute.' },
            arguments: { type: 'object', description: 'Input arguments conforming to tool schema.' },
          },
          required: ['toolId', 'arguments'],
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'aamarva_send_message',
        description: 'Send an end-to-end encrypted private message to an authorized peer agent.',
        parameters: {
          type: 'object',
          properties: {
            connectionId: { type: 'string', description: 'Active peer connection channel ID.' },
            content: { type: 'string', description: 'Plaintext message string to send.' },
          },
          required: ['connectionId', 'content'],
          additionalProperties: false,
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'aamarva_get_messages',
        description: 'Retrieve and decrypt private messages from an active peer connection.',
        parameters: {
          type: 'object',
          properties: {
            connectionId: { type: 'string', description: 'Active peer connection channel ID.' },
          },
          required: ['connectionId'],
          additionalProperties: false,
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'aamarva_cluster_send_message',
        description: 'Send an encrypted group message to a cluster with recipient restrictions.',
        parameters: {
          type: 'object',
          properties: {
            clusterId: { type: 'string', description: 'Target multi-agent cluster ID.' },
            ciphertext: { type: 'string', description: 'Encrypted ciphertext payload.' },
            nonce: { type: 'string', description: 'Cryptographic IV / nonce.' },
            recipients: { type: 'array', items: { type: 'string' }, description: 'Authorized recipient agent IDs.' },
          },
          required: ['clusterId', 'ciphertext', 'nonce'],
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'aamarva_watchtower_activity',
        description: 'Retrieve recent fleet audit activity and security telemetry snapshot.',
        parameters: {
          type: 'object',
          properties: {
            limit: { type: 'number', description: 'Maximum number of events.' },
          },
          additionalProperties: false,
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'aamarva_get_agents',
        description: 'List sovereign fleet accounts (master and slave agents) in caller fleet.',
        parameters: {
          type: 'object',
          properties: {
            q: { type: 'string', description: 'Search query.' },
            page: { type: 'number', description: 'Page number.' },
            limit: { type: 'number', description: 'Items per page.' },
          },
          additionalProperties: false,
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'aamarva_get_clusters',
        description: 'List multi-agent clusters the caller belongs to.',
        parameters: { type: 'object', properties: {}, additionalProperties: false },
      },
    },
  ];
}

/**
 * Creates OpenAI-compatible tool wrappers for the AAMARVA client.
 * Compatible with OpenAI Agents SDK.
 */
export function getOpenAITools(client?: Aamarva): any[] {
  const activeClient = client || new Aamarva();
  const defs = getOpenAIToolDefinitions();

  return defs.map((def) => ({
    ...def,
    execute: async (args: any) => {
      const name = def.function.name;
      switch (name) {
        case 'aamarva_floor_list_tools': return activeClient.getFloorTools();
        case 'aamarva_floor_request_access': return activeClient.requestFloorAccess(args.toolId, args.reason);
        case 'aamarva_floor_check_status': return activeClient.getFloorRequestStatus(args.requestId);
        case 'aamarva_floor_execute_tool': return activeClient.executeFloorTool(args.toolId, args.arguments);
        case 'aamarva_send_message': return activeClient.sendMessage(args.connectionId, args.content);
        case 'aamarva_get_messages': return activeClient.getMessages(args.connectionId);
        case 'aamarva_cluster_send_message': return activeClient.sendClusterMessage(args.clusterId, {
          ciphertext: args.ciphertext,
          nonce: args.nonce,
          recipients: args.recipients,
        });
        case 'aamarva_watchtower_activity': return activeClient.getWatchtowerActivity(args.limit);
        case 'aamarva_get_agents': return activeClient.getAgents(args);
        case 'aamarva_get_clusters': return activeClient.getClusters();
        default: throw new Error(`Unknown tool: ${name}`);
      }
    },
  }));
}

/**
 * Executes a named AAMARVA tool call.
 */
export async function executeOpenAIToolCall(
  client: Aamarva,
  toolName: string,
  args: any
): Promise<any> {
  const tools = getOpenAITools(client);
  const tool = tools.find((t) => t.function.name === toolName);
  if (!tool) throw new Error(`Unknown AAMARVA tool: ${toolName}`);
  return tool.execute(args);
}
