/**
 * AutoGen Integration for AAMARVA ADK
 *
 * Provides AutoGen tool definitions and agent registration utilities
 * for autonomous multi-agent workflows.
 */

import { Aamarva } from '../client.js';
import { executeOpenAIToolCall } from './openai.js';

export interface AutoGenTool {
  name: string;
  description: string;
  parameters: {
    type: string;
    properties: Record<string, unknown>;
    required?: string[];
  };
  execute: (args: any) => Promise<unknown>;
}

/**
 * Returns AutoGen-compatible tool objects bound to an AAMARVA client.
 */
export function getAutoGenTools(client?: Aamarva): AutoGenTool[] {
  const activeClient = client || new Aamarva();

  return [
    {
      name: 'aamarva_floor_list_tools',
      description: 'Discover available FLOOR tools, input schemas, and caller access status.',
      parameters: { type: 'object', properties: {} },
      execute: async () => activeClient.getFloorTools(),
    },
    {
      name: 'aamarva_floor_request_access',
      description: 'Request human-in-the-loop (HITL) approval for an AAMARVA FLOOR tool without executing it.',
      parameters: {
        type: 'object',
        properties: {
          toolId: { type: 'string', description: 'Identifier of the tool to request access for.' },
          reason: { type: 'string', description: 'Business justification for requesting access.' },
        },
        required: ['toolId'],
      },
      execute: async (args: { toolId: string; reason?: string }) =>
        activeClient.requestFloorAccess(args.toolId, args.reason),
    },
    {
      name: 'aamarva_floor_check_status',
      description: 'Check the status of a pending or processed FLOOR tool access request.',
      parameters: {
        type: 'object',
        properties: {
          requestId: { type: 'string', description: 'The tool access request ID.' },
        },
        required: ['requestId'],
      },
      execute: async (args: { requestId: string }) =>
        activeClient.getFloorRequestStatus(args.requestId),
    },
    {
      name: 'aamarva_floor_execute_tool',
      description: 'Execute an authorized AAMARVA FLOOR tool with input arguments. Fails closed if unauthorized.',
      parameters: {
        type: 'object',
        properties: {
          toolId: { type: 'string', description: 'Identifier of the tool to execute.' },
          arguments: { type: 'object', description: 'Tool arguments conforming to schema.' },
        },
        required: ['toolId', 'arguments'],
      },
      execute: async (args: { toolId: string; arguments: Record<string, any> }) =>
        activeClient.executeFloorTool(args.toolId, args.arguments),
    },
    {
      name: 'aamarva_send_message',
      description: 'Send an end-to-end encrypted private message to an authorized peer agent.',
      parameters: {
        type: 'object',
        properties: {
          connectionId: { type: 'string', description: 'Active connection channel ID.' },
          content: { type: 'string', description: 'Plaintext message.' },
        },
        required: ['connectionId', 'content'],
      },
      execute: async (args: { connectionId: string; content: string }) =>
        activeClient.sendMessage(args.connectionId, args.content),
    },
    {
      name: 'aamarva_get_messages',
      description: 'Retrieve and decrypt private messages from an active peer connection.',
      parameters: {
        type: 'object',
        properties: {
          connectionId: { type: 'string', description: 'Active connection channel ID.' },
        },
        required: ['connectionId'],
      },
      execute: async (args: { connectionId: string }) =>
        activeClient.getMessages(args.connectionId),
    },
    {
      name: 'aamarva_cluster_send_message',
      description: 'Send an encrypted group message to a cluster with recipient restrictions.',
      parameters: {
        type: 'object',
        properties: {
          clusterId: { type: 'string', description: 'Target cluster ID.' },
          ciphertext: { type: 'string', description: 'Encrypted ciphertext.' },
          nonce: { type: 'string', description: 'Cryptographic IV / nonce.' },
          recipients: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional authorized recipient agent IDs.',
          },
        },
        required: ['clusterId', 'ciphertext', 'nonce'],
      },
      execute: async (args: {
        clusterId: string;
        ciphertext: string;
        nonce: string;
        recipients?: string[];
      }) =>
        activeClient.sendClusterMessage(args.clusterId, {
          ciphertext: args.ciphertext,
          nonce: args.nonce,
          recipients: args.recipients,
        }),
    },
    {
      name: 'aamarva_watchtower_activity',
      description: 'Retrieve recent fleet audit activity and security telemetry snapshot.',
      parameters: {
        type: 'object',
        properties: {
          limit: { type: 'number', description: 'Maximum number of events.' },
        },
      },
      execute: async (args: { limit?: number }) =>
        activeClient.getWatchtowerActivity(args.limit),
    },
    {
      name: 'aamarva_agent_footprints',
      description: 'Retrieve cryptographic activity audit footprints for the agent.',
      parameters: {
        type: 'object',
        properties: {},
      },
      execute: async () => activeClient.getFootprints(),
    },
    {
      name: 'aamarva_webhook_events',
      description: 'Retrieve recent webhook event delivery history for the agent.',
      parameters: {
        type: 'object',
        properties: {},
      },
      execute: async () => activeClient.getWebhookEvents(),
    },
    {
      name: 'aamarva_get_agents',
      description: 'List sovereign fleet accounts (master and slave agents) in caller fleet.',
      parameters: {
        type: 'object',
        properties: {
          q: { type: 'string', description: 'Filter query string.' },
          page: { type: 'number', description: 'Page number.' },
          limit: { type: 'number', description: 'Items per page.' },
        },
      },
      execute: async (args: { q?: string; page?: number; limit?: number }) =>
        activeClient.getAgents(args),
    },
    {
      name: 'aamarva_get_clusters',
      description: 'List multi-agent clusters the caller belongs to.',
      parameters: {
        type: 'object',
        properties: {},
      },
      execute: async () => activeClient.getClusters(),
    },
  ];
}

/**
 * Registers AAMARVA tools onto an AutoGen ConversableAgent instance.
 */
export function registerAutoGenTools(agent: any, client?: Aamarva): void {
  const tools = getAutoGenTools(client);
  for (const tool of tools) {
    if (typeof agent.registerFunction === 'function') {
      agent.registerFunction(tool.name, tool.execute, {
        description: tool.description,
        parameters: tool.parameters,
      });
    } else if (agent.tools && Array.isArray(agent.tools)) {
      agent.tools.push(tool);
    }
  }
}

/**
 * Executes a named AutoGen tool.
 */
export async function executeAutoGenTool(
  client: Aamarva,
  name: string,
  args: Record<string, any>
): Promise<unknown> {
  return executeOpenAIToolCall(client, name, args);
}
