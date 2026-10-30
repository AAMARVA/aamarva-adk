/**
 * LangChain Integration for AAMARVA ADK
 *
 * Exposes AAMARVA sovereign fleet tools and FLOOR governance conforming to
 * the LangChain tool interface (callable invoke/call methods, JSON Schema).
 */

import { Aamarva } from '../client.js';
import { executeOpenAIToolCall } from './openai.js';

export interface LangChainTool {
  name: string;
  description: string;
  schema: Record<string, unknown>;
  invoke: (input: any) => Promise<string>;
  call: (input: any) => Promise<string>;
  func?: (input: any) => Promise<string>;
}

/**
 * Creates and returns an array of LangChain-compatible tools bound to the given AAMARVA client.
 */
export function getLangChainTools(client?: Aamarva): LangChainTool[] {
  const activeClient = client || new Aamarva();

  const toolDefs = [
    {
      name: 'aamarva_floor_list_tools',
      description: 'Discover available FLOOR tools, input schemas, and caller access status.',
      schema: {
        type: 'object',
        properties: {},
      },
      handler: async () => activeClient.getFloorTools(),
    },
    {
      name: 'aamarva_floor_request_access',
      description: 'Request human-in-the-loop (HITL) approval for an AAMARVA FLOOR tool without executing it.',
      schema: {
        type: 'object',
        properties: {
          toolId: { type: 'string', description: 'Identifier of the tool to request access for.' },
          reason: { type: 'string', description: 'Business justification for requesting access.' },
        },
        required: ['toolId'],
      },
      handler: async (input: { toolId: string; reason?: string }) =>
        activeClient.requestFloorAccess(input.toolId, input.reason),
    },
    {
      name: 'aamarva_floor_check_status',
      description: 'Check the status of a pending or processed FLOOR tool access request.',
      schema: {
        type: 'object',
        properties: {
          requestId: { type: 'string', description: 'The tool access request ID.' },
        },
        required: ['requestId'],
      },
      handler: async (input: { requestId: string }) =>
        activeClient.getFloorRequestStatus(input.requestId),
    },
    {
      name: 'aamarva_floor_execute_tool',
      description: 'Execute an authorized AAMARVA FLOOR tool with input arguments. Fails closed if unauthorized.',
      schema: {
        type: 'object',
        properties: {
          toolId: { type: 'string', description: 'Identifier of the tool to execute.' },
          arguments: { type: 'object', description: 'Tool arguments conforming to schema.' },
        },
        required: ['toolId', 'arguments'],
      },
      handler: async (input: { toolId: string; arguments: Record<string, any> }) =>
        activeClient.executeFloorTool(input.toolId, input.arguments),
    },
    {
      name: 'aamarva_send_message',
      description: 'Send an end-to-end encrypted private message to an authorized peer agent.',
      schema: {
        type: 'object',
        properties: {
          connectionId: { type: 'string', description: 'Active connection channel ID.' },
          content: { type: 'string', description: 'Plaintext message string.' },
        },
        required: ['connectionId', 'content'],
      },
      handler: async (input: { connectionId: string; content: string }) =>
        activeClient.sendMessage(input.connectionId, input.content),
    },
    {
      name: 'aamarva_get_messages',
      description: 'Retrieve and decrypt private messages from an active peer connection.',
      schema: {
        type: 'object',
        properties: {
          connectionId: { type: 'string', description: 'Active connection channel ID.' },
        },
        required: ['connectionId'],
      },
      handler: async (input: { connectionId: string }) =>
        activeClient.getMessages(input.connectionId),
    },
    {
      name: 'aamarva_cluster_send_message',
      description: 'Send an encrypted group message to a cluster with recipient restrictions.',
      schema: {
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
      handler: async (input: {
        clusterId: string;
        ciphertext: string;
        nonce: string;
        recipients?: string[];
      }) =>
        activeClient.sendClusterMessage(input.clusterId, {
          ciphertext: input.ciphertext,
          nonce: input.nonce,
          recipients: input.recipients,
        }),
    },
    {
      name: 'aamarva_watchtower_activity',
      description: 'Retrieve recent fleet audit activity and security telemetry snapshot.',
      schema: {
        type: 'object',
        properties: {
          limit: { type: 'number', description: 'Maximum number of events.' },
        },
      },
      handler: async (input: { limit?: number }) =>
        activeClient.getWatchtowerActivity(input?.limit),
    },
    {
      name: 'aamarva_agent_footprints',
      description: 'Retrieve cryptographic activity audit footprints for the current agent.',
      schema: {
        type: 'object',
        properties: {},
      },
      handler: async () => activeClient.getFootprints(),
    },
    {
      name: 'aamarva_webhook_events',
      description: 'Retrieve recent webhook event delivery history for the agent.',
      schema: {
        type: 'object',
        properties: {},
      },
      handler: async () => activeClient.getWebhookEvents(),
    },
    {
      name: 'aamarva_get_agents',
      description: 'List sovereign fleet accounts (master and slave agents) in caller fleet.',
      schema: {
        type: 'object',
        properties: {
          q: { type: 'string', description: 'Search query.' },
          page: { type: 'number', description: 'Page number.' },
          limit: { type: 'number', description: 'Items per page.' },
        },
      },
      handler: async (input: { q?: string; page?: number; limit?: number }) =>
        activeClient.getAgents(input),
    },
    {
      name: 'aamarva_get_clusters',
      description: 'List multi-agent clusters the caller belongs to.',
      schema: {
        type: 'object',
        properties: {},
      },
      handler: async () => activeClient.getClusters(),
    },
  ];

  return toolDefs.map((def) => {
    const runner = async (rawInput: any): Promise<string> => {
      let args = rawInput;
      if (typeof rawInput === 'string') {
        try {
          args = JSON.parse(rawInput);
        } catch {
          args = { input: rawInput };
        }
      }
      try {
        const res = await def.handler(args || {});
        return typeof res === 'string' ? res : JSON.stringify(res);
      } catch (err: any) {
        return JSON.stringify({ error: err?.message || String(err) });
      }
    };

    return {
      name: def.name,
      description: def.description,
      schema: def.schema,
      invoke: runner,
      call: runner,
      func: runner,
    };
  });
}

/**
 * Executes a LangChain tool by name.
 */
export async function executeLangChainTool(
  client: Aamarva,
  toolName: string,
  input: any
): Promise<string> {
  const tools = getLangChainTools(client);
  const tool = tools.find((t) => t.name === toolName);
  if (!tool) {
    throw new Error(`LangChain tool not found: ${toolName}`);
  }
  return tool.invoke(input);
}
