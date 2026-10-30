/**
 * OpenAI Agents & Function Calling Integration for AAMARVA ADK
 *
 * Exposes AAMARVA sovereign fleet tools, FLOOR human-in-the-loop governance,
 * and end-to-end encrypted messaging conforming to the OpenAI Chat Completions
 * and OpenAI Agents SDK tool specifications.
 */

import { Aamarva } from '../client.js';

export interface OpenAIFunctionParameterProperty {
  type: string;
  description?: string;
  enum?: string[];
  items?: Record<string, unknown>;
}

export interface OpenAIToolDefinition {
  type: 'function';
  function: {
    name: string;
    description: string;
    parameters: {
      type: 'object';
      properties: Record<string, OpenAIFunctionParameterProperty>;
      required?: string[];
      additionalProperties?: boolean;
    };
    strict?: boolean;
  };
}

export interface OpenAIToolCallPayload {
  id?: string;
  type?: 'function';
  function: {
    name: string;
    arguments: string | Record<string, unknown>;
  };
}

export interface OpenAIToolCallResult {
  tool_call_id: string;
  role: 'tool';
  name?: string;
  content: string;
}

/**
 * Returns the array of OpenAI-compatible function calling tool definitions.
 */
export function getOpenAITools(client?: Aamarva): OpenAIToolDefinition[] {
  return [
    {
      type: 'function',
      function: {
        name: 'aamarva_floor_list_tools',
        description: 'Discover available FLOOR tools, input schemas, and caller access status.',
        parameters: {
          type: 'object',
          properties: {},
          additionalProperties: false,
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'aamarva_floor_request_access',
        description: 'Request human-in-the-loop (HITL) approval for an AAMARVA FLOOR tool without executing it.',
        parameters: {
          type: 'object',
          properties: {
            toolId: {
              type: 'string',
              description: 'Identifier of the tool to request access for.',
            },
            reason: {
              type: 'string',
              description: 'Business or operational justification for requesting tool access.',
            },
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
            requestId: {
              type: 'string',
              description: 'The tool access request ID.',
            },
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
        description: 'Execute an authorized AAMARVA FLOOR tool with input arguments. Fails closed if unauthorized or revoked.',
        parameters: {
          type: 'object',
          properties: {
            toolId: {
              type: 'string',
              description: 'Identifier of the tool to execute.',
            },
            arguments: {
              type: 'object',
              description: 'JSON object with input arguments matching the tool schema.',
            },
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
            connectionId: {
              type: 'string',
              description: 'Active peer connection channel ID.',
            },
            content: {
              type: 'string',
              description: 'Plaintext message string to encrypt and transmit.',
            },
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
        description: 'Retrieve and decrypt private messages from an active peer connection channel.',
        parameters: {
          type: 'object',
          properties: {
            connectionId: {
              type: 'string',
              description: 'Active peer connection channel ID.',
            },
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
        description: 'Send an encrypted group message to a cluster with optional recipient restrictions.',
        parameters: {
          type: 'object',
          properties: {
            clusterId: {
              type: 'string',
              description: 'Target multi-agent cluster ID.',
            },
            ciphertext: {
              type: 'string',
              description: 'Encrypted ciphertext payload.',
            },
            nonce: {
              type: 'string',
              description: 'Cryptographic initialization vector / nonce.',
            },
            recipients: {
              type: 'array',
              description: 'Optional authorized recipient agent IDs.',
              items: { type: 'string' },
            },
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
            limit: {
              type: 'number',
              description: 'Maximum number of activity events to return.',
            },
          },
          additionalProperties: false,
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'aamarva_agent_footprints',
        description: 'Retrieve cryptographic activity audit footprints for the authenticated agent.',
        parameters: {
          type: 'object',
          properties: {},
          additionalProperties: false,
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'aamarva_webhook_events',
        description: 'Retrieve recent webhook event delivery history for the agent.',
        parameters: {
          type: 'object',
          properties: {},
          additionalProperties: false,
        },
      },
    },
    {
      type: 'function',
      function: {
        name: 'aamarva_get_agents',
        description: 'List sovereign fleet accounts (master and slave agents) belonging to caller fleet.',
        parameters: {
          type: 'object',
          properties: {
            q: { type: 'string', description: 'Filter query string.' },
            page: { type: 'number', description: 'Page number for pagination.' },
            limit: { type: 'number', description: 'Results per page.' },
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
        parameters: {
          type: 'object',
          properties: {},
          additionalProperties: false,
        },
      },
    },
  ];
}

/**
 * Executes a named AAMARVA tool call with validated arguments.
 */
export async function executeOpenAIToolCall(
  client: Aamarva,
  toolName: string,
  args: Record<string, any>
): Promise<unknown> {
  switch (toolName) {
    case 'aamarva_floor_list_tools':
      return client.getFloorTools();
    case 'aamarva_floor_request_access':
      return client.requestFloorAccess(args.toolId, args.reason);
    case 'aamarva_floor_check_status':
      return client.getFloorRequestStatus(args.requestId);
    case 'aamarva_floor_execute_tool':
      return client.executeFloorTool(args.toolId, args.arguments);
    case 'aamarva_send_message':
      return client.sendMessage(args.connectionId, args.content);
    case 'aamarva_get_messages':
      return client.getMessages(args.connectionId);
    case 'aamarva_cluster_send_message':
      return client.sendClusterMessage(args.clusterId, {
        ciphertext: args.ciphertext,
        nonce: args.nonce,
        recipients: args.recipients,
      });
    case 'aamarva_watchtower_activity':
      return client.getWatchtowerActivity(args.limit);
    case 'aamarva_agent_footprints':
      return client.getFootprints();
    case 'aamarva_webhook_events':
      return client.getWebhookEvents();
    case 'aamarva_get_agents':
      return client.getAgents(args);
    case 'aamarva_get_clusters':
      return client.getClusters();
    default:
      throw new Error(`Unknown AAMARVA tool: ${toolName}`);
  }
}

/**
 * Handles an OpenAI tool call payload and returns an OpenAI tool response message.
 */
export async function handleOpenAIToolCall(
  client: Aamarva,
  toolCall: OpenAIToolCallPayload
): Promise<OpenAIToolCallResult> {
  const toolName = toolCall.function.name;
  let parsedArgs: Record<string, any> = {};

  if (typeof toolCall.function.arguments === 'string') {
    try {
      parsedArgs = JSON.parse(toolCall.function.arguments || '{}');
    } catch (e) {
      return {
        tool_call_id: toolCall.id || 'call_default',
        role: 'tool',
        name: toolName,
        content: JSON.stringify({ error: 'Malformed JSON arguments in tool call' }),
      };
    }
  } else if (typeof toolCall.function.arguments === 'object' && toolCall.function.arguments !== null) {
    parsedArgs = toolCall.function.arguments;
  }

  try {
    const result = await executeOpenAIToolCall(client, toolName, parsedArgs);
    return {
      tool_call_id: toolCall.id || 'call_default',
      role: 'tool',
      name: toolName,
      content: typeof result === 'string' ? result : JSON.stringify(result),
    };
  } catch (err: any) {
    return {
      tool_call_id: toolCall.id || 'call_default',
      role: 'tool',
      name: toolName,
      content: JSON.stringify({
        error: err?.message || String(err),
      }),
    };
  }
}
