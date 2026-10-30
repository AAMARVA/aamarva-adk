/**
 * Google ADK & Gemini Function Calling Integration for AAMARVA ADK
 *
 * Exposes AAMARVA sovereign fleet tools as genuine Google Gemini-compatible
 * FunctionDeclarations for use with the @google/genai SDK.
 */

import { Aamarva } from '../client.js';
import { executeOpenAIToolCall } from './openai.js';

/**
 * Returns the array of genuine Google GenAI FunctionDeclaration objects.
 */
export function getGoogleFunctionDeclarations(): any[] {
  return [
    {
      name: 'aamarva_floor_list_tools',
      description: 'Discover available FLOOR tools, input schemas, and caller access status.',
      parameters: { type: 'OBJECT', properties: {} },
    },
    {
      name: 'aamarva_floor_request_access',
      description: 'Request human-in-the-loop (HITL) approval for an AAMARVA FLOOR tool.',
      parameters: {
        type: 'OBJECT',
        properties: {
          toolId: { type: 'STRING', description: 'Identifier of the tool to request access for.' },
          reason: { type: 'STRING', description: 'Business justification for requesting access.' },
        },
        required: ['toolId'],
      },
    },
    {
      name: 'aamarva_floor_check_status',
      description: 'Check the status of a pending or processed FLOOR tool access request.',
      parameters: {
        type: 'OBJECT',
        properties: {
          requestId: { type: 'STRING', description: 'The tool access request ID.' },
        },
        required: ['requestId'],
      },
    },
    {
      name: 'aamarva_floor_execute_tool',
      description: 'Execute an authorized AAMARVA FLOOR tool with input arguments.',
      parameters: {
        type: 'OBJECT',
        properties: {
          toolId: { type: 'STRING', description: 'Identifier of the tool to execute.' },
          arguments: { type: 'OBJECT', description: 'Input arguments conforming to tool schema.' },
        },
        required: ['toolId', 'arguments'],
      },
    },
    {
      name: 'aamarva_send_message',
      description: 'Send an end-to-end encrypted private message to an authorized peer agent.',
      parameters: {
        type: 'OBJECT',
        properties: {
          connectionId: { type: 'STRING', description: 'Active connection channel ID.' },
          content: { type: 'STRING', description: 'Plaintext message to send.' },
        },
        required: ['connectionId', 'content'],
      },
    },
    {
      name: 'aamarva_get_messages',
      description: 'Retrieve and decrypt private messages from an active peer connection.',
      parameters: {
        type: 'OBJECT',
        properties: {
          connectionId: { type: 'STRING', description: 'Active connection channel ID.' },
        },
        required: ['connectionId'],
      },
    },
    {
      name: 'aamarva_cluster_send_message',
      description: 'Send an encrypted group message to a cluster with recipient restrictions.',
      parameters: {
        type: 'OBJECT',
        properties: {
          clusterId: { type: 'STRING', description: 'Target cluster ID.' },
          ciphertext: { type: 'STRING', description: 'Encrypted ciphertext.' },
          nonce: { type: 'STRING', description: 'Cryptographic IV / nonce.' },
          recipients: { type: 'ARRAY', items: { type: 'STRING' }, description: 'Authorized recipient agent IDs.' },
        },
        required: ['clusterId', 'ciphertext', 'nonce'],
      },
    },
    {
      name: 'aamarva_watchtower_activity',
      description: 'Retrieve recent fleet audit activity and security telemetry snapshot.',
      parameters: {
        type: 'OBJECT',
        properties: {
          limit: { type: 'INTEGER', description: 'Maximum number of events.' },
        },
      },
    },
    {
      name: 'aamarva_get_agents',
      description: 'List sovereign fleet accounts in caller fleet.',
      parameters: {
        type: 'OBJECT',
        properties: {
          q: { type: 'STRING', description: 'Search query.' },
          page: { type: 'INTEGER', description: 'Page number.' },
          limit: { type: 'INTEGER', description: 'Items per page.' },
        },
      },
    },
    {
      name: 'aamarva_get_clusters',
      description: 'List multi-agent clusters the caller belongs to.',
      parameters: { type: 'OBJECT', properties: {} },
    },
  ];
}

export const getGoogleAdkFunctionDeclarations = getGoogleFunctionDeclarations;

/**
 * Returns a Tool object compatible with Google GenAI SDK.
 */
export function getGoogleAdkTools(): any {
  return {
    functionDeclarations: getGoogleFunctionDeclarations(),
  };
}

/**
 * Executes a Google GenAI function call.
 */
export async function executeGoogleFunctionCall(
  client: Aamarva,
  call: { name: string; args: any }
): Promise<any> {
  const result = await executeOpenAIToolCall(client, call.name, call.args);
  return {
    content: result,
  };
}

export const executeGoogleAdkFunction = executeGoogleFunctionCall;
