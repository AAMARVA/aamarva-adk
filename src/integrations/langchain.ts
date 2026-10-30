/**
 * LangChain Integration for AAMARVA ADK
 *
 * Exposes AAMARVA sovereign fleet tools and FLOOR governance as genuine
 * LangChain-compatible StructuredTool instances.
 */

import { Aamarva } from '../client.js';

/**
 * Dynamically imports LangChain dependencies to keep them optional.
 */
async function getLangChainModules() {
  try {
    const { StructuredTool } = await import('@langchain/core/tools');
    const { z } = await import('zod');
    return { StructuredTool, z };
  } catch (err) {
    throw new Error(
      'LangChain dependencies not found. Please install @langchain/core and zod to use this integration.'
    );
  }
}

/**
 * Returns an array of genuine LangChain StructuredTool instances.
 */
export async function getLangChainTools(client?: Aamarva): Promise<any[]> {
  const activeClient = client || new Aamarva();
  const { StructuredTool, z } = await getLangChainModules();

  const toolDefs = [
    {
      name: 'aamarva_floor_list_tools',
      description: 'Discover available FLOOR tools, input schemas, and caller access status.',
      schema: z.object({}),
      func: async () => activeClient.getFloorTools(),
    },
    {
      name: 'aamarva_floor_request_access',
      description: 'Request human-in-the-loop (HITL) approval for an AAMARVA FLOOR tool.',
      schema: z.object({
        toolId: z.string().describe('Identifier of the tool to request access for.'),
        reason: z.string().optional().describe('Business justification for requesting access.'),
      }),
      func: async (input: any) =>
        activeClient.requestFloorAccess(input.toolId, input.reason),
    },
    {
      name: 'aamarva_floor_check_status',
      description: 'Check the status of a pending or processed FLOOR tool access request.',
      schema: z.object({
        requestId: z.string().describe('The tool access request ID.'),
      }),
      func: async (input: any) =>
        activeClient.getFloorRequestStatus(input.requestId),
    },
    {
      name: 'aamarva_floor_execute_tool',
      description: 'Execute an authorized AAMARVA FLOOR tool with input arguments.',
      schema: z.object({
        toolId: z.string().describe('Identifier of the tool to execute.'),
        arguments: z.record(z.string(), z.any()).describe('Tool arguments conforming to schema.'),
      }),
      func: async (input: any) =>
        activeClient.executeFloorTool(input.toolId, input.arguments),
    },
    {
      name: 'aamarva_send_message',
      description: 'Send an end-to-end encrypted private message to an authorized peer agent.',
      schema: z.object({
        connectionId: z.string().describe('Active connection channel ID.'),
        content: z.string().describe('Plaintext message string.'),
      }),
      func: async (input: any) =>
        activeClient.sendMessage(input.connectionId, input.content),
    },
    {
      name: 'aamarva_get_messages',
      description: 'Retrieve and decrypt private messages from an active peer connection.',
      schema: z.object({
        connectionId: z.string().describe('Active connection channel ID.'),
      }),
      func: async (input: any) =>
        activeClient.getMessages(input.connectionId),
    },
    {
      name: 'aamarva_cluster_send_message',
      description: 'Send an encrypted group message to a cluster with recipient restrictions.',
      schema: z.object({
        clusterId: z.string().describe('Target cluster ID.'),
        ciphertext: z.string().describe('Encrypted ciphertext.'),
        nonce: z.string().describe('Cryptographic IV / nonce.'),
        recipients: z.array(z.string()).optional().describe('Optional authorized recipient agent IDs.'),
      }),
      func: async (input: any) =>
        activeClient.sendClusterMessage(input.clusterId, {
          ciphertext: input.ciphertext,
          nonce: input.nonce,
          recipients: input.recipients,
        }),
    },
    {
      name: 'aamarva_watchtower_activity',
      description: 'Retrieve recent fleet audit activity snapshot.',
      schema: z.object({
        limit: z.number().optional().describe('Maximum number of events.'),
      }),
      func: async (input: any) =>
        activeClient.getWatchtowerActivity(input?.limit),
    },
    {
      name: 'aamarva_get_agents',
      description: 'List sovereign fleet accounts in caller fleet.',
      schema: z.object({
        q: z.string().optional().describe('Search query.'),
        page: z.number().optional().describe('Page number.'),
        limit: z.number().optional().describe('Items per page.'),
      }),
      func: async (input: any) =>
        activeClient.getAgents(input),
    },
    {
      name: 'aamarva_get_clusters',
      description: 'List multi-agent clusters the caller belongs to.',
      schema: z.object({}),
      func: async () => activeClient.getClusters(),
    },
  ];

  return toolDefs.map((t) => {
    class AamarvaTool extends StructuredTool {
      name = t.name;
      description = t.description;
      schema = t.schema;
      async _call(arg: any) {
        const res = await t.func(arg);
        return typeof res === 'string' ? res : JSON.stringify(res);
      }
    }
    return new AamarvaTool();
  });
}
