/**
 * LlamaIndex Integration for AAMARVA ADK
 *
 * Exposes AAMARVA sovereign fleet tools as genuine LlamaIndex-compatible
 * FunctionTool instances.
 */

import { Aamarva } from '../client.js';

/**
 * Dynamically imports LlamaIndex dependencies.
 */
async function getLlamaIndexModules() {
  try {
    const { FunctionTool } = await import('llamaindex');
    return { FunctionTool };
  } catch (err) {
    throw new Error(
      'LlamaIndex dependencies not found. Please install llamaindex to use this integration.'
    );
  }
}

/**
 * Returns an array of genuine LlamaIndex FunctionTool instances.
 */
export async function getLlamaIndexTools(client?: Aamarva): Promise<any[]> {
  const activeClient = client || new Aamarva();
  const { FunctionTool } = await getLlamaIndexModules();

  const toolDefs = [
    {
      name: 'aamarva_floor_list_tools',
      description: 'Discover available FLOOR tools, schemas, and caller access status.',
      fn: async () => activeClient.getFloorTools(),
    },
    {
      name: 'aamarva_floor_request_access',
      description: 'Request human-in-the-loop (HITL) approval for an AAMARVA FLOOR tool.',
      fn: async (args: any) =>
        activeClient.requestFloorAccess(args.toolId, args.reason),
    },
    {
      name: 'aamarva_floor_check_status',
      description: 'Check the status of a pending or processed FLOOR tool access request.',
      fn: async (args: any) =>
        activeClient.getFloorRequestStatus(args.requestId),
    },
    {
      name: 'aamarva_floor_execute_tool',
      description: 'Execute an authorized AAMARVA FLOOR tool with input arguments.',
      fn: async (args: any) =>
        activeClient.executeFloorTool(args.toolId, args.arguments),
    },
    {
      name: 'aamarva_send_message',
      description: 'Send an end-to-end encrypted private message to an authorized peer agent.',
      fn: async (args: any) =>
        activeClient.sendMessage(args.connectionId, args.content),
    },
    {
      name: 'aamarva_get_messages',
      description: 'Retrieve and decrypt private messages from an active peer connection.',
      fn: async (args: any) =>
        activeClient.getMessages(args.connectionId),
    },
    {
      name: 'aamarva_cluster_send_message',
      description: 'Send an encrypted group message to a cluster with recipient restrictions.',
      fn: async (args: any) =>
        activeClient.sendClusterMessage(args.clusterId, {
          ciphertext: args.ciphertext,
          nonce: args.nonce,
          recipients: args.recipients,
        }),
    },
    {
      name: 'aamarva_watchtower_activity',
      description: 'Retrieve recent fleet audit activity snapshot.',
      fn: async (args: any) =>
        activeClient.getWatchtowerActivity(args.limit),
    },
    {
      name: 'aamarva_get_agents',
      description: 'List sovereign fleet accounts in caller fleet.',
      fn: async (args: any) =>
        activeClient.getAgents(args),
    },
    {
      name: 'aamarva_get_clusters',
      description: 'List multi-agent clusters the caller belongs to.',
      fn: async () => activeClient.getClusters(),
    },
  ];

  return toolDefs.map((def) => FunctionTool.from(def.fn as any, {
    name: def.name,
    description: def.description,
  }));
}
