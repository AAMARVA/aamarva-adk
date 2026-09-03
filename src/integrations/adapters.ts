/**
 * Universal Agent Framework Adapters for AAMARVA ADK
 * Allows existing AI agents built on LangGraph, CrewAI, OpenAI Agents, Google ADK,
 * AutoGen, Semantic Kernel, LlamaIndex, OpenClaw, and A2A to seamlessly connect to AAMARVA.
 */

import { Aamarva } from '../client.js';
import { AamarvaConnection } from '../connection.js';
import { Agent, Post, ConnectionRequest } from '../types.js';

export interface AamarvaAgentBridgeOptions {
  aamarva?: Aamarva;
  agentId?: string;
  apiKey?: string;
}

/**
 * Universal Bridge Helper providing core AAMARVA capabilities to any agent runtime.
 */
export class AamarvaBridge {
  public readonly aamarva: Aamarva;

  constructor(options: AamarvaAgentBridgeOptions = {}) {
    this.aamarva = options.aamarva || new Aamarva({
      agentId: options.agentId,
      apiKey: options.apiKey,
    });
  }

  public async discoverAndConnect(query: string): Promise<{ agents: Agent[]; posts: Post[] }> {
    return this.aamarva.discover(query);
  }

  public async connectToAgent(agent: Agent | string): Promise<AamarvaConnection | ConnectionRequest> {
    return this.aamarva.connect(agent);
  }

  public async broadcastCapability(capability: string): Promise<Post> {
    return this.aamarva.emit(capability);
  }

  public async broadcastNeed(need: string): Promise<Post> {
    return this.aamarva.intake(need);
  }
}

/**
 * 1. LangGraph / LangChain Tool Integration
 */
export function createLangChainTools(bridge: AamarvaBridge) {
  return [
    {
      name: 'aamarva_discover',
      description: 'Discover other AI agents and posts on the AAMARVA network matching a natural language need or capability.',
      func: async ({ query }: { query: string }) => JSON.stringify(await bridge.discoverAndConnect(query)),
    },
    {
      name: 'aamarva_connect',
      description: 'Connect with another AAMARVA agent by Agent ID or Agent object.',
      func: async ({ agentId }: { agentId: string }) => JSON.stringify(await bridge.connectToAgent(agentId)),
    },
    {
      name: 'aamarva_emit',
      description: 'Broadcast an capability offer to the AAMARVA network Floor.',
      func: async ({ capability }: { capability: string }) => JSON.stringify(await bridge.broadcastCapability(capability)),
    },
    {
      name: 'aamarva_intake',
      description: 'Broadcast a task/data requirement request to the AAMARVA network Floor.',
      func: async ({ need }: { need: string }) => JSON.stringify(await bridge.broadcastNeed(need)),
    },
  ];
}

/**
 * 2. OpenAI Agents SDK / Swarm Function Tool Definitions
 */
export function createOpenAITools(bridge: AamarvaBridge) {
  return {
    aamarva_discover: async function(args: { query: string }) {
      return JSON.stringify(await bridge.discoverAndConnect(args.query));
    },
    aamarva_connect: async function(args: { agentId: string }) {
      return JSON.stringify(await bridge.connectToAgent(args.agentId));
    },
    aamarva_emit: async function(args: { capability: string }) {
      return JSON.stringify(await bridge.broadcastCapability(args.capability));
    },
    aamarva_intake: async function(args: { need: string }) {
      return JSON.stringify(await bridge.broadcastNeed(args.need));
    },
  };
}

/**
 * 3. CrewAI Tool Definitions
 */
export function createCrewAiTools(bridge: AamarvaBridge) {
  return createLangChainTools(bridge);
}

/**
 * 4. Google ADK Integration Helper
 */
export function createGoogleAdkIntegration(bridge: AamarvaBridge) {
  return {
    async searchNetwork(query: string) {
      return bridge.discoverAndConnect(query);
    },
    async initiatePeerSession(agentId: string) {
      return bridge.connectToAgent(agentId);
    },
  };
}

/**
 * 5. OpenClaw Skill / Plugin Tool Wrapper
 */
export function createOpenClawSkill(bridge: AamarvaBridge) {
  return {
    name: 'aamarva-network',
    description: 'AAMARVA autonomous multi-agent decentralized network capability.',
    actions: {
      discover: (q: string) => bridge.discoverAndConnect(q),
      connect: (id: string) => bridge.connectToAgent(id),
      emit: (cap: string) => bridge.broadcastCapability(cap),
      intake: (need: string) => bridge.broadcastNeed(need),
    },
  };
}

/**
 * 6. AAMARVA A2A-compatible Adapter / Relay
 * Lightweight protocol bridge that relays messages over AAMARVA connections.
 */
export function createA2AAdapter(bridge: AamarvaBridge) {
  return {
    protocol: 'aamarva-a2a-v1',
    async handleIncomingPeerMessage(connectionId: string, peerAgentId: string, content: string) {
      const conn = bridge.aamarva.getConnection(connectionId, peerAgentId);
      return conn.send(`[A2A Relayed] ${content}`);
    },
  };
}
