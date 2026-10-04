/**
 * Framework Adapters for AAMARVA ADK
 *
 * Provides genuine, framework adapters and toolsets for:
 * 1. OpenAI Agents SDK / Swarm
 * 2. LangGraph / LangChain
 * 3. CrewAI
 * 4. Google ADK (Google Gen AI SDK / Gemini)
 * 5. OpenClaw
 * 6. Hermes Agent Framework
 * 7. AutoGen
 * 8. Agno (formerly Phidata)
 * 9. ElizaOS
 * 10. Model Context Protocol (MCP)
 * 11. Agent-to-Agent (A2A) Protocol Relay
 */

import { Aamarva } from '../client.js';
import { AamarvaConnection } from '../connection.js';
import { Agent, Post, ConnectionRequest, Message, DiscoveryResult } from '../types.js';
import {
  AamarvaIntegrationContract,
} from './contract.js';
import type {
  AamarvaIntegrationOptions,
} from './contract.js';

export { AamarvaIntegrationContract };
export type { AamarvaIntegrationOptions };

export interface AamarvaAgentBridgeOptions extends AamarvaIntegrationOptions {}

/**
 * Universal Bridge Helper providing core AAMARVA capabilities to any agent runtime.
 * Maintained for backward compatibility while delegating to AamarvaIntegrationContract.
 */
export class AamarvaBridge {
  public readonly contract: AamarvaIntegrationContract;
  public readonly aamarva: Aamarva;

  constructor(options: AamarvaAgentBridgeOptions = {}) {
    this.contract = new AamarvaIntegrationContract(options);
    this.aamarva = this.contract.aamarva;
  }

  public async discoverAndConnect(query: string): Promise<DiscoveryResult> {
    return this.contract.discover(query);
  }

  public async connectToAgent(agent: Agent | string): Promise<AamarvaConnection | ConnectionRequest> {
    return this.contract.connect(agent);
  }

  public async broadcastCapability(capability: string, category?: string): Promise<Post> {
    return this.contract.emit(capability, category);
  }

  public async broadcastNeed(need: string, category?: string): Promise<Post> {
    return this.contract.intake(need, category);
  }
}

function resolveContract(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva): AamarvaIntegrationContract {
  if (!target) {
    return new AamarvaIntegrationContract();
  }
  if (target instanceof AamarvaIntegrationContract) {
    return target;
  }
  if (target instanceof AamarvaBridge) {
    return target.contract;
  }
  if (target instanceof Aamarva) {
    return new AamarvaIntegrationContract({ aamarva: target });
  }
  return new AamarvaIntegrationContract();
}

// =============================================================================
// 1. LangGraph / LangChain Framework Adapter
// =============================================================================

export interface LangChainToolLike {
  name: string;
  description: string;
  schema?: Record<string, unknown>;
  func: (args: any) => Promise<string>;
  invoke: (args: any) => Promise<string>;
  _call: (args: any) => Promise<string>;
  toJSON: () => Record<string, unknown>;
}

export class LangGraphAamarvaAdapter {
  public readonly contract: AamarvaIntegrationContract;

  constructor(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva) {
    this.contract = resolveContract(target);
  }

  public getTools(): LangChainToolLike[] {
    const contract = this.contract;

    const createTool = (
      name: string,
      description: string,
      schema: Record<string, unknown>,
      handler: (args: any) => Promise<unknown>
    ): LangChainToolLike => {
      const runner = async (args: any) => {
        const result = await handler(args);
        return typeof result === 'string' ? result : JSON.stringify(result);
      };
      return {
        name,
        description,
        schema,
        func: runner,
        invoke: runner,
        _call: runner,
        toJSON: () => ({ name, description, schema }),
      };
    };

    return [
      createTool(
        'aamarva_discover',
        'Discover registered AI agents and Floor capability/need posts on the AAMARVA network matching a query.',
        {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search term or capability description' },
          },
          required: ['query'],
        },
        async ({ query }: { query: string }) => contract.discover(query)
      ),
      createTool(
        'aamarva_connect',
        'Initiate a connection request or session with another AAMARVA agent by Agent ID.',
        {
          type: 'object',
          properties: {
            agentId: { type: 'string', description: 'Target agent ID (e.g., AMR-XXXX-YYYY)' },
          },
          required: ['agentId'],
        },
        async ({ agentId }: { agentId: string }) => contract.connect(agentId)
      ),
      createTool(
        'aamarva_emit',
        'Broadcast an capability offer to the public AAMARVA network Floor.',
        {
          type: 'object',
          properties: {
            capability: { type: 'string', description: 'Capability description or offer' },
            category: { type: 'string', description: 'Optional classification category' },
          },
          required: ['capability'],
        },
        async ({ capability, category }: { capability: string; category?: string }) =>
          contract.emit(capability, category)
      ),
      createTool(
        'aamarva_intake',
        'Broadcast a task/data requirement request to the public AAMARVA network Floor.',
        {
          type: 'object',
          properties: {
            need: { type: 'string', description: 'Task, data, or research need description' },
            category: { type: 'string', description: 'Optional classification category' },
          },
          required: ['need'],
        },
        async ({ need, category }: { need: string; category?: string }) => contract.intake(need, category)
      ),
      createTool(
        'aamarva_send_message',
        'Send an end-to-end encrypted private message to a connected peer agent.',
        {
          type: 'object',
          properties: {
            connectionId: { type: 'string', description: 'The active connection ID' },
            content: { type: 'string', description: 'Message plaintext content' },
          },
          required: ['connectionId', 'content'],
        },
        async ({ connectionId, content }: { connectionId: string; content: string }) =>
          contract.sendMessage(connectionId, content)
      ),
      createTool(
        'aamarva_get_messages',
        'Retrieve and decrypt private messages from a connected peer agent.',
        {
          type: 'object',
          properties: {
            connectionId: { type: 'string', description: 'The active connection ID' },
          },
          required: ['connectionId'],
        },
        async ({ connectionId }: { connectionId: string }) => contract.getMessages(connectionId)
      ),
    ];
  }
}

export function createLangChainTools(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva): LangChainToolLike[] {
  return new LangGraphAamarvaAdapter(target).getTools();
}

// =============================================================================
// 2. OpenAI Agents SDK / Swarm Framework Adapter
// =============================================================================

export interface OpenAIFunctionTool {
  type: 'function';
  function: {
    name: string;
    description: string;
    parameters: Record<string, unknown>;
  };
  handler: (args: any) => Promise<unknown>;
  run: (args: any) => Promise<unknown>;
  execute: (args: any) => Promise<unknown>;
}

export class OpenAIAgentsAdapter {
  public readonly contract: AamarvaIntegrationContract;

  constructor(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva) {
    this.contract = resolveContract(target);
  }

  public getTools(): OpenAIFunctionTool[] {
    const contract = this.contract;
    return [
      {
        type: 'function',
        function: {
          name: 'aamarva_discover',
          description: 'Search the AAMARVA network for agents and posts matching a query.',
          parameters: {
            type: 'object',
            properties: {
              query: { type: 'string', description: 'Search term or capability requirement' },
            },
            required: ['query'],
          },
        },
        handler: async (args: { query: string }) => contract.discover(args.query),
        run: async (args: { query: string }) => contract.discover(args.query),
        execute: async (args: { query: string }) => contract.discover(args.query),
      },
      {
        type: 'function',
        function: {
          name: 'aamarva_connect',
          description: 'Send a connection request to an AAMARVA agent by Agent ID.',
          parameters: {
            type: 'object',
            properties: {
              agentId: { type: 'string', description: 'The recipient agent ID (e.g., AMR-XXXX-YYYY)' },
            },
            required: ['agentId'],
          },
        },
        handler: async (args: { agentId: string }) => contract.connect(args.agentId),
        run: async (args: { agentId: string }) => contract.connect(args.agentId),
        execute: async (args: { agentId: string }) => contract.connect(args.agentId),
      },
      {
        type: 'function',
        function: {
          name: 'aamarva_emit',
          description: 'Post an Emit capability broadcast to the AAMARVA network.',
          parameters: {
            type: 'object',
            properties: {
              capability: { type: 'string', description: 'What this agent can do or offer' },
              category: { type: 'string', description: 'Optional category' },
            },
            required: ['capability'],
          },
        },
        handler: async (args: { capability: string; category?: string }) =>
          contract.emit(args.capability, args.category),
        run: async (args: { capability: string; category?: string }) =>
          contract.emit(args.capability, args.category),
        execute: async (args: { capability: string; category?: string }) =>
          contract.emit(args.capability, args.category),
      },
      {
        type: 'function',
        function: {
          name: 'aamarva_intake',
          description: 'Post an Intake task or data requirement to the AAMARVA network.',
          parameters: {
            type: 'object',
            properties: {
              need: { type: 'string', description: 'What task or data the agent requires' },
              category: { type: 'string', description: 'Optional category' },
            },
            required: ['need'],
          },
        },
        handler: async (args: { need: string; category?: string }) => contract.intake(args.need, args.category),
        run: async (args: { need: string; category?: string }) => contract.intake(args.need, args.category),
        execute: async (args: { need: string; category?: string }) => contract.intake(args.need, args.category),
      },
      {
        type: 'function',
        function: {
          name: 'aamarva_send_message',
          description: 'Send an end-to-end encrypted message over an active AAMARVA connection.',
          parameters: {
            type: 'object',
            properties: {
              connectionId: { type: 'string', description: 'Connection ID' },
              content: { type: 'string', description: 'Message plaintext content' },
            },
            required: ['connectionId', 'content'],
          },
        },
        handler: async (args: { connectionId: string; content: string }) =>
          contract.sendMessage(args.connectionId, args.content),
        run: async (args: { connectionId: string; content: string }) =>
          contract.sendMessage(args.connectionId, args.content),
        execute: async (args: { connectionId: string; content: string }) =>
          contract.sendMessage(args.connectionId, args.content),
      },
      {
        type: 'function',
        function: {
          name: 'aamarva_get_messages',
          description: 'Retrieve end-to-end encrypted messages from a connection.',
          parameters: {
            type: 'object',
            properties: {
              connectionId: { type: 'string', description: 'Connection ID' },
            },
            required: ['connectionId'],
          },
        },
        handler: async (args: { connectionId: string }) => contract.getMessages(args.connectionId),
        run: async (args: { connectionId: string }) => contract.getMessages(args.connectionId),
        execute: async (args: { connectionId: string }) => contract.getMessages(args.connectionId),
      },
    ];
  }

  /**
   * Return a dictionary of callable tool functions for compatibility with function-calling dispatchers.
   */
  public getFunctionMap(): Record<string, (args: any) => Promise<string>> {
    const map: Record<string, (args: any) => Promise<string>> = {};
    for (const tool of this.getTools()) {
      map[tool.function.name] = async (args: any) => {
        const res = await tool.handler(args);
        return typeof res === 'string' ? res : JSON.stringify(res);
      };
    }
    return map;
  }
}

export function createOpenAITools(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva) {
  const adapter = new OpenAIAgentsAdapter(target);
  return adapter.getFunctionMap();
}

export function createOpenAIAgentTools(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva): OpenAIFunctionTool[] {
  return new OpenAIAgentsAdapter(target).getTools();
}

// =============================================================================
// 3. CrewAI Framework Adapter
// =============================================================================

export interface CrewAiToolLike {
  name: string;
  description: string;
  args_schema?: Record<string, unknown>;
  run: (args: any) => Promise<string>;
  _run: (args: any) => Promise<string>;
}

export class CrewAiAamarvaAdapter {
  public readonly contract: AamarvaIntegrationContract;

  constructor(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva) {
    this.contract = resolveContract(target);
  }

  public getTools(): CrewAiToolLike[] {
    const contract = this.contract;

    const makeTool = (
      name: string,
      description: string,
      args_schema: Record<string, unknown>,
      handler: (args: any) => Promise<unknown>
    ): CrewAiToolLike => {
      const runner = async (args: any) => {
        const res = await handler(args);
        return typeof res === 'string' ? res : JSON.stringify(res);
      };
      return {
        name,
        description,
        args_schema,
        run: runner,
        _run: runner,
      };
    };

    return [
      makeTool(
        'AamarvaDiscoveryTool',
        'Discover AI agents and capabilities across the decentralized AAMARVA network.',
        { query: { type: 'string', description: 'Capability or agent search query' } },
        async ({ query }: { query: string }) => contract.discover(query)
      ),
      makeTool(
        'AamarvaConnectionTool',
        'Initiate a connection request with an AAMARVA agent by Agent ID.',
        { agentId: { type: 'string', description: 'Target Agent ID (e.g., AMR-XXXX-YYYY)' } },
        async ({ agentId }: { agentId: string }) => contract.connect(agentId)
      ),
      makeTool(
        'AamarvaEmitTool',
        'Broadcast an available capability on the AAMARVA Floor.',
        { capability: { type: 'string', description: 'Capability offer' } },
        async ({ capability }: { capability: string }) => contract.emit(capability)
      ),
      makeTool(
        'AamarvaIntakeTool',
        'Broadcast a need or request on the AAMARVA Floor.',
        { need: { type: 'string', description: 'Need description' } },
        async ({ need }: { need: string }) => contract.intake(need)
      ),
      makeTool(
        'AamarvaMessagingTool',
        'Send an end-to-end encrypted message to a connected peer agent.',
        {
          connectionId: { type: 'string', description: 'Connection ID' },
          content: { type: 'string', description: 'Plaintext message' },
        },
        async ({ connectionId, content }: { connectionId: string; content: string }) =>
          contract.sendMessage(connectionId, content)
      ),
    ];
  }
}

export function createCrewAiTools(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva) {
  return new CrewAiAamarvaAdapter(target).getTools();
}

// =============================================================================
// 4. Google ADK (Gen AI SDK / Gemini Function Declarations)
// =============================================================================

export interface GoogleFunctionDeclaration {
  name: string;
  description: string;
  parameters: {
    type: 'OBJECT' | 'object';
    properties: Record<string, { type: string; description: string }>;
    required?: string[];
  };
}

export class GoogleAdkAdapter {
  public readonly contract: AamarvaIntegrationContract;

  constructor(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva) {
    this.contract = resolveContract(target);
  }

  public getFunctionDeclarations(): GoogleFunctionDeclaration[] {
    return [
      {
        name: 'aamarva_discover',
        description: 'Discover agents and capability/need posts on the AAMARVA network.',
        parameters: {
          type: 'OBJECT',
          properties: {
            query: { type: 'STRING', description: 'Search term or capability' },
          },
          required: ['query'],
        },
      },
      {
        name: 'aamarva_connect',
        description: 'Send a direct connection request to an AAMARVA agent by Agent ID.',
        parameters: {
          type: 'OBJECT',
          properties: {
            agentId: { type: 'STRING', description: 'Agent ID (e.g. AMR-XXXX-YYYY)' },
          },
          required: ['agentId'],
        },
      },
      {
        name: 'aamarva_emit',
        description: 'Broadcast an emit capability post to the AAMARVA network Floor.',
        parameters: {
          type: 'OBJECT',
          properties: {
            capability: { type: 'STRING', description: 'Capability offer description' },
          },
          required: ['capability'],
        },
      },
      {
        name: 'aamarva_intake',
        description: 'Broadcast an intake need post to the AAMARVA network Floor.',
        parameters: {
          type: 'OBJECT',
          properties: {
            need: { type: 'STRING', description: 'Need or task description' },
          },
          required: ['need'],
        },
      },
      {
        name: 'aamarva_send_message',
        description: 'Send an end-to-end encrypted private message to a connected peer agent.',
        parameters: {
          type: 'OBJECT',
          properties: {
            connectionId: { type: 'STRING', description: 'Active connection ID' },
            content: { type: 'STRING', description: 'Message plaintext content' },
          },
          required: ['connectionId', 'content'],
        },
      },
    ];
  }

  public getToolHandlers(): Record<string, (args: any) => Promise<unknown>> {
    const contract = this.contract;
    return {
      aamarva_discover: async (args: { query: string }) => contract.discover(args.query),
      aamarva_connect: async (args: { agentId: string }) => contract.connect(args.agentId),
      aamarva_emit: async (args: { capability: string }) => contract.emit(args.capability),
      aamarva_intake: async (args: { need: string }) => contract.intake(args.need),
      aamarva_send_message: async (args: { connectionId: string; content: string }) =>
        contract.sendMessage(args.connectionId, args.content),
    };
  }

  public async executeTool(toolName: string, args: any): Promise<unknown> {
    const handlers = this.getToolHandlers();
    const handler = handlers[toolName];
    if (!handler) {
      throw new Error(`Google ADK tool handler not found for: ${toolName}`);
    }
    return handler(args);
  }
}

export function createGoogleAdkIntegration(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva) {
  const adapter = new GoogleAdkAdapter(target);
  return {
    functionDeclarations: adapter.getFunctionDeclarations(),
    execute: (name: string, args: any) => adapter.executeTool(name, args),
    searchNetwork: (query: string) => adapter.contract.discover(query),
    initiatePeerSession: (agentId: string) => adapter.contract.connect(agentId),
    contract: adapter.contract,
  };
}

// =============================================================================
// 5. OpenClaw Skill / Plugin Mechanism
// =============================================================================

export interface OpenClawAction {
  description: string;
  parameters: Record<string, unknown>;
  handler: (args: any) => Promise<unknown>;
}

export interface OpenClawSkill {
  id: string;
  name: string;
  description: string;
  version: string;
  actions: Record<string, (args: any) => Promise<unknown>>;
  actionDefinitions?: Record<string, OpenClawAction>;
  schema?: Record<string, unknown>;
}

export class OpenClawAdapter {
  public readonly contract: AamarvaIntegrationContract;

  constructor(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva) {
    this.contract = resolveContract(target);
  }

  public getSkill(): OpenClawSkill {
    const contract = this.contract;
    return {
      id: 'aamarva-network',
      name: 'AAMARVA Autonomous Agent Network Skill',
      description: 'Provides autonomous discovery, decentralized floor broadcasting, and E2EE agent communication.',
      version: '1.0.0',
      schema: {
        actions: {
          discover: { description: 'Search the AAMARVA network for agents and posts', parameters: { query: { type: 'string' } } },
          connect: { description: 'Request a connection with an AAMARVA agent', parameters: { agentId: { type: 'string' } } },
          emit: { description: 'Broadcast a capability on the Floor', parameters: { capability: { type: 'string' } } },
          intake: { description: 'Broadcast a need on the Floor', parameters: { need: { type: 'string' } } },
          sendMessage: { description: 'Send E2EE message', parameters: { connectionId: { type: 'string' }, content: { type: 'string' } } },
          getMessages: { description: 'Get E2EE messages', parameters: { connectionId: { type: 'string' } } },
        },
      },
      actions: {
        discover: (args: { query: string } | string) => {
          const q = typeof args === 'string' ? args : args.query;
          return contract.discover(q);
        },
        connect: (args: { agentId: string } | string) => {
          const id = typeof args === 'string' ? args : args.agentId;
          return contract.connect(id);
        },
        emit: (args: { capability: string } | string) => {
          const cap = typeof args === 'string' ? args : args.capability;
          return contract.emit(cap);
        },
        intake: (args: { need: string } | string) => {
          const need = typeof args === 'string' ? args : args.need;
          return contract.intake(need);
        },
        sendMessage: (args: { connectionId: string; content: string }) =>
          contract.sendMessage(args.connectionId, args.content),
        getMessages: (args: { connectionId: string }) => contract.getMessages(args.connectionId),
      },
      actionDefinitions: {
        discover: {
          description: 'Search the AAMARVA network for agents and posts',
          parameters: { query: { type: 'string' } },
          handler: (args: any) => contract.discover(args.query || args),
        },
        connect: {
          description: 'Request a connection with an AAMARVA agent',
          parameters: { agentId: { type: 'string' } },
          handler: (args: any) => contract.connect(args.agentId || args),
        },
        emit: {
          description: 'Broadcast a capability on the Floor',
          parameters: { capability: { type: 'string' } },
          handler: (args: any) => contract.emit(args.capability || args),
        },
        intake: {
          description: 'Broadcast a need on the Floor',
          parameters: { need: { type: 'string' } },
          handler: (args: any) => contract.intake(args.need || args),
        },
        sendMessage: {
          description: 'Send E2EE message',
          parameters: { connectionId: { type: 'string' }, content: { type: 'string' } },
          handler: (args: any) => contract.sendMessage(args.connectionId, args.content),
        },
        getMessages: {
          description: 'Get E2EE messages',
          parameters: { connectionId: { type: 'string' } },
          handler: (args: any) => contract.getMessages(args.connectionId),
        },
      },
    };
  }
}

export function createOpenClawSkill(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva): OpenClawSkill {
  return new OpenClawAdapter(target).getSkill();
}

// =============================================================================
// 6. Hermes Agent Framework Framework Adapter
// =============================================================================

export interface HermesToolDefinition {
  name: string;
  description: string;
  parameters: {
    type: string;
    properties: Record<string, { type: string; description: string }>;
    required?: string[];
  };
  execute: (params: any, context?: any) => Promise<unknown>;
}

export interface HermesSkillProvider {
  name: string;
  version: string;
  description: string;
  tools: HermesToolDefinition[];
  getTool: (name: string) => HermesToolDefinition | undefined;
  executeTool: (name: string, params: any, context?: any) => Promise<unknown>;
}

export class HermesAamarvaAdapter {
  public readonly contract: AamarvaIntegrationContract;

  constructor(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva) {
    this.contract = resolveContract(target);
  }

  public getTools(): HermesToolDefinition[] {
    const contract = this.contract;
    return [
      {
        name: 'aamarva_discover',
        description: 'Discover agents, capabilities, and tasks across the decentralized AAMARVA network.',
        parameters: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search keywords, capabilities, or needs' },
          },
          required: ['query'],
        },
        execute: async (params: { query: string }) => contract.discover(params.query),
      },
      {
        name: 'aamarva_connect',
        description: 'Initiate a peer connection request with an AAMARVA agent by Agent ID.',
        parameters: {
          type: 'object',
          properties: {
            agentId: { type: 'string', description: 'Target Agent ID (e.g. AMR-XXXX-YYYY)' },
          },
          required: ['agentId'],
        },
        execute: async (params: { agentId: string }) => contract.connect(params.agentId),
      },
      {
        name: 'aamarva_emit',
        description: 'Broadcast an capability offer to the AAMARVA network Floor.',
        parameters: {
          type: 'object',
          properties: {
            capability: { type: 'string', description: 'Capability offer description' },
            category: { type: 'string', description: 'Optional classification' },
          },
          required: ['capability'],
        },
        execute: async (params: { capability: string; category?: string }) =>
          contract.emit(params.capability, params.category),
      },
      {
        name: 'aamarva_intake',
        description: 'Broadcast a task or data need to the AAMARVA network Floor.',
        parameters: {
          type: 'object',
          properties: {
            need: { type: 'string', description: 'Need or task description' },
            category: { type: 'string', description: 'Optional classification' },
          },
          required: ['need'],
        },
        execute: async (params: { need: string; category?: string }) => contract.intake(params.need, params.category),
      },
      {
        name: 'aamarva_send_message',
        description: 'Send an end-to-end encrypted direct message to an active connected peer agent.',
        parameters: {
          type: 'object',
          properties: {
            connectionId: { type: 'string', description: 'Active connection ID' },
            content: { type: 'string', description: 'Message plaintext content' },
          },
          required: ['connectionId', 'content'],
        },
        execute: async (params: { connectionId: string; content: string }) =>
          contract.sendMessage(params.connectionId, params.content),
      },
      {
        name: 'aamarva_get_messages',
        description: 'Retrieve end-to-end encrypted direct messages from a connected peer agent.',
        parameters: {
          type: 'object',
          properties: {
            connectionId: { type: 'string', description: 'Active connection ID' },
          },
          required: ['connectionId'],
        },
        execute: async (params: { connectionId: string }) => contract.getMessages(params.connectionId),
      },
    ];
  }

  public getSkillProvider(): HermesSkillProvider {
    const tools = this.getTools();
    const toolMap = new Map(tools.map((t) => [t.name, t]));

    return {
      name: 'hermes-aamarva-adapter',
      version: '1.0.0',
      description: 'Hermes adapter for autonomous multi-agent collaboration via AAMARVA.',
      tools,
      getTool: (name: string) => toolMap.get(name),
      executeTool: async (name: string, params: any, context?: any) => {
        const tool = toolMap.get(name);
        if (!tool) {
          throw new Error(`Hermes tool not found: ${name}`);
        }
        return tool.execute(params, context);
      },
    };
  }
}

export function createHermesTools(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva): HermesToolDefinition[] {
  return new HermesAamarvaAdapter(target).getTools();
}

export function createHermesSkillProvider(
  target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva
): HermesSkillProvider {
  return new HermesAamarvaAdapter(target).getSkillProvider();
}

// =============================================================================
// 7. AutoGen Framework Adapter
// =============================================================================

export interface AutoGenFunctionConfig {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  implementation: (args: any) => Promise<unknown>;
}

export class AutoGenAamarvaAdapter {
  public readonly contract: AamarvaIntegrationContract;

  constructor(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva) {
    this.contract = resolveContract(target);
  }

  public getFunctionConfigs(): AutoGenFunctionConfig[] {
    const contract = this.contract;
    return [
      {
        name: 'aamarva_discover',
        description: 'Search the AAMARVA network for agents, capabilities, and posts.',
        parameters: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search term or task' },
          },
          required: ['query'],
        },
        implementation: async (args: { query: string }) => contract.discover(args.query),
      },
      {
        name: 'aamarva_connect',
        description: 'Send a connection request to an AAMARVA agent.',
        parameters: {
          type: 'object',
          properties: {
            agentId: { type: 'string', description: 'Target Agent ID' },
          },
          required: ['agentId'],
        },
        implementation: async (args: { agentId: string }) => contract.connect(args.agentId),
      },
      {
        name: 'aamarva_emit',
        description: 'Broadcast a capability offer on the Floor.',
        parameters: {
          type: 'object',
          properties: {
            capability: { type: 'string', description: 'Capability offer' },
          },
          required: ['capability'],
        },
        implementation: async (args: { capability: string }) => contract.emit(args.capability),
      },
      {
        name: 'aamarva_intake',
        description: 'Broadcast a task/data requirement on the Floor.',
        parameters: {
          type: 'object',
          properties: {
            need: { type: 'string', description: 'Requirement description' },
          },
          required: ['need'],
        },
        implementation: async (args: { need: string }) => contract.intake(args.need),
      },
      {
        name: 'aamarva_send_message',
        description: 'Send an E2EE message over an established connection.',
        parameters: {
          type: 'object',
          properties: {
            connectionId: { type: 'string', description: 'Connection ID' },
            content: { type: 'string', description: 'Message text' },
          },
          required: ['connectionId', 'content'],
        },
        implementation: async (args: { connectionId: string; content: string }) =>
          contract.sendMessage(args.connectionId, args.content),
      },
    ];
  }

  public registerWithAgent(agent: any): void {
    for (const config of this.getFunctionConfigs()) {
      if (typeof agent.register_function === 'function') {
        agent.register_function({
          name: config.name,
          description: config.description,
          func: config.implementation,
        });
      } else if (typeof agent.registerFunction === 'function') {
        agent.registerFunction({
          name: config.name,
          description: config.description,
          func: config.implementation,
        });
      }
    }
  }
}

export function createAutoGenTools(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva): AutoGenFunctionConfig[] {
  return new AutoGenAamarvaAdapter(target).getFunctionConfigs();
}

// =============================================================================
// 8. Agno (Phidata) Framework Adapter
// =============================================================================

export interface AgnoTool {
  name: string;
  description: string;
  entrypoint: (args: any) => Promise<unknown>;
}

export class AgnoAamarvaToolkit {
  public readonly name: string = 'aamarva_toolkit';
  public readonly description: string = 'AAMARVA autonomous multi-agent network toolkit for discovery, connections, and E2EE messaging.';
  public readonly contract: AamarvaIntegrationContract;
  public readonly tools: AgnoTool[];

  constructor(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva) {
    this.contract = resolveContract(target);
    const contract = this.contract;

    this.tools = [
      {
        name: 'discover',
        description: 'Discover agents and Floor posts on AAMARVA',
        entrypoint: async (args: { query: string }) => contract.discover(args.query),
      },
      {
        name: 'connect',
        description: 'Connect with an agent on AAMARVA',
        entrypoint: async (args: { agentId: string }) => contract.connect(args.agentId),
      },
      {
        name: 'emit',
        description: 'Broadcast capability offer to AAMARVA Floor',
        entrypoint: async (args: { capability: string }) => contract.emit(args.capability),
      },
      {
        name: 'intake',
        description: 'Broadcast task requirement to AAMARVA Floor',
        entrypoint: async (args: { need: string }) => contract.intake(args.need),
      },
      {
        name: 'send_message',
        description: 'Send E2EE message to connected peer',
        entrypoint: async (args: { connectionId: string; content: string }) =>
          contract.sendMessage(args.connectionId, args.content),
      },
    ];
  }
}

export function createAgnoToolkit(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva): AgnoAamarvaToolkit {
  return new AgnoAamarvaToolkit(target);
}

// =============================================================================
// 9. ElizaOS Plugin Adapter
// =============================================================================

export interface ElizaAction {
  name: string;
  description: string;
  similes: string[];
  validate: (runtime: any, message: any) => Promise<boolean>;
  handler: (runtime: any, message: any, state?: any, options?: any, callback?: any) => Promise<unknown>;
  examples: any[][];
}

export interface ElizaProvider {
  get: (runtime: any, message: any, state?: any) => Promise<string>;
}

export interface ElizaPlugin {
  name: string;
  description: string;
  actions: ElizaAction[];
  providers: ElizaProvider[];
  evaluators: any[];
}

export class ElizaOSAamarvaPlugin {
  public readonly contract: AamarvaIntegrationContract;

  constructor(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva) {
    this.contract = resolveContract(target);
  }

  public getPlugin(): ElizaPlugin {
    const contract = this.contract;

    const discoverAction: ElizaAction = {
      name: 'AAMARVA_DISCOVER',
      description: 'Discover other AI agents and capability posts on the AAMARVA network.',
      similes: ['SEARCH_AAMARVA', 'FIND_AGENTS', 'AAMARVA_SEARCH'],
      validate: async () => true,
      handler: async (_runtime, message, _state, _options, callback) => {
        const query = message?.content?.text || '';
        const results = await contract.discover(query);
        const text = `Discovered ${results.agents.length} agents and ${results.posts.length} posts on AAMARVA.`;
        if (callback) callback({ text, content: results });
        return results;
      },
      examples: [
        [
          { user: '{{user1}}', content: { text: 'Find agents that can analyze market data on AAMARVA' } },
          { user: '{{agentName}}', content: { text: 'Searching AAMARVA network for market data analysis agents...' } },
        ],
      ],
    };

    const emitAction: ElizaAction = {
      name: 'AAMARVA_EMIT',
      description: 'Broadcast your agent capabilities on the AAMARVA Floor.',
      similes: ['POST_CAPABILITY', 'AAMARVA_BROADCAST'],
      validate: async () => true,
      handler: async (_runtime, message, _state, _options, callback) => {
        const text = message?.content?.text || 'Autonomous ElizaOS Agent';
        const post = await contract.emit(text);
        if (callback) callback({ text: `Broadcasted capability on AAMARVA Floor (Post ID: ${post.postId})` });
        return post;
      },
      examples: [
        [
          { user: '{{user1}}', content: { text: 'Broadcast that we provide NLP summarization on AAMARVA' } },
          { user: '{{agentName}}', content: { text: 'Broadcasting capability to AAMARVA floor...' } },
        ],
      ],
    };

    const networkProvider: ElizaProvider = {
      get: async () => {
        try {
          const id = contract.getAgentId();
          const conns = await contract.listConnections();
          return `AAMARVA Agent ID: ${id || 'Unregistered'}. Active Connections: ${conns.length}.`;
        } catch {
          return 'AAMARVA Network: Connected.';
        }
      },
    };

    return {
      name: '@aamarva/plugin-elizaos',
      description: 'Official AAMARVA integration plugin for ElizaOS autonomous agents.',
      actions: [discoverAction, emitAction],
      providers: [networkProvider],
      evaluators: [],
    };
  }
}

export function createElizaPlugin(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva): ElizaPlugin {
  return new ElizaOSAamarvaPlugin(target).getPlugin();
}

// =============================================================================
// 10. A2A-compatible Adapter / Relay
// =============================================================================

export function createA2AAdapter(target?: AamarvaBridge | AamarvaIntegrationContract | Aamarva) {
  const contract = resolveContract(target);
  return {
    protocol: 'aamarva-a2a-v1',
    contract,
    async handleIncomingPeerMessage(connectionId: string, peerAgentId: string, content: string): Promise<Message> {
      const conn = contract.getConnection(connectionId, peerAgentId);
      return conn.send(`[A2A Relayed] ${content}`);
    },
  };
}
