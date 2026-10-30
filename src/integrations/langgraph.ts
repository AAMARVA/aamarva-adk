/**
 * LangGraph Integration for AAMARVA ADK
 *
 * Provides LangGraph-compatible tool node runners and state handlers
 * that process tool calls against AAMARVA sovereign fleet capabilities.
 */

import { Aamarva } from '../client.js';
import { executeOpenAIToolCall } from './openai.js';

export interface LangGraphToolCall {
  id?: string;
  name: string;
  args: Record<string, unknown> | string;
}

export interface LangGraphToolMessage {
  tool_call_id: string;
  content: string;
  name: string;
}

export interface LangGraphStateWithMessages {
  messages: Array<{
    role?: string;
    content?: any;
    tool_calls?: LangGraphToolCall[];
    additional_kwargs?: {
      tool_calls?: LangGraphToolCall[];
    };
  }>;
}

/**
 * Executes an individual LangGraph tool call or action.
 */
export async function executeLangGraphAction(
  client: Aamarva,
  action: { tool: string; toolInput: Record<string, unknown> | string }
): Promise<{ output: string }> {
  let args = action.toolInput;
  if (typeof args === 'string') {
    try {
      args = JSON.parse(args);
    } catch {
      args = { input: args };
    }
  }

  try {
    const result = await executeOpenAIToolCall(client, action.tool, args as Record<string, any>);
    return {
      output: typeof result === 'string' ? result : JSON.stringify(result),
    };
  } catch (err: any) {
    return {
      output: JSON.stringify({ error: err?.message || String(err) }),
    };
  }
}

/**
 * Processes an array of LangGraph tool calls and generates response messages.
 */
export async function executeLangGraphToolCalls(
  client: Aamarva,
  toolCalls: LangGraphToolCall[]
): Promise<LangGraphToolMessage[]> {
  const responses: LangGraphToolMessage[] = [];

  for (const call of toolCalls) {
    let args = call.args;
    if (typeof args === 'string') {
      try {
        args = JSON.parse(args);
      } catch {
        args = { input: args };
      }
    }

    try {
      const res = await executeOpenAIToolCall(client, call.name, (args || {}) as Record<string, any>);
      responses.push({
        tool_call_id: call.id || `call_${Date.now()}`,
        name: call.name,
        content: typeof res === 'string' ? res : JSON.stringify(res),
      });
    } catch (err: any) {
      responses.push({
        tool_call_id: call.id || `call_${Date.now()}`,
        name: call.name,
        content: JSON.stringify({ error: err?.message || String(err) }),
      });
    }
  }

  return responses;
}

/**
 * Creates a LangGraph ToolNode runner function that can be added to a StateGraph.
 */
export function createLangGraphToolNode(client?: Aamarva) {
  const activeClient = client || new Aamarva();

  return async function toolNode(state: LangGraphStateWithMessages): Promise<{ messages: LangGraphToolMessage[] }> {
    const lastMessage = state.messages[state.messages.length - 1];
    const toolCalls: LangGraphToolCall[] =
      lastMessage?.tool_calls ||
      lastMessage?.additional_kwargs?.tool_calls ||
      [];

    if (!toolCalls.length) {
      return { messages: [] };
    }

    const messages = await executeLangGraphToolCalls(activeClient, toolCalls);
    return { messages };
  };
}
