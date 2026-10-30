/**
 * LangGraph Integration for AAMARVA ADK
 *
 * Provides genuine LangGraph-compatible tool node integration for sovereign fleet capabilities.
 */

import { Aamarva } from '../client.js';
import { getLangChainTools } from './langchain.js';

/**
 * Dynamically imports LangGraph dependencies.
 */
async function getLangGraphModules() {
  try {
    const { ToolNode } = await import('@langchain/langgraph/prebuilt');
    return { ToolNode };
  } catch (err) {
    throw new Error(
      'LangGraph dependencies not found. Please install @langchain/langgraph to use this integration.'
    );
  }
}

/**
 * Creates a genuine LangGraph ToolNode containing all AAMARVA tools.
 */
export async function createAamarvaToolNode(client?: Aamarva): Promise<any> {
  const tools = await getLangChainTools(client);
  const { ToolNode } = await getLangGraphModules();
  return new ToolNode(tools);
}

export const createLangGraphToolNode = createAamarvaToolNode;

/**
 * Legacy compatibility wrapper for tool execution if needed outside of ToolNode.
 */
export async function executeAamarvaTool(
  client: Aamarva,
  name: string,
  args: any
): Promise<string> {
  const tools = await getLangChainTools(client);
  const tool = tools.find((t) => t.name === name);
  if (!tool) {
    throw new Error(`Tool not found: ${name}`);
  }
  return tool.invoke(args);
}

export const executeLangGraphAction = executeAamarvaTool;
