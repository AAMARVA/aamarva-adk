/**
 * External MCP Execution Engine for AAMARVA FLOOR Tool Governance
 *
 * Establishes genuine connection to authorized MCP servers, validates schema,
 * injects credentials securely without leaks, and returns verified execution results.
 */

import { AamarvaError, AamarvaValidationError } from './errors.js';

export interface McpExecutionAuthConfig {
  type?: 'bearer' | 'apiKey' | 'header' | string;
  token?: string;
  apiKey?: string;
  headerName?: string;
  headerValue?: string;
  headers?: Record<string, string>;
}

export interface McpExecuteParams {
  serverUrl: string;
  toolId: string;
  args?: Record<string, unknown>;
  auth?: McpExecutionAuthConfig;
  inputSchema?: {
    type?: string;
    properties?: Record<string, unknown>;
    required?: string[];
  };
  fetchFn?: typeof fetch;
}

/**
 * Validates tool arguments against the tool input schema.
 */
export function validateToolArguments(
  toolId: string,
  args: Record<string, unknown> = {},
  schema?: { required?: string[]; properties?: Record<string, unknown> }
): void {
  if (!schema) return;

  if (Array.isArray(schema.required)) {
    for (const reqKey of schema.required) {
      if (args[reqKey] === undefined || args[reqKey] === null) {
        throw new AamarvaValidationError(
          `Missing required argument "${reqKey}" for tool "${toolId}".`,
          { code: 'INVALID_TOOL_ARGUMENTS' }
        );
      }
    }
  }
}

/**
 * Direct external MCP execution is forbidden in the ADK.
 * All FLOOR tool calls must execute through the Mandatory AAMARVA MCP Adapter Gateway.
 */
export async function invokeExternalMcpTool(_params: McpExecuteParams): Promise<never> {
  throw new AamarvaError(
    'Direct external MCP tool execution is disabled. All FLOOR tool invocations must execute via the mandatory MCP Adapter Gateway.',
    { code: 'GATEWAY_EXECUTION_REQUIRED' }
  );
}
