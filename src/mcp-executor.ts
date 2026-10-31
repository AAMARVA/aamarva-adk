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
 * Executes an external MCP tool over HTTP JSON-RPC after authorization approval.
 */
export async function invokeExternalMcpTool(params: McpExecuteParams): Promise<any> {
  const { serverUrl, toolId, args = {}, auth, inputSchema, fetchFn } = params;

  if (!serverUrl || typeof serverUrl !== 'string' || !serverUrl.trim()) {
    throw new AamarvaError('Cannot invoke MCP tool: valid MCP serverUrl is required.', {
      code: 'FLOOR_EXECUTION_FAILED',
    });
  }

  // 1. Validate tool arguments against schema
  validateToolArguments(toolId, args, inputSchema);

  // 2. Build secure request headers (credentials are never logged or leaked)
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream, */*',
  };

  if (auth) {
    if (auth.token || auth.type === 'bearer') {
      const token = auth.token || auth.headerValue;
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
    } else if (auth.apiKey || auth.type === 'apiKey') {
      const headerName = auth.headerName || 'X-API-Key';
      const keyVal = auth.apiKey || auth.headerValue;
      if (keyVal) {
        headers[headerName] = keyVal;
      }
    } else if (auth.headerName && auth.headerValue) {
      headers[auth.headerName] = auth.headerValue;
    }

    if (auth.headers && typeof auth.headers === 'object') {
      for (const [k, v] of Object.entries(auth.headers)) {
        if (typeof v === 'string') {
          headers[k] = v;
        }
      }
    }
  }

  // 3. Construct MCP JSON-RPC 2.0 tools/call payload
  const jsonRpcPayload = {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: {
      name: toolId,
      arguments: args,
    },
  };

  const execFetch = fetchFn || (typeof fetch !== 'undefined' ? fetch : undefined);
  if (!execFetch) {
    throw new AamarvaError('Fetch API is not available in current environment for MCP tool execution.', {
      code: 'MCP_INVOCATION_FAILED',
    });
  }

  let response: Response;
  try {
    response = await execFetch(serverUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(jsonRpcPayload),
    });
  } catch (netErr: any) {
    throw new AamarvaError(`Failed to reach MCP server at endpoint: ${netErr.message}`, {
      code: 'MCP_SERVER_UNREACHABLE',
      cause: netErr,
    });
  }

  if (!response.ok) {
    throw new AamarvaError(
      `MCP server rejected invocation with HTTP status ${response.status}.`,
      { code: 'MCP_INVOCATION_FAILED' }
    );
  }

  let resultJson: any;
  try {
    const text = await response.text();
    resultJson = JSON.parse(text);
  } catch (parseErr: any) {
    throw new AamarvaError('MCP server returned malformed non-JSON response.', {
      code: 'MCP_INVOCATION_FAILED',
      cause: parseErr,
    });
  }

  if (resultJson.error) {
    const errMessage = resultJson.error.message || 'Unknown MCP tool error';
    throw new AamarvaError(`External MCP tool execution error: ${errMessage}`, {
      code: 'MCP_TOOL_ERROR',
    });
  }

  // Extract result conforming to MCP protocol result envelope
  const res = resultJson.result !== undefined ? resultJson.result : resultJson.data !== undefined ? resultJson.data : resultJson;
  return res;
}
