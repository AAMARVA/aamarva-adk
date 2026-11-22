/**
 * MCP Gateway Executor for AAMARVA ADK.
 *
 * Decrypts Core-relayed MCP Gateway token envelopes locally using the Agent's
 * P-256 private key and dispatches authenticated JSON-RPC 2.0 requests to the
 * Gateway /mcp endpoint using the decrypted bearer token.
 */

import crypto from 'node:crypto';
import { AamarvaError, AamarvaValidationError } from './errors.js';
import {
  decryptGatewayTokenEnvelope,
  getLocalIdentityKeyPair,
} from './crypto.js';
import type {
  ExecuteGatewayMcpToolOptions,
  GatewayTokenEnvelope,
  GatewayTokenEnvelopePlaintext,
} from './types.js';

export interface GatewayMcpCallResult {
  toolId?: string;
  toolName: string;
  gatewayId: string;
  mcpServerId: string;
  tokenId: string;
  result: unknown;
  raw?: unknown;
}

export function normalizeGatewayMcpUrl(rawGatewayUrl: string): string {
  if (typeof rawGatewayUrl !== 'string' || !rawGatewayUrl.trim()) {
    throw new AamarvaValidationError('gatewayUrl is required for MCP Gateway execution.', {
      code: 'GATEWAY_URL_INVALID',
    });
  }

  let parsed: URL;
  try {
    parsed = new URL(rawGatewayUrl.trim());
  } catch {
    throw new AamarvaValidationError(`Invalid gatewayUrl: "${rawGatewayUrl}".`, {
      code: 'GATEWAY_URL_INVALID',
    });
  }

  if (parsed.username || parsed.password) {
    throw new AamarvaValidationError('gatewayUrl must not contain embedded user credentials.', {
      code: 'GATEWAY_URL_INVALID',
    });
  }

  const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '::1';
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLocalhost)) {
    throw new AamarvaValidationError(
      `Unsupported gatewayUrl protocol "${parsed.protocol}": HTTPS is required (HTTP allowed only for localhost).`,
      { code: 'GATEWAY_URL_INVALID' }
    );
  }

  const trimmedPath = parsed.pathname.replace(/\/+$/, '');
  parsed.pathname = trimmedPath.endsWith('/mcp') ? trimmedPath : `${trimmedPath}/mcp`;
  return parsed.toString();
}

function parseMcpResponseBody(rawText: string, contentType: string): any {
  const ct = (contentType || '').toLowerCase();
  if (ct.includes('text/event-stream')) {
    const lines = rawText.split(/\r?\n/);
    const dataLines: string[] = [];
    for (const line of lines) {
      if (line.startsWith('data:')) {
        dataLines.push(line.slice(5).trim());
      }
    }
    const candidate = dataLines.filter(Boolean).pop();
    if (!candidate) {
      throw new AamarvaError('Gateway /mcp SSE response did not contain a JSON-RPC data payload.', {
        code: 'GATEWAY_MCP_CALL_FAILED',
      });
    }
    return JSON.parse(candidate);
  }

  if (!rawText || !rawText.trim()) {
    return {};
  }
  return JSON.parse(rawText);
}

export async function executeGatewayMcpTool(
  options: ExecuteGatewayMcpToolOptions
): Promise<GatewayMcpCallResult> {
  if (!options || typeof options !== 'object') {
    throw new AamarvaValidationError('executeGatewayMcpTool options object is required.');
  }

  const toolName = typeof options.toolName === 'string' ? options.toolName.trim() : '';
  if (!toolName) {
    throw new AamarvaValidationError('toolName is required for MCP Gateway execution.');
  }

  if (options.arguments !== undefined && (typeof options.arguments !== 'object' || options.arguments === null || Array.isArray(options.arguments))) {
    throw new AamarvaValidationError('arguments must be a plain object.');
  }

  const mcpUrl = normalizeGatewayMcpUrl(options.gatewayUrl);
  const envelope: GatewayTokenEnvelope = options.tokenEnvelope;

  const expectedAgentId = (options.expectedAgentId || '').trim();
  const expectedAccountId = (options.expectedAccountId || '').trim();
  if (!expectedAgentId || !expectedAccountId) {
    throw new AamarvaValidationError('expectedAgentId and expectedAccountId are required for Gateway token decryption.', {
      code: 'GATEWAY_CONTEXT_INVALID',
    });
  }

  const privateKey =
    options.privateKey ?? getLocalIdentityKeyPair(expectedAgentId, options.keyEpoch).privateKey;

  const decrypted: GatewayTokenEnvelopePlaintext = decryptGatewayTokenEnvelope(envelope, privateKey, {
    expectedAgentId,
    expectedAccountId,
    expectedTokenId: options.expectedTokenId,
    expectedGatewayId: options.expectedGatewayId,
    expectedMcpServerId: options.expectedMcpServerId,
    toolName,
  });

  const fetchFn = options.fetch || globalThis.fetch.bind(globalThis);
  const timeoutMs = options.timeoutMs || 15000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  const rpcId = crypto.randomUUID();
  const rpcPayload = {
    jsonrpc: '2.0',
    id: rpcId,
    method: 'tools/call',
    params: {
      name: toolName,
      arguments: options.arguments || {},
    },
  };

  try {
    const response = await fetchFn(mcpUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
        ...options.headers,
        'Authorization': `Bearer ${decrypted.token}`,
      },
      body: JSON.stringify(rpcPayload),
      signal: controller.signal,
    });

    clearTimeout(timer);

    const contentType = response.headers.get('content-type') || '';
    const rawText = await response.text();
    let parsed: any;
    try {
      parsed = parseMcpResponseBody(rawText, contentType);
    } catch (parseErr: any) {
      if (parseErr instanceof AamarvaError) throw parseErr;
      throw new AamarvaError(`Gateway /mcp returned non-JSON response (HTTP ${response.status}).`, {
        code: 'GATEWAY_MCP_CALL_FAILED',
        statusCode: response.status,
      });
    }

    if (!response.ok) {
      const errMsg = parsed?.error?.message || parsed?.message || `Gateway /mcp HTTP ${response.status}`;
      throw new AamarvaError(String(errMsg), {
        code: response.status === 401 || response.status === 403 ? 'GATEWAY_ACCESS_DENIED' : 'GATEWAY_MCP_CALL_FAILED',
        statusCode: response.status,
      });
    }

    if (parsed && typeof parsed === 'object' && parsed.error) {
      const rpcErrMsg =
        typeof parsed.error === 'object' && parsed.error.message
          ? String(parsed.error.message)
          : String(parsed.error);
      throw new AamarvaError(`Gateway /mcp JSON-RPC error: ${rpcErrMsg}`, {
        code: 'GATEWAY_MCP_CALL_FAILED',
      });
    }

    const resultValue = parsed && typeof parsed === 'object' && 'result' in parsed ? parsed.result : parsed;

    return {
      toolName,
      gatewayId: decrypted.gatewayId,
      mcpServerId: decrypted.mcpServerId,
      tokenId: decrypted.tokenId,
      result: resultValue,
      raw: parsed,
    };
  } catch (err: any) {
    clearTimeout(timer);
    if (err instanceof AamarvaError) {
      throw err;
    }
    if (err?.name === 'AbortError') {
      throw new AamarvaError(`Gateway /mcp request timed out after ${timeoutMs}ms.`, {
        code: 'GATEWAY_MCP_TIMEOUT',
      });
    }
    throw new AamarvaError(`Gateway /mcp invocation failed: ${err?.message || String(err)}`, {
      code: 'GATEWAY_MCP_CALL_FAILED',
    });
  }
}
