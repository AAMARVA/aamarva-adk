/**
 * External MCP Execution Engine for AAMARVA FLOOR Tool Governance
 *
 * Security hardening:
 * - Strict SSRF validation (HTTPS required by default, private/loopback/metadata IPs blocked, DNS rebinding check)
 * - Redirect rejection (redirect: 'manual', fails closed on 3xx)
 * - Schema argument validation
 * - Full support for FLOOR auth modes (none, bearer, api_key, custom_header)
 * - Official @modelcontextprotocol/sdk Client/StreamableHTTPClientTransport when available, with hardened JSON-RPC fallback
 * - Credential redaction: tokens and header values are never included in errors or logs
 */

import dns from 'node:dns';
import net from 'node:net';
import { createRequire } from 'node:module';
import { AamarvaError, AamarvaValidationError } from './errors.js';

export interface McpExecutionAuthConfig {
  type?: 'none' | 'bearer' | 'api_key' | 'apiKey' | 'custom_header' | 'header' | string;
  authType?: 'none' | 'bearer' | 'api_key' | 'apiKey' | 'custom_header' | 'header' | string;
  token?: string;
  apiKey?: string;
  headerName?: string;
  authHeaderName?: string;
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
  timeoutMs?: number;
  allowInsecureHttpForLocalhost?: boolean;
  useMcpSdk?: boolean;
}

function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map((p) => Number(p));
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function isRestrictedIpv4(ip: string, allowLoopback: boolean): boolean {
  const n = ipv4ToInt(ip);
  const inCidr = (base: string, maskBits: number) => {
    const mask = maskBits === 0 ? 0 : (~((1 << (32 - maskBits)) - 1)) >>> 0;
    return (n & mask) === (ipv4ToInt(base) & mask);
  };

  // Cloud metadata (169.254.0.0/16) is ALWAYS blocked, even in local dev mode.
  if (inCidr('169.254.0.0', 16)) return true;
  if (inCidr('0.0.0.0', 8)) return true;
  if (inCidr('127.0.0.0', 8)) {
    return !(allowLoopback && ip === '127.0.0.1');
  }
  if (inCidr('10.0.0.0', 8)) return true;
  if (inCidr('172.16.0.0', 12)) return true;
  if (inCidr('192.168.0.0', 16)) return true;
  if (inCidr('100.64.0.0', 10)) return true; // CGNAT
  if (inCidr('224.0.0.0', 4)) return true;  // Multicast / reserved
  return false;
}

function isRestrictedIp(rawIp: string, allowLoopback: boolean): boolean {
  const clean = rawIp.trim().toLowerCase().replace(/^\[|\]$/g, '').split('%')[0];
  if (net.isIPv4(clean)) {
    return isRestrictedIpv4(clean, allowLoopback);
  }
  if (net.isIPv6(clean)) {
    if (clean === '::') return true;
    if (clean === '::1') return !allowLoopback;
    if (clean.startsWith('::ffff:')) {
      const mapped = clean.slice('::ffff:'.length);
      if (net.isIPv4(mapped)) {
        return isRestrictedIpv4(mapped, allowLoopback);
      }
      // Handle hex form like ::ffff:7f00:1
      const hexParts = mapped.split(':');
      if (hexParts.length === 2) {
        const hi = parseInt(hexParts[0], 16);
        const lo = parseInt(hexParts[1], 16);
        if (!Number.isNaN(hi) && !Number.isNaN(lo)) {
          const ipv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
          return isRestrictedIpv4(ipv4, allowLoopback);
        }
      }
      return true;
    }
    // ULA fc00::/7 (fc.. or fd..)
    if (clean.startsWith('fc') || clean.startsWith('fd')) return true;
    // Link-local fe80::/10 (fe80..febf)
    if (/^fe[89ab][0-9a-f]/i.test(clean)) return true;
    // Multicast ff00::/8
    if (clean.startsWith('ff')) return true;
    return false;
  }
  return true;
}

function isLocalhostHostname(hostname: string): boolean {
  const lower = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  return lower === 'localhost' || lower === '127.0.0.1' || lower === '::1';
}

function isPermittedLocalDev(): boolean {
  return (
    typeof process !== 'undefined' &&
    process.env?.AAMARVA_ALLOW_LOCALHOST_MCP_HTTP === '1'
  );
}

/**
 * Validates that an MCP server URL is safe against SSRF and credential exfiltration.
 */
export async function assertSafeMcpServerUrl(
  rawUrl: string,
  options: { allowInsecureHttpForLocalhost?: boolean; resolveDns?: boolean } = {}
): Promise<URL> {
  if (!rawUrl || typeof rawUrl !== 'string' || !rawUrl.trim()) {
    throw new AamarvaError('Cannot invoke MCP tool: valid MCP serverUrl is required.', {
      code: 'FLOOR_EXECUTION_FAILED',
    });
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw new AamarvaError('Cannot invoke MCP tool: malformed MCP serverUrl.', {
      code: 'FLOOR_EXECUTION_FAILED',
    });
  }

  if (parsed.username || parsed.password) {
    throw new AamarvaError('Refusing MCP serverUrl containing embedded URL credentials.', {
      code: 'FLOOR_EXECUTION_FAILED',
    });
  }

  const allowLocal = Boolean(options.allowInsecureHttpForLocalhost || isPermittedLocalDev());
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');

  if (parsed.protocol === 'http:') {
    if (!allowLocal || !isLocalhostHostname(hostname)) {
      throw new AamarvaError('Refusing insecure non-HTTPS MCP serverUrl.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }
  } else if (parsed.protocol !== 'https:') {
    throw new AamarvaError(`Refusing unsupported MCP serverUrl protocol "${parsed.protocol}".`, {
      code: 'FLOOR_EXECUTION_FAILED',
    });
  }

  if (!hostname) {
    throw new AamarvaError('Refusing MCP serverUrl with empty hostname.', {
      code: 'FLOOR_EXECUTION_FAILED',
    });
  }

  const isLocalName = isLocalhostHostname(hostname);
  if (hostname === 'metadata.google.internal' || hostname.endsWith('.metadata.google.internal')) {
    throw new AamarvaError('Refusing cloud metadata MCP serverUrl.', {
      code: 'FLOOR_EXECUTION_FAILED',
    });
  }

  if (net.isIP(hostname) !== 0) {
    if (isRestrictedIp(hostname, allowLocal)) {
      throw new AamarvaError('Refusing MCP serverUrl targeting restricted or private IP address.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }
  } else if (isLocalName || hostname.endsWith('.localhost')) {
    if (!(allowLocal && isLocalName)) {
      throw new AamarvaError('Refusing MCP serverUrl targeting localhost.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }
  } else if (options.resolveDns) {
    try {
      const records = await dns.promises.lookup(hostname, { all: true });
      for (const rec of records) {
        if (isRestrictedIp(rec.address, false)) {
          throw new AamarvaError('Refusing MCP serverUrl whose DNS resolution points to a restricted IP.', {
            code: 'FLOOR_EXECUTION_FAILED',
          });
        }
      }
    } catch (err: any) {
      if (err instanceof AamarvaError) throw err;
      throw new AamarvaError('Failed to resolve MCP server endpoint hostname.', {
        code: 'MCP_SERVER_UNREACHABLE',
      });
    }
  }

  return parsed;
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

function assertCleanHeaderValue(name: string, val: string): void {
  if (/[\r\n\0]/.test(name) || /[\r\n\0]/.test(val)) {
    throw new AamarvaError('Invalid header characters in MCP auth configuration.', {
      code: 'FLOOR_EXECUTION_FAILED',
    });
  }
}

export function buildMcpAuthHeaders(auth?: McpExecutionAuthConfig): Record<string, string> {
  const headers: Record<string, string> = {};
  if (!auth) return headers;

  const rawType = (auth.type || auth.authType || '').trim().toLowerCase();
  const headerName = (auth.headerName || auth.authHeaderName || '').trim();
  const rawVal = auth.headerValue !== undefined ? String(auth.headerValue) : undefined;

  if (rawType === 'none') {
    return headers;
  }

  if (rawType === 'bearer' || auth.token) {
    const token = auth.token || rawVal;
    if (token) {
      assertCleanHeaderValue('Authorization', token);
      headers['Authorization'] = /^bearer\s+/i.test(token) ? token : `Bearer ${token}`;
    }
  } else if (rawType === 'apikey' || rawType === 'api_key' || auth.apiKey) {
    const hName = headerName || 'X-API-Key';
    const keyVal = auth.apiKey || rawVal;
    if (keyVal) {
      assertCleanHeaderValue(hName, keyVal);
      headers[hName] = keyVal;
    }
  } else if (rawType === 'custom_header' || rawType === 'header' || (headerName && rawVal)) {
    if (headerName && rawVal) {
      assertCleanHeaderValue(headerName, rawVal);
      headers[headerName] = rawVal;
    }
  }

  if (auth.headers && typeof auth.headers === 'object') {
    for (const [k, v] of Object.entries(auth.headers)) {
      if (typeof v === 'string') {
        assertCleanHeaderValue(k, v);
        headers[k] = v;
      }
    }
  }

  return headers;
}

function tryLoadMcpClientSdk(): {
  Client: any;
  StreamableHTTPClientTransport: any;
} | null {
  try {
    const require = createRequire(import.meta.url);
    const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
    const { StreamableHTTPClientTransport } = require('@modelcontextprotocol/sdk/client/streamableHttp.js');
    if (Client && StreamableHTTPClientTransport) {
      return { Client, StreamableHTTPClientTransport };
    }
    return null;
  } catch {
    return null;
  }
}

async function invokeViaJsonRpcFallback(
  serverUrl: URL,
  toolId: string,
  args: Record<string, unknown>,
  authHeaders: Record<string, string>,
  execFetch: typeof fetch,
  timeoutMs: number
): Promise<any> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream, */*',
    ...authHeaders,
  };

  const jsonRpcPayload = {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: {
      name: toolId,
      arguments: args,
    },
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await execFetch(serverUrl.toString(), {
      method: 'POST',
      headers,
      body: JSON.stringify(jsonRpcPayload),
      redirect: 'manual',
      signal: controller.signal,
    });
  } catch (netErr: any) {
    clearTimeout(timer);
    if (netErr?.name === 'AbortError') {
      throw new AamarvaError(`MCP server request timed out after ${timeoutMs}ms.`, {
        code: 'MCP_SERVER_UNREACHABLE',
      });
    }
    throw new AamarvaError(`Failed to reach MCP server at endpoint: ${netErr?.message || 'network error'}`, {
      code: 'MCP_SERVER_UNREACHABLE',
    });
  }
  clearTimeout(timer);

  if (response.status >= 300 && response.status < 400) {
    throw new AamarvaError('MCP server attempted HTTP redirect; redirects are disallowed.', {
      code: 'FLOOR_EXECUTION_FAILED',
    });
  }

  if (!response.ok) {
    throw new AamarvaError(
      `MCP server rejected invocation with HTTP status ${response.status}.`,
      { code: 'MCP_INVOCATION_FAILED' }
    );
  }

  const contentType = response.headers.get('content-type') || '';
  const text = await response.text();
  let resultJson: any;

  if (contentType.includes('text/event-stream')) {
    const dataLines = text
      .split(/\r?\n/)
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).trim())
      .filter(Boolean);
    if (dataLines.length === 0) {
      throw new AamarvaError('MCP server returned empty SSE stream.', {
        code: 'MCP_INVOCATION_FAILED',
      });
    }
    try {
      resultJson = JSON.parse(dataLines[dataLines.length - 1]);
    } catch {
      throw new AamarvaError('MCP server returned malformed JSON in SSE response.', {
        code: 'MCP_INVOCATION_FAILED',
      });
    }
  } else {
    try {
      resultJson = JSON.parse(text);
    } catch {
      throw new AamarvaError('MCP server returned malformed non-JSON response.', {
        code: 'MCP_INVOCATION_FAILED',
      });
    }
  }

  if (resultJson?.error) {
    const errMessage = resultJson.error.message || 'Unknown MCP tool error';
    throw new AamarvaError(`External MCP tool execution error: ${errMessage}`, {
      code: 'MCP_TOOL_ERROR',
    });
  }

  return resultJson?.result !== undefined
    ? resultJson.result
    : resultJson?.data !== undefined
    ? resultJson.data
    : resultJson;
}

/**
 * Executes an external MCP tool over Streamable HTTP MCP protocol (with hardened JSON-RPC fallback) after authorization approval.
 */
export async function invokeExternalMcpTool(params: McpExecuteParams): Promise<any> {
  const {
    serverUrl,
    toolId,
    args = {},
    auth,
    inputSchema,
    fetchFn,
    timeoutMs = 30000,
    allowInsecureHttpForLocalhost,
    useMcpSdk = true,
  } = params;

  const isCustomFetch = Boolean(fetchFn);
  const safeUrl = await assertSafeMcpServerUrl(serverUrl, {
    allowInsecureHttpForLocalhost,
    resolveDns: !isCustomFetch,
  });

  validateToolArguments(toolId, args, inputSchema);

  const authHeaders = buildMcpAuthHeaders(auth);

  const execFetch = fetchFn || (typeof fetch !== 'undefined' ? fetch : undefined);
  if (!execFetch) {
    throw new AamarvaError('Fetch API is not available in current environment for MCP tool execution.', {
      code: 'MCP_INVOCATION_FAILED',
    });
  }

  const guardedFetch: typeof fetch = async (input: any, init?: RequestInit) => {
    const targetUrl = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input?.url || '';
    if (targetUrl) {
      await assertSafeMcpServerUrl(targetUrl, {
        allowInsecureHttpForLocalhost,
        resolveDns: !isCustomFetch,
      });
    }
    const mergedHeaders = {
      ...((init?.headers as Record<string, string>) || {}),
      ...authHeaders,
    };
    const resp = await execFetch(input, {
      ...init,
      headers: mergedHeaders,
      redirect: 'manual',
    });
    if (resp.status >= 300 && resp.status < 400) {
      throw new AamarvaError('MCP server attempted HTTP redirect; redirects are disallowed.', {
        code: 'FLOOR_EXECUTION_FAILED',
      });
    }
    return resp;
  };

  const sdk = useMcpSdk ? tryLoadMcpClientSdk() : null;
  if (sdk) {
    const client = new sdk.Client(
      { name: 'aamarva-adk', version: '2.0.0' },
      { capabilities: {} }
    );
    const transport = new sdk.StreamableHTTPClientTransport(safeUrl, {
      fetch: guardedFetch,
      requestInit: { headers: authHeaders },
    });

    try {
      await client.connect(transport);
      const callRes = await client.callTool({
        name: toolId,
        arguments: args,
      });
      return callRes;
    } catch (sdkErr: any) {
      const code = sdkErr?.code;
      // Preserve explicit security / validation failures without falling back
      if (sdkErr instanceof AamarvaError && (code === 'FLOOR_EXECUTION_FAILED' || code === 'INVALID_TOOL_ARGUMENTS')) {
        throw sdkErr;
      }
      // If server returned HTTP 401/403, surface failure directly
      const msg = String(sdkErr?.message || '');
      if (/\b(401|403)\b/.test(msg)) {
        throw new AamarvaError('MCP server rejected credentials with unauthorized status.', {
          code: 'MCP_INVOCATION_FAILED',
        });
      }
      // Fall back to direct stateless JSON-RPC tools/call for endpoints that don't expose MCP session initialization
    } finally {
      try {
        await client.close();
      } catch {
        // Ignore close errors
      }
    }
  }

  return invokeViaJsonRpcFallback(safeUrl, toolId, args, authHeaders, execFetch, timeoutMs);
}
