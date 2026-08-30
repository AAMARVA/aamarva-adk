/**
 * HTTP Client Layer with single-flight auth, single-flight token refresh, timeouts, safe retries, and error normalization.
 */

import { AamarvaConfig, ApiResponse, AuthTokens } from './types.js';
import { normalizeError, AamarvaAuthError, AamarvaTimeoutError } from './errors.js';

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE' | 'PUT' | 'HEAD';
  path: string;
  query?: Record<string, string | number | boolean | undefined | null>;
  body?: unknown;
  headers?: Record<string, string>;
  auth?: boolean;
  timeoutMs?: number;
  retries?: number;
  skipAutoAuth?: boolean;
}

export class HttpClient {
  private baseUrl: string;
  private agentId?: string;
  private apiKey?: string;
  private accessToken?: string;
  private refreshToken?: string;
  private timeoutMs: number;
  private maxRetries: number;
  private fetchFn: typeof fetch;
  private autoLogin: boolean;

  private authPromise: Promise<void> | null = null;
  private refreshPromise: Promise<boolean> | null = null;

  constructor(config: AamarvaConfig = {}) {
    const defaultUrl = 'https://aamarva.com/api';
    const rawUrl = config.baseUrl || (typeof process !== 'undefined' && process.env?.AAMARVA_BASE_URL) || defaultUrl;
    this.baseUrl = rawUrl.replace(/\/+$/, '');

    this.agentId = config.agentId || (typeof process !== 'undefined' && process.env?.AAMARVA_AGENT_ID) || undefined;
    this.apiKey = config.apiKey || (typeof process !== 'undefined' && process.env?.AAMARVA_API_KEY) || undefined;
    this.accessToken = config.accessToken || (typeof process !== 'undefined' && process.env?.AAMARVA_ACCESS_TOKEN) || undefined;
    this.refreshToken = config.refreshToken || (typeof process !== 'undefined' && process.env?.AAMARVA_REFRESH_TOKEN) || undefined;
    this.timeoutMs = config.timeoutMs || 15000;
    this.maxRetries = typeof config.maxRetries === 'number' ? config.maxRetries : 3;
    this.fetchFn = config.fetch || globalThis.fetch.bind(globalThis);
    this.autoLogin = config.autoLogin !== false;
  }

  public setTokens(tokens: AuthTokens): void {
    this.accessToken = tokens.accessToken;
    this.refreshToken = tokens.refreshToken;
  }

  public getTokens(): { accessToken?: string; refreshToken?: string } {
    return {
      accessToken: this.accessToken,
      refreshToken: this.refreshToken,
    };
  }

  public setCredentials(agentId: string, apiKey: string): void {
    this.agentId = agentId;
    this.apiKey = apiKey;
    this.accessToken = undefined;
    this.refreshToken = undefined;
  }

  public getAgentId(): string | undefined {
    return this.agentId;
  }

  public getBaseUrl(): string {
    return this.baseUrl;
  }

  /**
   * Authenticate using agentId and apiKey (Single-flight execution)
   */
  public async ensureAuthenticated(): Promise<void> {
    if (this.accessToken) {
      return;
    }

    if (!this.agentId || !this.apiKey) {
      throw new AamarvaAuthError(
        'Authentication required, but no credentials were provided.',
        {
          hint: 'Provide agentId & apiKey or set AAMARVA_AGENT_ID & AAMARVA_API_KEY environment variables.',
        }
      );
    }

    if (this.authPromise) {
      return this.authPromise;
    }

    this.authPromise = (async () => {
      try {
        const response = await this.rawRequest<{
          tokens?: AuthTokens;
          accessToken?: string;
          refreshToken?: string;
        }>({
          method: 'POST',
          path: '/auth/login',
          body: {
            agentId: this.agentId,
            apiKey: this.apiKey,
          },
          auth: false,
          retries: 1,
        });

        const data = response.data;
        if (data?.tokens?.accessToken) {
          this.accessToken = data.tokens.accessToken;
          this.refreshToken = data.tokens.refreshToken;
        } else if (data?.accessToken) {
          this.accessToken = data.accessToken;
          this.refreshToken = data.refreshToken;
        }
      } finally {
        this.authPromise = null;
      }
    })();

    return this.authPromise;
  }

  /**
   * Refresh session access token (Single-flight execution)
   */
  public async refreshAccessToken(): Promise<boolean> {
    if (!this.refreshToken) {
      return false;
    }

    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = (async () => {
      try {
        const response = await this.rawRequest<{
          accessToken?: string;
          refreshToken?: string;
        }>({
          method: 'POST',
          path: '/auth/refresh',
          body: {
            refreshToken: this.refreshToken,
          },
          auth: false,
          retries: 1,
        });

        if (response.data?.accessToken) {
          this.accessToken = response.data.accessToken;
          if (response.data.refreshToken) {
            this.refreshToken = response.data.refreshToken;
          }
          return true;
        }
        return false;
      } catch {
        this.accessToken = undefined;
        return false;
      } finally {
        this.refreshPromise = null;
      }
    })();

    return this.refreshPromise;
  }

  /**
   * High-level request method with single-flight auth, auto-refresh on 401, retries, and error handling
   */
  public async request<T = unknown>(options: RequestOptions): Promise<ApiResponse<T>> {
    const isAuthRequired = options.auth !== false;

    if (isAuthRequired && this.autoLogin && !this.accessToken) {
      await this.ensureAuthenticated();
    }

    try {
      return await this.executeWithRetry<T>(options);
    } catch (err: unknown) {
      if (err instanceof AamarvaAuthError && isAuthRequired) {
        const refreshed = await this.refreshAccessToken();
        if (refreshed) {
          return await this.executeWithRetry<T>(options);
        } else if (this.agentId && this.apiKey) {
          this.accessToken = undefined;
          await this.ensureAuthenticated();
          return await this.executeWithRetry<T>(options);
        }
      }
      throw err;
    }
  }

  private async executeWithRetry<T>(options: RequestOptions): Promise<ApiResponse<T>> {
    const method = options.method || 'GET';
    const isIdempotent = method === 'GET' || method === 'HEAD';
    const maxAttempts = options.retries !== undefined ? options.retries : isIdempotent ? this.maxRetries : 0;

    let attempt = 0;
    let lastError: unknown;

    while (attempt <= maxAttempts) {
      try {
        return await this.rawRequest<T>(options);
      } catch (err: unknown) {
        lastError = err;
        attempt++;

        const errObj = (typeof err === 'object' && err !== null) ? (err as Record<string, unknown>) : null;
        const statusCode = typeof errObj?.statusCode === 'number' ? errObj.statusCode : undefined;
        const isRetryableStatus = statusCode === 429 || (statusCode !== undefined && statusCode >= 500 && statusCode <= 504);
        const isNetworkFailure = statusCode === undefined;

        if (attempt <= maxAttempts && isIdempotent && (isRetryableStatus || isNetworkFailure)) {
          let delayMs = Math.min(Math.pow(2, attempt) * 300, 5000);
          if (statusCode === 429 && typeof errObj?.retryAfterSeconds === 'number') {
            delayMs = Math.max(delayMs, errObj.retryAfterSeconds * 1000);
          }
          await new Promise((resolve) => setTimeout(resolve, delayMs));
          continue;
        }

        throw err;
      }
    }

    throw lastError;
  }

  public async rawRequest<T = unknown>(options: RequestOptions): Promise<ApiResponse<T>> {
    const method = options.method || 'GET';
    let url = `${this.baseUrl}${options.path.startsWith('/') ? options.path : '/' + options.path}`;

    if (options.query) {
      const searchParams = new URLSearchParams();
      for (const [key, value] of Object.entries(options.query)) {
        if (value !== undefined && value !== null) {
          searchParams.append(key, String(value));
        }
      }
      const qs = searchParams.toString();
      if (qs) {
        url += (url.includes('?') ? '&' : '?') + qs;
      }
    }

    const headers: Record<string, string> = {
      'Accept': 'application/json',
      ...options.headers,
    };

    if (options.body && method !== 'GET' && method !== 'HEAD') {
      headers['Content-Type'] = 'application/json';
    }

    if (options.auth !== false && this.accessToken) {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }

    const timeout = options.timeoutMs || this.timeoutMs;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
      const response = await this.fetchFn(url, {
        method,
        headers,
        body: options.body && method !== 'GET' && method !== 'HEAD' ? JSON.stringify(options.body) : undefined,
        signal: controller.signal,
      });

      clearTimeout(timer);

      const contentType = response.headers.get('content-type') || '';
      let data: unknown;

      if (contentType.includes('application/json')) {
        data = await response.json().catch(() => null);
      } else {
        const text = await response.text();
        try {
          data = JSON.parse(text);
        } catch {
          data = { message: text };
        }
      }

      if (!response.ok) {
        throw normalizeError(null, response.status, data);
      }

      if (data && typeof data === 'object' && 'success' in data) {
        return data as ApiResponse<T>;
      }

      return {
        success: true,
        data: data as T,
      };
    } catch (err: unknown) {
      clearTimeout(timer);
      const errObj = (typeof err === 'object' && err !== null) ? (err as Record<string, unknown>) : null;
      if (errObj?.name === 'AbortError') {
        throw new AamarvaTimeoutError(`Request to ${options.path} timed out after ${timeout}ms.`);
      }
      throw normalizeError(err);
    }
  }
}
