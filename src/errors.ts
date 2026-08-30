/**
 * Actionable, typed error classes for the AAMARVA ADK.
 */

export interface ErrorOptions {
  statusCode?: number;
  code?: string;
  hint?: string;
  details?: unknown;
  cause?: Error;
}

export class AamarvaError extends Error {
  public readonly statusCode?: number;
  public readonly code: string;
  public readonly hint?: string;
  public readonly details?: unknown;

  constructor(message: string, options: ErrorOptions = {}) {
    super(message);
    this.name = 'AamarvaError';
    this.statusCode = options.statusCode;
    this.code = options.code || 'AAMARVA_ERROR';
    this.hint = options.hint;
    this.details = options.details;
    if (options.cause) {
      this.cause = options.cause;
    }
  }

  public override toString(): string {
    let result = `${this.name} [${this.code}]: ${this.message}`;
    if (this.statusCode) {
      result += ` (HTTP ${this.statusCode})`;
    }
    if (this.hint) {
      result += `\nHint: ${this.hint}`;
    }
    return result;
  }
}

export class AamarvaAuthError extends AamarvaError {
  constructor(message: string = 'AAMARVA authentication failed.', options: ErrorOptions = {}) {
    super(message, {
      statusCode: options.statusCode || 401,
      code: options.code || 'AUTH_FAILED',
      hint: options.hint || 'Verify your AAMARVA_AGENT_ID and AAMARVA_API_KEY credentials. You can run `npx aamarva init` to re-configure.',
      ...options,
    });
    this.name = 'AamarvaAuthError';
  }
}

export class AamarvaForbiddenError extends AamarvaError {
  constructor(message: string = 'Access forbidden to this AAMARVA resource.', options: ErrorOptions = {}) {
    super(message, {
      statusCode: options.statusCode || 403,
      code: options.code || 'FORBIDDEN',
      hint: options.hint || 'Check that your agent owns this resource or has permission to perform this action.',
      ...options,
    });
    this.name = 'AamarvaForbiddenError';
  }
}

export class AamarvaNotFoundError extends AamarvaError {
  constructor(message: string = 'Requested AAMARVA resource not found.', options: ErrorOptions = {}) {
    super(message, {
      statusCode: options.statusCode || 404,
      code: options.code || 'NOT_FOUND',
      hint: options.hint || 'Verify the identifier (agentId, postId, connectionId, or requestId) exists and is spelled correctly.',
      ...options,
    });
    this.name = 'AamarvaNotFoundError';
  }
}

export class AamarvaConflictError extends AamarvaError {
  constructor(message: string = 'AAMARVA resource conflict.', options: ErrorOptions = {}) {
    super(message, {
      statusCode: options.statusCode || 409,
      code: options.code || 'CONFLICT',
      hint: options.hint || 'The requested action conflicts with existing state (e.g. email/agentId already exists or request already pending).',
      ...options,
    });
    this.name = 'AamarvaConflictError';
  }
}

export class AamarvaRateLimitError extends AamarvaError {
  public readonly retryAfterSeconds?: number;

  constructor(message: string = 'AAMARVA rate limit exceeded.', options: ErrorOptions & { retryAfterSeconds?: number } = {}) {
    const hint = options.retryAfterSeconds 
      ? `Rate limit exceeded. Please back off and retry after ${options.retryAfterSeconds} seconds.`
      : 'Rate limit exceeded. Reduce request frequency or observe Retry-After headers.';
    
    super(message, {
      statusCode: options.statusCode || 429,
      code: options.code || 'RATE_LIMITED',
      hint: options.hint || hint,
      ...options,
    });
    this.name = 'AamarvaRateLimitError';
    this.retryAfterSeconds = options.retryAfterSeconds;
  }
}

export class AamarvaValidationError extends AamarvaError {
  constructor(message: string = 'Invalid input parameters for AAMARVA request.', options: ErrorOptions = {}) {
    super(message, {
      statusCode: options.statusCode || 400,
      code: options.code || 'VALIDATION_FAILED',
      hint: options.hint || 'Review the required request payload fields and parameter types.',
      ...options,
    });
    this.name = 'AamarvaValidationError';
  }
}

export class AamarvaTimeoutError extends AamarvaError {
  constructor(message: string = 'AAMARVA request timed out.', options: ErrorOptions = {}) {
    super(message, {
      code: options.code || 'TIMEOUT',
      hint: options.hint || 'The request exceeded the configured timeout limit. Check network connectivity or increase timeoutMs.',
      ...options,
    });
    this.name = 'AamarvaTimeoutError';
  }
}

export class AamarvaNetworkError extends AamarvaError {
  constructor(message: string = 'Failed to connect to AAMARVA API.', options: ErrorOptions = {}) {
    super(message, {
      code: options.code || 'NETWORK_ERROR',
      hint: options.hint || 'Check your internet connection and verify the base URL is reachable.',
      ...options,
    });
    this.name = 'AamarvaNetworkError';
  }
}

export class AamarvaServerError extends AamarvaError {
  constructor(message: string = 'AAMARVA server error encountered.', options: ErrorOptions = {}) {
    super(message, {
      statusCode: options.statusCode || 500,
      code: options.code || 'SERVER_ERROR',
      hint: options.hint || 'The AAMARVA server encountered an unexpected error. Safe requests will automatically retry with backoff.',
      ...options,
    });
    this.name = 'AamarvaServerError';
  }
}

/**
 * Normalizes any HTTP response or runtime error into a standard AamarvaError instance.
 */
export function normalizeError(err: unknown, statusCode?: number, responseData?: unknown): AamarvaError {
  if (err instanceof AamarvaError) {
    return err;
  }

  const resObj = (typeof responseData === 'object' && responseData !== null) ? (responseData as Record<string, unknown>) : null;
  const errObj = (typeof err === 'object' && err !== null) ? (err as Record<string, unknown>) : null;

  // Extract nested error objects (e.g. { error: { code: '...', message: '...' } }) safely
  let message = 'An unexpected error occurred';
  if (resObj?.error && typeof resObj.error === 'object' && (resObj.error as Record<string, unknown>).message) {
    message = String((resObj.error as Record<string, unknown>).message);
  } else if (typeof resObj?.error === 'string') {
    message = resObj.error;
  } else if (typeof resObj?.message === 'string') {
    message = resObj.message;
  } else if (errObj?.message && typeof errObj.message === 'string') {
    message = errObj.message;
  }

  let code = 'AAMARVA_ERROR';
  if (resObj?.error && typeof resObj.error === 'object' && (resObj.error as Record<string, unknown>).code) {
    code = String((resObj.error as Record<string, unknown>).code);
  } else if (typeof resObj?.code === 'string') {
    code = resObj.code;
  } else if (typeof errObj?.code === 'string') {
    code = errObj.code;
  }

  const status = statusCode || (typeof errObj?.status === 'number' ? errObj.status : typeof errObj?.statusCode === 'number' ? errObj.statusCode : undefined);
  const causeErr = err instanceof Error ? err : undefined;

  switch (status) {
    case 400:
    case 422:
      return new AamarvaValidationError(message, { statusCode: status, code, details: responseData, cause: causeErr });
    case 401:
      return new AamarvaAuthError(message, { statusCode: status, code, details: responseData, cause: causeErr });
    case 403:
      return new AamarvaForbiddenError(message, { statusCode: status, code, details: responseData, cause: causeErr });
    case 404:
      return new AamarvaNotFoundError(message, { statusCode: status, code, details: responseData, cause: causeErr });
    case 409:
      return new AamarvaConflictError(message, { statusCode: status, code, details: responseData, cause: causeErr });
    case 429: {
      const rawRetry = resObj?.retryAfter || resObj?.retry_after;
      const retrySeconds = typeof rawRetry === 'number' ? rawRetry : typeof rawRetry === 'string' ? parseInt(rawRetry, 10) || undefined : undefined;
      return new AamarvaRateLimitError(message, { statusCode: status, code, details: responseData, retryAfterSeconds: retrySeconds, cause: causeErr });
    }
    case 500:
    case 502:
    case 503:
    case 504:
      return new AamarvaServerError(message, { statusCode: status, code, details: responseData, cause: causeErr });
    default:
      if (errObj?.name === 'AbortError' || errObj?.name === 'TimeoutError') {
        return new AamarvaTimeoutError(message, { cause: causeErr });
      }
      if (errObj?.code === 'ENOTFOUND' || errObj?.code === 'ECONNREFUSED' || errObj?.code === 'ECONNRESET') {
        return new AamarvaNetworkError(message, { cause: causeErr });
      }
      return new AamarvaError(message, { statusCode: status, code, details: responseData, cause: causeErr });
  }
}
