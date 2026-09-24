import { normalizeOrigin } from './origin.js';
import type { CapabilityManager, GuardResult, HttpMethod, WorkerToolName } from '../capability/grants.js';

const METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const CREDENTIAL_OR_ROUTING_HEADERS = new Set(['authorization', 'proxy-authorization', 'proxy-authenticate', 'cookie', 'set-cookie', 'host', 'forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'connection', 'proxy-connection', 'transfer-encoding', 'content-length', 'upgrade', 'x-http-method-override', 'x-method-override']);

export interface RequestEvaluation {
  readonly allowed: boolean;
  readonly reason: string;
  readonly request?: Readonly<{ toolName: string; url: string; origin: string; path: string; method: string; bodyBytes: number; endpointAuthorizationId: string; body?: string | Buffer }>;
}

export interface WorkerRequestDecision {
  readonly allowed: boolean;
  readonly reason: string;
  readonly context?: GuardResult['context'];
  readonly release?: () => void;
  readonly request?: Readonly<Record<string, unknown>>;
  readonly authorizeEndpoint?: (request: { origin: string; method: string; path: string; technique: string; endpointAuthorizationId: string }) => boolean;
}

interface GuardCapability {
  readonly tools: readonly string[];
  readonly methods: readonly string[];
  readonly origins: readonly string[];
  readonly maxRequestBodyBytes: number;
  readonly authorizeEndpoint: (input: { origin: string; method: string; path: string; endpointAuthorizationId: string }) => boolean;
}

export function evaluateRequest(input: unknown, capability: unknown): RequestEvaluation {
  if (!isObject(input) || !isObject(capability)) return deny('request or capability is unavailable');
  const candidate = input as Record<string, unknown>;
  const cap = capability as Partial<GuardCapability>;
  if (!Array.isArray(cap.tools) || !Array.isArray(cap.methods) || !Array.isArray(cap.origins) ||
      !Number.isInteger(cap.maxRequestBodyBytes) || (cap.maxRequestBodyBytes ?? -1) < 0 || typeof cap.authorizeEndpoint !== 'function') {
    return deny('capability is invalid');
  }
  const toolName = typeof candidate.toolName === 'string' ? candidate.toolName : '';
  if (!cap.tools.includes(toolName)) return deny('tool is outside capability');
  if (typeof candidate.url !== 'string' || candidate.url.length > 8192 || typeof candidate.method !== 'string' ||
      candidate.method !== candidate.method.toUpperCase() || !METHODS.has(candidate.method)) return deny('request URL or method is invalid');
  if (candidate.technique !== undefined && typeof candidate.technique !== 'string') return deny('request is invalid');
  if (candidate.endpointAuthorizationId !== undefined && (typeof candidate.endpointAuthorizationId !== 'string' || candidate.endpointAuthorizationId.length > 128)) {
    return deny('endpoint authorization is invalid');
  }
  let target: URL;
  let origin: string;
  try {
    target = new URL(candidate.url);
    if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password || target.hash) return deny('request URL is invalid');
    const port = target.port || (target.protocol === 'https:' ? '443' : '80');
    origin = normalizeOrigin(`${target.protocol}//${target.hostname}:${port}`);
  } catch { return deny('request URL is invalid'); }
  const method = candidate.method;
  if (!cap.methods.includes(method)) return deny('method is outside capability');
  if (!cap.origins.includes(origin)) return deny('origin is outside capability');
  let bodyBytes = 0;
  if (candidate.body !== undefined) {
    if (typeof candidate.body !== 'string' && !Buffer.isBuffer(candidate.body)) return deny('request body is invalid');
    bodyBytes = Buffer.byteLength(candidate.body);
  }
  if (bodyBytes > Number(cap.maxRequestBodyBytes)) return deny('request body exceeds policy limit');
  if (method === 'GET' || method === 'HEAD') if (bodyBytes !== 0) return deny('read-only requests cannot include a body');
  if (candidate.headers !== undefined) {
    if (!isObject(candidate.headers)) return deny('request headers are invalid');
    const headers = candidate.headers as Record<string, unknown>;
    if (Object.entries(headers).some(([name, value]) => typeof value !== 'string' || CREDENTIAL_OR_ROUTING_HEADERS.has(name.toLowerCase()))) {
      return deny('credential or routing header is forbidden');
    }
  }
  const endpointAuthorizationId = typeof candidate.endpointAuthorizationId === 'string' ? candidate.endpointAuthorizationId : '';
  let endpointAllowed = false;
  try { endpointAllowed = cap.authorizeEndpoint({ origin, method, path: target.pathname || '/', endpointAuthorizationId }) === true; } catch { endpointAllowed = false; }
  if (!endpointAllowed) return deny('endpoint authorization is unavailable');
  return Object.freeze({
    allowed: true,
    reason: 'authorized',
    request: Object.freeze({
      toolName, url: target.toString(), origin, path: target.pathname || '/', method, bodyBytes, endpointAuthorizationId,
      ...(candidate.body !== undefined ? { body: candidate.body as string | Buffer } : {})
    })
  });
}

export class WorkerRequestGuard {
  constructor(private readonly capabilities: Pick<CapabilityManager,
    'acquireTool' | 'acquireWorkerRequest' | 'hasOpenWorkerIdentity' | 'workerCapabilityFor' | 'connectionIdForWorker'>) {}

  authorize(sessionId: string | undefined, toolName: WorkerToolName, input: unknown): WorkerRequestDecision {
    if (typeof sessionId !== 'string' || !sessionId) return deny('worker identity is unavailable');
    if (toolName === 'revoke_capability') {
      const capability = this.capabilities.workerCapabilityFor(sessionId);
      return this.capabilities.hasOpenWorkerIdentity(sessionId)
        ? Object.freeze({ allowed: true, reason: 'self-revocation allowed', ...(capability ? { context: capability.context } : {}) })
        : deny('worker identity is unavailable');
    }
    const capability = this.capabilities.workerCapabilityFor(sessionId);
    if (!capability) return deny('no active capability or current policy');
    if (!capability.tools.includes(toolName)) return deny('tool is outside capability');

    if (toolName === 'authorized_request') {
      const evaluation = evaluateRequest({ ...(isObject(input) ? input : {}), toolName }, capability);
      if (!evaluation.allowed || !evaluation.request) return deny(evaluation.reason);
      const normalized = evaluation.request as NonNullable<RequestEvaluation['request']>;
      const admitted = this.capabilities.acquireWorkerRequest(sessionId, {
        toolName,
        method: normalized.method as HttpMethod,
        origin: normalized.origin,
        path: normalized.path,
        endpointAuthorizationId: normalized.endpointAuthorizationId,
        bodyBytes: normalized.bodyBytes
      });
      const hopAuthorization = (request: { origin: string; method: string; path: string; technique: string; endpointAuthorizationId: string }): boolean => {
        const current = this.capabilities.workerCapabilityFor(sessionId);
        if (!current || current.context.connectionId !== capability.context.connectionId ||
            current.context.policyRevision !== capability.context.policyRevision || !current.origins.includes(request.origin) ||
            !current.methods.includes(request.method as HttpMethod) || request.technique !== current.context.technique) return false;
        return current.authorizeEndpoint({
          origin: request.origin,
          method: request.method as HttpMethod,
          path: request.path,
          endpointAuthorizationId: request.endpointAuthorizationId
        });
      };
      return combineAdmission(admitted, normalized, hopAuthorization, capability.context);
    }

    if (toolName === 'navigate') {
      const candidate = isObject(input) ? input : {};
      if (typeof candidate.url !== 'string' || candidate.url.length > 8192) return deny('navigation URL is invalid');
      let target: URL;
      let origin: string;
      try {
        target = new URL(candidate.url);
        if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password || target.hash) return deny('navigation URL is invalid');
        origin = normalizeOrigin(`${target.protocol}//${target.hostname}:${target.port || (target.protocol === 'https:' ? '443' : '80')}`);
      } catch { return deny('navigation URL is invalid'); }
      if (!capability.methods.some((method) => method === 'GET' || method === 'HEAD') || !capability.origins.includes(origin)) {
        return deny('navigation is outside capability');
      }
      const admitted = this.capabilities.acquireWorkerRequest(sessionId, {
        toolName,
        method: 'GET',
        origin,
        path: target.pathname || '/',
        endpointAuthorizationId: 'page-navigation',
        checkEndpoint: false
      });
      return combineAdmission(admitted, { url: target.toString(), origin, path: target.pathname || '/' }, undefined, capability.context);
    }

    if (toolName === 'observe_page' || toolName === 'act_on_observed_element') {
      if (!capability.origins.length || !capability.methods.some((method) => method === 'GET' || method === 'HEAD')) {
        return deny('page tools exceed read-only capability');
      }
    }
    return combineAdmission(this.capabilities.acquireTool(sessionId, toolName), undefined, undefined, capability.context);
  }

  connectionIdForWorker(sessionId: string | undefined): string | undefined {
    return this.capabilities.connectionIdForWorker(sessionId);
  }
}

function combineAdmission(
  admission: GuardResult,
  request: Readonly<Record<string, unknown>> | undefined,
  authorizeEndpoint?: WorkerRequestDecision['authorizeEndpoint'],
  fallbackContext?: WorkerRequestDecision['context']
): WorkerRequestDecision {
  return admission.allowed
    ? Object.freeze({ allowed: true, reason: 'authorized', ...(admission.context ? { context: admission.context } : {}), ...(admission.release ? { release: admission.release } : {}), ...(request ? { request } : {}), ...(authorizeEndpoint ? { authorizeEndpoint } : {}) })
    : Object.freeze({ allowed: false, reason: admission.reason, ...(fallbackContext ? { context: fallbackContext } : {}) });
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function deny(reason: string): RequestEvaluation {
  return Object.freeze({ allowed: false, reason });
}
