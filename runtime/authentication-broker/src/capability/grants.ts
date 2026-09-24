import type { BrokerPolicy } from '../policy/schema.js';
import type { ConnectionId, ConnectionIdResolver, ConnectionRegistry } from './connection-registry.js';

export type WorkerToolName = 'session_status' | 'open_login' | 'observe_page' | 'navigate' | 'act_on_observed_element' | 'authorized_request' | 'revoke_capability';
export type CapabilityRole = 'mapper' | 'tester' | 'validator';
export type HttpMethod = 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS';

export interface GrantInput {
  connectionId: string;
  accountAlias: string;
  role: CapabilityRole;
  tools: WorkerToolName[];
  technique: string;
  policyReference: string;
  methods: HttpMethod[];
  origins: string[];
}

export interface GuardedRequest {
  toolName: WorkerToolName;
  method: HttpMethod;
  origin: string;
  technique: string;
  endpointAuthorizationId: string;
  bodyBytes?: number;
  // Deliberately ignored if supplied by an untrusted caller. Identity/account
  // values come only from the server registry and researcher-issued capability.
  accountAlias?: string;
  connectionId?: string;
}

export interface RequestContext {
  engagementId: string;
  accountAlias: string;
  policyRevision: string;
}

export interface GuardResult {
  allowed: boolean;
  reason: string;
  context?: RequestContext;
  release?: () => void;
}

interface Capability {
  readonly connectionId: ConnectionId;
  readonly engagementId: string;
  readonly policyRevision: string;
  readonly accountAlias: string;
  readonly role: CapabilityRole;
  readonly tools: ReadonlySet<WorkerToolName>;
  readonly technique: string;
  readonly policyReference: string;
  readonly methods: ReadonlySet<HttpMethod>;
  readonly origins: ReadonlySet<string>;
  readonly expiresAtMs: number;
  remainingRequests: number;
  activeRequests: number;
  rateTokens: number;
  lastRefillMs: number;
}

interface CapabilitySummary {
  connectionId: string;
  accountAlias: string;
  policyRevision: string;
  policyReference: string;
  expiresAtUtc: string;
}

interface CapabilityManagerOptions {
  getPolicy: () => BrokerPolicy | undefined;
  now: () => Date;
  /** Missing or uncertain verification is equivalent to unverified. */
  egressIsVerified?: () => boolean;
  /** Required endpoint-level authorization lookup; no default allow exists. */
  authorizeEndpoint: (context: RequestContext & { policyReference: string; origin: string; method: HttpMethod; endpointAuthorizationId: string }) => boolean;
}

type RegistryAccess = ConnectionIdResolver & Partial<Pick<ConnectionRegistry, 'list' | 'onClosed'>>;

const roleTools: Record<CapabilityRole, ReadonlySet<WorkerToolName>> = {
  mapper: new Set(['session_status', 'observe_page', 'navigate']),
  tester: new Set(['session_status', 'open_login', 'observe_page', 'navigate', 'act_on_observed_element', 'authorized_request']),
  validator: new Set(['session_status', 'observe_page', 'navigate', 'authorized_request'])
};

export class CapabilityManager {
  private readonly capabilities = new Map<ConnectionId, Capability>();
  private readonly getPolicy: () => BrokerPolicy | undefined;
  private readonly now: () => Date;
  private readonly egressIsVerified: () => boolean;
  private readonly authorizeEndpoint: CapabilityManagerOptions['authorizeEndpoint'];
  private readonly registry: RegistryAccess;

  constructor(registry: RegistryAccess, options: CapabilityManagerOptions) {
    this.registry = registry;
    this.getPolicy = options.getPolicy;
    this.now = options.now;
    this.egressIsVerified = options.egressIsVerified ?? (() => false);
    this.authorizeEndpoint = options.authorizeEndpoint;
    registry.onClosed?.((connectionId) => this.capabilities.delete(connectionId));
  }

  grant(input: GrantInput): CapabilitySummary {
    if (!this.isEgressVerified()) throw new Error('Capability grant requires verified egress protection');
    const connectionId = input.connectionId as ConnectionId;
    if (!this.registry.list?.().some((record) => record.connectionId === connectionId)) throw new Error('Capability grant requires an open researcher-selected connection');
    const policy = this.currentPolicy();
    if (!policy) throw new Error('Current policy is unavailable or stale');
    const policyGrants = policy.grants.filter((candidate) => candidate.accountAlias === input.accountAlias &&
      candidate.technique === input.technique && candidate.policyReference === input.policyReference);
    const policyGrant = policyGrants.length === 1 ? policyGrants[0] : undefined;
    if (!policyGrant || !policy.accountAliases.includes(input.accountAlias)) throw new Error('Capability grant is not present in current policy');
    if (!input.tools.length || input.tools.some((tool) => !roleTools[input.role]?.has(tool))) throw new Error('Capability tools exceed the selected role');
    if (!input.methods.length || input.methods.some((method) => !policyGrant.methods.includes(method))) throw new Error('Capability methods exceed the policy grant');
    if (!input.origins.length || input.origins.some((origin) => !policy.targetOrigins.includes(origin))) throw new Error('Capability origin is not an exact target origin');
    if (new Set(input.tools).size !== input.tools.length || new Set(input.methods).size !== input.methods.length || new Set(input.origins).size !== input.origins.length) {
      throw new Error('Capability grant contains duplicate values');
    }

    const nowMs = this.now().getTime();
    const expiresAtMs = Math.min(Date.parse(policy.limits.expiresAtUtc), Date.parse(policy.policySnapshot.freshUntilUtc));
    const capability: Capability = {
      connectionId,
      engagementId: policy.engagementId,
      policyRevision: policy.policySnapshot.revision,
      accountAlias: input.accountAlias,
      role: input.role,
      tools: new Set(input.tools),
      technique: input.technique,
      policyReference: input.policyReference,
      methods: new Set(input.methods),
      origins: new Set(input.origins),
      expiresAtMs,
      remainingRequests: policy.limits.maxRequestsPerCapability,
      activeRequests: 0,
      rateTokens: policy.limits.requestsPerSecond,
      lastRefillMs: nowMs
    };
    this.capabilities.set(connectionId, capability);
    return this.summary(capability);
  }

  acquire(sessionId: string | undefined, request: GuardedRequest): GuardResult {
    const connectionId = this.registry.resolve(sessionId);
    if (!connectionId) return denied('worker identity is unavailable');
    const capability = this.capabilities.get(connectionId);
    if (!capability) return denied('no active capability');
    const nowMs = this.now().getTime();
    const policy = this.currentPolicy();
    if (!policy || policy.policySnapshot.revision !== capability.policyRevision || policy.engagementId !== capability.engagementId) {
      this.capabilities.delete(connectionId);
      return denied('policy changed or is unavailable');
    }
    if (!this.isEgressVerified()) {
      this.capabilities.delete(connectionId);
      return denied('egress protection is unverified');
    }
    if (nowMs >= capability.expiresAtMs) {
      this.capabilities.delete(connectionId);
      return denied('capability expired');
    }
    if (!capability.tools.has(request.toolName)) return denied('tool is outside capability');
    if (request.technique !== capability.technique) return denied('technique is outside capability');
    if (!capability.methods.has(request.method) || !policy.targetOrigins.includes(request.origin) || !capability.origins.has(request.origin)) return denied('method or origin is outside capability');
    if (!Number.isSafeInteger(request.bodyBytes ?? 0) || (request.bodyBytes ?? 0) < 0 || (request.bodyBytes ?? 0) > policy.limits.maxRequestBodyBytes) return denied('request body exceeds policy limit');
    const currentGrants = policy.grants.filter((candidate) => candidate.accountAlias === capability.accountAlias &&
      candidate.technique === capability.technique && candidate.policyReference === capability.policyReference);
    const currentGrant = currentGrants.length === 1 ? currentGrants[0] : undefined;
    if (!currentGrant || !currentGrant.methods.includes(request.method)) {
      this.capabilities.delete(connectionId);
      return denied('policy grant is no longer current');
    }
    const context: RequestContext = {
      engagementId: capability.engagementId,
      accountAlias: capability.accountAlias,
      policyRevision: capability.policyRevision
    };
    let endpointAllowed = false;
    try {
      endpointAllowed = this.authorizeEndpoint({ ...context, policyReference: capability.policyReference, origin: request.origin, method: request.method, endpointAuthorizationId: request.endpointAuthorizationId });
    } catch {
      endpointAllowed = false;
    }
    if (!endpointAllowed) return denied('endpoint authorization is unavailable');
    if (capability.activeRequests >= policy.limits.maxConcurrentRequests) return denied('concurrency ceiling reached');
    refill(capability, nowMs, policy.limits.requestsPerSecond);
    if (capability.rateTokens < 1) return denied('request rate ceiling reached');
    if (capability.remainingRequests < 1) return denied('request budget exhausted');

    capability.rateTokens -= 1;
    capability.remainingRequests -= 1;
    capability.activeRequests += 1;
    let released = false;
    return {
      allowed: true,
      reason: 'authorized',
      context,
      release: () => {
        if (released) return;
        released = true;
        capability.activeRequests = Math.max(0, capability.activeRequests - 1);
      }
    };
  }

  revoke(connectionId: string): boolean {
    return this.capabilities.delete(connectionId as ConnectionId);
  }

  revokeForSession(sessionId?: string): boolean {
    const connectionId = this.registry.resolve(sessionId);
    return connectionId ? this.capabilities.delete(connectionId) : false;
  }

  hasCapability(connectionId: string): boolean {
    return this.capabilities.has(connectionId as ConnectionId);
  }

  accountAliasFor(connectionId: string): string | undefined {
    return this.capabilities.get(connectionId as ConnectionId)?.accountAlias;
  }

  private currentPolicy(): BrokerPolicy | undefined {
    const policy = this.getPolicy();
    if (!policy) return undefined;
    const nowMs = this.now().getTime();
    const capturedAt = Date.parse(policy.policySnapshot.capturedAtUtc);
    const freshUntil = Date.parse(policy.policySnapshot.freshUntilUtc);
    const expiresAt = Date.parse(policy.limits.expiresAtUtc);
    if (!Number.isFinite(nowMs) || !Number.isFinite(capturedAt) || !Number.isFinite(freshUntil) || !Number.isFinite(expiresAt) ||
        capturedAt > nowMs || freshUntil <= nowMs || expiresAt <= nowMs) return undefined;
    return policy;
  }

  private isEgressVerified(): boolean {
    try { return this.egressIsVerified() === true; } catch { return false; }
  }

  private summary(capability: Capability): CapabilitySummary {
    return {
      connectionId: capability.connectionId,
      accountAlias: capability.accountAlias,
      policyRevision: capability.policyRevision,
      policyReference: capability.policyReference,
      expiresAtUtc: new Date(capability.expiresAtMs).toISOString()
    };
  }
}

function refill(capability: Capability, nowMs: number, requestsPerSecond: number): void {
  const elapsedSeconds = Math.max(0, nowMs - capability.lastRefillMs) / 1000;
  capability.rateTokens = Math.min(requestsPerSecond, capability.rateTokens + elapsedSeconds * requestsPerSecond);
  capability.lastRefillMs = nowMs;
}

function denied(reason: string): GuardResult {
  return { allowed: false, reason };
}
