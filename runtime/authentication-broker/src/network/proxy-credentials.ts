import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import type { BrokerPolicy } from '../policy/schema.js';
import type { ProxyCapabilityContext } from './origin-proxy.js';

export type ProxyScopeMode = 'blocked' | 'login' | 'target';

export interface ProxyScopeUpdate {
  readonly mode: ProxyScopeMode;
  readonly origins: readonly string[];
  readonly methods: readonly string[];
  readonly technique?: string;
}

interface ProxyCredentialRecord {
  readonly username: string;
  readonly password: string;
  readonly engagementId: string;
  readonly accountAlias: string;
  readonly policyRevision: string;
  readonly expiresAtUtc: string;
  readonly maxRequestBodyBytes: number;
  readonly policy: BrokerPolicy;
  generation: number;
  scope: ProxyScopeUpdate;
}

export class ProxyCredentialRegistry {
  private readonly records = new Map<string, ProxyCredentialRecord>();
  private readonly now: () => Date;

  constructor(options: { now?: () => Date } = {}) {
    this.now = options.now ?? (() => new Date());
  }

  issue(policy: BrokerPolicy, accountAlias: string): { username: string; password: string } {
    const now = this.now().getTime();
    const policyFreshUntilMs = Date.parse(policy?.policySnapshot?.freshUntilUtc ?? '');
    const policyExpiresAtMs = Date.parse(policy?.limits?.expiresAtUtc ?? '');
    const expiresAtMs = Math.min(policyFreshUntilMs, policyExpiresAtMs);
    if (!policy || !policy.accountAliases.includes(accountAlias) || !Number.isFinite(now) ||
        !Number.isFinite(policyFreshUntilMs) || !Number.isFinite(policyExpiresAtMs) || expiresAtMs <= now) {
      throw new Error('Proxy credentials are unavailable for this account');
    }
    const username = randomUUID();
    const password = randomBytes(32).toString('base64url');
    this.records.set(username, {
      username,
      password,
      engagementId: policy.engagementId,
      accountAlias,
      policyRevision: policy.policySnapshot.revision,
      expiresAtUtc: new Date(expiresAtMs).toISOString(),
      maxRequestBodyBytes: policy.limits.maxRequestBodyBytes,
      policy,
      generation: 0,
      scope: Object.freeze({ mode: 'blocked', origins: Object.freeze([]), methods: Object.freeze([]) })
    });
    return Object.freeze({ username, password });
  }

  setScope(username: string, update: ProxyScopeUpdate): void {
    const record = this.records.get(username);
    if (!record || Date.parse(record.expiresAtUtc) <= this.now().getTime()) throw new Error('Proxy scope exceeds policy or has expired');
    if (update.mode === 'blocked') {
      if (update.origins.length || update.methods.length) throw new Error('Proxy scope exceeds policy');
      const next = Object.freeze({ mode: 'blocked' as const, origins: Object.freeze([] as string[]), methods: Object.freeze([] as string[]) });
      if (!sameScope(record.scope, next)) { record.generation += 1; record.scope = next; }
      return;
    }
    // OAuth/OIDC commonly returns from the identity provider to an app callback.
    // The managed browser's bootstrap route separately limits target origins to GET/HEAD.
    const originPolicy = update.mode === 'login'
      ? [...record.policy.loginOrigins.map(({ origin }) => origin), ...record.policy.targetOrigins]
      : record.policy.targetOrigins;
    const methodPolicy = update.mode === 'login'
      ? new Set(['GET', 'HEAD', 'POST', 'OPTIONS'])
      : new Set(record.policy.grants.filter((grant) => grant.accountAlias === record.accountAlias).flatMap(({ methods }) => methods));
    if (!Array.isArray(update.origins) || !update.origins.length || new Set(update.origins).size !== update.origins.length ||
        update.origins.some((origin) => !originPolicy.includes(origin)) || !Array.isArray(update.methods) || !update.methods.length ||
        new Set(update.methods).size !== update.methods.length || update.methods.some((method) => !methodPolicy.has(method)) ||
        (update.mode === 'target' && typeof update.technique !== 'string')) {
      throw new Error('Proxy scope exceeds policy');
    }
    const next = Object.freeze({
      mode: update.mode,
      origins: Object.freeze([...update.origins]),
      methods: Object.freeze([...update.methods]),
      technique: update.technique ?? 'attended-login'
    });
    if (!sameScope(record.scope, next)) { record.generation += 1; record.scope = next; }
  }

  resolveCapability(proxyAuthorization: string | undefined): ProxyCapabilityContext | undefined {
    const parsed = parseBasicAuthorization(proxyAuthorization);
    if (!parsed) return undefined;
    const record = this.records.get(parsed.username);
    if (!record || record.scope.mode === 'blocked' || Date.parse(record.expiresAtUtc) <= this.now().getTime() ||
        !equalSecret(record.password, parsed.password)) return undefined;
    return Object.freeze({
      capabilityId: `${record.username}:${record.generation}`,
      engagementId: record.engagementId,
      accountAlias: record.accountAlias,
      policyRevision: record.policyRevision,
      technique: record.scope.technique ?? 'attended-login',
      allowedOrigins: record.scope.origins,
      allowedMethods: record.scope.methods,
      expiresAtUtc: record.expiresAtUtc,
      maxRequestBodyBytes: record.maxRequestBodyBytes
    });
  }

  isCurrent(capability: ProxyCapabilityContext | undefined): boolean {
    if (!capability || typeof capability.capabilityId !== 'string') return false;
    const separator = capability.capabilityId.lastIndexOf(':');
    if (separator < 1) return false;
    const username = capability.capabilityId.slice(0, separator);
    const generation = Number(capability.capabilityId.slice(separator + 1));
    const record = this.records.get(username);
    return Boolean(record && Number.isInteger(generation) && generation === record.generation && record.scope.mode !== 'blocked' &&
      Date.parse(record.expiresAtUtc) > this.now().getTime() && record.engagementId === capability.engagementId &&
      record.accountAlias === capability.accountAlias && record.policyRevision === capability.policyRevision);
  }

  revoke(username: string): void {
    this.records.delete(username);
  }
}

function sameScope(left: ProxyScopeUpdate, right: ProxyScopeUpdate): boolean {
  return left.mode === right.mode && left.technique === right.technique && left.origins.length === right.origins.length &&
    left.methods.length === right.methods.length && left.origins.every((value, index) => value === right.origins[index]) &&
    left.methods.every((value, index) => value === right.methods[index]);
}

function parseBasicAuthorization(value: string | undefined): { username: string; password: string } | undefined {
  if (typeof value !== 'string' || value.length > 512) return undefined;
  const match = /^Basic ([A-Za-z0-9+/]+={0,2})$/i.exec(value);
  if (!match) return undefined;
  try {
    const bytes = Buffer.from(match[1]!, 'base64');
    if (bytes.toString('base64').replace(/=+$/, '') !== match[1]!.replace(/=+$/, '')) return undefined;
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    const separator = decoded.indexOf(':');
    if (separator < 1) return undefined;
    return { username: decoded.slice(0, separator), password: decoded.slice(separator + 1) };
  } catch { return undefined; }
}

function equalSecret(expected: string, actual: string): boolean {
  const left = Buffer.from(expected, 'utf8');
  const right = Buffer.from(actual, 'utf8');
  return left.length === right.length && timingSafeEqual(left, right);
}
