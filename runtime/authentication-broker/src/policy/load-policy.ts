import { readFile } from 'node:fs/promises';
import { BrokerPolicySchema, type BrokerPolicy, type DeepReadonly } from './schema.js';
import { normalizeOrigin } from './origin.js';

export async function loadPolicy(filePath: string, now: Date): Promise<DeepReadonly<BrokerPolicy>> {
  if (!Number.isFinite(now.getTime())) throw new Error('Policy reference time is invalid');

  let rawText: string;
  try {
    rawText = await readFile(filePath, 'utf8');
  } catch {
    throw new Error('Policy file is unavailable or invalid');
  }

  let raw: unknown;
  try {
    raw = JSON.parse(rawText) as unknown;
  } catch {
    throw new Error('Policy file is unavailable or invalid');
  }

  const parsed = BrokerPolicySchema.safeParse(raw);
  if (!parsed.success) throw new Error('Policy does not satisfy schema version 1');

  const policy = parsed.data;
  let normalized: BrokerPolicy;
  try {
    normalized = {
      ...policy,
      policySnapshot: { ...policy.policySnapshot },
      loginOrigins: policy.loginOrigins.map((login) => ({ ...login, origin: normalizeOrigin(login.origin) })),
      refreshOrigins: policy.refreshOrigins.map((refresh) => ({ ...refresh, origin: normalizeOrigin(refresh.origin) })),
      targetOrigins: policy.targetOrigins.map(normalizeOrigin),
      grants: policy.grants.map((grant) => ({ ...grant, methods: [...grant.methods] })),
      accountAliases: [...policy.accountAliases],
      stopConditions: [...policy.stopConditions],
      limits: { ...policy.limits }
    };
  } catch {
    throw new Error('Policy contains an invalid origin');
  }

  validateRelations(normalized, now);
  return deepFreeze(normalized);
}

function validateRelations(policy: BrokerPolicy, now: Date): void {
  const capturedAt = Date.parse(policy.policySnapshot.capturedAtUtc);
  const freshUntil = Date.parse(policy.policySnapshot.freshUntilUtc);
  const expiresAt = Date.parse(policy.limits.expiresAtUtc);
  const nowMs = now.getTime();
  if (!validHttpUrl(policy.policySnapshot.url) || !Number.isFinite(capturedAt) || !Number.isFinite(freshUntil) ||
      !Number.isFinite(expiresAt) || capturedAt > nowMs || freshUntil <= nowMs || freshUntil <= capturedAt || expiresAt <= nowMs) {
    throw new Error('Policy snapshot or capability is stale or expired');
  }

  assertUnique(policy.accountAliases);
  assertUnique(policy.targetOrigins);
  assertUnique(policy.loginOrigins.map(({ origin }) => origin));
  assertUnique(policy.refreshOrigins.map(({ origin }) => origin));
  const targets = new Set(policy.targetOrigins);
  if (policy.loginOrigins.some(({ origin }) => targets.has(origin)) ||
      policy.refreshOrigins.some(({ origin }) => targets.has(origin))) {
    throw new Error('Login and refresh origins cannot be worker target origins');
  }
  if (new Set(policy.loginOrigins.map(({ origin }) => origin)).size !== policy.loginOrigins.length) {
    throw new Error('Policy contains duplicate origins');
  }

  const aliases = new Set(policy.accountAliases);
  for (const grant of policy.grants) {
    if (!aliases.has(grant.accountAlias) || !grant.technique.trim() || !grant.policyReference.trim()) {
      throw new Error('Policy grant is missing an explicit account or reference');
    }
    assertUnique(grant.methods);
  }
  for (const refresh of policy.refreshOrigins) {
    if (!refresh.policyReference.trim()) throw new Error('Refresh requires an explicit policy reference');
    assertUnique(refresh.methods);
  }
}

function assertUnique(values: readonly string[]): void {
  if (new Set(values).size !== values.length) throw new Error('Policy contains duplicate values');
}

function validHttpUrl(input: string): boolean {
  try {
    const parsed = new URL(input);
    return (parsed.protocol === 'https:' || parsed.protocol === 'http:') && Boolean(parsed.hostname) &&
      !parsed.username && !parsed.password;
  } catch {
    return false;
  }
}

function deepFreeze<T>(value: T): DeepReadonly<T> {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value as DeepReadonly<T>;
}
