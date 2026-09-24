import assert from 'node:assert/strict';
import test from 'node:test';
import type { BrokerPolicy } from '../policy/schema.js';

type ConnectionRegistry = {
  new(options: { identityMode: 'stateful' | 'single-worker' }): {
    registerSession(sessionId: string): string;
    closeSession(sessionId: string): boolean;
  };
};

type Request = {
  toolName: 'session_status' | 'open_login' | 'observe_page' | 'navigate' | 'act_on_observed_element' | 'authorized_request' | 'revoke_capability';
  method: 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS';
  origin: string;
  technique: string;
  endpointAuthorizationId: string;
  bodyBytes?: number;
  accountAlias?: string;
  connectionId?: string;
};

type AcquireResult = {
  allowed: boolean;
  reason: string;
  context?: { engagementId: string; accountAlias: string; policyRevision: string };
  release?: () => void;
};

type CapabilityManager = {
  new(registry: InstanceType<ConnectionRegistry>, options: {
    getPolicy: () => BrokerPolicy | undefined;
    now: () => Date;
    egressIsVerified?: () => boolean;
    authorizeEndpoint: (context: { engagementId: string; accountAlias: string; origin: string; method: string; endpointAuthorizationId: string }) => boolean;
  }): {
    grant(input: {
      connectionId: string;
      accountAlias: string;
      role: 'mapper' | 'tester' | 'validator';
      tools: Request['toolName'][];
      technique: string;
      policyReference: string;
      methods: Request['method'][];
      origins: string[];
    }): { connectionId: string; accountAlias: string; policyRevision: string; policyReference: string; expiresAtUtc: string };
    acquire(sessionId: string | undefined, request: Request): AcquireResult;
    revoke(connectionId: string): boolean;
    hasCapability(connectionId: string): boolean;
  };
};

async function getDependencies(): Promise<{ ConnectionRegistry: ConnectionRegistry; CapabilityManager: CapabilityManager }> {
  const [registryModule, grantModule] = await Promise.all([
    import('./connection-registry.js').catch(() => undefined),
    import('./grants.js').catch(() => undefined)
  ]);
  assert.equal(typeof (registryModule as { ConnectionRegistry?: unknown } | undefined)?.ConnectionRegistry, 'function', 'ConnectionRegistry must be implemented');
  assert.equal(typeof (grantModule as { CapabilityManager?: unknown } | undefined)?.CapabilityManager, 'function', 'CapabilityManager must be implemented');
  return {
    ConnectionRegistry: (registryModule as unknown as { ConnectionRegistry: ConnectionRegistry }).ConnectionRegistry,
    CapabilityManager: (grantModule as unknown as { CapabilityManager: CapabilityManager }).CapabilityManager
  };
}

function policy(revision = 'rules-r1'): BrokerPolicy {
  return {
    schemaVersion: 1,
    engagementId: 'synthetic-demo-2026-09-24',
    policySnapshot: {
      url: 'https://program.example/rules',
      revision,
      capturedAtUtc: '2026-09-24T00:00:00.000Z',
      freshUntilUtc: '2026-09-24T08:00:00.000Z'
    },
    accountAliases: ['researcher-a', 'researcher-b'],
    loginOrigins: [{ origin: 'https://login.example:443', purpose: 'user-attended sign-in only' }],
    refreshOrigins: [],
    targetOrigins: ['https://app.example:443'],
    grants: [
      { accountAlias: 'researcher-a', technique: 'read-only mapping', methods: ['GET', 'HEAD'], policyReference: 'Synthetic rules > mapping' },
      { accountAlias: 'researcher-b', technique: 'read-only mapping', methods: ['GET'], policyReference: 'Synthetic rules > mapping' }
    ],
    limits: {
      requestsPerSecond: 1,
      maxConcurrentRequests: 1,
      maxRequestsPerCapability: 4,
      maxRequestBodyBytes: 1024,
      expiresAtUtc: '2026-09-24T08:00:00.000Z'
    },
    stopConditions: ['scope ambiguity']
  };
}

function baseGrant(connectionId: string, accountAlias = 'researcher-a') {
  return {
    connectionId,
    accountAlias,
    role: 'tester' as const,
    tools: ['authorized_request'] as Request['toolName'][],
    technique: 'read-only mapping',
    policyReference: 'Synthetic rules > mapping',
    methods: ['GET'] as Request['method'][],
    origins: ['https://app.example:443']
  };
}

function request(overrides: Partial<Request> = {}): Request {
  return {
    toolName: 'authorized_request',
    method: 'GET',
    origin: 'https://app.example:443',
    technique: 'read-only mapping',
    endpointAuthorizationId: 'Synthetic rules > mapping',
    ...overrides
  };
}

test('denies by default and ignores caller-supplied connection or account identifiers', async () => {
  const { ConnectionRegistry, CapabilityManager } = await getDependencies();
  const registry = new ConnectionRegistry({ identityMode: 'stateful' });
  const sessionId = 'sdk-session-a';
  const connectionId = registry.registerSession(sessionId);
  let endpointChecks = 0;
  const manager = new CapabilityManager(registry, {
    getPolicy: () => policy(),
    now: () => new Date('2026-09-24T02:00:00.000Z'),
    egressIsVerified: () => true,
    authorizeEndpoint: () => { endpointChecks += 1; return true; }
  });

  const result = manager.acquire(undefined, request({ connectionId, accountAlias: 'researcher-a' }));
  assert.equal(result.allowed, false);
  assert.equal(endpointChecks, 0);
  assert.equal(manager.hasCapability(connectionId), false);
});

test('requires and records the exact current policy reference selected by the researcher', async () => {
  const { ConnectionRegistry, CapabilityManager } = await getDependencies();
  const registry = new ConnectionRegistry({ identityMode: 'stateful' });
  const connectionId = registry.registerSession('sdk-session-reference');
  const manager = new CapabilityManager(registry, {
    getPolicy: () => policy(),
    now: () => new Date('2026-09-24T02:00:00.000Z'),
    egressIsVerified: () => true,
    authorizeEndpoint: () => true
  });

  assert.throws(() => manager.grant({ ...baseGrant(connectionId), policyReference: 'Unlisted program rule' }), /current policy/);
  const capability = manager.grant(baseGrant(connectionId));
  assert.equal(capability.policyReference, 'Synthetic rules > mapping');
});

test('binds every request to the server-mapped account and explicit policy grant', async () => {
  const { ConnectionRegistry, CapabilityManager } = await getDependencies();
  const registry = new ConnectionRegistry({ identityMode: 'stateful' });
  const sessionA = 'sdk-session-a';
  const sessionB = 'sdk-session-b';
  const connectionA = registry.registerSession(sessionA);
  const connectionB = registry.registerSession(sessionB);
  let policyNow = policy();
  const checkedAccounts: string[] = [];
  const manager = new CapabilityManager(registry, {
    getPolicy: () => policyNow,
    now: () => new Date('2026-09-24T02:00:00.000Z'),
    egressIsVerified: () => true,
    authorizeEndpoint: (context) => { checkedAccounts.push(context.accountAlias); return context.accountAlias === 'researcher-a'; }
  });
  manager.grant(baseGrant(connectionA));
  manager.grant(baseGrant(connectionB, 'researcher-b'));

  const forged = manager.acquire(sessionA, request({ accountAlias: 'researcher-b', connectionId: connectionB }));
  assert.equal(forged.allowed, true);
  assert.deepEqual(forged.context, {
    engagementId: 'synthetic-demo-2026-09-24',
    accountAlias: 'researcher-a',
    policyRevision: 'rules-r1'
  });
  forged.release?.();

  const otherAccount = manager.acquire(sessionB, request());
  assert.equal(otherAccount.allowed, false);
  assert.deepEqual(checkedAccounts, ['researcher-a', 'researcher-b']);
  assert.equal(manager.acquire(sessionA, request({ method: 'POST' })).allowed, false);
  assert.equal(manager.acquire(sessionA, request({ origin: 'https://other.example:443' })).allowed, false);
  assert.equal(manager.acquire(sessionA, request({ technique: 'ungranted technique' })).allowed, false);

  policyNow = policy('rules-r2');
  assert.equal(manager.acquire(sessionA, request()).allowed, false);
  assert.equal(manager.hasCapability(connectionA), false);
});

test('applies rate, concurrency, body, and budget ceilings before dispatch', async () => {
  const { ConnectionRegistry, CapabilityManager } = await getDependencies();
  const registry = new ConnectionRegistry({ identityMode: 'stateful' });
  const sessionId = 'sdk-session-limited';
  const connectionId = registry.registerSession(sessionId);
  let now = new Date('2026-09-24T02:00:00.000Z');
  const manager = new CapabilityManager(registry, {
    getPolicy: () => policy(),
    now: () => now,
    egressIsVerified: () => true,
    authorizeEndpoint: () => true
  });
  manager.grant(baseGrant(connectionId));

  const first = manager.acquire(sessionId, request());
  assert.equal(first.allowed, true);
  assert.equal(manager.acquire(sessionId, request()).allowed, false);
  first.release?.();
  now = new Date(now.getTime() + 1000);
  assert.equal(manager.acquire(sessionId, request({ bodyBytes: 1025 })).allowed, false);
  const second = manager.acquire(sessionId, request());
  assert.equal(second.allowed, true);
  second.release?.();
  now = new Date(now.getTime() + 1000);
  const third = manager.acquire(sessionId, request());
  assert.equal(third.allowed, true);
  third.release?.();
  now = new Date(now.getTime() + 1000);
  const fourth = manager.acquire(sessionId, request());
  assert.equal(fourth.allowed, true);
  fourth.release?.();
  now = new Date(now.getTime() + 1000);
  assert.equal(manager.acquire(sessionId, request()).allowed, false);
});

test('revocation, connection close, expiry, and policy staleness remove capability immediately', async (t) => {
  const { ConnectionRegistry, CapabilityManager } = await getDependencies();
  const make = (id: string, getPolicy: () => BrokerPolicy | undefined, now: () => Date) => {
    const registry = new ConnectionRegistry({ identityMode: 'stateful' });
    const sessionId = `sdk-${id}`;
    const connectionId = registry.registerSession(sessionId);
    const manager = new CapabilityManager(registry, { getPolicy, now, egressIsVerified: () => true, authorizeEndpoint: () => true });
    manager.grant(baseGrant(connectionId));
    return { registry, manager, sessionId, connectionId };
  };

  await t.test('explicit revoke', () => {
    const state = make('revoke', () => policy(), () => new Date('2026-09-24T02:00:00.000Z'));
    assert.equal(state.manager.revoke(state.connectionId), true);
    assert.equal(state.manager.acquire(state.sessionId, request()).allowed, false);
  });
  await t.test('connection close', () => {
    const state = make('close', () => policy(), () => new Date('2026-09-24T02:00:00.000Z'));
    assert.equal(state.registry.closeSession(state.sessionId), true);
    assert.equal(state.manager.hasCapability(state.connectionId), false);
    assert.equal(state.manager.acquire(state.sessionId, request()).allowed, false);
  });
  await t.test('expiry', () => {
    let now = new Date('2026-09-24T02:00:00.000Z');
    const state = make('expiry', () => policy(), () => now);
    now = new Date('2026-09-24T08:00:00.000Z');
    assert.equal(state.manager.acquire(state.sessionId, request()).allowed, false);
    assert.equal(state.manager.hasCapability(state.connectionId), false);
  });
  await t.test('missing or stale current policy', () => {
    let current: BrokerPolicy | undefined = policy();
    const state = make('stale', () => current, () => new Date('2026-09-24T02:00:00.000Z'));
    current = undefined;
    assert.equal(state.manager.acquire(state.sessionId, request()).allowed, false);
    assert.equal(state.manager.hasCapability(state.connectionId), false);
  });
});

test('requires verified egress to create a capability and revokes it if verification is lost', async () => {
  const { ConnectionRegistry, CapabilityManager } = await getDependencies();
  const registry = new ConnectionRegistry({ identityMode: 'stateful' });
  const sessionId = 'sdk-egress';
  const connectionId = registry.registerSession(sessionId);
  let egressVerified = false;
  const manager = new CapabilityManager(registry, {
    getPolicy: () => policy(),
    now: () => new Date('2026-09-24T02:00:00.000Z'),
    egressIsVerified: () => egressVerified,
    authorizeEndpoint: () => true
  });

  assert.throws(() => manager.grant(baseGrant(connectionId)), /egress/);
  assert.equal(manager.hasCapability(connectionId), false);
  egressVerified = true;
  manager.grant(baseGrant(connectionId));
  egressVerified = false;
  assert.equal(manager.acquire(sessionId, request()).allowed, false);
  assert.equal(manager.hasCapability(connectionId), false);
});
