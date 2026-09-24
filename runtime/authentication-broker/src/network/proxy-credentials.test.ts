import assert from 'node:assert/strict';
import test from 'node:test';
import type { BrokerPolicy } from '../policy/schema.js';

type RegistryApi = typeof import('./proxy-credentials.js');

async function getApi(): Promise<RegistryApi> {
  let module: RegistryApi | undefined;
  try { module = await import('./proxy-credentials.js'); } catch { module = undefined; }
  assert.equal(typeof module?.ProxyCredentialRegistry, 'function', 'per-session proxy credentials must be broker-owned');
  return module!;
}

function policy(): BrokerPolicy {
  return {
    schemaVersion: 1, engagementId: 'synthetic-demo-2026-09-24',
    policySnapshot: { url: 'https://program.example/rules', revision: 'r1', capturedAtUtc: '2026-09-24T00:00:00Z', freshUntilUtc: '2026-09-24T08:00:00Z' },
    accountAliases: ['researcher-a'], loginOrigins: [{ origin: 'https://login.example:443', purpose: 'user-attended sign-in only' }],
    refreshOrigins: [], targetOrigins: ['https://app.example:443'],
    grants: [{ accountAlias: 'researcher-a', technique: 'read-only mapping', methods: ['GET'], policyReference: 'rules > map' }],
    endpointAuthorizations: [],
    limits: { requestsPerSecond: 1, maxConcurrentRequests: 1, maxRequestsPerCapability: 8, maxRequestBodyBytes: 0, expiresAtUtc: '2026-09-24T08:00:00Z' },
    stopConditions: ['synthetic stop']
  } as BrokerPolicy;
}

test('keeps proxy secrets private and grants only the current login or target scope', async () => {
  const { ProxyCredentialRegistry } = await getApi();
  const registry = new ProxyCredentialRegistry({ now: () => new Date('2026-09-24T02:00:00Z') });
  const credentials = registry.issue(policy(), 'researcher-a');
  const basic = `Basic ${Buffer.from(`${credentials.username}:${credentials.password}`).toString('base64')}`;
  assert.equal(registry.resolveCapability(basic), undefined, 'new proxy credentials begin blocked');

  registry.setScope(credentials.username, { mode: 'login', origins: ['https://login.example:443'], methods: ['GET', 'POST'] });
  const login = registry.resolveCapability(basic);
  assert.deepEqual(login?.allowedOrigins, ['https://login.example:443']);
  assert.equal(registry.resolveCapability('Basic synthetic-invalid'), undefined);
  assert.equal(registry.isCurrent(login), true);

  registry.setScope(credentials.username, { mode: 'target', origins: ['https://app.example:443'], methods: ['GET'], technique: 'read-only mapping' });
  const target = registry.resolveCapability(basic);
  assert.deepEqual(target?.allowedOrigins, ['https://app.example:443']);
  assert.equal(target?.allowedMethods.includes('POST'), false);
  assert.equal(registry.isCurrent(login), false, 'a previous scope snapshot must not remain current');
  assert.equal(JSON.stringify(target).includes(credentials.password), false);

  registry.setScope(credentials.username, { mode: 'blocked', origins: [], methods: [] });
  assert.equal(registry.resolveCapability(basic), undefined);
  registry.revoke(credentials.username);
  assert.equal(registry.resolveCapability(basic), undefined);
});

test('rejects proxy scope broadening beyond the assigned account policy', async () => {
  const { ProxyCredentialRegistry } = await getApi();
  const registry = new ProxyCredentialRegistry({ now: () => new Date('2026-09-24T02:00:00Z') });
  const credentials = registry.issue(policy(), 'researcher-a');
  assert.throws(() => registry.setScope(credentials.username, { mode: 'target', origins: ['https://outside.example:443'], methods: ['GET'] }), /scope exceeds policy/i);
  assert.throws(() => registry.setScope(credentials.username, { mode: 'target', origins: ['https://app.example:443'], methods: ['POST'] }), /scope exceeds policy/i);
  assert.throws(() => registry.setScope(credentials.username, { mode: 'login', origins: ['https://outside.example:443'], methods: ['GET'] }), /scope exceeds policy/i);
});

test('permits only policy-listed target origins in attended login for read-only OAuth returns', async () => {
  const { ProxyCredentialRegistry } = await getApi();
  const registry = new ProxyCredentialRegistry({ now: () => new Date('2026-09-24T02:00:00Z') });
  const credentials = registry.issue(policy(), 'researcher-a');
  registry.setScope(credentials.username, {
    mode: 'login',
    origins: ['https://login.example:443', 'https://app.example:443'],
    methods: ['GET', 'HEAD', 'POST', 'OPTIONS']
  });
  const basic = `Basic ${Buffer.from(`${credentials.username}:${credentials.password}`).toString('base64')}`;
  const login = registry.resolveCapability(basic);
  assert.deepEqual(login?.allowedOrigins, ['https://login.example:443', 'https://app.example:443']);
  assert.equal(login?.allowedMethods.includes('GET'), true);
  assert.throws(() => registry.setScope(credentials.username, {
    mode: 'login', origins: ['https://login.example:443', 'https://outside.example:443'], methods: ['GET']
  }), /scope exceeds policy/i);
});
