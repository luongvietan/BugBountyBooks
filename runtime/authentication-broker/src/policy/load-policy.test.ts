import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const NOW = new Date('2026-09-24T02:00:00.000Z');

type PolicyFixture = {
  schemaVersion: number;
  engagementId: string;
  policySnapshot: { url: string; revision: string; capturedAtUtc: string; freshUntilUtc: string };
  accountAliases: string[];
  loginOrigins: Array<{ origin: string; purpose: string }>;
  refreshOrigins: Array<{ origin: string; methods: string[]; policyReference: string }>;
  targetOrigins: string[];
  grants: Array<{ accountAlias: string; technique: string; methods: string[]; policyReference: string }>;
  limits: { requestsPerSecond: number; maxConcurrentRequests: number; maxRequestsPerCapability: number; maxRequestBodyBytes: number; expiresAtUtc: string };
  stopConditions: string[];
  [key: string]: unknown;
};

type LoadedPolicy = {
  targetOrigins: readonly string[];
  grants: readonly unknown[];
  policySnapshot: Readonly<{ url: string }>;
};

function validPolicy(): PolicyFixture {
  return {
    schemaVersion: 1,
    engagementId: 'synthetic-demo-2026-09-24',
    policySnapshot: {
      url: 'https://program.example/rules',
      revision: 'synthetic revision',
      capturedAtUtc: '2026-09-24T00:00:00.000Z',
      freshUntilUtc: '2026-10-01T00:00:00.000Z'
    },
    accountAliases: ['researcher-a', 'researcher-b'],
    loginOrigins: [{ origin: 'https://login.example:443', purpose: 'user-attended sign-in only' }],
    refreshOrigins: [],
    targetOrigins: ['https://APP.example'],
    grants: [{
      accountAlias: 'researcher-a',
      technique: 'read-only application mapping',
      methods: ['GET', 'HEAD'],
      policyReference: 'Synthetic rules > authorized read-only test'
    }],
    limits: {
      requestsPerSecond: 1,
      maxConcurrentRequests: 1,
      maxRequestsPerCapability: 100,
      maxRequestBodyBytes: 65536,
      expiresAtUtc: '2026-09-24T08:00:00.000Z'
    },
    stopConditions: ['scope or method ambiguity', 'service degradation']
  };
}

async function getLoader(): Promise<(filePath: string, now: Date) => Promise<LoadedPolicy>> {
  let module: Record<string, unknown> | undefined;
  try {
    module = await import('./load-policy.js') as unknown as Record<string, unknown>;
  } catch {
    module = undefined;
  }
  const loadPolicy = module?.loadPolicy;
  assert.equal(typeof loadPolicy, 'function', 'loadPolicy must be implemented');
  return loadPolicy as (filePath: string, now: Date) => Promise<LoadedPolicy>;
}

async function withPolicy<T>(value: unknown, run: (filePath: string) => Promise<T>): Promise<T> {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'broker-policy-test-'));
  const filePath = path.join(directory, 'broker-policy.json');
  try {
    writeFileSync(filePath, JSON.stringify(value), { encoding: 'utf8', mode: 0o600 });
    return await run(filePath);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('loads a current policy, canonicalizes origins, and freezes nested data', async () => {
  const loadPolicy = await getLoader();
  await withPolicy(validPolicy(), async (filePath) => {
    const policy = await loadPolicy(filePath, NOW);
    assert.deepEqual(policy.targetOrigins, ['https://app.example:443']);
    assert.equal(Object.isFrozen(policy), true);
    assert.equal(Object.isFrozen(policy.targetOrigins), true);
    assert.equal(Object.isFrozen(policy.grants), true);
    assert.equal(Object.isFrozen(policy.policySnapshot), true);
  });
});

test('rejects missing grants, references, limits, and unknown fields', async (t) => {
  const loadPolicy = await getLoader();
  const cases: Array<[string, (policy: PolicyFixture) => void]> = [
    ['no grants', (policy) => { policy.grants = []; }],
    ['blank policy reference', (policy) => { policy.grants[0]!.policyReference = '  '; }],
    ['missing limits', (policy) => { Object.assign(policy, { limits: undefined }); }],
    ['unknown field', (policy) => { policy.workerSuppliedAccount = 'researcher-b'; }]
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, async () => {
      const input = validPolicy();
      mutate(input);
      await withPolicy(input, (filePath) => assert.rejects(loadPolicy(filePath, NOW)));
    });
  }
});

test('does not include policy contents in a validation error', async () => {
  const loadPolicy = await getLoader();
  const input = validPolicy();
  input.accountAliases = ['researcher-cookie-canary-DO-NOT-LOG'];
  await withPolicy(input, async (filePath) => {
    await assert.rejects(loadPolicy(filePath, NOW), (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.match(error.message, /does not satisfy schema/);
      assert.doesNotMatch(error.message, /researcher-cookie-canary-DO-NOT-LOG/);
      return true;
    });
  });
});

test('rejects an expired session grant or stale policy snapshot', async (t) => {
  const loadPolicy = await getLoader();
  const cases: Array<[string, (policy: PolicyFixture) => void]> = [
    ['stale snapshot', (policy) => { policy.policySnapshot.freshUntilUtc = '2026-09-24T01:00:00.000Z'; }],
    ['expired capability', (policy) => { policy.limits.expiresAtUtc = '2026-09-24T01:00:00.000Z'; }],
    ['future capture', (policy) => { policy.policySnapshot.capturedAtUtc = '2026-09-25T00:00:00.000Z'; }],
    ['malformed UTC timestamp', (policy) => { policy.policySnapshot.capturedAtUtc = 'yesterday'; }]
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, async () => {
      const input = validPolicy();
      mutate(input);
      await withPolicy(input, (filePath) => assert.rejects(loadPolicy(filePath, NOW)));
    });
  }
});

test('rejects normalized origin duplicates and login/target overlap', async (t) => {
  const loadPolicy = await getLoader();
  const cases: Array<[string, (policy: PolicyFixture) => void]> = [
    ['duplicate normalized target origins', (policy) => { policy.targetOrigins.push('https://app.example:443'); }],
    ['login origin repeated as target', (policy) => { policy.loginOrigins.push({ origin: 'https://app.example:443', purpose: 'user-attended sign-in only' }); }]
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, async () => {
      const input = validPolicy();
      mutate(input);
      await withPolicy(input, (filePath) => assert.rejects(loadPolicy(filePath, NOW)));
    });
  }
});

test('rejects grants for unknown accounts, undocumented refresh, and excessive limits', async (t) => {
  const loadPolicy = await getLoader();
  const cases: Array<[string, (policy: PolicyFixture) => void]> = [
    ['unknown account alias', (policy) => { policy.grants[0]!.accountAlias = 'researcher-c'; }],
    ['refresh without policy reference', (policy) => { policy.refreshOrigins = [{ origin: 'https://login.example:443', methods: ['POST'], policyReference: '' }]; }],
    ['over-ceiling request rate', (policy) => { policy.limits.requestsPerSecond = 1.01; }],
    ['over-ceiling request budget', (policy) => { policy.limits.maxRequestsPerCapability = 101; }],
    ['over-ceiling body size', (policy) => { policy.limits.maxRequestBodyBytes = 65537; }]
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, async () => {
      const input = validPolicy();
      mutate(input);
      await withPolicy(input, (filePath) => assert.rejects(loadPolicy(filePath, NOW)));
    });
  }
});

test('loads the checked-in synthetic example without returning its contents', async () => {
  const loadPolicy = await getLoader();
  const example = new URL('../../examples/broker-policy.example.json', import.meta.url);
  const policy = await loadPolicy(fileURLToPath(example), new Date('2026-09-24T00:00:00.000Z'));
  assert.equal(policy.targetOrigins[0], 'https://app.example:443');
});
