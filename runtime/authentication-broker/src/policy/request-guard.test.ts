import assert from 'node:assert/strict';
import test from 'node:test';

type GuardApi = {
  evaluateRequest: (input: unknown, capability: unknown) => { allowed: boolean; reason: string; request?: unknown };
};

async function getApi(): Promise<GuardApi> {
  let module: GuardApi | undefined;
  try { module = await import('./request-guard.js') as unknown as GuardApi; } catch { module = undefined; }
  assert.equal(typeof module?.evaluateRequest, 'function', 'pure worker request guard must be implemented');
  return module!;
}

const capability = {
  tools: ['authorized_request', 'navigate', 'observe_page'],
  methods: ['GET'],
  origins: ['https://app.example:443'],
  maxRequestBodyBytes: 64,
  authorizeEndpoint: (input: { origin: string; method: string; path: string; endpointAuthorizationId: string }) =>
    input.origin === 'https://app.example:443' && input.method === 'GET' && input.path === '/account' && input.endpointAuthorizationId === 'account-read'
};

test('allows only exact canonical origin, method, authorized path, tool, and body ceiling', async () => {
  const { evaluateRequest } = await getApi();
  const result = evaluateRequest({
    toolName: 'authorized_request', url: 'https://app.example:443/account?view=summary', method: 'GET', endpointAuthorizationId: 'account-read', body: undefined
  }, capability);
  assert.equal(result.allowed, true);
  const normalized = result.request as Record<string, unknown>;
  assert.equal(normalized.origin, 'https://app.example:443');
  assert.equal(normalized.path, '/account');
});

test('denies missing capability, malformed/off-origin URL, method, endpoint, and oversized request before dispatch', async () => {
  const { evaluateRequest } = await getApi();
  const base = { toolName: 'authorized_request', url: 'https://app.example:443/account', method: 'GET', endpointAuthorizationId: 'account-read' };
  for (const [input, cap] of [
    [base, undefined],
    [{ ...base, url: 'https://evil.example/account' }, capability],
    [{ ...base, method: 'POST' }, capability],
    [{ ...base, url: 'https://app.example:443/admin' }, capability],
    [{ ...base, body: 'x'.repeat(65) }, capability]
  ] as const) {
    const result = evaluateRequest(input, cap);
    assert.equal(result.allowed, false);
    assert.equal(result.request, undefined);
  }
});

test('denies page tools when a capability has HEAD but not GET', async () => {
  const { WorkerRequestGuard } = await import('./request-guard.js');
  const calls: string[] = [];
  const workerCapability = {
    context: { connectionId: 'connection-a', engagementId: 'engagement-a', accountAlias: 'researcher-a', policyRevision: 'revision-a', role: 'mapper', technique: 'mapping', policyReference: 'rules', methods: ['HEAD'], origins: ['https://app.example:443'] },
    tools: ['observe_page', 'navigate'], methods: ['HEAD'], origins: ['https://app.example:443'], maxRequestBodyBytes: 0,
    authorizeEndpoint: () => false
  };
  const capabilities = {
    workerCapabilityFor: () => workerCapability,
    acquireTool: () => { calls.push('tool'); return { allowed: true, reason: 'authorized' }; },
    acquireWorkerRequest: (_sessionId: string, request: { method: string }) => {
      calls.push(`request:${request.method}`);
      return { allowed: request.method === 'HEAD', reason: 'denied' };
    },
    hasOpenWorkerIdentity: () => true,
    connectionIdForWorker: () => 'connection-a'
  };
  const guard = new WorkerRequestGuard(capabilities as never);
  assert.equal(guard.authorize('worker-a', 'observe_page', {}).allowed, false);
  assert.equal(guard.authorize('worker-a', 'navigate', { url: 'https://app.example/account' }).allowed, false);
  assert.deepEqual(calls, []);
});

test('ignores caller identity, account, technique, and method-override fields', async () => {
  const { evaluateRequest } = await getApi();
  const result = evaluateRequest({
    toolName: 'authorized_request', url: 'https://app.example:443/account', method: 'GET', endpointAuthorizationId: 'account-read',
    accountAlias: 'researcher-b', connectionId: 'forged', technique: 'ungranted', headers: { 'X-HTTP-Method-Override': 'DELETE' }
  }, capability);
  assert.equal(result.allowed, false);
});
