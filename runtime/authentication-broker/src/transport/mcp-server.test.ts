import assert from 'node:assert/strict';
import test from 'node:test';
import type { BrokerPolicy } from '../policy/schema.js';

type ServerApi = {
  createBrokerMcpServer: (options: Record<string, unknown>) => Promise<{
    listen(): Promise<{ host: string; port: number }>;
    close(): Promise<void>;
  }>;
};

async function getApi(): Promise<ServerApi> {
  let module: ServerApi | undefined;
  try { module = await import('./mcp-server.js') as unknown as ServerApi; } catch { module = undefined; }
  assert.equal(typeof module?.createBrokerMcpServer, 'function', 'local stateful MCP broker server must be implemented');
  return module!;
}

function policy(): BrokerPolicy {
  return {
    schemaVersion: 1,
    engagementId: 'synthetic-demo-2026-09-24',
    policySnapshot: { url: 'https://program.example/rules', revision: 'rules-r1', capturedAtUtc: '2026-09-24T00:00:00.000Z', freshUntilUtc: '2026-09-24T08:00:00.000Z' },
    accountAliases: ['researcher-a', 'researcher-b'],
    loginOrigins: [{ origin: 'https://login.example:443', purpose: 'user-attended sign-in only' }],
    refreshOrigins: [],
    targetOrigins: ['https://app.example:443'],
    grants: [
      { accountAlias: 'researcher-a', technique: 'read-only mapping', methods: ['GET'], policyReference: 'Synthetic rules > mapping' },
      { accountAlias: 'researcher-b', technique: 'read-only mapping', methods: ['GET'], policyReference: 'Synthetic rules > mapping B' }
    ],
    endpointAuthorizations: [
      { accountAlias: 'researcher-a', technique: 'read-only mapping', endpointAuthorizationId: 'account-read', origin: 'https://app.example:443', method: 'GET', path: '/account', policyReference: 'Synthetic rules > mapping' },
      { accountAlias: 'researcher-b', technique: 'read-only mapping', endpointAuthorizationId: 'account-read-b', origin: 'https://app.example:443', method: 'GET', path: '/account', policyReference: 'Synthetic rules > mapping B' }
    ],
    limits: { requestsPerSecond: 1, maxConcurrentRequests: 1, maxRequestsPerCapability: 7, maxRequestBodyBytes: 0, expiresAtUtc: '2026-09-24T08:00:00.000Z' },
    stopConditions: ['stop if real user data appears']
  } as BrokerPolicy;
}

test('serves exactly seven worker tools over stateful MCP and keeps researcher control separate', async (t) => {
  const { createBrokerMcpServer } = await getApi();
  const [{ ConnectionRegistry }, { CapabilityManager }, { WorkerRequestGuard }, { SessionManager }, { MetadataAuditLog }] = await Promise.all([
    import('../capability/connection-registry.js'), import('../capability/grants.js'), import('../policy/request-guard.js'),
    import('../session/session-manager.js'), import('../audit/metadata-log.js')
  ]);
  let nowMs = Date.parse('2026-09-24T02:00:00.000Z');
  const currentPolicy = policy();
  const registry = new ConnectionRegistry({ identityMode: 'stateful' });
  const capabilityManager = new CapabilityManager(registry, {
    getPolicy: () => currentPolicy, now: () => new Date(nowMs), egressIsVerified: () => true,
    authorizeEndpoint: (request) => request.origin === 'https://app.example:443' && request.method === 'GET' &&
      request.path === '/account' && ((request.accountAlias === 'researcher-a' && request.endpointAuthorizationId === 'account-read') ||
      (request.accountAlias === 'researcher-b' && request.endpointAuthorizationId === 'account-read-b'))
  });
  const pageCalls: string[] = [];
  const contexts: Array<{ accountAlias: string; closed: number }> = [];
  const apiAccounts: string[] = [];
  let nextResearcherBStatus: number | undefined;
  const sessions = new SessionManager({
    profileRoot: 'C:\\Synthetic\\Broker\\profiles',
    getPolicy: () => currentPolicy,
    now: () => new Date(nowMs),
    prepareProfileDirectory: async () => undefined,
    selectProfileMode: async () => ({ mode: 'memory', reason: 'protection-unverified' }),
    acquireLock: async () => ({ release: async () => undefined }),
    createProxyCredentials: () => ({ username: 'synthetic-session', password: 'synthetic-proxy-capability-secret-123456' }),
    createContext: async ({ accountAlias }) => {
      const state = { accountAlias, closed: 0 };
      contexts.push(state);
      return {
        openLogin: async (origin: string) => { pageCalls.push(`login:${origin}`); },
        activateTarget: () => undefined,
        pauseTarget: () => undefined,
        setTargetScope: (origins: readonly string[]) => { pageCalls.push(`scope:${origins.join(',')}`); },
        setApiScope: (origins: readonly string[], methods: readonly string[], technique: string) => { pageCalls.push(`api-scope:${origins.join(',')}:${methods.join(',')}:${technique}`); },
        navigate: async (url: string) => { pageCalls.push(`navigate:${url}`); return { navigated: true }; },
        observePage: async () => ({ title: 'Synthetic account page', url: 'https://app.example/account' }),
        clickObservedLink: async (id: string) => { pageCalls.push(`click:${id}`); return { navigated: true }; },
        fillResearcherControlledField: async (_id: string, value: string) => { pageCalls.push(`fill:${value}`); return { filled: true }; },
        authorizedRequest: async () => {
          apiAccounts.push(accountAlias);
          const status = accountAlias === 'researcher-b' ? nextResearcherBStatus : undefined;
          if (status !== undefined) nextResearcherBStatus = undefined;
          return {
            status: status ?? 200,
            body: JSON.stringify({ account: accountAlias, password: 'synthetic-password-secret', accessToken: 'synthetic-access-token', message: 'Bearer synthetic-bearer-secret' }),
            headers: { 'Set-Cookie': 'session=synthetic-cookie-secret', 'content-type': 'application/json' }
          };
        },
        close: async () => { state.closed += 1; }
      };
    },
    onAuthorizationStop: ({ engagementId, accountAlias }) => { capabilityManager.revokeAccount(engagementId, accountAlias); }
  });
  const audit = new MetadataAuditLog({ now: () => new Date(nowMs) });
  const app = await createBrokerMcpServer({
    port: 0, identityMode: 'stateful', registry, capabilities: capabilityManager,
    guard: new WorkerRequestGuard(capabilityManager), sessions, audit, getPolicy: () => currentPolicy
  });
  const address = await app.listen();
  t.after(async () => { await app.close(); });
  const base = `http://${address.host}:${address.port}`;
  const headers = { accept: 'application/json, text/event-stream', 'content-type': 'application/json' };
  let requestId = 1;
  async function post(payload: unknown, sessionId?: string): Promise<{ status: number; headers: Headers; json?: Record<string, unknown> }> {
    const response = await fetch(`${base}/mcp`, {
      method: 'POST', headers: { ...headers, ...(sessionId ? { 'mcp-session-id': sessionId } : {}) }, body: JSON.stringify(payload)
    });
    const text = await response.text();
    let json: Record<string, unknown> | undefined;
    try { json = JSON.parse(text) as Record<string, unknown>; } catch { json = undefined; }
    return { status: response.status, headers: response.headers, ...(json ? { json } : {}) };
  }
  const initialize = await post({
    jsonrpc: '2.0', id: requestId++, method: 'initialize',
    params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'synthetic-worker', version: '1.0.0' } }
  });
  assert.equal(initialize.status, 200, JSON.stringify(initialize.json));
  const sessionId = initialize.headers.get('mcp-session-id');
  assert.ok(sessionId);
  await post({ jsonrpc: '2.0', method: 'notifications/initialized' }, sessionId!);

  const initializeB = await post({
    jsonrpc: '2.0', id: requestId++, method: 'initialize',
    params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'synthetic-worker-b', version: '1.0.0' } }
  });
  assert.equal(initializeB.status, 200, JSON.stringify(initializeB.json));
  const sessionIdB = initializeB.headers.get('mcp-session-id');
  assert.ok(sessionIdB);
  await post({ jsonrpc: '2.0', method: 'notifications/initialized' }, sessionIdB!);

  const list = await post({ jsonrpc: '2.0', id: requestId++, method: 'tools/list', params: {} }, sessionId!);
  assert.equal(list.status, 200);
  const tools = ((list.json?.result as { tools?: Array<{ name: string; inputSchema?: unknown; description?: string }> } | undefined)?.tools ?? []);
  assert.deepEqual(tools.map(({ name }) => name).sort(), [
    'act_on_observed_element', 'authorized_request', 'navigate', 'observe_page', 'open_login', 'revoke_capability', 'session_status'
  ]);
  const advertised = JSON.stringify(tools).toLowerCase();
  assert.equal(/evaluate|cookie|storage|shell|cdp/.test(advertised), false);

  async function callTool(name: string, args: Record<string, unknown> = {}, workerSessionId = sessionId!): Promise<Record<string, unknown>> {
    const response = await post({ jsonrpc: '2.0', id: requestId++, method: 'tools/call', params: { name, arguments: args } }, workerSessionId);
    assert.equal(response.status, 200, `${name}: ${JSON.stringify(response.json)}`);
    const result = response.json?.result as Record<string, unknown> | undefined;
    assert.ok(result, `${name} returned no MCP result`);
    const content = result.content as Array<{ text: string }> | undefined;
    const value = JSON.parse(content?.[0]?.text ?? '{}') as Record<string, unknown>;
    nowMs += 1100;
    return { ...value, isError: result.isError === true };
  }

  const deniedBeforeGrant = await callTool('session_status');
  assert.equal(deniedBeforeGrant.isError, true);
  assert.equal(pageCalls.length, 0);

  const controlOrigin = `${base}`;
  const connectionsResponse = await fetch(`${base}/researcher/connections`, { headers: { origin: controlOrigin } });
  assert.equal(connectionsResponse.status, 200);
  const connections = await connectionsResponse.json() as Array<{ connectionId: string }>;
  assert.equal(connections.length, 2);
  const connectionId = connections[0]!.connectionId;
  const grantResponse = await fetch(`${base}/researcher/grant`, {
    method: 'POST', headers: { origin: controlOrigin, 'content-type': 'application/json' },
    body: JSON.stringify({
      connectionId, accountAlias: 'researcher-a', role: 'tester',
      tools: ['session_status', 'open_login', 'observe_page', 'navigate', 'act_on_observed_element', 'authorized_request', 'revoke_capability'],
      technique: 'read-only mapping', policyReference: 'Synthetic rules > mapping', methods: ['GET'], origins: ['https://app.example:443']
    })
  });
  assert.equal(grantResponse.status, 200, await grantResponse.text());
  const connectionB = connections[1]!.connectionId;
  assert.equal((await callTool('session_status', {}, sessionIdB!)).isError, true, 'worker B must not inherit worker A capability');
  const grantResponseB = await fetch(`${base}/researcher/grant`, {
    method: 'POST', headers: { origin: controlOrigin, 'content-type': 'application/json' },
    body: JSON.stringify({
      connectionId: connectionB, accountAlias: 'researcher-b', role: 'tester',
      tools: ['session_status', 'open_login', 'authorized_request', 'revoke_capability'],
      technique: 'read-only mapping', policyReference: 'Synthetic rules > mapping B', methods: ['GET'], origins: ['https://app.example:443']
    })
  });
  assert.equal(grantResponseB.status, 200, await grantResponseB.text());
  assert.equal((await callTool('session_status')).state, 'not_configured');
  assert.equal((await callTool('session_status', {}, sessionIdB!)).state, 'not_configured');
  assert.equal((await callTool('open_login', { origin: 'https://login.example:443' })).state, 'user_action_required');
  const confirmLogin = async (connectionId: string) => fetch(`${base}/researcher/confirm-login`, {
    method: 'POST', headers: { origin: controlOrigin, 'content-type': 'application/json' },
    body: JSON.stringify({ connectionId, confirmed: true })
  });
  const confirmA = await confirmLogin(connectionId);
  assert.equal(confirmA.status, 200);
  assert.equal((await confirmA.json() as { state: string }).state, 'active');
  assert.equal((await callTool('open_login', { origin: 'https://login.example:443' }, sessionIdB!)).state, 'user_action_required');
  const confirmB = await confirmLogin(connectionB);
  assert.equal(confirmB.status, 200);
  assert.equal((await callTool('observe_page')).title, 'Synthetic account page');
  assert.equal((await callTool('navigate', { url: 'https://evil.example/path' })).isError, true);
  assert.equal((await callTool('navigate', { url: 'https://app.example:443/account' })).navigated, true);
  assert.equal((await callTool('act_on_observed_element', { action: 'fill_field', id: '00000000-0000-4000-8000-000000000001', value: 'synthetic-user-input-secret' })).filled, true);
  const apiResult = await callTool('authorized_request', { url: 'https://app.example:443/account', method: 'GET', endpointAuthorizationId: 'account-read' });
  assert.equal((apiResult.body as { account?: string }).account, 'researcher-a');
  const safeApiResult = JSON.stringify(apiResult);
  for (const canary of ['synthetic-password-secret', 'synthetic-access-token', 'synthetic-bearer-secret', 'synthetic-cookie-secret', 'Set-Cookie']) {
    assert.equal(safeApiResult.includes(canary), false, `tool result leaked ${canary}`);
  }
  assert.equal((await callTool('authorized_request', { url: 'https://app.example:443/account', method: 'GET', endpointAuthorizationId: 'account-read', body: 'not-allowed' })).isError, true);
  assert.equal((await callTool('authorized_request', { url: 'https://app.example:443/admin', method: 'GET', endpointAuthorizationId: 'account-read' })).isError, true);
  const apiResultB = await callTool('authorized_request', { url: 'https://app.example:443/account', method: 'GET', endpointAuthorizationId: 'account-read-b' }, sessionIdB!);
  assert.equal((apiResultB.body as { account?: string }).account, 'researcher-b');
  assert.deepEqual(apiAccounts, ['researcher-a', 'researcher-b']);
  nextResearcherBStatus = 403;
  const forbidden = await callTool('authorized_request', { url: 'https://app.example:443/account', method: 'GET', endpointAuthorizationId: 'account-read-b' }, sessionIdB!);
  assert.equal(forbidden.status, 403);
  assert.equal((await callTool('session_status', {}, sessionIdB!)).isError, true, '403 revokes the account capability pending researcher review');
  const confirmAuthorizationReview = await fetch(`${base}/researcher/confirm-authorization-review`, {
    method: 'POST', headers: { origin: controlOrigin, 'content-type': 'application/json' },
    body: JSON.stringify({ connectionId: connectionB, confirmed: true })
  });
  assert.equal(confirmAuthorizationReview.status, 200);
  assert.equal((await confirmAuthorizationReview.json() as { state: string }).state, 'active');
  const regrantAfterReview = await fetch(`${base}/researcher/grant`, {
    method: 'POST', headers: { origin: controlOrigin, 'content-type': 'application/json' },
    body: JSON.stringify({
      connectionId: connectionB, accountAlias: 'researcher-b', role: 'tester',
      tools: ['session_status', 'open_login', 'authorized_request', 'revoke_capability'],
      technique: 'read-only mapping', policyReference: 'Synthetic rules > mapping B', methods: ['GET'], origins: ['https://app.example:443']
    })
  });
  assert.equal(regrantAfterReview.status, 200);
  assert.equal((await callTool('session_status', {}, sessionIdB!)).state, 'active');
  assert.equal(((await callTool('authorized_request', { url: 'https://app.example:443/account', method: 'GET', endpointAuthorizationId: 'account-read' })).body as { account?: string }).account, 'researcher-a');
  assert.equal(apiAccounts.filter((account) => account === 'researcher-a').length, 2);
  assert.equal((await callTool('authorized_request', { url: 'https://app.example:443/account', method: 'GET', endpointAuthorizationId: 'account-read' })).isError, true, 'the capability budget must deny before API dispatch');
  assert.equal(apiAccounts.filter((account) => account === 'researcher-a').length, 2);
  assert.equal((await callTool('revoke_capability')).revoked, true);
  const requireLogin = await fetch(`${base}/researcher/require-login`, {
    method: 'POST', headers: { origin: controlOrigin, 'content-type': 'application/json' },
    body: JSON.stringify({ connectionId: connectionB, confirmed: true })
  });
  assert.equal(requireLogin.status, 200);
  assert.equal((await requireLogin.json() as { state: string }).state, 'user_action_required');
  assert.equal((await callTool('open_login', { origin: 'https://login.example:443' }, sessionIdB!)).state, 'user_action_required');
  assert.equal((await confirmLogin(connectionB)).status, 200);
  const closeResponse = await fetch(`${base}/researcher/close`, {
    method: 'POST', headers: { origin: controlOrigin, 'content-type': 'application/json' },
    body: JSON.stringify({ connectionId, confirmed: true })
  });
  assert.equal(closeResponse.status, 200);
  assert.deepEqual(await closeResponse.json(), { closed: true });
  assert.equal(contexts[0]?.closed, 1);
  const closeResponseB = await fetch(`${base}/researcher/close`, {
    method: 'POST', headers: { origin: controlOrigin, 'content-type': 'application/json' },
    body: JSON.stringify({ connectionId: connectionB, confirmed: true })
  });
  assert.equal(closeResponseB.status, 200);
  assert.deepEqual(await closeResponseB.json(), { closed: true });
  assert.equal(contexts[1]?.closed, 1);
  assert.equal(registry.list().length, 0);
  assert.ok(audit.snapshot().length >= 12);
  assert.equal(JSON.stringify(audit.snapshot()).includes('synthetic-user-input-secret'), false);
  assert.equal(pageCalls.some((call) => call.includes('navigate:https://evil.example')), false);
});
