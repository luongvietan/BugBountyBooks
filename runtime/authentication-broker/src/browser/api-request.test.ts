import assert from 'node:assert/strict';
import { createServer as createHttpServer, type IncomingMessage, type Server as HttpServer, type ServerResponse } from 'node:http';
import { createConnection, type Socket } from 'node:net';
import test from 'node:test';
import { request as playwrightRequest } from 'playwright';

type Cookie = {
  name: string; value: string; domain: string; path: string; expires: number;
  httpOnly: boolean; secure: boolean; sameSite: 'Strict' | 'Lax' | 'None'; partitionKey?: string;
};
type CookieJar = {
  cookies: (urls?: string | string[]) => Promise<Cookie[]>;
  addCookies: (cookies: Cookie[]) => Promise<void>;
  clearCookies: (filter?: { name?: string; domain?: string; path?: string }) => Promise<void>;
};
type ApiResponse = { status: number; headers: Readonly<Record<string, string>>; body: string; bodySuppressed: boolean };
type TestApiRequestContext = {
  fetch: (url: string, options: unknown) => Promise<{
    status: () => number;
    headersArray: () => Promise<Array<{ name: string; value: string }>>;
    body: () => Promise<Buffer>;
  }>;
  storageState: () => Promise<{ cookies: Cookie[] }>;
  dispose: () => Promise<void>;
};
type ApiRequestModule = {
  createApiRequestAdapter: (options: {
    context: CookieJar;
    proxy: { server: string; username: string; password: string };
    authorize: (request: { origin: string; method: string; path: string; technique: string; endpointAuthorizationId: string }) => boolean;
    allowedOrigins: readonly string[];
    allowedMethods: readonly string[];
    allowedRequestHeaders: readonly string[];
    technique: string;
    endpointAuthorizationId: string;
    maxRequestBodyBytes: number;
    maxResponseBytes: number;
    isEgressVerified: () => boolean;
    testOnlyAllowEphemeralProxy?: boolean;
    newContext?: (options: unknown) => Promise<TestApiRequestContext>;
  }) => { request: (input: unknown) => Promise<ApiResponse> };
};

async function getApi(): Promise<ApiRequestModule> {
  let module: ApiRequestModule | undefined;
  try { module = await import('./api-request.js') as unknown as ApiRequestModule; } catch { module = undefined; }
  assert.equal(typeof module?.createApiRequestAdapter, 'function', 'broker-only API request adapter must be implemented');
  return module!;
}

async function listen<T extends HttpServer>(server: T): Promise<{ address: string; port: number }> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.removeListener('error', reject); resolve(); });
  });
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return { address: address.address, port: address.port };
}

function sendSyntheticResponse(_request: IncomingMessage, response: ServerResponse, body = 'synthetic account response'): void {
  response.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Set-Cookie': 'refresh=synthetic-refresh-secret; Path=/; HttpOnly; SameSite=Lax', Connection: 'close' });
  response.end(body);
}

class SyntheticCookieJar implements CookieJar {
  values: Cookie[];
  constructor(value: string) {
    this.values = [{ name: 'session', value, domain: 'app.example', path: '/', expires: -1, httpOnly: true, secure: false, sameSite: 'Lax' }];
  }
  async cookies(): Promise<Cookie[]> { return this.values.map((cookie) => ({ ...cookie })); }
  async addCookies(cookies: Cookie[]): Promise<void> { this.values.push(...cookies.map((cookie) => ({ ...cookie }))); }
  async clearCookies(filter?: { name?: string; domain?: string; path?: string }): Promise<void> {
    this.values = this.values.filter((cookie) => !(cookie.name === filter?.name && cookie.domain === filter?.domain && cookie.path === filter?.path));
  }
}

const origin = 'http://app.example:8080';
const proxyCapability = {
  engagementId: 'synthetic-demo-2026-09-24', accountAlias: 'researcher-a', policyRevision: 'rules-r1', technique: 'read-only mapping',
  allowedOrigins: [origin], allowedMethods: ['GET', 'POST'], expiresAtUtc: '2099-09-24T08:00:00.000Z', maxRequestBodyBytes: 1024
};

async function createProxy(mock: HttpServer, mockPort: number, credential: { username: string; password: string }, allowed = [origin]) {
  const { createOriginProxy } = await import('../network/origin-proxy.js');
  const expectedHeaders = new Map([
    [`Basic ${Buffer.from(`${credential.username}:${credential.password}`).toString('base64')}`, 'researcher-a'],
    [`Basic ${Buffer.from('session-b:synthetic-proxy-capability-secret-b').toString('base64')}`, 'researcher-b']
  ]);
  let resolvedAuth = false;
  const authorized: string[] = [];
  const proxy = createOriginProxy({
    port: 0,
    resolver: async (hostname) => { assert.equal(hostname, 'app.example'); return ['8.8.8.8']; },
    resolveCapability: (value) => {
      const accountAlias = value ? expectedHeaders.get(value) : undefined;
      if (accountAlias) resolvedAuth = true;
      return accountAlias ? { ...proxyCapability, accountAlias, allowedOrigins: allowed } : undefined;
    },
    authorize: (_context, request) => { authorized.push(`${request.origin} ${request.method}`); return allowed.includes(request.origin) && ['GET', 'POST', 'CONNECT'].includes(request.method); },
    destinationConnectorForTests: (destination) => {
      assert.equal(destination.address, '8.8.8.8');
      return createConnection({ host: '127.0.0.1', port: mockPort });
    }
  });
  return { proxy, diagnostics: () => ({ resolvedAuth, authorized: [...authorized] }) };
}

test('routes each account API request through the pinned origin proxy and keeps cookie values internal', async () => {
  const { createApiRequestAdapter } = await getApi();
  const seenCookies: string[] = [];
  const mock = createHttpServer((request, response) => {
    seenCookies.push(request.headers.cookie ?? '');
    const alias = (request.headers.cookie ?? '').includes('researcher-a') ? 'researcher-a' : 'researcher-b';
    sendSyntheticResponse(request, response, alias);
  });
  const mockAddress = await listen(mock);
  const capabilityA = { username: 'session-a', password: 'synthetic-proxy-capability-secret-a' };
  const { proxy, diagnostics } = await createProxy(mock, mockAddress.port, capabilityA);
  const proxyAddress = await proxy.start();
  const createTestRequestContext = async (requestOptions: unknown): Promise<TestApiRequestContext> => {
    const configured = requestOptions as { proxy: { server: string; username: string; password: string }; ignoreHTTPSErrors: boolean; maxRedirects: number; storageState: { origins: unknown[] } };
    assert.equal(configured.ignoreHTTPSErrors, false);
    assert.equal(configured.maxRedirects, 0);
    assert.equal(configured.proxy.server, `http://${proxyAddress.address}:${proxyAddress.port}`);
    assert.deepEqual(configured.storageState.origins, []);
    return await playwrightRequest.newContext(requestOptions as Parameters<typeof playwrightRequest.newContext>[0]) as unknown as TestApiRequestContext;
  };
  const contextA = new SyntheticCookieJar('synthetic-cookie-researcher-a');
  const adapterA = createApiRequestAdapter({
    context: contextA,
    proxy: { server: `http://${proxyAddress.address}:${proxyAddress.port}`, ...capabilityA },
    authorize: (request) => request.origin === origin && request.method === 'GET' && request.endpointAuthorizationId === 'account-read',
    allowedOrigins: [origin], allowedMethods: ['GET'], allowedRequestHeaders: [], technique: 'read-only mapping',
    endpointAuthorizationId: 'account-read', maxRequestBodyBytes: 1024, maxResponseBytes: 4096, isEgressVerified: () => true,
    testOnlyAllowEphemeralProxy: true, newContext: createTestRequestContext
  });
  const contextB = new SyntheticCookieJar('synthetic-cookie-researcher-b');
  const adapterB = createApiRequestAdapter({
    context: contextB,
    proxy: { server: `http://${proxyAddress.address}:${proxyAddress.port}`, username: 'session-b', password: 'synthetic-proxy-capability-secret-b' },
    authorize: (request) => request.origin === origin && request.method === 'GET' && request.endpointAuthorizationId === 'account-read',
    allowedOrigins: [origin], allowedMethods: ['GET'], allowedRequestHeaders: [], technique: 'read-only mapping',
    endpointAuthorizationId: 'account-read', maxRequestBodyBytes: 1024, maxResponseBytes: 4096, isEgressVerified: () => true,
    testOnlyAllowEphemeralProxy: true, newContext: createTestRequestContext
  });
  try {
    const resultA = await adapterA.request({ url: `${origin}/account`, method: 'GET' });
    const resultB = await adapterB.request({ url: `${origin}/account`, method: 'GET' });
    assert.equal(resultA.status, 200, JSON.stringify(diagnostics()));
    assert.equal(resultA.body, 'researcher-a');
    assert.equal(resultB.body, 'researcher-b');
    assert.deepEqual(seenCookies, ['session=synthetic-cookie-researcher-a', 'session=synthetic-cookie-researcher-b']);
    assert.equal(contextA.values.some((cookie) => cookie.name === 'refresh' && cookie.value === 'synthetic-refresh-secret'), true);
    for (const output of [JSON.stringify(resultA), JSON.stringify(resultB)]) {
      assert.equal(output.includes('synthetic-cookie-'), false);
      assert.equal(output.includes('synthetic-refresh-secret'), false);
      assert.equal(output.includes('synthetic-proxy-capability-secret'), false);
      assert.equal(output.toLowerCase().includes('set-cookie'), false);
    }
  } finally {
    await Promise.all([proxy.close(), new Promise<void>((resolve, reject) => mock.close((error) => error ? reject(error) : resolve()))]);
  }
});

test('rejects credential and routing headers, off-scope origins, and unverified egress before network dispatch', async () => {
  const { createApiRequestAdapter } = await getApi();
  let factoryCalls = 0;
  let egressVerified = false;
  const adapter = createApiRequestAdapter({
    context: new SyntheticCookieJar('synthetic-cookie'),
    proxy: { server: 'http://127.0.0.1:8766', username: 'session-a', password: 'synthetic-proxy-capability-secret-a' },
    authorize: () => true,
    allowedOrigins: [origin], allowedMethods: ['GET', 'POST'], allowedRequestHeaders: ['content-type'], technique: 'authorized api test',
    endpointAuthorizationId: 'account-read', maxRequestBodyBytes: 64, maxResponseBytes: 128, isEgressVerified: () => egressVerified,
    newContext: async () => { factoryCalls += 1; throw new Error('must not be called'); }
  });
  await assert.rejects(adapter.request({ url: `${origin}/account`, method: 'GET' }), /egress/i);
  egressVerified = true;
  await assert.rejects(adapter.request({ url: `${origin}/account`, method: 'GET', headers: { Cookie: 'synthetic-cookie' } }), /credential or routing header/i);
  await assert.rejects(adapter.request({ url: 'http://evil.example:8080/account', method: 'GET' }), /origin/i);
  await assert.rejects(adapter.request({ url: `${origin}/account`, method: 'POST', body: 'x'.repeat(65) }), /body/i);
  assert.equal(factoryCalls, 0);
});

test('checks redirect hops separately and never replays a state-changing request', async () => {
  const { createApiRequestAdapter } = await getApi();
  const redirectCalls: string[] = [];
  const adapter = createApiRequestAdapter({
    context: new SyntheticCookieJar('synthetic-cookie'),
    proxy: { server: 'http://127.0.0.1:8766', username: 'session-a', password: 'synthetic-proxy-capability-secret-a' },
    authorize: ({ origin: requestedOrigin, method }) => { redirectCalls.push(`${requestedOrigin} ${method}`); return requestedOrigin === origin && method === 'GET'; },
    allowedOrigins: [origin, 'http://other.example:8080'], allowedMethods: ['GET', 'POST'], allowedRequestHeaders: ['content-type'], technique: 'read-only mapping',
    endpointAuthorizationId: 'account-read', maxRequestBodyBytes: 64, maxResponseBytes: 128, isEgressVerified: () => true,
    newContext: async () => ({
      fetch: async () => ({ status: () => 302, headersArray: async () => [{ name: 'location', value: 'http://other.example:8080/next' }], body: async () => Buffer.from('redirect') }),
      storageState: async () => ({ cookies: [] }), dispose: async () => undefined
    })
  });
  const getResult = await adapter.request({ url: `${origin}/start`, method: 'GET' });
  assert.equal(getResult.status, 302);
  assert.deepEqual(redirectCalls, [`${origin} GET`, 'http://other.example:8080 GET']);

  let postCalls = 0;
  const postAdapter = createApiRequestAdapter({
    context: new SyntheticCookieJar('synthetic-cookie'),
    proxy: { server: 'http://127.0.0.1:8766', username: 'session-a', password: 'synthetic-proxy-capability-secret-a' },
    authorize: () => { postCalls += 1; return true; },
    allowedOrigins: [origin], allowedMethods: ['POST'], allowedRequestHeaders: ['content-type'], technique: 'authorized api test',
    endpointAuthorizationId: 'post', maxRequestBodyBytes: 64, maxResponseBytes: 128, isEgressVerified: () => true,
    newContext: async () => ({
      fetch: async () => ({ status: () => 302, headersArray: async () => [{ name: 'location', value: `${origin}/confirm` }], body: async () => Buffer.from('redirect') }),
      storageState: async () => ({ cookies: [] }), dispose: async () => undefined
    })
  });
  const postResult = await postAdapter.request({ url: `${origin}/submit`, method: 'POST', body: 'synthetic=true', headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  assert.equal(postResult.status, 302);
  assert.equal(postCalls, 1);
});
