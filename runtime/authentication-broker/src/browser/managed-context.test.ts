import assert from 'node:assert/strict';
import test from 'node:test';

type RouteLike = {
  request: () => { url: () => string; method: () => string };
  continue: () => Promise<void>;
  abort: (reason?: string) => Promise<void>;
};
type SocketRouteLike = { close: (options?: { code?: number; reason?: string }) => Promise<void> };
type TestPage = {
  close: () => Promise<void>;
  goto: (url: string, options?: unknown) => Promise<void>;
  on: (event: string, callback: (...args: unknown[]) => void) => void;
  locator: (selector: string) => { evaluateAll: (callback: unknown) => Promise<unknown[]>; nth: (index: number) => { evaluate: (callback: unknown, argument?: unknown) => Promise<unknown>; fill: (value: string, options?: unknown) => Promise<void> } };
  isClosed: () => boolean;
};
type TestContext = {
  route: (pattern: string, handler: (route: RouteLike) => Promise<void>) => Promise<void>;
  routeWebSocket: (pattern: string, handler: (route: SocketRouteLike) => Promise<void>) => Promise<void>;
  pages: () => TestPage[];
  newPage: () => Promise<TestPage>;
  on: (event: string, callback: (...args: unknown[]) => void) => void;
  close: () => Promise<void>;
};
type ManagedContextModule = {
  createManagedContext: (options: {
    mode: 'persistent' | 'memory';
    profilePath?: string;
    engagementId: string;
    accountAlias: string;
    policyRevision: string;
    profileProtectionVerified: boolean;
    loginOrigins: readonly string[];
    targetOrigins: readonly string[];
    proxyCredentials: { username: string; password: string };
    reserveTargetRequest: () => Promise<(() => void) | undefined>;
    onTargetResponseStatus: (status: number) => void;
    isEgressVerified: () => boolean;
    onProxyScopeChange?: (scope: { mode: string; origins: readonly string[]; methods: readonly string[]; technique?: string }) => void;
    createAuthorizedRequest?: (context: TestContext, proxyCredentials: { username: string; password: string }) => (input: unknown) => Promise<{ status: number; body: string }>;
    engine?: {
      launch: (options: unknown) => Promise<{ newContext: (options: unknown) => Promise<TestContext>; close: () => Promise<void> }>;
      launchPersistentContext: (path: string, options: unknown) => Promise<TestContext>;
    };
  }) => Promise<{
    openLogin: (origin: string) => Promise<void>;
    activateTarget: () => void;
    pauseTarget: () => void;
    setTargetScope: (origins: readonly string[], methods?: readonly string[], technique?: string) => void;
    setApiScope: (origins: readonly string[], methods: readonly string[], technique: string) => void;
    navigate: (url: string, allowedOrigins?: readonly string[], allowedMethods?: readonly string[]) => Promise<{ navigated: boolean }>;
    observePage: (allowedOrigins?: readonly string[], allowedMethods?: readonly string[]) => Promise<unknown>;
    clickObservedLink: (id: string, allowedOrigins?: readonly string[], allowedMethods?: readonly string[]) => Promise<{ navigated: boolean }>;
    fillResearcherControlledField: (id: string, value: string, allowedOrigins?: readonly string[], allowedMethods?: readonly string[]) => Promise<{ filled: boolean }>;
    authorizedRequest?: (input: unknown) => Promise<{ status: number; body: string }>;
    close: () => Promise<void>;
  }>;
};

async function getApi(): Promise<ManagedContextModule> {
  let module: ManagedContextModule | undefined;
  try { module = await import('./managed-context.js') as unknown as ManagedContextModule; } catch { module = undefined; }
  assert.equal(typeof module?.createManagedContext, 'function', 'managed browser context factory must be implemented');
  return module!;
}

function fakeEngine() {
  const contextListeners = new Map<string, Array<(...args: unknown[]) => void>>();
  const pageListeners = new WeakMap<TestPage, Map<string, Array<(...args: unknown[]) => void>>>();
  const state: { launchOptions?: Record<string, unknown>; contextOptions?: Record<string, unknown>; persistentPath?: string; routeHandler?: (route: RouteLike) => Promise<void>; websocketHandler?: (route: SocketRouteLike) => Promise<void>; pageClosed: number; contextClosed: number; emitContext: (event: string, ...args: unknown[]) => void; emitPage: (page: TestPage, event: string, ...args: unknown[]) => void } = {
    pageClosed: 0, contextClosed: 0,
    emitContext: (event, ...args) => { for (const callback of contextListeners.get(event) ?? []) callback(...args); },
    emitPage: (page, event, ...args) => { for (const callback of pageListeners.get(page)?.get(event) ?? []) callback(...args); }
  };
  const makePage = (): TestPage => {
    const listeners = new Map<string, Array<(...args: unknown[]) => void>>();
    const page: TestPage = {
      close: async () => { state.pageClosed += 1; },
      goto: async () => undefined,
      on: (event, callback) => { const list = listeners.get(event) ?? []; list.push(callback); listeners.set(event, list); },
      locator: () => ({ evaluateAll: async () => [], nth: () => ({ evaluate: async () => undefined, fill: async () => undefined }) }),
      isClosed: () => false
    };
    pageListeners.set(page, listeners);
    return page;
  };
  const initialPage = makePage();
  const pages: TestPage[] = [initialPage];
  const context: TestContext = {
    route: async (_pattern, handler) => { state.routeHandler = handler; },
    routeWebSocket: async (_pattern, handler) => { state.websocketHandler = handler; },
    pages: () => pages,
    newPage: async () => { const page = makePage(); pages.push(page); return page; },
    on: (event, callback) => { const list = contextListeners.get(event) ?? []; list.push(callback); contextListeners.set(event, list); },
    close: async () => { state.contextClosed += 1; }
  };
  const engine = {
    launch: async (options: unknown) => {
      state.launchOptions = options as Record<string, unknown>;
      return {
        newContext: async (options: unknown) => { state.contextOptions = options as Record<string, unknown>; return context; },
        close: async () => undefined
      };
    },
    launchPersistentContext: async (profilePath: string, options: unknown) => {
      state.persistentPath = profilePath;
      state.contextOptions = options as Record<string, unknown>;
      return context;
    }
  };
  return { engine, state, context };
}

function baseOptions(engine: ReturnType<typeof fakeEngine>['engine']) {
  return {
    mode: 'memory' as const,
    engagementId: 'engagement-a',
    accountAlias: 'researcher-a',
    policyRevision: 'revision-1',
    profileProtectionVerified: false,
    loginOrigins: ['https://login.identity.example:443'],
    targetOrigins: ['https://app.example:443'],
    proxyCredentials: { username: 'session-researcher-a', password: 'synthetic-proxy-capability-secret' },
    isEgressVerified: () => true,
    reserveTargetRequest: async () => () => undefined,
    onTargetResponseStatus: () => undefined,
    engine
  };
}

test('requires verified egress and broker-owned proxy credentials before launching a browser', async () => {
  const { createManagedContext } = await getApi();
  const fake = fakeEngine();
  await assert.rejects(createManagedContext({ ...baseOptions(fake.engine), isEgressVerified: () => false }), /egress/i);
  await assert.rejects(createManagedContext({ ...baseOptions(fake.engine), proxyCredentials: { username: 'worker', password: '' } }), /proxy credentials/i);
  assert.equal(fake.state.launchOptions, undefined);
});

test('starts a fresh in-memory context with strict defaults and blocks traffic until bootstrap is opened', async () => {
  const { createManagedContext } = await getApi();
  const fake = fakeEngine();
  const managed = await createManagedContext(baseOptions(fake.engine));
  assert.equal(fake.state.launchOptions?.headless, false);
  const proxy = fake.state.launchOptions?.proxy as { server: string; bypass: string; username: string; password: string };
  assert.equal(proxy.server, 'http://127.0.0.1:8766');
  assert.equal(proxy.bypass, '<-loopback>');
  assert.equal(proxy.password, 'synthetic-proxy-capability-secret');
  assert.equal(JSON.stringify(fake.state.launchOptions).includes('synthetic-proxy-capability-secret'), true);
  assert.deepEqual(fake.state.contextOptions, { acceptDownloads: false, serviceWorkers: 'block', ignoreHTTPSErrors: false });
  assert.equal(fake.state.pageClosed, 1);

  const decisions: Array<{ result: string; origin: string; method: string }> = [];
  const route = async (url: string, method: string) => {
    let result = '';
    const request = { url: () => url, method: () => method };
    await fake.state.routeHandler!({
      request: () => request,
      continue: async () => { result = 'allowed'; },
      abort: async () => { result = 'blocked'; }
    });
    if (result === 'allowed') fake.state.emitContext('requestfinished', request);
    decisions.push({ result, origin: new URL(url).origin, method });
  };
  await route('https://app.example:443/', 'GET');
  await route('https://login.identity.example:443/', 'GET');
  assert.deepEqual(decisions.map(({ result }) => result), ['blocked', 'blocked']);

  await managed.openLogin('https://login.identity.example:443');
  await route('https://login.identity.example:443/sign-in', 'POST');
  await route('https://login.identity.example:443/delete', 'DELETE');
  await route('https://app.example:443/callback', 'GET');
  await route('https://evil.example:443/escape', 'GET');
  assert.deepEqual(decisions.slice(-4).map(({ result }) => result), ['allowed', 'blocked', 'allowed', 'blocked']);

  managed.activateTarget();
  await route('https://app.example:443/profile', 'GET');
  managed.setTargetScope(['https://app.example:443'], ['GET']);
  await route('https://login.identity.example:443/sign-in', 'GET');
  await route('https://app.example:443/profile', 'GET');
  await route('https://app.example:443/profile', 'HEAD');
  await route('https://app.example:443/profile', 'POST');
  assert.deepEqual(decisions.slice(-5).map(({ result }) => result), ['blocked', 'blocked', 'allowed', 'blocked', 'blocked']);

  let socketClosed = false;
  await fake.state.websocketHandler!({ close: async (options) => { socketClosed = options?.code === 1008; } });
  assert.equal(socketClosed, true);
  await managed.pauseTarget();
  await assert.rejects(managed.navigate('https://app.example:443/'), /session is not active/i);
  await managed.close();
  assert.equal(fake.state.contextClosed, 1);
});

test('keeps API write methods out of the managed page request route', async () => {
  const { createManagedContext } = await getApi();
  const fake = fakeEngine();
  const scopes: Array<{ mode: string; origins: readonly string[]; methods: readonly string[]; technique?: string }> = [];
  const managed = await createManagedContext({
    ...baseOptions(fake.engine),
    onProxyScopeChange: (scope) => { scopes.push(scope); }
  });
  await managed.openLogin('https://login.identity.example:443');
  managed.activateTarget();
  managed.setTargetScope(['https://app.example:443'], ['GET']);
  managed.setApiScope(['https://app.example:443'], ['GET', 'POST'], 'approved-api-test');
  const route = async (method: string) => {
    let result = '';
    await fake.state.routeHandler!({
      request: () => ({ url: () => 'https://app.example:443/account', method: () => method }),
      continue: async () => { result = 'allowed'; }, abort: async () => { result = 'blocked'; }
    });
    return result;
  };
  assert.equal(await route('GET'), 'allowed');
  assert.equal(await route('POST'), 'blocked');
  assert.deepEqual(scopes.at(-1), {
    mode: 'target', origins: ['https://app.example:443'], methods: ['GET', 'POST'], technique: 'approved-api-test'
  });
  await managed.close();
});

test('counts target page exchanges until completion and reports target 401, 403, and 429 responses', async () => {
  const { createManagedContext } = await getApi();
  const fake = fakeEngine();
  let reserved = 0;
  let released = 0;
  const statuses: number[] = [];
  const managed = await createManagedContext({
    ...baseOptions(fake.engine),
    reserveTargetRequest: async () => { reserved += 1; return () => { released += 1; }; },
    onTargetResponseStatus: (status) => statuses.push(status)
  });
  await managed.openLogin('https://login.identity.example:443');
  managed.activateTarget();
  managed.setTargetScope(['https://app.example:443'], ['GET']);
  const request = { url: () => 'https://app.example:443/profile', method: () => 'GET' };
  await fake.state.routeHandler!({ request: () => request, continue: async () => undefined, abort: async () => undefined });
  assert.equal(reserved, 1);
  assert.equal(released, 0, 'the budget slot stays held while the network request is active');
  fake.state.emitContext('requestfinished', request);
  assert.equal(released, 1);
  const page = fake.context.pages().at(-1)!;
  for (const status of [401, 403, 429]) fake.state.emitPage(page, 'response', { url: () => 'https://app.example:443/profile', status: () => status });
  fake.state.emitPage(page, 'response', { url: () => 'https://evil.example:443/profile', status: () => 403 });
  assert.deepEqual(statuses, [401, 403, 429]);
  await managed.close();
});

test('opens persistent mode only with an exact verified profile path', async () => {
  const { createManagedContext } = await getApi();
  const fake = fakeEngine();
  const managed = await createManagedContext({ ...baseOptions(fake.engine), mode: 'persistent', profileProtectionVerified: true, profilePath: 'C:\\Synthetic\\private-profile' });
  assert.equal(fake.state.persistentPath, 'C:\\Synthetic\\private-profile');
  assert.equal(fake.state.launchOptions, undefined);
  await managed.close();
  const second = fakeEngine();
  await assert.rejects(createManagedContext({ ...baseOptions(second.engine), mode: 'persistent', profileProtectionVerified: true }), /profile path/i);
  assert.equal(second.state.persistentPath, undefined);
  await assert.rejects(createManagedContext({ ...baseOptions(second.engine), mode: 'persistent', profileProtectionVerified: true, profilePath: '\\\\server\\share\\profile' }), /profile path/i);
});

test('keeps the API cookie-jar adapter inside the managed context and disables it if adapter setup fails', async () => {
  const { createManagedContext } = await getApi();
  const fake = fakeEngine();
  let factoryContext: TestContext | undefined;
  const managed = await createManagedContext({
    ...baseOptions(fake.engine),
    createAuthorizedRequest: (context, credentials) => {
      factoryContext = context;
      assert.equal(credentials.username, 'session-researcher-a');
      return async () => ({ status: 200, body: 'synthetic result' });
    }
  });
  assert.equal(factoryContext, fake.context);
  assert.ok(managed.authorizedRequest);
  assert.equal((await managed.authorizedRequest({})).body, 'synthetic result');
  assert.equal(JSON.stringify(managed).includes('synthetic-proxy-capability-secret'), false);
  await managed.close();

  const failing = fakeEngine();
  const browserOnly = await createManagedContext({
    ...baseOptions(failing.engine),
    createAuthorizedRequest: () => { throw new Error('adapter detail with secret'); }
  });
  assert.equal(browserOnly.authorizedRequest, undefined);
  await browserOnly.close();
});
