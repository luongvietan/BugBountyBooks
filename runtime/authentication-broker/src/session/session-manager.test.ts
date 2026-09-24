import assert from 'node:assert/strict';
import test from 'node:test';
import type { BrokerPolicy } from '../policy/schema.js';

type SessionSnapshot = {
  engagementId: string;
  accountAlias: string;
  policyRevision: string;
  state: string;
  storageMode: string;
  createdAtUtc: string;
  lastCheckedAtUtc: string;
  revoked: boolean;
};

type TestContext = {
  openLogin: (origin: string) => Promise<void>;
  close: () => Promise<void>;
  authorizedRequest?: (request: unknown) => Promise<{ status: number; body: string }>;
};

type SessionManagerApi = {
  SessionManager: new (options: {
    profileRoot: string;
    getPolicy: (engagementId: string) => BrokerPolicy | undefined;
    now: () => Date;
    prepareProfileDirectory: (directory: string) => Promise<void>;
    selectProfileMode: (directory: string) => Promise<{ mode: 'persistent' | 'memory'; reason: string }>;
    acquireLock: (options: { directory: string; profileKey: string }) => Promise<{ release: () => Promise<void> }>;
    createProxyCredentials: (input: { engagementId: string; accountAlias: string }) => { username: string; password: string };
    createContext: (input: {
      engagementId: string;
      accountAlias: string;
      policyRevision: string;
      mode: 'persistent' | 'memory';
      profilePath?: string;
      loginOrigins: readonly string[];
      targetOrigins: readonly string[];
      proxyCredentials: { username: string; password: string };
    }) => Promise<TestContext>;
    onRateLimit?: (input: { engagementId: string; accountAlias: string }) => void;
  }) => {
    start: (engagementId: string, accountAlias: string) => Promise<SessionSnapshot>;
    openLogin: (engagementId: string, accountAlias: string, origin: string) => Promise<SessionSnapshot>;
    confirmAttendedLogin: (engagementId: string, accountAlias: string) => SessionSnapshot;
    getSnapshot: (engagementId: string, accountAlias: string) => SessionSnapshot | undefined;
    authorizedRequest: (engagementId: string, accountAlias: string, request: unknown) => Promise<{ status: number; body: string }>;
    requireResearcherAction: (engagementId: string, accountAlias: string) => SessionSnapshot;
    revoke: (engagementId: string, accountAlias: string, closeProfile?: boolean) => Promise<SessionSnapshot>;
    closeAll: () => Promise<void>;
  };
};

async function getApi(): Promise<SessionManagerApi> {
  let module: SessionManagerApi | undefined;
  try { module = await import('./session-manager.js') as unknown as SessionManagerApi; } catch { module = undefined; }
  assert.equal(typeof module?.SessionManager, 'function', 'isolated session manager must be implemented');
  return module!;
}

function policy(revision = 'revision-1', engagementId = 'engagement-a'): BrokerPolicy {
  return {
    schemaVersion: 1,
    engagementId,
    policySnapshot: { url: 'https://program.example/rules', revision, capturedAtUtc: '2026-09-24T00:00:00Z', freshUntilUtc: '2026-10-01T00:00:00Z' },
    accountAliases: ['researcher-a', 'researcher-b', 'validator'],
    loginOrigins: [{ origin: 'https://login.identity.example:443', purpose: 'user-attended sign-in only' }],
    refreshOrigins: [],
    targetOrigins: ['https://app.example:443'],
    grants: [{ accountAlias: 'researcher-a', technique: 'read-only mapping', methods: ['GET'], policyReference: 'section 4' }],
    limits: { requestsPerSecond: 1, maxConcurrentRequests: 1, maxRequestsPerCapability: 10, maxRequestBodyBytes: 1024, expiresAtUtc: '2026-09-25T00:00:00Z' },
    stopConditions: ['stop if real user data appears']
  } as BrokerPolicy;
}

function makeManager(
  SessionManager: SessionManagerApi['SessionManager'],
  options: { mode?: 'persistent' | 'memory'; statuses?: Array<number | Error>; revision?: string; openCalls?: string[]; created?: Array<Record<string, unknown>>; rateLimits?: number[]; closeFails?: boolean; lockReleases?: number[] } = {}
) {
  const clock = new Date('2026-09-24T02:00:00.000Z');
  const created: Array<Record<string, unknown>> = options.created ?? [];
  const openCalls = options.openCalls ?? [];
  const statuses = options.statuses ?? [];
  const rateLimits = options.rateLimits ?? [];
  const lockReleases = options.lockReleases ?? [];
  let statusIndex = 0;
  const manager = new SessionManager({
    profileRoot: 'C:\\Synthetic\\BugHuntSkills\\AuthenticationBroker\\profiles',
    getPolicy: (engagementId) => policy(options.revision, engagementId),
    now: () => clock,
    prepareProfileDirectory: async () => undefined,
    selectProfileMode: async () => ({
      mode: options.mode ?? 'memory',
      reason: options.mode === 'persistent' ? 'protection-verified' : 'protection-unverified'
    }),
    acquireLock: async () => ({ release: async () => { lockReleases.push(1); } }),
    createProxyCredentials: ({ engagementId, accountAlias }) => ({ username: `session-${engagementId}-${accountAlias}`, password: 'synthetic-proxy-capability-secret' }),
    createContext: async (input) => {
      created.push(input as unknown as Record<string, unknown>);
      return {
        openLogin: async (origin) => { openCalls.push(origin); },
        close: async () => { if (options.closeFails) throw new Error('synthetic close failure'); },
        authorizedRequest: async () => {
          const next = statuses[statusIndex++];
          if (next instanceof Error) throw next;
          return { status: next ?? 200, body: 'synthetic response' };
        }
      };
    },
    onRateLimit: () => { rateLimits.push(Date.now()); }
  });
  return { manager, created, openCalls, rateLimits, lockReleases, apiCalls: () => statusIndex };
}

test('creates exactly one private context per engagement/account and exposes metadata only', async () => {
  const { SessionManager } = await getApi();
  const { manager, created } = makeManager(SessionManager);
  const first = await manager.start('engagement-a', 'researcher-a');
  const same = await manager.start('engagement-a', 'researcher-a');
  const otherAccount = await manager.start('engagement-a', 'researcher-b');
  const otherEngagement = await manager.start('engagement-b', 'researcher-a');
  assert.equal(first.state, 'login_required');
  assert.equal(first.storageMode, 'memory');
  assert.equal(created.length, 3);
  assert.deepEqual(new Set(created.map((entry) => entry.accountAlias)), new Set(['researcher-a', 'researcher-b']));
  assert.notEqual((created[0]?.proxyCredentials as { username?: string })?.username, (created[1]?.proxyCredentials as { username?: string })?.username);
  assert.equal(created[0]?.profilePath, undefined);
  assert.equal(same.createdAtUtc, first.createdAtUtc);
  assert.equal(otherAccount.accountAlias, 'researcher-b');
  assert.equal(otherEngagement.engagementId, 'engagement-b');
  const outward = JSON.stringify([first, otherAccount, otherEngagement]);
  assert.equal(outward.includes('synthetic-proxy-capability-secret'), false);
  assert.equal(outward.includes('C:\\Synthetic'), false);
  assert.equal(outward.includes('cookie'), false);
});

test('requires an exact policy login origin and researcher confirmation before session use', async () => {
  const { SessionManager } = await getApi();
  const { manager, openCalls } = makeManager(SessionManager);
  await manager.start('engagement-a', 'researcher-a');
  await assert.rejects(manager.openLogin('engagement-a', 'researcher-a', 'https://evil.example:443'), /login origin/i);
  const handoff = await manager.openLogin('engagement-a', 'researcher-a', 'https://login.identity.example:443');
  assert.equal(handoff.state, 'user_action_required');
  assert.deepEqual(openCalls, ['https://login.identity.example:443']);
  await assert.rejects(manager.authorizedRequest('engagement-a', 'researcher-a', {}), /session is not active/i);
  const active = manager.confirmAttendedLogin('engagement-a', 'researcher-a');
  assert.equal(active.state, 'active');
  assert.equal((await manager.authorizedRequest('engagement-a', 'researcher-a', {})).status, 200);
});

test('requires re-login after persistent and in-memory broker restarts', async () => {
  const { SessionManager } = await getApi();
  const persistentFirst = makeManager(SessionManager, { mode: 'persistent' });
  const beforeRestart = await persistentFirst.manager.start('engagement-a', 'researcher-a');
  assert.equal(beforeRestart.state, 'login_required');
  assert.equal(typeof persistentFirst.created[0]?.profilePath, 'string');
  const persistentRestart = makeManager(SessionManager, { mode: 'persistent' });
  const afterPersistentRestart = await persistentRestart.manager.start('engagement-a', 'researcher-a');
  assert.equal(afterPersistentRestart.state, 'login_required');
  assert.equal(persistentRestart.created[0]?.profilePath, persistentFirst.created[0]?.profilePath);

  const memoryFirst = makeManager(SessionManager, { mode: 'memory' });
  await memoryFirst.manager.start('engagement-a', 'researcher-a');
  const memoryRestart = makeManager(SessionManager, { mode: 'memory' });
  const afterMemoryRestart = await memoryRestart.manager.start('engagement-a', 'researcher-a');
  assert.equal(afterMemoryRestart.state, 'login_required');
  assert.equal(memoryRestart.created[0]?.profilePath, undefined);
});

test('assigns a separate hashed persistent profile to each account and validator', async () => {
  const { SessionManager } = await getApi();
  const { manager, created } = makeManager(SessionManager, { mode: 'persistent' });
  await manager.start('engagement-a', 'researcher-a');
  await manager.start('engagement-a', 'researcher-b');
  await manager.start('engagement-a', 'validator');
  const paths = created.map((entry) => entry.profilePath as string);
  assert.equal(new Set(paths).size, 3);
  assert.equal(paths.every((profilePath) => typeof profilePath === 'string' && profilePath.length > 50), true);
  assert.equal(paths.some((profilePath) => profilePath.includes('researcher-a') || profilePath.includes('researcher-b') || profilePath.includes('validator')), false);
});

test('handles 401, 403, 429, and timeout without automatic request replay', async () => {
  const { SessionManager } = await getApi();
  const statuses = [403, 429, new Error('synthetic timeout')];
  const state = makeManager(SessionManager, { statuses });
  await state.manager.start('engagement-a', 'researcher-a');
  await state.manager.openLogin('engagement-a', 'researcher-a', 'https://login.identity.example:443');
  state.manager.confirmAttendedLogin('engagement-a', 'researcher-a');
  assert.equal((await state.manager.authorizedRequest('engagement-a', 'researcher-a', {})).status, 403);
  assert.equal(state.manager.getSnapshot('engagement-a', 'researcher-a')?.state, 'active');
  assert.equal((await state.manager.authorizedRequest('engagement-a', 'researcher-a', {})).status, 429);
  assert.equal(state.rateLimits.length, 1);
  await assert.rejects(state.manager.authorizedRequest('engagement-a', 'researcher-a', {}), /outcome is unknown/i);
  assert.equal(state.manager.getSnapshot('engagement-a', 'researcher-a')?.state, 'user_action_required');
  assert.equal(state.apiCalls(), 3);
  await assert.rejects(state.manager.authorizedRequest('engagement-a', 'researcher-a', {}), /session is not active/i);

  const expired = makeManager(SessionManager, { statuses: [401] });
  await expired.manager.start('engagement-a', 'researcher-a');
  await expired.manager.openLogin('engagement-a', 'researcher-a', 'https://login.identity.example:443');
  expired.manager.confirmAttendedLogin('engagement-a', 'researcher-a');
  assert.equal((await expired.manager.authorizedRequest('engagement-a', 'researcher-a', {})).status, 401);
  assert.equal(expired.manager.getSnapshot('engagement-a', 'researcher-a')?.state, 'expired');
  assert.equal(expired.apiCalls(), 1);
});

test('hands challenges to the researcher and revokes the context and capability state', async () => {
  const { SessionManager } = await getApi();
  const { manager } = makeManager(SessionManager);
  await manager.start('engagement-a', 'researcher-a');
  const challenge = manager.requireResearcherAction('engagement-a', 'researcher-a');
  assert.equal(challenge.state, 'user_action_required');
  const revoked = await manager.revoke('engagement-a', 'researcher-a', true);
  assert.equal(revoked.state, 'revoked');
  assert.equal(revoked.revoked, true);
  assert.equal(manager.getSnapshot('engagement-a', 'researcher-a'), undefined, 'a closed context is detached from the active session map');
});

test('requires a fresh attended login after the researcher closes a revoked profile', async () => {
  const { SessionManager } = await getApi();
  const { manager, created } = makeManager(SessionManager);
  await manager.start('engagement-a', 'researcher-a');
  await manager.openLogin('engagement-a', 'researcher-a', 'https://login.identity.example:443');
  manager.confirmAttendedLogin('engagement-a', 'researcher-a');
  await manager.revoke('engagement-a', 'researcher-a', true);
  assert.equal(manager.getSnapshot('engagement-a', 'researcher-a'), undefined, 'closed profiles must be detached from the live session map');
  const restarted = await manager.start('engagement-a', 'researcher-a');
  assert.equal(restarted.state, 'login_required');
  assert.equal(created.length, 2);
});

test('keeps the profile lock when browser shutdown fails', async () => {
  const { SessionManager } = await getApi();
  const state = makeManager(SessionManager, { closeFails: true });
  await state.manager.start('engagement-a', 'researcher-a');

  await assert.rejects(state.manager.revoke('engagement-a', 'researcher-a', true), /could not be closed safely/i);
  assert.deepEqual(state.lockReleases, [], 'a possibly live browser still owns the profile');
  assert.equal(state.manager.getSnapshot('engagement-a', 'researcher-a')?.state, 'error');

  await assert.rejects(state.manager.closeAll(), /could not be closed safely/i);
  assert.deepEqual(state.lockReleases, [], 'shutdown retries must also retain the profile lock on failure');
});
