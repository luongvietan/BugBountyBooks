import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import type { BrokerPolicy } from '../policy/schema.js';
import type { AuthorizedApiScope } from '../browser/api-request.js';
import type { HttpMethod } from '../capability/grants.js';
import { normalizeOrigin } from '../policy/origin.js';
import { acquireProfileLock, type ProfileLockHandle } from './profile-lock.js';
import { selectProfileMode, type ProfileProtectionDecision } from './profile-protection.js';
import { NetworkRequestBudget } from './network-request-budget.js';

export type SessionState = 'not_configured' | 'login_required' | 'user_action_required' | 'active' | 'expired' | 'revoked' | 'error';

export interface SessionSnapshot {
  readonly engagementId: string;
  readonly accountAlias: string;
  readonly policyRevision: string;
  readonly state: SessionState;
  readonly storageMode: 'persistent' | 'memory';
  readonly createdAtUtc: string;
  readonly lastCheckedAtUtc: string;
  readonly revoked: boolean;
}

export interface SessionApiRequestResult {
  readonly status: number;
  readonly body: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly bodySuppressed?: boolean;
}

export interface SessionContextHandle {
  openLogin(origin: string): Promise<void>;
  activateTarget?(): void;
  pauseTarget?(): void;
  setTargetScope?(origins: readonly string[], methods?: readonly string[], technique?: string): void;
  setApiScope?(origins: readonly string[], methods: readonly string[], technique: string): void;
  navigate?(url: string, allowedOrigins?: readonly string[], allowedMethods?: readonly HttpMethod[]): Promise<{ navigated: boolean }>;
  observePage?(allowedOrigins?: readonly string[], allowedMethods?: readonly HttpMethod[]): Promise<unknown>;
  clickObservedLink?(id: string, allowedOrigins?: readonly string[], allowedMethods?: readonly HttpMethod[]): Promise<{ navigated: boolean }>;
  fillResearcherControlledField?(id: string, value: string, allowedOrigins?: readonly string[], allowedMethods?: readonly HttpMethod[]): Promise<{ filled: boolean }>;
  authorizedRequest?: (request: unknown, scope?: AuthorizedApiScope) => Promise<SessionApiRequestResult>;
  close(): Promise<void>;
}

export interface SessionContextOptions {
  readonly engagementId: string;
  readonly accountAlias: string;
  readonly policyRevision: string;
  readonly mode: 'persistent' | 'memory';
  readonly profileProtectionVerified: boolean;
  readonly profilePath?: string;
  readonly loginOrigins: readonly string[];
  readonly targetOrigins: readonly string[];
  readonly proxyCredentials: { readonly username: string; readonly password: string };
  readonly reserveTargetRequest: () => Promise<(() => void) | undefined>;
  readonly onTargetResponseStatus: (status: number) => void;
}

export interface SessionManagerOptions {
  profileRoot: string;
  getPolicy: (engagementId: string) => BrokerPolicy | undefined;
  now?: () => Date;
  prepareProfileDirectory?: (directory: string) => Promise<void>;
  selectProfileMode?: (directory: string) => Promise<ProfileProtectionDecision>;
  acquireLock?: (options: { directory: string; profileKey: string }) => Promise<ProfileLockHandle>;
  createProxyCredentials: (input: { engagementId: string; accountAlias: string }) => { username: string; password: string };
  createContext: (options: SessionContextOptions) => Promise<SessionContextHandle>;
  onAuthorizationStop?: (input: { engagementId: string; accountAlias: string; status: 403 | 429 }) => void;
}

interface ManagedSession {
  readonly engagementId: string;
  readonly accountAlias: string;
  readonly policyRevision: string;
  readonly policyFreshUntilMs: number;
  readonly policyExpiresAtMs: number;
  readonly storageMode: 'persistent' | 'memory';
  readonly createdAtUtc: string;
  readonly lock: ProfileLockHandle;
  readonly context: SessionContextHandle;
  readonly networkBudget: NetworkRequestBudget;
  state: SessionState;
  lastCheckedAtUtc: string;
  revoked: boolean;
  busy: boolean;
  closed: boolean;
  actionReason?: 'attended-login' | 'authorization-review';
}

export class SessionManager {
  private readonly sessions = new Map<string, ManagedSession>();
  private readonly pending = new Map<string, Promise<ManagedSession>>();
  private readonly networkBudgets = new Map<string, { revision: string; budget: NetworkRequestBudget }>();
  private readonly profileRoot: string;
  private readonly getPolicy: SessionManagerOptions['getPolicy'];
  private readonly now: () => Date;
  private readonly prepareProfileDirectory: (directory: string) => Promise<void>;
  private readonly selectProfileMode: NonNullable<SessionManagerOptions['selectProfileMode']>;
  private readonly acquireLock: NonNullable<SessionManagerOptions['acquireLock']>;
  private readonly createProxyCredentials: SessionManagerOptions['createProxyCredentials'];
  private readonly createContext: SessionManagerOptions['createContext'];
  private readonly onAuthorizationStop: NonNullable<SessionManagerOptions['onAuthorizationStop']>;

  constructor(options: SessionManagerOptions) {
    if (typeof options.profileRoot !== 'string' || !path.isAbsolute(options.profileRoot)) throw new Error('Session profile root must be absolute');
    this.profileRoot = path.resolve(options.profileRoot);
    this.getPolicy = options.getPolicy;
    this.now = options.now ?? (() => new Date());
    this.prepareProfileDirectory = options.prepareProfileDirectory ?? preparePrivateProfileDirectory;
    this.selectProfileMode = options.selectProfileMode ?? selectProfileMode;
    this.acquireLock = options.acquireLock ?? acquireProfileLock;
    this.createProxyCredentials = options.createProxyCredentials;
    this.createContext = options.createContext;
    this.onAuthorizationStop = options.onAuthorizationStop ?? (() => undefined);
  }

  async start(engagementId: string, accountAlias: string): Promise<SessionSnapshot> {
    const key = sessionKey(engagementId, accountAlias);
    const existing = this.sessions.get(key);
    if (existing && !existing.closed) return this.snapshot(existing);
    if (existing?.closed) this.sessions.delete(key);
    const activePending = this.pending.get(key);
    if (activePending) return this.snapshot(await activePending);
    const operation = this.createSession(engagementId, accountAlias, key);
    this.pending.set(key, operation);
    try {
      const created = await operation;
      this.sessions.set(key, created);
      return this.snapshot(created);
    } finally {
      if (this.pending.get(key) === operation) this.pending.delete(key);
    }
  }

  async openLogin(engagementId: string, accountAlias: string, origin: string): Promise<SessionSnapshot> {
    const key = sessionKey(engagementId, accountAlias);
    let current = this.sessions.get(key);
    if (!current || current.closed) {
      await this.start(engagementId, accountAlias);
      current = this.requireSession(engagementId, accountAlias);
    }
    const policy = this.requireCurrentPolicy(engagementId, accountAlias, current.policyRevision);
    let normalized: string;
    try { normalized = normalizeOrigin(origin); } catch { throw new Error('Login origin is not permitted by current policy'); }
    if (normalized !== origin || !policy.loginOrigins.some((entry) => entry.origin === normalized)) {
      throw new Error('Login origin is not permitted by current policy');
    }
    if ((current.state !== 'login_required' && current.state !== 'user_action_required') || current.actionReason === 'authorization-review') throw new Error('Session is not awaiting attended sign-in');
    try {
      await current.context.openLogin(normalized);
      current.state = 'user_action_required';
      current.actionReason = 'attended-login';
      current.lastCheckedAtUtc = this.now().toISOString();
      return this.snapshot(current);
    } catch {
      current.state = 'error';
      current.lastCheckedAtUtc = this.now().toISOString();
      throw new Error('Attended login window could not be opened');
    }
  }

  confirmAttendedLogin(engagementId: string, accountAlias: string): SessionSnapshot {
    const current = this.requireSession(engagementId, accountAlias);
    this.requireCurrentPolicy(engagementId, accountAlias, current.policyRevision);
    if (current.state !== 'user_action_required' || current.actionReason === 'authorization-review') throw new Error('Session is not awaiting researcher confirmation');
    try { current.context.activateTarget?.(); } catch { throw new Error('Managed target page could not be enabled'); }
    current.state = 'active';
    delete current.actionReason;
    current.lastCheckedAtUtc = this.now().toISOString();
    return this.snapshot(current);
  }

  confirmResearcherResume(engagementId: string, accountAlias: string): SessionSnapshot {
    const current = this.requireSession(engagementId, accountAlias);
    this.requireCurrentPolicy(engagementId, accountAlias, current.policyRevision);
    if (current.state !== 'user_action_required' || current.actionReason !== 'authorization-review' || current.revoked) throw new Error('Session is not awaiting authorization review');
    try { current.context.activateTarget?.(); } catch { throw new Error('Managed target page could not be enabled'); }
    current.state = 'active';
    delete current.actionReason;
    current.lastCheckedAtUtc = this.now().toISOString();
    return this.snapshot(current);
  }

  requireResearcherAction(engagementId: string, accountAlias: string): SessionSnapshot {
    const current = this.requireSession(engagementId, accountAlias);
    if (current.state === 'revoked' || current.state === 'error') throw new Error('Session cannot be resumed');
    if (current.actionReason === 'authorization-review') throw new Error('Authorization review must be confirmed before sign-in');
    try { current.context.pauseTarget?.(); } catch { current.state = 'error'; throw new Error('Managed session could not be paused safely'); }
    current.state = 'user_action_required';
    current.actionReason = 'attended-login';
    current.lastCheckedAtUtc = this.now().toISOString();
    return this.snapshot(current);
  }

  getSnapshot(engagementId: string, accountAlias: string): SessionSnapshot | undefined {
    const current = this.sessions.get(sessionKey(engagementId, accountAlias));
    return current ? this.snapshot(current) : undefined;
  }

  async navigate(engagementId: string, accountAlias: string, url: string, allowedOrigins: readonly string[], allowedMethods: readonly HttpMethod[] = ['GET']): Promise<{ navigated: boolean }> {
    return this.performPageAction(engagementId, accountAlias, allowedOrigins, allowedMethods, async (context) => {
      if (!context.navigate) throw new Error('Managed page navigation is unavailable');
      return context.navigate(url, allowedOrigins, allowedMethods);
    });
  }

  async observePage(engagementId: string, accountAlias: string, allowedOrigins: readonly string[], allowedMethods: readonly HttpMethod[] = ['GET']): Promise<unknown> {
    return this.performPageAction(engagementId, accountAlias, allowedOrigins, allowedMethods, async (context) => {
      if (!context.observePage) throw new Error('Managed page observation is unavailable');
      return context.observePage(allowedOrigins, allowedMethods);
    });
  }

  async clickObservedLink(engagementId: string, accountAlias: string, id: string, allowedOrigins: readonly string[], allowedMethods: readonly HttpMethod[] = ['GET']): Promise<{ navigated: boolean }> {
    return this.performPageAction(engagementId, accountAlias, allowedOrigins, allowedMethods, async (context) => {
      if (!context.clickObservedLink) throw new Error('Managed link action is unavailable');
      return context.clickObservedLink(id, allowedOrigins, allowedMethods);
    });
  }

  async fillResearcherControlledField(engagementId: string, accountAlias: string, id: string, value: string, allowedOrigins: readonly string[], allowedMethods: readonly HttpMethod[] = ['GET']): Promise<{ filled: boolean }> {
    return this.performPageAction(engagementId, accountAlias, allowedOrigins, allowedMethods, async (context) => {
      if (!context.fillResearcherControlledField) throw new Error('Managed field action is unavailable');
      return context.fillResearcherControlledField(id, value, allowedOrigins, allowedMethods);
    });
  }

  async authorizedRequest(engagementId: string, accountAlias: string, request: unknown, scope?: AuthorizedApiScope): Promise<SessionApiRequestResult> {
    const current = this.requireSession(engagementId, accountAlias);
    try { this.requireCurrentPolicy(engagementId, accountAlias, current.policyRevision); } catch {
      current.state = 'revoked';
      current.revoked = true;
      throw new Error('Session policy is stale or unavailable');
    }
    if (current.state !== 'active' || current.revoked) throw new Error('Session is not active');
    if (current.busy) throw new Error('Session request is already in progress');
    if (!current.context.authorizedRequest) throw new Error('API request capability is disabled for this session');
    current.busy = true;
    try {
      if (current.context.setApiScope) {
        if (!scope) throw new Error('API capability scope is unavailable');
        current.context.setApiScope(scope.allowedOrigins, scope.allowedMethods, scope.technique);
      } else if (current.context.setTargetScope) {
        throw new Error('API capability scope is unavailable');
      }
      const requestScope = scope ? Object.freeze({
        ...scope,
        reserveRequest: () => current.networkBudget.acquire(),
        onResponseStatus: (status: number) => this.handleTargetResponseStatus(engagementId, accountAlias, status)
      }) : undefined;
      const result = await current.context.authorizedRequest(request, requestScope);
      if (!result || !Number.isInteger(result.status) || result.status < 100 || result.status > 599 || typeof result.body !== 'string' ||
          (result.headers !== undefined && (!result.headers || typeof result.headers !== 'object' || Array.isArray(result.headers))) ||
          (result.bodySuppressed !== undefined && typeof result.bodySuppressed !== 'boolean')) {
        current.state = 'error';
        throw new Error('Broker returned an invalid API result');
      }
      current.lastCheckedAtUtc = this.now().toISOString();
      if (result.status === 401 || result.status === 403 || result.status === 429) this.handleTargetResponseStatus(engagementId, accountAlias, result.status);
      return Object.freeze({
        status: result.status,
        body: result.body,
        ...(result.headers ? { headers: Object.freeze({ ...result.headers }) } : {}),
        ...(result.bodySuppressed !== undefined ? { bodySuppressed: result.bodySuppressed } : {})
      });
    } catch {
      try { current.context.pauseTarget?.(); } catch { current.state = 'error'; }
      const failedState = current.state as SessionState;
      if (failedState !== 'error' && failedState !== 'expired') current.state = 'user_action_required';
      current.lastCheckedAtUtc = this.now().toISOString();
      throw new Error('Request outcome is unknown; no automatic replay occurred');
    } finally {
      current.busy = false;
    }
  }

  handleTargetResponseStatus(engagementId: string, accountAlias: string, status: number): void {
    if (status !== 401 && status !== 403 && status !== 429) return;
    const current = this.sessions.get(sessionKey(engagementId, accountAlias));
    if (!current || current.closed || current.state !== 'active' || current.revoked) return;
    let paused = true;
    try { current.context.pauseTarget?.(); } catch { paused = false; }
    current.state = paused ? (status === 401 ? 'expired' : 'user_action_required') : 'error';
    if (paused) current.actionReason = status === 401 ? 'attended-login' : 'authorization-review';
    else delete current.actionReason;
    current.lastCheckedAtUtc = this.now().toISOString();
    if (status === 403 || status === 429) {
      try { this.onAuthorizationStop({ engagementId, accountAlias, status }); } catch { /* account capability revocation remains fail closed at the caller */ }
    }
  }

  async revoke(engagementId: string, accountAlias: string, closeProfile = false): Promise<SessionSnapshot> {
    const current = this.requireSession(engagementId, accountAlias);
    current.revoked = true;
    current.state = 'revoked';
    current.lastCheckedAtUtc = this.now().toISOString();
    try { current.context.pauseTarget?.(); } catch { /* state remains revoked */ }
    if (closeProfile) {
      try {
        await current.context.close();
        current.closed = true;
        await current.lock.release();
        this.sessions.delete(sessionKey(engagementId, accountAlias));
      } catch {
        current.state = 'error';
        throw new Error('Managed session could not be closed safely');
      }
    }
    return this.snapshot(current);
  }

  async closeAll(): Promise<void> {
    const current = [...this.sessions.entries()];
    const results = await Promise.allSettled(current.map(async ([key, session]) => {
      try {
        await session.context.close();
        session.closed = true;
        await session.lock.release();
        this.sessions.delete(key);
      } catch {
        session.state = 'error';
        session.revoked = true;
        session.lastCheckedAtUtc = this.now().toISOString();
        throw new Error('Managed session could not be closed safely');
      }
    }));
    if (results.some((result) => result.status === 'rejected')) {
      for (const entry of this.networkBudgets.values()) entry.budget.close();
      this.networkBudgets.clear();
      throw new Error('One or more managed sessions could not be closed safely');
    }
    for (const entry of this.networkBudgets.values()) entry.budget.close();
    this.networkBudgets.clear();
  }

  private async createSession(engagementId: string, accountAlias: string, key: string): Promise<ManagedSession> {
    const policy = this.requireCurrentPolicy(engagementId, accountAlias);
    const profilePath = path.join(this.profileRoot, profileDirectoryName(engagementId, accountAlias));
    let profileReady = true;
    try { await this.prepareProfileDirectory(profilePath); } catch { profileReady = false; }
    let decision: ProfileProtectionDecision;
    try {
      decision = profileReady ? await this.selectProfileMode(profilePath) : { mode: 'memory', reason: 'protection-unverified' };
    } catch { decision = { mode: 'memory', reason: 'protection-unverified' }; }
    const mode = decision?.mode === 'persistent' && decision.reason === 'protection-verified' ? 'persistent' : 'memory';
    let lock: ProfileLockHandle;
    try {
      lock = await this.acquireLock({ directory: path.join(this.profileRoot, '.locks'), profileKey: key });
    } catch {
      throw new Error('Account profile is already in use or cannot be safely locked');
    }
    try {
      const networkBudget = this.networkBudgetFor(key, policy);
      const proxyCredentials = this.createProxyCredentials({ engagementId, accountAlias });
      if (!proxyCredentials || typeof proxyCredentials.username !== 'string' || !proxyCredentials.username ||
          typeof proxyCredentials.password !== 'string' || proxyCredentials.password.length < 32) {
        throw new Error('Broker proxy credentials are unavailable');
      }
      const contextOptions: SessionContextOptions = {
        engagementId,
        accountAlias,
        policyRevision: policy.policySnapshot.revision,
        mode,
        profileProtectionVerified: mode === 'persistent',
        ...(mode === 'persistent' ? { profilePath } : {}),
        loginOrigins: Object.freeze(policy.loginOrigins.map(({ origin }) => normalizeOrigin(origin))),
        targetOrigins: Object.freeze(policy.targetOrigins.map(normalizeOrigin)),
        proxyCredentials: Object.freeze({ username: proxyCredentials.username, password: proxyCredentials.password }),
        reserveTargetRequest: () => networkBudget.acquire(),
        onTargetResponseStatus: (status) => this.handleTargetResponseStatus(engagementId, accountAlias, status)
      };
      const context = await this.createContext(contextOptions);
      const createdAtUtc = this.now().toISOString();
      return {
        engagementId,
        accountAlias,
        policyRevision: policy.policySnapshot.revision,
        policyFreshUntilMs: Date.parse(policy.policySnapshot.freshUntilUtc),
        policyExpiresAtMs: Date.parse(policy.limits.expiresAtUtc),
        storageMode: mode,
        createdAtUtc,
        lastCheckedAtUtc: createdAtUtc,
        lock,
        context,
        networkBudget,
        state: 'login_required',
        revoked: false,
        busy: false,
        closed: false
      };
    } catch {
      await lock.release();
      throw new Error('Managed browser session could not be started');
    }
  }

  private requireCurrentPolicy(engagementId: string, accountAlias: string, expectedRevision?: string): BrokerPolicy {
    let policy: BrokerPolicy | undefined;
    try { policy = this.getPolicy(engagementId); } catch { policy = undefined; }
    const now = this.now().getTime();
    if (!policy || policy.engagementId !== engagementId || !policy.accountAliases.includes(accountAlias) ||
        Date.parse(policy.policySnapshot.freshUntilUtc) <= now || Date.parse(policy.limits.expiresAtUtc) <= now ||
        (expectedRevision !== undefined && policy.policySnapshot.revision !== expectedRevision)) {
      throw new Error('A current broker policy does not authorize this session');
    }
    return policy;
  }

  private requireSession(engagementId: string, accountAlias: string): ManagedSession {
    const session = this.sessions.get(sessionKey(engagementId, accountAlias));
    if (!session) throw new Error('Session is not configured');
    return session;
  }

  private async performPageAction<T>(
    engagementId: string,
    accountAlias: string,
    allowedOrigins: readonly string[],
    allowedMethods: readonly HttpMethod[],
    action: (context: SessionContextHandle) => Promise<T>
  ): Promise<T> {
    const current = this.requireSession(engagementId, accountAlias);
    try { this.requireCurrentPolicy(engagementId, accountAlias, current.policyRevision); } catch {
      current.state = 'revoked';
      current.revoked = true;
      throw new Error('Session policy is stale or unavailable');
    }
    if (current.state !== 'active' || current.revoked) throw new Error('Session is not active');
    if (current.busy) throw new Error('Session request is already in progress');
    let policy: BrokerPolicy | undefined;
    try { policy = this.getPolicy(engagementId); } catch { policy = undefined; }
    const origins = canonicalCapabilityOrigins(allowedOrigins, policy?.targetOrigins ?? []);
    const methods = canonicalPageMethods(allowedMethods);
    current.busy = true;
    try {
      current.context.setTargetScope?.(origins, methods);
      const result = await action(current.context);
      current.lastCheckedAtUtc = this.now().toISOString();
      return result;
    } catch {
      try { current.context.pauseTarget?.(); } catch { current.state = 'error'; }
      const state = current.state as SessionState;
      if (state !== 'error' && state !== 'revoked') current.state = 'user_action_required';
      current.lastCheckedAtUtc = this.now().toISOString();
      throw new Error('Managed page action was blocked or failed');
    } finally { current.busy = false; }
  }

  private snapshot(session: ManagedSession): SessionSnapshot {
    let currentPolicy: BrokerPolicy | undefined;
    try { currentPolicy = this.getPolicy(session.engagementId); } catch { currentPolicy = undefined; }
    const policyFresh = Math.min(session.policyFreshUntilMs, session.policyExpiresAtMs) > this.now().getTime() &&
      currentPolicy?.policySnapshot.revision === session.policyRevision && currentPolicy.engagementId === session.engagementId;
    if (!policyFresh && session.state !== 'revoked') {
      try { session.context.pauseTarget?.(); } catch { /* session is revoked even if a page cannot be closed */ }
      session.state = 'revoked';
      session.revoked = true;
    }
    return Object.freeze({
      engagementId: session.engagementId,
      accountAlias: session.accountAlias,
      policyRevision: session.policyRevision,
      state: session.state,
      storageMode: session.storageMode,
      createdAtUtc: session.createdAtUtc,
      lastCheckedAtUtc: session.lastCheckedAtUtc,
      revoked: session.revoked
    });
  }

  private networkBudgetFor(key: string, policy: BrokerPolicy): NetworkRequestBudget {
    const revision = policy.policySnapshot.revision;
    const existing = this.networkBudgets.get(key);
    if (existing?.revision === revision) return existing.budget;
    existing?.budget.close();
    const budget = new NetworkRequestBudget({
      requestsPerSecond: policy.limits.requestsPerSecond,
      maxConcurrentRequests: policy.limits.maxConcurrentRequests,
      maxRequests: policy.limits.maxRequestsPerCapability,
      now: () => this.now().getTime()
    });
    this.networkBudgets.set(key, { revision, budget });
    return budget;
  }
}

function sessionKey(engagementId: string, accountAlias: string): string {
  if (typeof engagementId !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9._-]{2,127}$/.test(engagementId) ||
      typeof accountAlias !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(accountAlias)) {
    throw new Error('Session identity is invalid');
  }
  return `${engagementId.length}:${engagementId}${accountAlias.length}:${accountAlias}`;
}

function profileDirectoryName(engagementId: string, accountAlias: string): string {
  return createHash('sha256').update(sessionKey(engagementId, accountAlias)).digest('hex');
}

function canonicalCapabilityOrigins(origins: readonly string[], targetOrigins: readonly string[]): readonly string[] {
  if (!Array.isArray(origins) || !origins.length) throw new Error('Page capability has no approved origins');
  const result = origins.map((origin) => {
    let normalized: string;
    try { normalized = normalizeOrigin(origin); } catch { throw new Error('Page capability origin is invalid'); }
    if (normalized !== origin || !targetOrigins.includes(origin)) throw new Error('Page capability exceeds current target policy');
    return origin;
  });
  if (new Set(result).size !== result.length) throw new Error('Page capability contains duplicate origins');
  return Object.freeze(result);
}

function canonicalPageMethods(methods: readonly HttpMethod[]): readonly HttpMethod[] {
  if (!Array.isArray(methods) || !methods.length || new Set(methods).size !== methods.length ||
      methods.some((method) => method !== 'GET' && method !== 'HEAD') || !methods.includes('GET')) {
    throw new Error('Page capability does not authorize GET navigation');
  }
  return Object.freeze([...methods]);
}

async function preparePrivateProfileDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true });
  if (process.platform !== 'win32') return;
  const user = process.env.USERNAME;
  const domain = process.env.USERDOMAIN;
  if (!user) throw new Error('Current user cannot be determined');
  const identity = domain ? `${domain}\\${user}` : user;
  try {
    execFileSync('icacls.exe', [directory, '/inheritance:r', '/grant:r', `${identity}:(OI)(CI)F`], { stdio: 'ignore', windowsHide: true });
  } catch {
    throw new Error('Current-user-only profile permissions could not be set');
  }
}
