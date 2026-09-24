import { chromium, type Browser, type BrowserContext, type LaunchOptions, type Page } from 'playwright';
import { normalizeOrigin } from '../policy/origin.js';
import { managedBrowserNetworkOptions } from '../network/egress-preflight.js';
import type { AuthorizedApiScope } from './api-request.js';
import { createPageTools, type ObservedElement, type PageAutomationSurface, type PageObservation } from './page-tools.js';

const PAGE_ELEMENT_SELECTOR = 'a,button,input,textarea,select,[role="button"],[role="link"],[role="textbox"]';
const LOGIN_METHODS = new Set(['GET', 'HEAD', 'POST', 'OPTIONS']);
const READ_ONLY_METHODS = new Set(['GET', 'HEAD']);
const API_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);

export interface ManagedBrowserEngine {
  launch(options: unknown): Promise<unknown>;
  launchPersistentContext(userDataDir: string, options: unknown): Promise<unknown>;
}

export interface ManagedContextOptions {
  readonly mode: 'persistent' | 'memory';
  readonly profilePath?: string;
  readonly profileProtectionVerified: boolean;
  readonly engagementId: string;
  readonly accountAlias: string;
  readonly policyRevision: string;
  readonly loginOrigins: readonly string[];
  readonly targetOrigins: readonly string[];
  readonly proxyCredentials: { readonly username: string; readonly password: string };
  readonly reserveTargetRequest: () => Promise<(() => void) | undefined>;
  readonly onTargetResponseStatus: (status: number) => void;
  readonly isEgressVerified: () => boolean;
  readonly onProxyScopeChange?: (scope: { mode: 'blocked' | 'login' | 'target'; origins: readonly string[]; methods: readonly string[]; technique?: string }) => void;
  readonly onProxyCredentialsClosed?: () => void;
  readonly sanitizeObservation?: (value: string) => string;
  /** Internal-only adapter. If setup fails, browser API requests remain disabled. */
  readonly createAuthorizedRequest?: (context: BrowserContext, proxyCredentials: ManagedContextOptions['proxyCredentials']) => ((input: unknown, scope?: AuthorizedApiScope) => Promise<{
    status: number; body: string; headers?: Readonly<Record<string, string>>; bodySuppressed?: boolean;
  }>);
  /** Test-only browser engine seam. */
  readonly engine?: ManagedBrowserEngine;
}

export interface ManagedContextHandle {
  openLogin(origin: string): Promise<void>;
  activateTarget(): void;
  pauseTarget(): void;
  setTargetScope(origins: readonly string[], methods?: readonly string[], technique?: string): void;
  setApiScope(origins: readonly string[], methods: readonly string[], technique: string): void;
  navigate(url: string, allowedOrigins?: readonly string[], allowedMethods?: readonly string[]): Promise<{ navigated: boolean }>;
  observePage(allowedOrigins?: readonly string[], allowedMethods?: readonly string[]): Promise<PageObservation>;
  clickObservedLink(id: string, allowedOrigins?: readonly string[], allowedMethods?: readonly string[]): Promise<{ navigated: boolean }>;
  fillResearcherControlledField(id: string, value: string, allowedOrigins?: readonly string[], allowedMethods?: readonly string[]): Promise<{ filled: boolean }>;
  close(): Promise<void>;
  authorizedRequest?: (input: unknown, scope?: AuthorizedApiScope) => Promise<{ status: number; body: string; headers?: Readonly<Record<string, string>>; bodySuppressed?: boolean }>;
}

export async function createManagedContext(options: ManagedContextOptions): Promise<ManagedContextHandle> {
  assertEgress(options.isEgressVerified);
  if (typeof options.engagementId !== 'string' || !options.engagementId || typeof options.accountAlias !== 'string' || !options.accountAlias ||
      typeof options.policyRevision !== 'string' || !options.policyRevision) throw new Error('Managed browser session identity is invalid');
  if (!validProxyCredential(options.proxyCredentials)) throw new Error('Broker proxy credentials are unavailable');
  if (options.mode === 'persistent') {
    if (options.profileProtectionVerified !== true || typeof options.profilePath !== 'string' || !isAbsoluteProfilePath(options.profilePath)) {
      throw new Error('Persistent browser profile path or protection verification is invalid');
    }
  } else if (options.mode !== 'memory' || options.profilePath !== undefined || options.profileProtectionVerified === true) {
    throw new Error('In-memory browser mode must not use a profile path');
  }

  const loginOrigins = normalizeOriginSet(options.loginOrigins);
  const targetOrigins = normalizeOriginSet(options.targetOrigins);
  if (!targetOrigins.length) throw new Error('Managed browser target policy is empty');
  const network = managedBrowserNetworkOptions();
  const proxy = Object.freeze({ ...network.proxy, username: options.proxyCredentials.username, password: options.proxyCredentials.password });
  const launchNetwork = { proxy, args: [...network.args] };
  const engine = options.engine ?? defaultEngine;
  let browser: Browser | undefined;
  let context: BrowserContext | undefined;
  try {
    if (options.mode === 'persistent') {
      context = await engine.launchPersistentContext(options.profilePath!, {
        ...launchNetwork,
        headless: false,
        acceptDownloads: false,
        serviceWorkers: 'block',
        ignoreHTTPSErrors: false
      } as NonNullable<Parameters<typeof chromium.launchPersistentContext>[1]>) as BrowserContext;
    } else {
      browser = await engine.launch({ ...launchNetwork, headless: false } as LaunchOptions) as Browser;
      context = await browser.newContext({ acceptDownloads: false, serviceWorkers: 'block', ignoreHTTPSErrors: false });
    }

    let phase: 'blocked' | 'bootstrap' | 'target' = 'blocked';
    let activeTargetOrigins: readonly string[] = Object.freeze([]);
    let activeTargetMethods: readonly string[] = Object.freeze([]);
    let currentPage: Page | undefined;
    let currentTools: ReturnType<typeof createPageTools> | undefined;
    const requestBudgetReleases = new Map<object, () => void>();
    const observedPages = new WeakSet<Page>();

    function releaseRequest(request: object): void {
      const release = requestBudgetReleases.get(request);
      if (!release) return;
      requestBudgetReleases.delete(request);
      try { release(); } catch { /* request cleanup cannot widen scope */ }
    }

    function observePage(page: Page): void {
      if (observedPages.has(page)) return;
      observedPages.add(page);
      page.on('download', (download) => { void download.cancel().catch(() => undefined); });
      page.on('response', (response) => {
        if (phase !== 'target') return;
        let responseOrigin: string;
        try { responseOrigin = normalizeOrigin(new URL(response.url()).origin); } catch { return; }
        if (!targetOrigins.includes(responseOrigin)) return;
        const status = response.status();
        if (status === 401 || status === 403 || status === 429) {
          try { options.onTargetResponseStatus(status); } catch { /* session manager owns fail-closed pause */ }
        }
      });
    }

    await context.route('**/*', async (route) => {
      const request = route.request();
      const url = request.url();
      const method = request.method();
      const allowed = (): boolean => isEgressVerified(options.isEgressVerified) &&
        isPageRequestAllowed(url, method, phase, loginOrigins, targetOrigins, activeTargetOrigins, activeTargetMethods);
      if (!allowed()) {
        try { await route.abort('blockedbyclient'); } catch { /* closed context */ }
        return;
      }
      let release: (() => void) | undefined;
      if (isTargetOrigin(url, targetOrigins)) {
        try { release = await options.reserveTargetRequest(); } catch { release = undefined; }
        if (!release || !allowed()) {
          try { release?.(); } catch { /* release a request whose phase changed while queued */ }
          try { await route.abort('blockedbyclient'); } catch { /* closed context */ }
          return;
        }
        requestBudgetReleases.set(request, release);
      }
      try { await route.continue(); }
      catch {
        releaseRequest(request);
        try { await route.abort('failed'); } catch { /* closed context */ }
      }
    });
    context.on('requestfinished', (request) => releaseRequest(request));
    context.on('requestfailed', (request) => releaseRequest(request));
    notifyProxyScope('blocked', [], []);
    await context.routeWebSocket('**/*', (route) => route.close({ code: 1008, reason: 'WebSockets are disabled' }));
    context.on('page', (page) => observePage(page));
    // Persistent profiles can reopen a prior tab. Close every pre-existing page before returning control.
    for (const page of context.pages()) {
      try { await page.close(); } catch { /* startup remains blocked by the proxy capability until explicit login */ }
    }
    let authorizedRequest: ManagedContextHandle['authorizedRequest'];
    if (options.createAuthorizedRequest) {
      try { authorizedRequest = options.createAuthorizedRequest(context, options.proxyCredentials); } catch { authorizedRequest = undefined; }
    }

    function attachPageTools(page: Page): void {
      currentPage = page;
      currentTools = createPageTools(createPageSurface(page), {
        targetOrigins,
        isTargetActive: () => phase === 'target',
        ...(options.sanitizeObservation ? { sanitizeText: options.sanitizeObservation } : {})
      });
      // `page` events normally install this listener first. The listener is idempotent in
      // behavior and attaching here also covers engines that do not emit that event in tests.
      observePage(page);
    }

    function setTargetScope(origins: readonly string[], methods: readonly string[] = ['GET'], technique = 'read-only-page'): void {
      const permitted = normalizeOriginSet(origins);
      if (permitted.some((origin) => !targetOrigins.includes(origin))) throw new Error('Page capability exceeds current target policy');
      if (!Array.isArray(methods) || new Set(methods).size !== methods.length || methods.some((method) => !READ_ONLY_METHODS.has(method)) ||
          (permitted.length > 0 && !methods.includes('GET')) || (!permitted.length && methods.length > 0)) throw new Error('Page capability methods exceed read-only policy');
      activeTargetOrigins = Object.freeze(permitted);
      activeTargetMethods = Object.freeze([...methods]);
      if (currentTools) currentTools.setAllowedOrigins(permitted);
      notifyProxyScope(permitted.length ? 'target' : 'blocked', permitted, activeTargetMethods, permitted.length ? technique : undefined);
    }

    function setApiScope(origins: readonly string[], methods: readonly string[], technique: string): void {
      const permitted = normalizeOriginSet(origins);
      if (!permitted.length || permitted.some((origin) => !targetOrigins.includes(origin)) || !Array.isArray(methods) || !methods.length ||
          new Set(methods).size !== methods.length || methods.some((method) => !API_METHODS.has(method)) ||
          typeof technique !== 'string' || !technique.trim() || technique.length > 128) {
        throw new Error('API capability exceeds current target policy');
      }
      notifyProxyScope('target', permitted, Object.freeze([...methods]), technique);
    }

    async function requirePageTools(allowedOrigins: readonly string[] = activeTargetOrigins, allowedMethods: readonly string[] = ['GET']): Promise<ReturnType<typeof createPageTools>> {
      if (phase !== 'target') throw new Error('Target session is not active');
      const permitted = normalizeOriginSet(allowedOrigins);
      if (!permitted.length || permitted.some((origin) => !targetOrigins.includes(origin))) throw new Error('Page capability exceeds current target policy');
      setTargetScope(permitted, allowedMethods);
      if (!currentPage || currentPage.isClosed()) {
        const page = await context!.newPage();
        attachPageTools(page);
      }
      if (!currentTools) throw new Error('Managed page tools are unavailable');
      currentTools.setAllowedOrigins(permitted);
      return currentTools;
    }

    return {
      async openLogin(origin: string): Promise<void> {
        let normalized: string;
        try { normalized = normalizeOrigin(origin); } catch { throw new Error('Login origin is not permitted'); }
        if (normalized !== origin || !loginOrigins.includes(normalized) || phase === 'target') throw new Error('Login origin is not permitted');
        phase = 'bootstrap';
        notifyProxyScope('login', loginOrigins, ['GET', 'HEAD', 'POST', 'OPTIONS']);
        try {
          const page = await context!.newPage();
          attachPageTools(page);
          await page.goto(normalized, { waitUntil: 'domcontentloaded', timeout: 30_000 });
        } catch {
          phase = 'blocked';
          notifyProxyScope('blocked', [], []);
          throw new Error('Attended login window could not be opened');
        }
      },
      activateTarget(): void {
        phase = 'target';
        setTargetScope([], []);
      },
      pauseTarget(): void {
        phase = 'blocked';
        activeTargetOrigins = Object.freeze([]);
        activeTargetMethods = Object.freeze([]);
        try { notifyProxyScope('blocked', [], []); }
        catch {
          try { options.onProxyCredentialsClosed?.(); } catch { /* credential revocation remains best-effort fail closed */ }
          throw new Error('Managed proxy scope could not be blocked safely');
        }
      },
      setTargetScope,
      setApiScope,
      async navigate(url: string, allowedOrigins?: readonly string[], allowedMethods?: readonly string[]): Promise<{ navigated: boolean }> {
        const tools = await requirePageTools(allowedOrigins, allowedMethods);
        return tools.navigate(url);
      },
      async observePage(allowedOrigins?: readonly string[], allowedMethods?: readonly string[]): Promise<PageObservation> {
        const tools = await requirePageTools(allowedOrigins, allowedMethods);
        return tools.observe();
      },
      async clickObservedLink(id: string, allowedOrigins?: readonly string[], allowedMethods?: readonly string[]): Promise<{ navigated: boolean }> {
        const tools = await requirePageTools(allowedOrigins, allowedMethods);
        return tools.clickObservedLink(id);
      },
      async fillResearcherControlledField(id: string, value: string, allowedOrigins?: readonly string[], allowedMethods?: readonly string[]): Promise<{ filled: boolean }> {
        const tools = await requirePageTools(allowedOrigins, allowedMethods);
        return tools.fillResearcherControlledField(id, value);
      },
      async close(): Promise<void> {
        phase = 'blocked';
        activeTargetOrigins = Object.freeze([]);
        activeTargetMethods = Object.freeze([]);
        let scopeBlocked = true;
        try { notifyProxyScope('blocked', [], []); } catch { scopeBlocked = false; }
        try { options.onProxyCredentialsClosed?.(); } catch { scopeBlocked = false; }
        for (const request of requestBudgetReleases.keys()) releaseRequest(request);
        try {
          await context?.close();
          if (browser) await browser.close();
          if (!scopeBlocked) throw new Error('proxy scope could not be revoked');
        } catch {
          throw new Error('Managed browser context could not be closed safely');
        }
      },
      ...(authorizedRequest ? { authorizedRequest } : {})
    };

    function notifyProxyScope(mode: 'blocked' | 'login' | 'target', origins: readonly string[], methods: readonly string[], technique?: string): void {
      try { options.onProxyScopeChange?.({ mode, origins: Object.freeze([...origins]), methods: Object.freeze([...methods]), ...(technique ? { technique } : {}) }); }
      catch { throw new Error('Managed proxy scope could not be updated safely'); }
    }
  } catch {
    try { await context?.close(); } catch { /* fail closed */ }
    try { await browser?.close(); } catch { /* fail closed */ }
    try { options.onProxyCredentialsClosed?.(); } catch { /* credentials remain blocked when context setup fails */ }
    throw new Error('Managed browser context could not be created safely');
  }
}

function createPageSurface(page: Page): PageAutomationSurface {
  const locator = page.locator(PAGE_ELEMENT_SELECTOR);
  return {
    url: () => page.url(),
    title: () => page.title(),
    navigate: async (url) => { await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30_000 }); },
    inspectElements: async () => locator.evaluateAll((elements) => elements.map((element, domIndex) => {
      const html = element as HTMLElement;
      const tag = html.tagName.toLowerCase();
      const input = html as HTMLInputElement;
      const style = window.getComputedStyle(html);
      const text = html.getAttribute('aria-label') ?? html.innerText ?? html.textContent ?? html.getAttribute('placeholder') ?? '';
      const anchor = html as HTMLAnchorElement;
      const role = html.getAttribute('role') ?? (tag === 'a' ? 'link' : tag === 'button' ? 'button' : tag === 'input' || tag === 'textarea' ? 'textbox' : '');
      return {
        domIndex, tag, type: tag === 'input' || tag === 'button' ? input.type ?? '' : '', name: input.name ?? '', role,
        text: text.slice(0, 2048), href: tag === 'a' ? anchor.href : '', target: tag === 'a' ? anchor.target : '',
        download: tag === 'a' && anchor.hasAttribute('download'), hasOnclick: html.hasAttribute('onclick'),
        disabled: 'disabled' in html && Boolean((html as HTMLInputElement).disabled),
        readOnly: 'readOnly' in html && Boolean((html as HTMLInputElement).readOnly),
        autoComplete: input.autocomplete ?? '', visible: html.getClientRects().length > 0 && style.visibility !== 'hidden' && style.display !== 'none'
      };
    })),
    inspectElement: async (domIndex) => {
      try {
        return await page.locator(PAGE_ELEMENT_SELECTOR).nth(domIndex).evaluate((element, index) => {
          const html = element as HTMLElement;
          const tag = html.tagName.toLowerCase();
          const input = html as HTMLInputElement;
          const style = window.getComputedStyle(html);
          const text = html.getAttribute('aria-label') ?? html.innerText ?? html.textContent ?? html.getAttribute('placeholder') ?? '';
          const anchor = html as HTMLAnchorElement;
          const role = html.getAttribute('role') ?? (tag === 'a' ? 'link' : tag === 'button' ? 'button' : tag === 'input' || tag === 'textarea' ? 'textbox' : '');
          return {
            domIndex: index, tag, type: tag === 'input' || tag === 'button' ? input.type ?? '' : '', name: input.name ?? '', role,
            text: text.slice(0, 2048), href: tag === 'a' ? anchor.href : '', target: tag === 'a' ? anchor.target : '',
            download: tag === 'a' && anchor.hasAttribute('download'), hasOnclick: html.hasAttribute('onclick'),
            disabled: 'disabled' in html && Boolean((html as HTMLInputElement).disabled),
            readOnly: 'readOnly' in html && Boolean((html as HTMLInputElement).readOnly),
            autoComplete: input.autocomplete ?? '', visible: html.getClientRects().length > 0 && style.visibility !== 'hidden' && style.display !== 'none'
          };
        }, domIndex);
      } catch { return undefined; }
    },
    fillElement: async (domIndex, value) => { await page.locator(PAGE_ELEMENT_SELECTOR).nth(domIndex).fill(value, { timeout: 5_000 }); }
  };
}

function isPageRequestAllowed(urlText: string, method: string, phase: 'blocked' | 'bootstrap' | 'target', loginOrigins: readonly string[], targetOrigins: readonly string[], activeTargetOrigins: readonly string[], activeTargetMethods: readonly string[]): boolean {
  if (phase === 'blocked') return false;
  let origin: string;
  try {
    const url = new URL(urlText);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
    origin = normalizeOrigin(url.origin);
  } catch { return false; }
  if (phase === 'target') return activeTargetOrigins.includes(origin) && activeTargetMethods.includes(method);
  if (loginOrigins.includes(origin)) return LOGIN_METHODS.has(method);
  return targetOrigins.includes(origin) && READ_ONLY_METHODS.has(method);
}

function isTargetOrigin(urlText: string, targetOrigins: readonly string[]): boolean {
  try {
    const url = new URL(urlText);
    return (url.protocol === 'http:' || url.protocol === 'https:') && targetOrigins.includes(normalizeOrigin(url.origin));
  } catch { return false; }
}

function normalizeOriginSet(origins: readonly string[]): string[] {
  if (!Array.isArray(origins)) throw new Error('Managed browser origins are invalid');
  return origins.map((origin) => {
    try {
      const normalized = normalizeOrigin(origin);
      if (normalized !== origin) throw new Error('non-canonical');
      return normalized;
    } catch { throw new Error('Managed browser origins are invalid'); }
  });
}

function validProxyCredential(value: ManagedContextOptions['proxyCredentials']): boolean {
  return Boolean(value) && /^[A-Za-z0-9._-]{1,128}$/.test(value.username) && typeof value.password === 'string' && value.password.length >= 32;
}

function assertEgress(check: () => boolean): void {
  if (isEgressVerified(check)) return;
  throw new Error('Managed browser launch requires verified egress protection');
}

function isEgressVerified(check: () => boolean): boolean {
  try { return check() === true; } catch { return false; }
}

function isAbsoluteProfilePath(value: string): boolean {
  return process.platform === 'win32' ? /^[A-Za-z]:\\/.test(value) && !/[?*<>|;]/.test(value) : value.startsWith('/');
}

const defaultEngine: ManagedBrowserEngine = {
  launch: (options) => chromium.launch(options as LaunchOptions) as Promise<unknown>,
  launchPersistentContext: (profilePath, options) => chromium.launchPersistentContext(profilePath, options as NonNullable<Parameters<typeof chromium.launchPersistentContext>[1]>) as Promise<unknown>
};
