import { request as playwrightRequest, type APIRequestContext } from 'playwright';
import { normalizeOrigin } from '../policy/origin.js';
import { BROKER_PROXY_HOST, BROKER_PROXY_PORT, BROKER_PROXY_URL } from '../network/egress-preflight.js';

export interface BrowserCookie {
  readonly name: string;
  readonly value: string;
  readonly domain: string;
  readonly path: string;
  readonly expires: number;
  readonly httpOnly: boolean;
  readonly secure: boolean;
  readonly sameSite: 'Strict' | 'Lax' | 'None';
  readonly partitionKey?: string;
}

export interface ApiCookieJar {
  cookies(urls?: string | string[]): Promise<BrowserCookie[]>;
  addCookies(cookies: BrowserCookie[]): Promise<void>;
  clearCookies(filter?: { name?: string; domain?: string; path?: string }): Promise<void>;
}

export interface AuthorizedApiRequest {
  readonly url: string;
  readonly method: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: string | Buffer;
}

export interface ApiRequestResult {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  readonly bodySuppressed: boolean;
}

export interface ApiRequestAdapterOptions {
  readonly context: ApiCookieJar;
  readonly proxy: { readonly server: string; readonly username: string; readonly password: string };
  readonly authorize: (request: { origin: string; method: string; path: string; technique: string; endpointAuthorizationId: string }) => boolean;
  readonly allowedOrigins: readonly string[];
  readonly allowedMethods: readonly string[];
  readonly allowedRequestHeaders: readonly string[];
  readonly technique: string;
  readonly endpointAuthorizationId: string;
  readonly maxRequestBodyBytes: number;
  readonly maxResponseBytes: number;
  readonly isEgressVerified: () => boolean;
  /** Injected only by tests. Production always uses Playwright's APIRequest factory. */
  readonly newContext?: (options: unknown) => Promise<ApiRequestContextLike>;
  /** Requires an injected loopback integration fixture; never configurable from a worker tool. */
  readonly testOnlyAllowEphemeralProxy?: boolean;
  readonly timeoutMs?: number;
  readonly maxRedirects?: number;
}

interface ApiRequestContextLike {
  fetch(url: string, options: unknown): Promise<{
    status(): number;
    headersArray(): Promise<Array<{ name: string; value: string }>>;
    body(): Promise<Buffer>;
  }>;
  storageState(): Promise<{ cookies: BrowserCookie[] }>;
  dispose(): Promise<void>;
}

interface ParsedTarget {
  readonly url: URL;
  readonly origin: string;
  readonly path: string;
}

export function createApiRequestAdapter(options: ApiRequestAdapterOptions): { request(input: unknown): Promise<ApiRequestResult> } {
  const allowedOrigins = new Set(options.allowedOrigins.map((origin) => {
    try {
      const normalized = normalizeOrigin(origin);
      if (normalized !== origin) throw new Error('non-canonical');
      return normalized;
    } catch { throw new Error('API request origin policy is invalid'); }
  }));
  const allowedMethods = new Set(options.allowedMethods);
  const allowedRequestHeaders = new Set(options.allowedRequestHeaders.map((header) => header.toLowerCase()));
  const proxyPort = parseLoopbackProxyPort(options.proxy.server, options.testOnlyAllowEphemeralProxy === true && options.newContext !== undefined);
  if (!allowedOrigins.size || !allowedMethods.size || !options.technique || !options.endpointAuthorizationId ||
      !Number.isInteger(options.maxRequestBodyBytes) || options.maxRequestBodyBytes < 0 || options.maxRequestBodyBytes > 65_536 ||
      !Number.isInteger(options.maxResponseBytes) || options.maxResponseBytes < 1 || options.maxResponseBytes > 2_097_152 ||
      !Number.isInteger(options.timeoutMs ?? 15_000) || (options.timeoutMs ?? 15_000) < 1 || (options.timeoutMs ?? 15_000) > 120_000 ||
      !Number.isInteger(options.maxRedirects ?? 5) || (options.maxRedirects ?? 5) < 0 || (options.maxRedirects ?? 5) > 5 ||
      typeof options.proxy.username !== 'string' || !options.proxy.username || typeof options.proxy.password !== 'string' || options.proxy.password.length < 32) {
    throw new Error('API request adapter configuration is invalid');
  }
  for (const method of allowedMethods) if (!/^[A-Z]{1,16}$/.test(method)) throw new Error('API request method policy is invalid');
  for (const header of allowedRequestHeaders) {
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(header) || isCredentialOrRoutingHeader(header)) throw new Error('API request header policy is invalid');
  }

  const createContext = options.newContext ?? ((contextOptions: unknown) => playwrightRequest.newContext(contextOptions as Parameters<typeof playwrightRequest.newContext>[0]) as Promise<unknown> as Promise<ApiRequestContextLike>);
  const timeoutMs = options.timeoutMs ?? 15_000;
  const maxRedirects = options.maxRedirects ?? 5;

  return {
    async request(input: unknown): Promise<ApiRequestResult> {
      const request = parseRequest(input, allowedRequestHeaders, options.maxRequestBodyBytes);
      if (!allowedMethods.has(request.method)) throw new Error('API request method is not authorized');
      assertEgress(options.isEgressVerified);

      let target = parseTarget(request.url);
      if (!allowedOrigins.has(target.origin)) throw new Error('API request origin is outside the session policy');
      let currentMethod = request.method;
      let currentBody = request.body;
      let finalStatus = 0;
      let finalHeaders: Readonly<Record<string, string>> = Object.freeze({});
      let finalBody = '';
      let bodySuppressed = false;

      for (let hop = 0; hop <= maxRedirects; hop += 1) {
        assertEgress(options.isEgressVerified);
        if (!allowedOrigins.has(target.origin) || !allowedMethods.has(currentMethod) ||
            !safeAuthorize(options.authorize, { origin: target.origin, method: currentMethod, path: target.path, technique: options.technique, endpointAuthorizationId: options.endpointAuthorizationId })) {
          if (hop > 0) break;
          throw new Error('API request is outside its endpoint authorization');
        }

        const jarCookies = await options.context.cookies(target.url.toString());
        const safeCookies = validateCookies(jarCookies);
        let apiContext: ApiRequestContextLike | undefined;
        try {
          apiContext = await createContext({
            proxy: { server: `http://${BROKER_PROXY_HOST}:${proxyPort}`, username: options.proxy.username, password: options.proxy.password },
            storageState: { cookies: safeCookies, origins: [] },
            maxRedirects: 0,
            timeout: timeoutMs,
            ignoreHTTPSErrors: false
          });
          const response = await apiContext.fetch(target.url.toString(), {
            method: currentMethod,
            ...(currentBody !== undefined ? { data: currentBody } : {}),
            ...(request.headers ? { headers: request.headers } : {}),
            timeout: timeoutMs,
            maxRedirects: 0,
            maxRetries: 0,
            failOnStatusCode: false,
            ignoreHTTPSErrors: false
          });
          finalStatus = response.status();
          const responseHeaders = await response.headersArray();
          const cookieState = await apiContext.storageState();
          await syncCookies(options.context, safeCookies, validateCookies(cookieState.cookies));

          const location = headerValue(responseHeaders, 'location');
          finalHeaders = safeResponseHeaders(responseHeaders);
          if ([301, 302, 303, 307, 308].includes(finalStatus) && location && (currentMethod === 'GET' || currentMethod === 'HEAD') && hop < maxRedirects) {
            let next: ParsedTarget;
            try { next = parseTarget(new URL(location, target.url).toString()); } catch { break; }
            if (!allowedOrigins.has(next.origin) || !allowedMethods.has(currentMethod)) break;
            target = next;
            continue;
          }

          const contentLength = Number(headerValue(responseHeaders, 'content-length'));
          if (Number.isFinite(contentLength) && contentLength > options.maxResponseBytes) {
            bodySuppressed = true;
          } else {
            const body = await response.body();
            if (body.length > options.maxResponseBytes) bodySuppressed = true;
            else finalBody = body.toString('utf8');
          }
          break;
        } catch {
          throw new Error('API request outcome is unknown; no retry or automatic replay occurred');
        } finally {
          try { await apiContext?.dispose(); } catch { /* disposal errors do not expose request context */ }
        }
      }
      return Object.freeze({ status: finalStatus, headers: finalHeaders, body: bodySuppressed ? '' : finalBody, bodySuppressed });
    }
  };
}

function parseRequest(value: unknown, allowedHeaders: ReadonlySet<string>, maxBodyBytes: number): AuthorizedApiRequest & { readonly method: string; readonly body?: string | Buffer } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('API request is invalid');
  const candidate = value as Partial<AuthorizedApiRequest>;
  if (typeof candidate.url !== 'string' || candidate.url.length > 8192 || typeof candidate.method !== 'string' ||
      candidate.method !== candidate.method.toUpperCase() || !/^[A-Z]{1,16}$/.test(candidate.method)) throw new Error('API request is invalid');
  let body: string | Buffer | undefined;
  if (candidate.body !== undefined) {
    if (typeof candidate.body !== 'string' && !Buffer.isBuffer(candidate.body)) throw new Error('API request body is invalid');
    body = candidate.body;
    if (Buffer.byteLength(body) > maxBodyBytes) throw new Error('API request body exceeds the policy limit');
    if (candidate.method === 'GET' || candidate.method === 'HEAD') throw new Error('GET and HEAD requests cannot include a body');
  }
  let headers: Record<string, string> | undefined;
  if (candidate.headers !== undefined) {
    if (!candidate.headers || typeof candidate.headers !== 'object' || Array.isArray(candidate.headers)) throw new Error('API request headers are invalid');
    headers = {};
    for (const [name, value] of Object.entries(candidate.headers)) {
      const lower = name.toLowerCase();
      if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || typeof value !== 'string' || /[\r\n\u0000]/.test(value)) throw new Error('API request headers are invalid');
      if (isCredentialOrRoutingHeader(lower)) throw new Error('Caller-supplied credential or routing header is forbidden');
      if (!allowedHeaders.has(lower)) throw new Error('API request header is not authorized by the endpoint policy');
      headers[name] = value;
    }
  }
  return { url: candidate.url, method: candidate.method, ...(headers ? { headers } : {}), ...(body !== undefined ? { body } : {}) };
}

function parseTarget(value: string): ParsedTarget {
  let url: URL;
  let origin: string;
  try {
    url = new URL(value);
    if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.username || url.password || url.hash) throw new Error('invalid');
    origin = normalizeOrigin(url.origin);
    if (origin !== url.origin) throw new Error('non-canonical');
  } catch {
    throw new Error('API request URL is invalid');
  }
  return { url, origin, path: url.pathname || '/' };
}

function validateCookies(value: readonly BrowserCookie[]): BrowserCookie[] {
  if (!Array.isArray(value)) throw new Error('Cookie state is unavailable');
  const result: BrowserCookie[] = [];
  for (const cookie of value) {
    if (!cookie || typeof cookie.name !== 'string' || !cookie.name || typeof cookie.value !== 'string' ||
        typeof cookie.domain !== 'string' || !cookie.domain || typeof cookie.path !== 'string' || !cookie.path.startsWith('/') ||
        typeof cookie.expires !== 'number' || !Number.isFinite(cookie.expires) || typeof cookie.httpOnly !== 'boolean' ||
        typeof cookie.secure !== 'boolean' || !['Strict', 'Lax', 'None'].includes(cookie.sameSite) || cookie.partitionKey !== undefined) {
      throw new Error('Cookie state cannot be safely synchronized');
    }
    result.push(Object.freeze({ name: cookie.name, value: cookie.value, domain: cookie.domain, path: cookie.path, expires: cookie.expires,
      httpOnly: cookie.httpOnly, secure: cookie.secure, sameSite: cookie.sameSite }));
  }
  return result;
}

async function syncCookies(context: ApiCookieJar, previous: readonly BrowserCookie[], updated: readonly BrowserCookie[]): Promise<void> {
  for (const cookie of previous) await context.clearCookies({ name: cookie.name, domain: cookie.domain, path: cookie.path });
  if (updated.length) await context.addCookies([...updated]);
}

function safeResponseHeaders(headers: readonly { name: string; value: string }[]): Readonly<Record<string, string>> {
  const selected = new Set(['content-type', 'cache-control', 'etag']);
  const result: Record<string, string> = {};
  for (const { name, value } of headers) {
    const lower = name.toLowerCase();
    if (selected.has(lower) && !isCredentialOrRoutingHeader(lower) && !/[\r\n\u0000]/.test(value) && result[lower] === undefined) result[lower] = value;
  }
  return Object.freeze(result);
}

function headerValue(headers: readonly { name: string; value: string }[], name: string): string | undefined {
  return headers.find((header) => header.name.toLowerCase() === name)?.value;
}

function isCredentialOrRoutingHeader(name: string): boolean {
  return name === 'cookie' || name === 'cookie2' || name === 'authorization' || name === 'proxy-authorization' ||
    name === 'proxy-authenticate' || name === 'host' || name === 'forwarded' || name === 'connection' ||
    name === 'content-length' || name === 'transfer-encoding' || name === 'upgrade' || name === 'proxy-connection' ||
    name.startsWith('proxy-') || name.startsWith('x-forwarded-');
}

function safeAuthorize(authorize: ApiRequestAdapterOptions['authorize'], input: Parameters<ApiRequestAdapterOptions['authorize']>[0]): boolean {
  try { return authorize(input) === true; } catch { return false; }
}

function assertEgress(check: ApiRequestAdapterOptions['isEgressVerified']): void {
  try { if (check() === true) return; } catch { /* fail closed */ }
  throw new Error('API request requires verified egress protection');
}

function parseLoopbackProxyPort(server: string, allowEphemeral: boolean): number {
  let url: URL;
  try { url = new URL(server); } catch { throw new Error('API request proxy must be the broker loopback proxy'); }
  const port = Number(url.port);
  if (url.protocol !== 'http:' || url.hostname !== BROKER_PROXY_HOST || url.username || url.password || url.pathname !== '/' ||
      url.search || url.hash || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('API request proxy must be the broker loopback proxy');
  if (port === BROKER_PROXY_PORT) return port;
  if (!allowEphemeral) throw new Error('API request proxy must use the fixed broker loopback port');
  // Dynamic ports are accepted only when a test injected the request-context factory.
  return port;
}
