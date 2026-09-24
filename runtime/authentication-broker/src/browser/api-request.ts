import { ProxyAgent, fetch as undiciFetch, type Dispatcher } from 'undici';
import { normalizeOrigin } from '../policy/origin.js';
import { BROKER_PROXY_HOST, BROKER_PROXY_PORT } from '../network/egress-preflight.js';

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

export interface AuthorizedApiScope {
  readonly allowedOrigins: readonly string[];
  readonly allowedMethods: readonly string[];
  readonly technique: string;
  readonly endpointAuthorizationId: string;
  readonly authorizeEndpoint: (request: { origin: string; method: string; path: string; technique: string; endpointAuthorizationId: string }) => boolean;
  readonly reserveRequest?: () => Promise<(() => void) | undefined>;
  readonly onResponseStatus?: (status: number) => void;
}

export interface ApiRequestResult {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  readonly bodySuppressed: boolean;
}

interface FetchResponseLike {
  readonly status: number;
  readonly headers: {
    get(name: string): string | null;
    getSetCookie?: () => string[];
  };
  readonly body: ReadableStream<Uint8Array> | null;
}

interface FetchInitLike {
  readonly method: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: string | Buffer;
  readonly redirect: 'manual';
  readonly signal: AbortSignal;
  readonly dispatcher?: Dispatcher;
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
  /** Replaced only by loopback tests. Never accepted from a worker request. */
  readonly testOnlyFetch?: (url: string, init: FetchInitLike) => Promise<FetchResponseLike>;
  /** Dynamic proxy ports are allowed only with the test-only fetch seam. */
  readonly testOnlyAllowEphemeralProxy?: boolean;
  readonly timeoutMs?: number;
  readonly maxRedirects?: number;
}

interface ParsedTarget {
  readonly url: URL;
  readonly origin: string;
  readonly path: string;
}

export function createApiRequestAdapter(options: ApiRequestAdapterOptions): { request(input: unknown, scope?: AuthorizedApiScope): Promise<ApiRequestResult> } {
  const allowedOrigins = new Set(options.allowedOrigins.map((origin) => {
    try {
      const normalized = normalizeOrigin(origin);
      if (normalized !== origin) throw new Error('non-canonical');
      return normalized;
    } catch { throw new Error('API request origin policy is invalid'); }
  }));
  const allowedMethods = new Set(options.allowedMethods);
  const allowedRequestHeaders = new Set(options.allowedRequestHeaders.map((header) => header.toLowerCase()));
  const proxyPort = parseLoopbackProxyPort(options.proxy.server, options.testOnlyAllowEphemeralProxy === true);
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

  const timeoutMs = options.timeoutMs ?? 15_000;
  const maxRedirects = options.maxRedirects ?? 5;

  return {
    async request(input: unknown, scope?: AuthorizedApiScope): Promise<ApiRequestResult> {
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
        const cookie = cookieHeader(safeCookies);
        const headers: Record<string, string> = { 'accept-encoding': 'identity', ...request.headers };
        if (cookie) headers.cookie = cookie;
        const fetchInit: FetchInitLike = Object.freeze({
          method: currentMethod,
          headers: Object.freeze(headers),
          ...(currentBody !== undefined ? { body: currentBody } : {}),
          redirect: 'manual',
          signal: AbortSignal.timeout(timeoutMs)
        });

        let proxyAgent: ProxyAgent | undefined;
        let releaseRequest: (() => void) | undefined;
        try {
          assertEgress(options.isEgressVerified);
          if (scope?.reserveRequest) {
            releaseRequest = await scope.reserveRequest();
            if (!releaseRequest) throw new Error('API network request budget is exhausted or unavailable');
          } else if (!options.testOnlyFetch) {
            throw new Error('API network request budget is unavailable');
          }
          let response: FetchResponseLike;
          if (options.testOnlyFetch) {
            response = await options.testOnlyFetch(target.url.toString(), fetchInit);
          } else {
            proxyAgent = new ProxyAgent({
              uri: `http://${BROKER_PROXY_HOST}:${proxyPort}`,
              token: `Basic ${Buffer.from(`${options.proxy.username}:${options.proxy.password}`, 'utf8').toString('base64')}`
            });
            response = await undiciFetch(target.url.toString(), {
              ...fetchInit,
              dispatcher: proxyAgent
            } as Parameters<typeof undiciFetch>[1]) as unknown as FetchResponseLike;
          }
          finalStatus = response.status;
          try { scope?.onResponseStatus?.(finalStatus); } catch { throw new Error('API response status could not be handled safely'); }
          const responseCookies = responseCookiesFor(response.headers, target.url);
          if (responseCookies.length) await syncCookies(options.context, safeCookies, mergeCookies(safeCookies, responseCookies));
          const location = response.headers.get('location') ?? undefined;
          finalHeaders = safeResponseHeaders(response.headers);
          if ([301, 302, 303, 307, 308].includes(finalStatus) && location && (currentMethod === 'GET' || currentMethod === 'HEAD') && hop < maxRedirects) {
            let next: ParsedTarget;
            try { next = parseTarget(new URL(location, target.url).toString()); } catch { next = undefined as unknown as ParsedTarget; }
            if (next && allowedOrigins.has(next.origin) && allowedMethods.has(currentMethod) &&
                safeAuthorize(options.authorize, { origin: next.origin, method: currentMethod, path: next.path, technique: options.technique, endpointAuthorizationId: options.endpointAuthorizationId })) {
              try { await response.body?.cancel(); } catch { /* the redirect response body is not needed */ }
              target = next;
              continue;
            }
          }
          const bounded = await readCappedBody(response.body, options.maxResponseBytes);
          bodySuppressed = bounded.bodySuppressed;
          finalBody = bounded.body;
          break;
        } catch {
          throw new Error('API request outcome is unknown; no retry or automatic replay occurred');
        } finally {
          try { releaseRequest?.(); } catch { /* budget release cannot retry the request */ }
          try { await proxyAgent?.close(); } catch { /* connection cleanup cannot retry the request */ }
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
    if (!cookie || typeof cookie.name !== 'string' || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(cookie.name) ||
        typeof cookie.value !== 'string' || /[\r\n\u0000-\u001f\u007f;]/.test(cookie.value) ||
        typeof cookie.domain !== 'string' || !cookie.domain || /[\r\n\u0000-\u001f\u007f;]/.test(cookie.domain) ||
        typeof cookie.path !== 'string' || !cookie.path.startsWith('/') || /[\r\n\u0000-\u001f\u007f;]/.test(cookie.path) ||
        typeof cookie.expires !== 'number' || !Number.isFinite(cookie.expires) || typeof cookie.httpOnly !== 'boolean' ||
        typeof cookie.secure !== 'boolean' || !['Strict', 'Lax', 'None'].includes(cookie.sameSite) || cookie.partitionKey !== undefined) {
      throw new Error('Cookie state cannot be safely synchronized');
    }
    result.push(Object.freeze({ name: cookie.name, value: cookie.value, domain: cookie.domain, path: cookie.path, expires: cookie.expires,
      httpOnly: cookie.httpOnly, secure: cookie.secure, sameSite: cookie.sameSite }));
  }
  return result;
}

function cookieHeader(cookies: readonly BrowserCookie[]): string {
  return cookies.map(({ name, value }) => `${name}=${value}`).join('; ');
}

function responseCookiesFor(headers: FetchResponseLike['headers'], target: URL): BrowserCookie[] {
  const rawCookies = headers.getSetCookie?.() ?? [];
  return rawCookies.map((raw) => parseSetCookie(raw, target));
}

function parseSetCookie(raw: string, target: URL): BrowserCookie {
  if (typeof raw !== 'string' || raw.length > 8192 || /[\r\n\u0000]/.test(raw)) throw new Error('API response cookie cannot be synchronized');
  const parts = raw.split(';');
  const first = parts.shift() ?? '';
  const separator = first.indexOf('=');
  const name = first.slice(0, separator).trim();
  const value = first.slice(separator + 1).trim();
  if (separator <= 0 || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || /[\r\n\u0000-\u001f\u007f;]/.test(value)) {
    throw new Error('API response cookie cannot be synchronized');
  }
  let domain = target.hostname.toLowerCase();
  let domainAttribute = false;
  let cookiePath = defaultCookiePath(target.pathname);
  let expires = -1;
  let maxAge: number | undefined;
  let httpOnly = false;
  let secure = false;
  let sameSite: BrowserCookie['sameSite'] = 'Lax';
  for (const part of parts) {
    const index = part.indexOf('=');
    const key = (index < 0 ? part : part.slice(0, index)).trim().toLowerCase();
    const attribute = index < 0 ? '' : part.slice(index + 1).trim();
    if (key === 'domain') {
      const candidate = attribute.replace(/^\.+/, '').toLowerCase();
      if (!candidate || !(target.hostname.toLowerCase() === candidate || target.hostname.toLowerCase().endsWith(`.${candidate}`))) {
        throw new Error('API response cookie cannot be synchronized');
      }
      domain = `.${candidate}`;
      domainAttribute = true;
    } else if (key === 'path' && attribute.startsWith('/')) cookiePath = attribute;
    else if (key === 'expires') {
      const timestamp = Date.parse(attribute);
      if (Number.isFinite(timestamp)) expires = Math.floor(timestamp / 1000);
    } else if (key === 'max-age' && /^-?\d+$/.test(attribute)) maxAge = Number(attribute);
    else if (key === 'httponly') httpOnly = true;
    else if (key === 'secure') secure = true;
    else if (key === 'samesite') {
      const normalized = attribute.toLowerCase();
      if (normalized === 'strict') sameSite = 'Strict';
      else if (normalized === 'none') sameSite = 'None';
      else if (normalized === 'lax') sameSite = 'Lax';
    } else if (key === 'partitioned') throw new Error('Partitioned API cookies are not supported');
  }
  if (maxAge !== undefined) expires = maxAge <= 0 ? 0 : Math.floor(Date.now() / 1000) + maxAge;
  if ((sameSite === 'None' && !secure) || (name.startsWith('__Secure-') && !secure) ||
      (name.startsWith('__Host-') && (!secure || domainAttribute || cookiePath !== '/'))) {
    throw new Error('API response cookie cannot be synchronized');
  }
  return Object.freeze({ name, value, domain, path: cookiePath, expires, httpOnly, secure, sameSite });
}

function defaultCookiePath(pathname: string): string {
  if (!pathname.startsWith('/') || pathname === '/') return '/';
  const lastSlash = pathname.lastIndexOf('/');
  return lastSlash <= 0 ? '/' : pathname.slice(0, lastSlash);
}

function mergeCookies(previous: readonly BrowserCookie[], received: readonly BrowserCookie[]): BrowserCookie[] {
  const result = [...previous];
  for (const cookie of received) {
    for (let index = result.length - 1; index >= 0; index -= 1) {
      const current = result[index]!;
      if (current.name === cookie.name && current.domain === cookie.domain && current.path === cookie.path) result.splice(index, 1);
    }
    if (cookie.expires < 0 || cookie.expires > Math.floor(Date.now() / 1000)) result.push(cookie);
  }
  return result;
}

async function syncCookies(context: ApiCookieJar, previous: readonly BrowserCookie[], updated: readonly BrowserCookie[]): Promise<void> {
  for (const cookie of previous) await context.clearCookies({ name: cookie.name, domain: cookie.domain, path: cookie.path });
  if (updated.length) await context.addCookies([...updated]);
}

async function readCappedBody(body: ReadableStream<Uint8Array> | null, maximumBytes: number): Promise<{ body: string; bodySuppressed: boolean }> {
  if (!body) return { body: '', bodySuppressed: false };
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      if (next.value.byteLength > maximumBytes - bytes) {
        try { await reader.cancel(); } catch { /* response body is discarded */ }
        return { body: '', bodySuppressed: true };
      }
      bytes += next.value.byteLength;
      chunks.push(next.value);
    }
  } catch {
    throw new Error('API response body could not be read safely');
  } finally {
    try { reader.releaseLock(); } catch { /* stream may already be cancelled */ }
  }
  return { body: Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), bytes).toString('utf8'), bodySuppressed: false };
}

function safeResponseHeaders(headers: FetchResponseLike['headers']): Readonly<Record<string, string>> {
  const result: Record<string, string> = {};
  for (const name of ['content-type', 'cache-control', 'etag']) {
    const value = headers.get(name);
    if (typeof value === 'string' && !/[\r\n\u0000]/.test(value)) result[name] = value;
  }
  return Object.freeze(result);
}

function isCredentialOrRoutingHeader(name: string): boolean {
  return name === 'cookie' || name === 'cookie2' || name === 'authorization' || name === 'proxy-authorization' ||
    name === 'proxy-authenticate' || name === 'host' || name === 'forwarded' || name === 'connection' ||
    name === 'content-length' || name === 'transfer-encoding' || name === 'upgrade' || name === 'proxy-connection' ||
    name === 'accept-encoding' || name.startsWith('proxy-') || name.startsWith('x-forwarded-');
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
  return port;
}
