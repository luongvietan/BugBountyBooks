import { createServer, type Server, type Socket } from 'node:net';
import { normalizeOrigin } from '../policy/origin.js';
import { connectToPinnedAddress } from './dns-pin.js';
import { resolveAndPinDestination, type AddressResolver, type PinnedDestination } from './destination-policy.js';
import { BROKER_PROXY_HOST, BROKER_PROXY_PORT } from './egress-preflight.js';

export interface ProxyCapabilityContext {
  readonly capabilityId?: string;
  readonly engagementId: string;
  readonly accountAlias: string;
  readonly policyRevision: string;
  readonly technique: string;
  readonly allowedOrigins: readonly string[];
  readonly allowedMethods: readonly string[];
  readonly expiresAtUtc: string;
  readonly maxRequestBodyBytes: number;
}

export interface ProxyAuthorizationLease {
  readonly allowed: boolean;
  /** Rechecked after DNS resolution and for each outbound CONNECT tunnel chunk. */
  isCurrent?: () => boolean;
  release?: () => void;
}

export interface OriginProxyOptions {
  /** Port 0 is reserved for local tests; runtime setup uses the fixed port. */
  port?: number;
  resolver?: AddressResolver;
  resolveCapability: (proxyAuthorization: string | undefined) => ProxyCapabilityContext | undefined;
  authorize: (context: ProxyCapabilityContext, request: { origin: string; method: string; targetPath: string; technique: string }) => boolean | ProxyAuthorizationLease;
  /** Test-only seam. Production startup never sets this; workers cannot configure it. */
  destinationConnectorForTests?: (destination: PinnedDestination) => Socket;
  maxHeaderBytes?: number;
  connectionTimeoutMs?: number;
}

interface ParsedHeader {
  readonly method: string;
  readonly target: string;
  readonly version: string;
  readonly headers: readonly (readonly [string, string])[];
  readonly initialBytes: Buffer;
}

interface ParsedHttpRequest extends ParsedHeader {
  readonly kind: 'http';
  readonly origin: string;
  readonly host: string;
  readonly requestTarget: string;
  readonly contentLength: number;
}

interface ParsedConnectRequest extends ParsedHeader {
  readonly kind: 'connect';
  readonly originCandidates: readonly string[];
  readonly hostname: string;
  readonly port: number;
  readonly contentLength: 0;
}

type ParsedProxyRequest = ParsedHttpRequest | ParsedConnectRequest;

interface ActiveSocketState {
  stage: 'headers' | 'processing' | 'relaying' | 'closed';
  buffer: Buffer;
  upstream?: Socket;
  lease?: ProxyAuthorizationLease;
  bodyBytes: number;
  contentLength: number;
  tunneling: boolean;
  leaseReleased: boolean;
  cleaned: boolean;
}

export function createOriginProxy(options: OriginProxyOptions): {
  start: () => Promise<{ address: string; port: number }>;
  close: () => Promise<void>;
} {
  const port = options.port ?? BROKER_PROXY_PORT;
  const maxHeaderBytes = options.maxHeaderBytes ?? 16_384;
  const timeoutMs = options.connectionTimeoutMs ?? 15_000;
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Proxy port is invalid');
  if (!Number.isInteger(maxHeaderBytes) || maxHeaderBytes < 1024 || maxHeaderBytes > 65_536) throw new Error('Proxy header limit is invalid');
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120_000) throw new Error('Proxy timeout is invalid');

  const sockets = new Set<Socket>();
  let server: Server | undefined;
  let closing = false;

  function start(): Promise<{ address: string; port: number }> {
    if (server) return Promise.reject(new Error('Proxy is already started'));
    closing = false;
    server = createServer({ allowHalfOpen: true }, (client) => handleClient(client));
    server.maxConnections = 64;
    return new Promise((resolve, reject) => {
      const current = server!;
      current.once('error', reject);
      current.listen(port, BROKER_PROXY_HOST, () => {
        current.removeListener('error', reject);
        const address = current.address();
        if (!address || typeof address === 'string' || address.address !== BROKER_PROXY_HOST) {
          current.close();
          reject(new Error('Proxy did not bind to IPv4 loopback'));
          return;
        }
        resolve({ address: address.address, port: address.port });
      });
    });
  }

  function close(): Promise<void> {
    if (!server || closing) return Promise.resolve();
    closing = true;
    const current = server;
    server = undefined;
    for (const socket of sockets) socket.destroy();
    return new Promise((resolve, reject) => current.close((error) => error ? reject(error) : resolve()));
  }

  function handleClient(client: Socket): void {
    sockets.add(client);
    client.setNoDelay(true);
    client.setTimeout(timeoutMs);
    const state: ActiveSocketState = { stage: 'headers', buffer: Buffer.alloc(0), bodyBytes: 0, contentLength: 0, tunneling: false, leaseReleased: false, cleaned: false };
    const releaseLease = (): void => {
      if (state.leaseReleased) return;
      state.leaseReleased = true;
      try { state.lease?.release?.(); } catch { /* lease failure never restores access */ }
    };
    const cleanup = (): void => {
      if (state.cleaned) return;
      state.cleaned = true;
      state.stage = 'closed';
      sockets.delete(client);
      if (state.upstream) {
        sockets.delete(state.upstream);
        if (!state.upstream.destroyed) state.upstream.destroy();
      }
      releaseLease();
    };
    client.once('close', cleanup);
    client.once('error', cleanup);
    client.once('timeout', () => {
      if (state.stage === 'headers' || state.stage === 'processing') writeAndClose(client, 408, 'Request Timeout');
      else client.destroy();
    });
    client.on('data', (chunk: Buffer) => {
      if (state.stage === 'headers') {
        state.buffer = Buffer.concat([state.buffer, chunk]);
        const headerEnd = state.buffer.indexOf('\r\n\r\n');
        if (headerEnd < 0) {
          if (state.buffer.length > maxHeaderBytes) writeAndClose(client, 431, 'Request Header Fields Too Large');
          return;
        }
        if (headerEnd + 4 > maxHeaderBytes) {
          writeAndClose(client, 431, 'Request Header Fields Too Large');
          return;
        }
        const headerBytes = state.buffer.subarray(0, headerEnd + 4);
        const initialBytes = state.buffer.subarray(headerEnd + 4);
        state.buffer = Buffer.alloc(0);
        state.stage = 'processing';
        client.pause();
      void processHeader(client, state, headerBytes, initialBytes).catch(() => {
        state.upstream?.destroy();
        writeAndClose(client, 403, 'Forbidden');
      });
        return;
      }
      if (state.stage === 'relaying' && state.upstream && !state.tunneling) {
        state.bodyBytes += chunk.length;
        if (state.bodyBytes > state.contentLength) {
          client.destroy();
          state.upstream.destroy();
          return;
        }
        state.upstream.write(chunk);
        if (state.bodyBytes === state.contentLength) state.upstream.end();
      }
    });

    client.on('end', () => {
      if (state.stage === 'relaying' && state.upstream && state.bodyBytes !== state.contentLength) {
        client.destroy();
        state.upstream.destroy();
      }
    });

    async function processHeader(clientSocket: Socket, active: ActiveSocketState, headerBytes: Buffer, initialBytes: Buffer): Promise<void> {
      const parsed = parseRequestHeader(headerBytes, initialBytes);
      if (!parsed) {
        writeAndClose(clientSocket, 400, 'Bad Request');
        return;
      }
      if (parsed.headers.some(([name, value]) => name === 'upgrade' || (name === 'connection' && value.toLowerCase().split(',').some((part) => part.trim() === 'upgrade')))) {
        writeAndClose(clientSocket, 403, 'Forbidden');
        return;
      }
      const authorizationValues = parsed.headers.filter(([name]) => name === 'proxy-authorization').map(([, value]) => value);
      if (authorizationValues.length !== 1) {
        writeAndClose(clientSocket, 407, 'Proxy Authentication Required');
        return;
      }
      let capability: ProxyCapabilityContext | undefined;
      try { capability = options.resolveCapability(authorizationValues[0]); } catch { capability = undefined; }
      if (!validCapabilityContext(capability)) {
        writeAndClose(clientSocket, 407, 'Proxy Authentication Required');
        return;
      }
      const method = parsed.kind === 'connect' ? 'CONNECT' : parsed.method;
      const requestOrigin = parsed.kind === 'connect' ? matchConnectOrigin(parsed, capability.allowedOrigins) : parsed.origin;
      const targetOriginAllowed = requestOrigin !== undefined && capability.allowedOrigins.includes(requestOrigin);
      const methodAllowed = parsed.kind === 'connect'
        ? capability.allowedMethods.some((item) => ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(item))
        : capability.allowedMethods.includes(parsed.method);
      if (!targetOriginAllowed || !methodAllowed || Date.parse(capability.expiresAtUtc) <= Date.now()) {
        writeAndClose(clientSocket, 403, 'Forbidden');
        return;
      }
      if (parsed.kind === 'http' && (parsed.contentLength > capability.maxRequestBodyBytes || initialBytes.length > capability.maxRequestBodyBytes)) {
        writeAndClose(clientSocket, 413, 'Payload Too Large');
        return;
      }
      let lease: ProxyAuthorizationLease;
      try {
        const authorization = options.authorize(capability, {
          origin: requestOrigin!,
          method,
          targetPath: parsed.kind === 'http' ? parsed.requestTarget : '/',
          technique: capability.technique
        });
        lease = typeof authorization === 'boolean' ? { allowed: authorization } : authorization;
      } catch {
        lease = { allowed: false };
      }
      if (!lease || lease.allowed !== true) {
        try { lease?.release?.(); } catch { /* no sensitive output */ }
        writeAndClose(clientSocket, 403, 'Forbidden');
        return;
      }
      active.lease = lease;

      let destination: PinnedDestination;
      try { destination = await resolveAndPinDestination(requestOrigin!, options.resolver); } catch {
        writeAndClose(clientSocket, 403, 'Forbidden');
        return;
      }
      if (!leaseIsCurrent(active.lease)) {
        writeAndClose(clientSocket, 403, 'Forbidden');
        return;
      }
      if (clientSocket.destroyed || clientSocket.writableEnded || active.stage === 'closed') return;
      let upstream: Socket;
      try {
        upstream = options.destinationConnectorForTests
          ? options.destinationConnectorForTests(destination)
          : connectToPinnedAddress(destination);
      } catch {
        writeAndClose(clientSocket, 502, 'Bad Gateway');
        return;
      }
      active.upstream = upstream;
      sockets.add(upstream);
      upstream.setNoDelay(true);
      upstream.setTimeout(timeoutMs);
      upstream.once('error', () => {
        if (active.stage !== 'closed') writeAndClose(clientSocket, 502, 'Bad Gateway');
      });
      upstream.once('close', () => {
        sockets.delete(upstream);
        if (active.stage !== 'closed' && !clientSocket.destroyed) clientSocket.end();
      });
      upstream.once('timeout', () => upstream.destroy());
      upstream.once('connect', () => {
        if (clientSocket.destroyed || active.stage === 'closed') { upstream.destroy(); return; }
        if (!leaseIsCurrent(active.lease)) {
          upstream.destroy();
          writeAndClose(clientSocket, 403, 'Forbidden');
          return;
        }
        active.stage = 'relaying';
        if (parsed.kind === 'connect') {
          active.tunneling = true;
          clientSocket.write('HTTP/1.1 200 Connection Established\r\nProxy-Agent: BugHuntSkills-AuthenticationBroker\r\n\r\n');
          if (initialBytes.length) upstream.write(initialBytes);
          clientSocket.on('data', (chunk: Buffer) => {
            if (!leaseIsCurrent(active.lease)) { clientSocket.destroy(); upstream.destroy(); return; }
            if (!upstream.write(chunk)) clientSocket.pause();
          });
          upstream.on('drain', () => clientSocket.resume());
          upstream.on('data', (chunk: Buffer) => {
            if (!leaseIsCurrent(active.lease)) { clientSocket.destroy(); upstream.destroy(); return; }
            if (!clientSocket.write(chunk)) upstream.pause();
          });
          clientSocket.on('drain', () => upstream.resume());
          clientSocket.once('end', () => upstream.end());
          upstream.once('end', () => clientSocket.end());
          clientSocket.resume();
          return;
        }
        if (initialBytes.length > parsed.contentLength || initialBytes.length > capability!.maxRequestBodyBytes) {
          writeAndClose(clientSocket, 413, 'Payload Too Large');
          upstream.destroy();
          return;
        }
        active.contentLength = parsed.contentLength;
        active.bodyBytes = initialBytes.length;
        const requestHead = serializeUpstreamRequest(parsed);
        upstream.write(requestHead);
        if (initialBytes.length) upstream.write(initialBytes);
        if (active.bodyBytes === active.contentLength) upstream.end();
        upstream.pipe(clientSocket);
        clientSocket.resume();
      });
    }
  }

  return { start, close };
}

function leaseIsCurrent(lease: ProxyAuthorizationLease | undefined): boolean {
  if (!lease || lease.allowed !== true) return false;
  if (typeof lease.isCurrent !== 'function') return true;
  try { return lease.isCurrent() === true; } catch { return false; }
}

function parseRequestHeader(headerBytes: Buffer, initialBytes: Buffer): ParsedProxyRequest | undefined {
  const text = headerBytes.toString('latin1');
  const lines = text.slice(0, -4).split('\r\n');
  const requestLine = lines.shift();
  if (!requestLine) return undefined;
  const requestParts = requestLine.split(' ');
  if (requestParts.length !== 3 || !/^[A-Z]{1,16}$/.test(requestParts[0]!) || !/^HTTP\/1\.[01]$/.test(requestParts[2]!)) return undefined;
  const method = requestParts[0]!;
  const target = requestParts[1]!;
  const version = requestParts[2]!;
  const headers: Array<readonly [string, string]> = [];
  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon <= 0 || /^[ \t]/.test(line) || /[\r\n\u0000]/.test(line)) return undefined;
    const name = line.slice(0, colon);
    const value = line.slice(colon + 1).trim();
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)) return undefined;
    headers.push([name.toLowerCase(), value]);
  }
  const hostHeaders = headers.filter(([name]) => name === 'host');
  const authHeaders = headers.filter(([name]) => name === 'proxy-authorization');
  const lengthHeaders = headers.filter(([name]) => name === 'content-length');
  if (hostHeaders.length !== 1 || authHeaders.length > 1 || lengthHeaders.length > 1 || headers.some(([name]) => name === 'transfer-encoding')) return undefined;
  if (!connectionHeaderNames(headers)) return undefined;
  const host = hostHeaders[0]![1];

  if (method === 'CONNECT') {
    const authority = /^([^:/@\[\]]+):(\d{1,5})$/.exec(target);
    if (initialBytes.length !== 0 || !authority) return undefined;
    const explicitPort = Number(authority[2]);
    if (!Number.isInteger(explicitPort) || explicitPort < 1 || explicitPort > 65535) return undefined;
    let url: URL;
    let httpOrigin: string;
    let httpsOrigin: string;
    try {
      url = new URL(`https://${target}`);
      if (url.username || url.password || url.pathname !== '/' || url.hostname.toLowerCase() !== authority[1]!.toLowerCase()) return undefined;
      const hostname = url.hostname.toLowerCase();
      const port = explicitPort;
      httpOrigin = normalizeOrigin(`http://${hostname}:${port}`);
      httpsOrigin = normalizeOrigin(`https://${hostname}:${port}`);
      if (normalizeOrigin(`https://${host}`) !== httpsOrigin) return undefined;
    } catch { return undefined; }
    return { kind: 'connect', method, target, version, headers, initialBytes, originCandidates: Object.freeze([httpOrigin, httpsOrigin]), hostname: url.hostname.toLowerCase(), port: explicitPort, contentLength: 0 };
  }

  let url: URL;
  let origin: string;
  try {
    url = new URL(target);
    if (url.protocol !== 'http:' || url.username || url.password || url.hash) return undefined;
    origin = normalizeOrigin(url.origin);
    if (normalizeOrigin(`http://${host}`) !== origin) return undefined;
  } catch { return undefined; }
  const rawLength = lengthHeaders[0]?.[1];
  const contentLength = rawLength === undefined ? 0 : Number(rawLength);
  if (!Number.isSafeInteger(contentLength) || contentLength < 0) return undefined;
  if ((method === 'GET' || method === 'HEAD') && contentLength !== 0) return undefined;
  if (initialBytes.length > contentLength) return undefined;
  const requestTarget = `${url.pathname || '/'}${url.search}`;
  return { kind: 'http', method, target, version, headers, initialBytes, origin, host: url.host, requestTarget, contentLength };
}

function matchConnectOrigin(request: ParsedConnectRequest, allowedOrigins: readonly string[]): string | undefined {
  const matches = request.originCandidates.filter((origin) => allowedOrigins.includes(origin));
  return matches.length === 1 ? matches[0] : undefined;
}

function serializeUpstreamRequest(request: ParsedHttpRequest): string {
  const connectionNames = connectionHeaderNames(request.headers) ?? new Set<string>();
  const hopByHop = new Set(['connection', 'proxy-connection', 'proxy-authorization', 'proxy-authenticate', 'keep-alive', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', ...connectionNames]);
  const forwarded = request.headers.filter(([name]) => !hopByHop.has(name));
  const lines = [`${request.method} ${request.requestTarget} ${request.version}`, `Host: ${request.host}`];
  for (const [name, value] of forwarded) lines.push(`${name}: ${value}`);
  lines.push('Connection: close', '', '');
  return lines.join('\r\n');
}

function connectionHeaderNames(headers: readonly (readonly [string, string])[]): Set<string> | undefined {
  const critical = new Set(['host', 'content-length', 'transfer-encoding', 'connection', 'proxy-authorization']);
  const names = new Set<string>();
  for (const [headerName, value] of headers) {
    if (headerName !== 'connection') continue;
    const parts = value.split(',');
    if (!parts.length) return undefined;
    for (const part of parts) {
      const name = part.trim().toLowerCase();
      if (!name || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name) || critical.has(name)) return undefined;
      names.add(name);
    }
  }
  return names;
}

function validCapabilityContext(value: ProxyCapabilityContext | undefined): value is ProxyCapabilityContext {
  if (!value || typeof value.engagementId !== 'string' || !value.engagementId || typeof value.accountAlias !== 'string' ||
      !value.accountAlias || typeof value.policyRevision !== 'string' || !value.policyRevision || typeof value.technique !== 'string' ||
      !value.technique || !Array.isArray(value.allowedOrigins) || !value.allowedOrigins.length || !Array.isArray(value.allowedMethods) ||
      !value.allowedMethods.length || !Number.isSafeInteger(value.maxRequestBodyBytes) || value.maxRequestBodyBytes < 0) return false;
  const expiry = Date.parse(value.expiresAtUtc);
  return Number.isFinite(expiry) && expiry > Date.now() && value.allowedOrigins.every((origin) => {
    try { return normalizeOrigin(origin) === origin; } catch { return false; }
  });
}

function writeAndClose(socket: Socket, status: number, reason: string): void {
  if (socket.destroyed) return;
  const body = `${reason}\n`;
  socket.end(`HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
}
