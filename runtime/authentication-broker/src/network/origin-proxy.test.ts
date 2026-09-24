import assert from 'node:assert/strict';
import { createServer as createHttpServer, type Server as HttpServer } from 'node:http';
import { createConnection, createServer as createTcpServer, type Server as TcpServer, type Socket } from 'node:net';
import test from 'node:test';

type ProxyContext = {
  engagementId: string; accountAlias: string; policyRevision: string; technique: string;
  allowedOrigins: readonly string[]; allowedMethods: readonly string[]; expiresAtUtc: string; maxRequestBodyBytes: number;
};
type ProxyModule = {
  createOriginProxy: (options: {
    port?: number;
    resolver: (hostname: string) => Promise<readonly string[]>;
    resolveCapability: (proxyAuthorization: string | undefined) => ProxyContext | undefined;
    authorize: (context: ProxyContext, request: { origin: string; method: string; targetPath: string; technique: string }) => boolean | { allowed: boolean; release?: () => void };
    destinationConnectorForTests?: (destination: { hostname: string; address: string; port: number; family: 4 | 6 }) => Socket;
    maxHeaderBytes?: number;
  }) => {
    start: () => Promise<{ address: string; port: number }>;
    close: () => Promise<void>;
  };
};

async function getProxyFactory(): Promise<ProxyModule['createOriginProxy']> {
  let module: ProxyModule | undefined;
  try { module = await import('./origin-proxy.js') as unknown as ProxyModule; } catch { module = undefined; }
  assert.equal(typeof module?.createOriginProxy, 'function', 'origin filtering proxy must be implemented');
  return module!.createOriginProxy;
}

const token = 'synthetic-proxy-capability-secret';
const httpOrigin = 'http://app.example:8080';
const httpsOrigin = 'https://app.example:443';

function context(origins = [httpOrigin]): ProxyContext {
  return {
    engagementId: 'synthetic-demo-2026-09-24',
    accountAlias: 'researcher-a',
    policyRevision: 'rules-r1',
    technique: 'read-only mapping',
    allowedOrigins: origins,
    allowedMethods: ['GET', 'HEAD'],
    expiresAtUtc: '2099-09-24T08:00:00.000Z',
    maxRequestBodyBytes: 1024
  };
}

async function listen<T extends HttpServer | TcpServer>(server: T): Promise<{ address: string; port: number }> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.removeListener('error', reject); resolve(); });
  });
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return { address: address.address, port: address.port };
}

async function sendRaw(address: string, port: number, message: string, afterConnect?: (socket: Socket) => void): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const socket = createConnection({ host: address, port });
    let response = '';
    socket.setTimeout(3000, () => socket.destroy(new Error('proxy mock timed out')));
    socket.once('connect', () => { socket.write(message); afterConnect?.(socket); });
    socket.on('data', (chunk) => { response += chunk.toString('latin1'); });
    socket.once('end', () => resolve(response));
    socket.once('error', reject);
  });
}

async function openConnect(address: string, port: number, message: string): Promise<{ socket: Socket; response: string }> {
  return await new Promise((resolve, reject) => {
    const socket = createConnection({ host: address, port });
    let received = '';
    const onData = (chunk: Buffer) => {
      received += chunk.toString('latin1');
      if (received.includes('\r\n\r\n')) resolve({ socket, response: received });
    };
    socket.setTimeout(3000, () => socket.destroy(new Error('proxy mock timed out')));
    socket.once('connect', () => socket.write(message));
    socket.on('data', onData);
    socket.once('error', reject);
  });
}

function rawRequest(origin: string, path = '/resource', extraHeaders = ''): string {
  const parsed = new URL(origin);
  return `GET ${origin}${path} HTTP/1.1\r\nHost: ${parsed.host}\r\nProxy-Authorization: Bearer ${token}\r\n${extraHeaders}Connection: close\r\n\r\n`;
}

test('forwards an authorized HTTP request to its pinned connector and strips proxy credentials', async () => {
  const createOriginProxy = await getProxyFactory();
  let upstreamHits = 0;
  let capturedPath = '';
  let authorizedPath = '';
  let capturedAuthorization: string | string[] | undefined;
  let capturedProxyAuthenticate: string | undefined;
  let capturedXHop: string | string[] | undefined;
  const mock = createHttpServer((request, response) => {
    upstreamHits += 1;
    capturedPath = request.url ?? '';
    capturedAuthorization = request.headers['proxy-authorization'];
    capturedProxyAuthenticate = request.headers['proxy-authenticate'];
    capturedXHop = request.headers['x-hop'];
    response.writeHead(200, { 'Content-Type': 'text/plain', Connection: 'close' });
    response.end('synthetic mock response');
  });
  const mockAddress = await listen(mock);
  const proxy = createOriginProxy({
    port: 0,
    resolver: async () => ['8.8.8.8'],
    resolveCapability: (header) => header === `Bearer ${token}` ? context() : undefined,
    authorize: (_context, request) => { authorizedPath = request.targetPath; return { allowed: true }; },
    destinationConnectorForTests: (destination) => {
      assert.equal(destination.address, '8.8.8.8');
      assert.equal(destination.hostname, 'app.example');
      return createConnection({ host: '127.0.0.1', port: mockAddress.port });
    }
  });
  try {
    const proxyAddress = await proxy.start();
    assert.equal(proxyAddress.address, '127.0.0.1');
    const response = await sendRaw(proxyAddress.address, proxyAddress.port, rawRequest(httpOrigin, '/path?q=synthetic', 'Connection: X-Hop\r\nX-Hop: synthetic-hop-value\r\nProxy-Authenticate: synthetic-proxy-value\r\n'));
    assert.match(response, /^HTTP\/1\.1 200/);
    assert.equal(response.includes('synthetic mock response'), true);
    assert.equal(upstreamHits, 1);
    assert.equal(capturedPath, '/path?q=synthetic');
    assert.equal(authorizedPath, '/path?q=synthetic');
    assert.equal(capturedAuthorization, undefined);
    assert.equal(capturedProxyAuthenticate, undefined);
    assert.equal(capturedXHop, undefined);
  } finally {
    await proxy.close();
    await new Promise<void>((resolve) => mock.close(() => resolve()));
  }
});

test('rejects oversized request bodies before opening an upstream connection', async () => {
  const createOriginProxy = await getProxyFactory();
  let upstreamConnects = 0;
  const proxy = createOriginProxy({
    port: 0,
    resolver: async () => ['8.8.8.8'],
    resolveCapability: (header) => header === `Bearer ${token}` ? { ...context(), allowedMethods: ['POST'] } : undefined,
    authorize: () => ({ allowed: true }),
    destinationConnectorForTests: () => { upstreamConnects += 1; return createConnection({ host: '127.0.0.1', port: 1 }); }
  });
  try {
    const address = await proxy.start();
    const response = await sendRaw(address.address, address.port,
      `POST ${httpOrigin}/submit HTTP/1.1\r\nHost: app.example:8080\r\nProxy-Authorization: Bearer ${token}\r\nContent-Length: 1025\r\nConnection: close\r\n\r\n`);
    assert.match(response, /^HTTP\/1\.1 413/);
    assert.equal(upstreamConnects, 0);
  } finally {
    await proxy.close();
  }
});

test('denies absent capability, off-scope origin, and wrong port before upstream dispatch', async () => {
  const createOriginProxy = await getProxyFactory();
  let upstreamConnects = 0;
  const proxy = createOriginProxy({
    port: 0,
    resolver: async () => ['8.8.8.8'],
    resolveCapability: (header) => header === `Bearer ${token}` ? context() : undefined,
    authorize: () => ({ allowed: true }),
    destinationConnectorForTests: () => { upstreamConnects += 1; return createConnection({ host: '127.0.0.1', port: 1 }); }
  });
  try {
    const address = await proxy.start();
    const absent = await sendRaw(address.address, address.port, `GET ${httpOrigin}/ HTTP/1.1\r\nHost: app.example:8080\r\nConnection: close\r\n\r\n`);
    assert.match(absent, /^HTTP\/1\.1 407/);
    const offScope = await sendRaw(address.address, address.port, rawRequest('http://other.example:8080'));
    const wrongPort = await sendRaw(address.address, address.port, rawRequest('http://app.example:8081'));
    assert.match(offScope, /^HTTP\/1\.1 403/);
    assert.match(wrongPort, /^HTTP\/1\.1 403/);
    assert.equal(upstreamConnects, 0);
  } finally {
    await proxy.close();
  }
});

test('rejects mixed public/private DNS answers before opening an upstream socket', async () => {
  const createOriginProxy = await getProxyFactory();
  let upstreamConnects = 0;
  const proxy = createOriginProxy({
    port: 0,
    resolver: async () => ['8.8.8.8', '169.254.169.254'],
    resolveCapability: (header) => header === `Bearer ${token}` ? context() : undefined,
    authorize: () => ({ allowed: true }),
    destinationConnectorForTests: () => { upstreamConnects += 1; return createConnection({ host: '127.0.0.1', port: 1 }); }
  });
  try {
    const address = await proxy.start();
    const response = await sendRaw(address.address, address.port, rawRequest(httpOrigin));
    assert.match(response, /^HTTP\/1\.1 403/);
    assert.equal(upstreamConnects, 0);
  } finally {
    await proxy.close();
  }
});

test('revalidates redirect destinations independently and never follows an off-scope redirect', async () => {
  const createOriginProxy = await getProxyFactory();
  let upstreamHits = 0;
  const mock = createHttpServer((_request, response) => {
    upstreamHits += 1;
    response.writeHead(302, { Location: 'http://other.example:8080/redirected', Connection: 'close' });
    response.end();
  });
  const mockAddress = await listen(mock);
  const proxy = createOriginProxy({
    port: 0,
    resolver: async () => ['8.8.8.8'],
    resolveCapability: (header) => header === `Bearer ${token}` ? context() : undefined,
    authorize: () => ({ allowed: true }),
    destinationConnectorForTests: () => createConnection({ host: '127.0.0.1', port: mockAddress.port })
  });
  try {
    const address = await proxy.start();
    const first = await sendRaw(address.address, address.port, rawRequest(httpOrigin));
    assert.match(first, /^HTTP\/1\.1 302/);
    const redirected = await sendRaw(address.address, address.port, rawRequest('http://other.example:8080', '/redirected'));
    assert.match(redirected, /^HTTP\/1\.1 403/);
    assert.equal(upstreamHits, 1);
  } finally {
    await proxy.close();
    await new Promise<void>((resolve) => mock.close(() => resolve()));
  }
});

test('supports scoped HTTPS CONNECT tunneling without decrypting TLS or forwarding proxy credentials', async () => {
  const createOriginProxy = await getProxyFactory();
  let upstreamConnects = 0;
  let upstreamBytes = '';
  const upstream = createTcpServer((socket) => {
    upstreamConnects += 1;
    socket.on('data', (chunk) => { upstreamBytes += chunk.toString('latin1'); });
  });
  const upstreamAddress = await listen(upstream);
  const proxy = createOriginProxy({
    port: 0,
    resolver: async () => ['8.8.8.8'],
    resolveCapability: (header) => header === `Bearer ${token}` ? context([httpsOrigin]) : undefined,
    authorize: () => ({ allowed: true }),
    destinationConnectorForTests: (destination) => {
      assert.equal(destination.hostname, 'app.example');
      assert.equal(destination.port, 443);
      return createConnection({ host: '127.0.0.1', port: upstreamAddress.port });
    }
  });
  try {
    const address = await proxy.start();
    const connection = await openConnect(address.address, address.port,
      `CONNECT app.example:443 HTTP/1.1\r\nHost: app.example:443\r\nProxy-Authorization: Bearer ${token}\r\n\r\n`);
    connection.socket.write('synthetic-tls-client-hello');
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(upstreamConnects, 1);
    assert.match(connection.response.split('\r\n')[0] ?? '', /^HTTP\/1\.1 200/);
    connection.socket.destroy();
    await new Promise((resolve) => setTimeout(resolve, 25));
    assert.equal(upstreamBytes.includes('synthetic-tls-client-hello'), true);
    assert.equal(upstreamBytes.includes(token), false);
  } finally {
    await proxy.close();
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
  }
});

test('enforces header-size limits and rejects WebSocket upgrade requests', async () => {
  const createOriginProxy = await getProxyFactory();
  let upstreamConnects = 0;
  const proxy = createOriginProxy({
    port: 0,
    maxHeaderBytes: 1024,
    resolver: async () => ['8.8.8.8'],
    resolveCapability: (header) => header === `Bearer ${token}` ? context() : undefined,
    authorize: () => ({ allowed: true }),
    destinationConnectorForTests: () => { upstreamConnects += 1; return createConnection({ host: '127.0.0.1', port: 1 }); }
  });
  try {
    const address = await proxy.start();
    const upgrade = await sendRaw(address.address, address.port, rawRequest(httpOrigin, '/', 'Upgrade: websocket\r\nConnection: Upgrade\r\n'));
    assert.match(upgrade, /^HTTP\/1\.1 403/);
    const large = await sendRaw(address.address, address.port, `GET ${httpOrigin}/ HTTP/1.1\r\nX-Fill: ${'a'.repeat(1200)}`);
    assert.match(large, /^HTTP\/1\.1 431/);
    assert.equal(upstreamConnects, 0);
  } finally {
    await proxy.close();
  }
});
