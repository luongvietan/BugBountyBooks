import { randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node';
import { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import type { MetadataAuditLog } from '../audit/metadata-log.js';
import type { ConnectionRegistry } from '../capability/connection-registry.js';
import type { CapabilityManager, CapabilityRole, HttpMethod, WorkerToolName } from '../capability/grants.js';
import type { BrokerPolicy } from '../policy/schema.js';
import type { WorkerRequestGuard } from '../policy/request-guard.js';
import { WorkerRequestGuard as DefaultWorkerRequestGuard } from '../policy/request-guard.js';
import type { OutputSanitizerOptions } from '../output/sanitize.js';
import { createOutputSanitizer } from '../output/sanitize.js';
import type { SessionManager } from '../session/session-manager.js';
import { ResearcherControlSurface } from '../admin/control-surface.js';
import { createMcpLoopbackGuard } from './host-guard.js';
import { registerWorkerTools, WORKER_TOOL_NAMES } from '../tools/worker-tools.js';

const DEFAULT_PORT = 8765;
const MAX_HTTP_BODY_BYTES = 65_536;
const API_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const;
const WORKER_TOOLS = WORKER_TOOL_NAMES as readonly WorkerToolName[];

const GrantSchema = z.object({
  connectionId: z.string().min(1).max(128),
  accountAlias: z.string().regex(/^[a-z0-9][a-z0-9._-]{0,63}$/),
  role: z.enum(['mapper', 'tester', 'validator']),
  tools: z.array(z.enum(WORKER_TOOLS as [WorkerToolName, ...WorkerToolName[]])).min(1).max(WORKER_TOOLS.length),
  technique: z.string().min(1).max(128),
  policyReference: z.string().min(1).max(512),
  methods: z.array(z.enum(API_METHODS)).min(1).max(API_METHODS.length),
  origins: z.array(z.string().min(1).max(2048)).min(1).max(64)
}).strict();
const ConnectionIdSchema = z.object({ connectionId: z.string().min(1).max(128) }).strict();
const CloseSchema = z.object({ connectionId: z.string().min(1).max(128), confirmed: z.literal(true) }).strict();
const ConfirmLoginSchema = z.object({ connectionId: z.string().min(1).max(128), confirmed: z.literal(true) }).strict();

export interface BrokerMcpServerOptions {
  /** Binds to 127.0.0.1 only. Port 0 is reserved for integration tests. */
  readonly port?: number;
  readonly identityMode: 'stateful' | 'single-worker';
  readonly registry: ConnectionRegistry;
  readonly capabilities: CapabilityManager;
  readonly guard?: WorkerRequestGuard;
  readonly sessions: SessionManager;
  readonly audit: Pick<MetadataAuditLog, 'append'>;
  readonly getPolicy: () => BrokerPolicy | undefined;
  readonly sanitizerOptions?: OutputSanitizerOptions;
}

interface BrokerConnection {
  readonly server: McpServer;
  readonly transport: NodeStreamableHTTPServerTransport;
  sessionId?: string;
  connectionId?: string;
  engagementId?: string;
  accountAlias?: string;
  policyRevision?: string;
  cleaning?: Promise<void>;
  closed: boolean;
}

export async function createBrokerMcpServer(options: BrokerMcpServerOptions): Promise<{
  listen(): Promise<{ host: string; port: number }>;
  close(): Promise<void>;
}> {
  if (!options || options.identityMode !== options.registry.identityMode) throw new Error('Broker connection identity mode does not match its registry');
  const requestedPort = options.port ?? DEFAULT_PORT;
  if (!Number.isInteger(requestedPort) || requestedPort < 0 || requestedPort > 65535) throw new Error('MCP listener port is invalid');
  const guard = options.guard ?? new DefaultWorkerRequestGuard(options.capabilities);
  const sanitizer = createOutputSanitizer(options.sanitizerOptions);
  const connections = new Map<string, BrokerConnection>();
  const server = createServer((request, response) => { void route(request, response); });
  let boundPort: number | undefined;
  let listening: Promise<{ host: string; port: number }> | undefined;
  let closing = false;

  const controlSurface = new ResearcherControlSurface({
    registry: options.registry,
    capabilities: options.capabilities,
    closeSession: (connectionId) => closeConnection(connectionId)
  });

  return {
    async listen() {
      if (listening) return listening;
      listening = new Promise((resolve, reject) => {
        const fail = (error: Error) => reject(new Error(`MCP listener could not start: ${safeErrorCode(error)}`));
        server.once('error', fail);
        server.listen(requestedPort, '127.0.0.1', () => {
          server.removeListener('error', fail);
          const address = server.address();
          if (!address || typeof address === 'string') { reject(new Error('MCP loopback address is unavailable')); return; }
          boundPort = address.port;
          resolve({ host: '127.0.0.1', port: address.port });
        });
      });
      return listening;
    },
    async close() {
      if (closing) return;
      closing = true;
      await Promise.all([...connections.keys()].map((id) => cleanupConnection(id, true)));
      await new Promise<void>((resolve) => {
        if (!server.listening) { resolve(); return; }
        server.close(() => resolve());
      });
      await options.sessions.closeAll();
    }
  };

  async function route(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const port = boundPort;
    if (!port || !createMcpLoopbackGuard(port)(request, response)) return;
    let pathname: string;
    try { pathname = new URL(request.url ?? '/', `http://127.0.0.1:${port}`).pathname; }
    catch { sendJson(response, 400, { error: 'Invalid request path' }); return; }
    if (pathname === '/mcp') { await routeMcp(request, response); return; }
    if (pathname.startsWith('/researcher/')) { await routeResearcher(pathname, request, response, port); return; }
    sendJson(response, 404, { error: 'Not found' });
  }

  async function routeMcp(request: IncomingMessage, response: ServerResponse): Promise<void> {
    if (!['POST', 'GET', 'DELETE'].includes(request.method ?? '')) {
      response.setHeader('Allow', 'POST, GET, DELETE');
      sendJson(response, 405, { error: 'Method not allowed' });
      return;
    }
    let body: unknown;
    if (request.method === 'POST') {
      if (!isJsonContentType(request.headers['content-type'])) { sendJson(response, 415, { error: 'JSON content type required' }); return; }
      const raw = await readBody(request, response);
      if (raw === undefined) return;
      try { body = JSON.parse(raw.toString('utf8')) as unknown; }
      catch { sendJson(response, 400, { error: 'Invalid JSON request' }); return; }
      if (!isRecord(body)) { sendJson(response, 400, { error: 'Invalid JSON request' }); return; }
    }

    const rawSessionId = request.headers['mcp-session-id'];
    if (Array.isArray(rawSessionId) || (rawSessionId !== undefined && (typeof rawSessionId !== 'string' || rawSessionId.length > 256 || !/^[A-Za-z0-9._-]+$/.test(rawSessionId)))) {
      sendJson(response, 400, { error: 'Invalid MCP session reference' });
      return;
    }
    const sessionId = typeof rawSessionId === 'string' ? rawSessionId : undefined;
    let connection: BrokerConnection | undefined;
    if (!sessionId) {
      if (request.method !== 'POST' || (body as { method?: unknown } | undefined)?.method !== 'initialize') {
        sendJson(response, 400, { error: 'An initialized MCP session is required' });
        return;
      }
      try { connection = await createConnection(); }
      catch { sendJson(response, 503, { error: 'MCP connection could not be created' }); return; }
    } else {
      connection = connections.get(sessionId);
      if (!connection || connection.closed) { sendJson(response, 404, { error: 'MCP session is not available' }); return; }
    }
    try {
      await connection.transport.handleRequest(request, response, body);
      if (!sessionId && !connection.sessionId) await closeUninitialized(connection);
    } catch {
      if (!response.headersSent) sendJson(response, 500, { error: 'MCP request failed' });
      if (!sessionId && !connection.sessionId) await closeUninitialized(connection);
    }
  }

  async function createConnection(): Promise<BrokerConnection> {
    let connection!: BrokerConnection;
    const mcpServer = new McpServer({ name: 'bughuntskills-authentication-broker', version: '0.1.0' });
    const transport = new NodeStreamableHTTPServerTransport({
      sessionIdGenerator: randomUUID,
      enableJsonResponse: true,
      maxRequestBodySize: MAX_HTTP_BODY_BYTES,
      onsessioninitialized: (sessionId) => {
        if (connection.sessionId || connections.has(sessionId)) throw new Error('MCP session identity collision');
        const connectionId = options.identityMode === 'stateful'
          ? options.registry.registerSession(sessionId)
          : options.registry.registerSingleWorkerConnection();
        connection.sessionId = sessionId;
        connection.connectionId = connectionId;
        connections.set(sessionId, connection);
      },
      onsessionclosed: (sessionId) => cleanupConnection(sessionId, false)
    });
    connection = { server: mcpServer, transport, closed: false };
    registerWorkerTools(mcpServer, {
      guard,
      sessions: options.sessions,
      revokeCapability: (sessionId) => options.capabilities.revokeForSession(sessionId),
      audit: options.audit,
      sanitizer,
      onCapabilityContext: (context) => {
        if (connection.closed) return;
        connection.engagementId = context.engagementId;
        connection.accountAlias = context.accountAlias;
        connection.policyRevision = context.policyRevision;
      }
    });
    await mcpServer.connect(transport);
    return connection;
  }

  async function routeResearcher(pathname: string, request: IncomingMessage, response: ServerResponse, port: number): Promise<void> {
    const expectedOrigin = `http://127.0.0.1:${port}`;
    if (request.headers.origin !== expectedOrigin) { sendJson(response, 403, { error: 'Researcher control requires the exact local browser origin' }); return; }
    if (pathname === '/researcher/connections' && request.method === 'GET') {
      const safe = sanitizer.sanitize(controlSurface.listConnections());
      sendJson(response, 200, safe);
      return;
    }
    if (request.method !== 'POST') {
      response.setHeader('Allow', pathname === '/researcher/connections' ? 'GET' : 'POST');
      sendJson(response, 405, { error: 'Researcher action method is not allowed' });
      return;
    }
    if (!isJsonContentType(request.headers['content-type'])) { sendJson(response, 415, { error: 'JSON content type required' }); return; }
    const raw = await readBody(request, response);
    if (raw === undefined) return;
    let input: unknown;
    try { input = JSON.parse(raw.toString('utf8')) as unknown; } catch { sendJson(response, 400, { error: 'Invalid researcher action' }); return; }
    try {
      if (pathname === '/researcher/grant') {
        const grant = GrantSchema.parse(input);
        const currentPolicy = safePolicy(options.getPolicy);
        if (!currentPolicy) throw new Error('policy unavailable');
        await writeAdminAudit(grant.connectionId, grant.accountAlias, 'capability-grant', 'allow', currentPolicy);
        const result = controlSurface.grant(grant);
        const connection = [...connections.values()].find((candidate) => candidate.connectionId === grant.connectionId);
        if (connection) {
          connection.engagementId = currentPolicy.engagementId;
          connection.accountAlias = grant.accountAlias;
          connection.policyRevision = currentPolicy.policySnapshot.revision;
        }
        await writeAdminAudit(grant.connectionId, grant.accountAlias, 'capability-grant', 'result', currentPolicy);
        sendJson(response, 200, sanitizer.sanitize(result));
        return;
      }
      if (pathname === '/researcher/revoke') {
        const { connectionId } = ConnectionIdSchema.parse(input);
        const alias = options.capabilities.accountAliasFor(connectionId) ?? 'unknown';
        const currentPolicy = safePolicy(options.getPolicy);
        if (!currentPolicy) throw new Error('policy unavailable');
        await writeAdminAudit(connectionId, alias, 'capability-revoke', 'allow', currentPolicy);
        const revoked = controlSurface.revoke(connectionId);
        if (revoked) await writeAdminAudit(connectionId, alias, 'capability-revoke', 'result', currentPolicy);
        sendJson(response, 200, { revoked });
        return;
      }
      if (pathname === '/researcher/require-login') {
        const { connectionId, confirmed } = ConfirmLoginSchema.parse(input);
        const connection = [...connections.values()].find((candidate) => candidate.connectionId === connectionId);
        if (!confirmed || !connection?.engagementId || !connection.accountAlias) throw new Error('session not assigned');
        const currentPolicy = safePolicy(options.getPolicy);
        if (!currentPolicy) throw new Error('policy unavailable');
        await writeAdminAudit(connectionId, connection.accountAlias, 'require-attended-login', 'allow', currentPolicy);
        const result = options.sessions.requireResearcherAction(connection.engagementId, connection.accountAlias);
        await writeAdminAudit(connectionId, connection.accountAlias, 'require-attended-login', 'result', currentPolicy);
        sendJson(response, 200, sanitizer.sanitize(result));
        return;
      }
      if (pathname === '/researcher/confirm-login') {
        const { connectionId, confirmed } = ConfirmLoginSchema.parse(input);
        const connection = [...connections.values()].find((candidate) => candidate.connectionId === connectionId);
        if (!confirmed || !connection?.engagementId || !connection.accountAlias) throw new Error('session not assigned');
        const currentPolicy = safePolicy(options.getPolicy);
        if (!currentPolicy) throw new Error('policy unavailable');
        await writeAdminAudit(connectionId, connection.accountAlias, 'confirm-attended-login', 'allow', currentPolicy);
        const result = options.sessions.confirmAttendedLogin(connection.engagementId, connection.accountAlias);
        await writeAdminAudit(connectionId, connection.accountAlias, 'confirm-attended-login', 'result', currentPolicy);
        sendJson(response, 200, sanitizer.sanitize(result));
        return;
      }
      if (pathname === '/researcher/confirm-authorization-review') {
        const { connectionId, confirmed } = ConfirmLoginSchema.parse(input);
        const connection = [...connections.values()].find((candidate) => candidate.connectionId === connectionId);
        if (!confirmed || !connection?.engagementId || !connection.accountAlias) throw new Error('session not assigned');
        const currentPolicy = safePolicy(options.getPolicy);
        if (!currentPolicy) throw new Error('policy unavailable');
        await writeAdminAudit(connectionId, connection.accountAlias, 'confirm-authorization-review', 'allow', currentPolicy);
        const result = options.sessions.confirmResearcherResume(connection.engagementId, connection.accountAlias);
        await writeAdminAudit(connectionId, connection.accountAlias, 'confirm-authorization-review', 'result', currentPolicy);
        sendJson(response, 200, sanitizer.sanitize(result));
        return;
      }
      if (pathname === '/researcher/close') {
        const { connectionId, confirmed } = CloseSchema.parse(input);
        const connection = [...connections.values()].find((candidate) => candidate.connectionId === connectionId);
        const alias = connection?.accountAlias ?? options.capabilities.accountAliasFor(connectionId) ?? 'unknown';
        const currentPolicy = safePolicy(options.getPolicy);
        if (!currentPolicy) throw new Error('policy unavailable');
        await writeAdminAudit(connectionId, alias, 'session-close', 'allow', currentPolicy);
        const closed = await controlSurface.closeSession(connectionId, confirmed);
        if (closed) await writeAdminAudit(connectionId, alias, 'session-close', 'result', currentPolicy);
        sendJson(response, 200, { closed });
        return;
      }
    } catch {
      sendJson(response, 400, { error: 'Researcher action was rejected' });
      return;
    }
    sendJson(response, 404, { error: 'Researcher action was not found' });
  }

  async function writeAdminAudit(connectionId: string, accountAlias: string, category: string, decision: 'allow' | 'result', policy: BrokerPolicy): Promise<void> {
    await options.audit.append({
      engagementId: policy.engagementId,
      connectionId,
      accountAlias,
      policyRevision: policy.policySnapshot.revision,
      method: 'ADMIN',
      category,
      decision,
      latencyMs: 0
    });
  }

  async function closeConnection(connectionId: string): Promise<boolean> {
    const connection = [...connections.values()].find((candidate) => candidate.connectionId === connectionId);
    if (!connection || connection.closed || !connection.sessionId) return false;
    try { await connection.server.close(); } catch { /* identity cleanup still revokes the capability */ }
    await cleanupConnection(connection.sessionId, false);
    return true;
  }

  async function cleanupConnection(sessionId: string, closeTransport: boolean): Promise<void> {
    const connection = connections.get(sessionId);
    if (!connection) return;
    if (connection.cleaning) return connection.cleaning;
    connection.cleaning = (async () => {
      connection.closed = true;
      if (closeTransport) {
        try { await connection.server.close(); } catch { /* close remaining resources */ }
      }
      const accountAlias = connection.accountAlias ?? (connection.connectionId ? options.capabilities.accountAliasFor(connection.connectionId) : undefined);
      const policy = safePolicy(options.getPolicy);
      const engagementId = connection.engagementId ?? policy?.engagementId;
      if (accountAlias && engagementId) {
        try { await options.sessions.revoke(engagementId, accountAlias, true); } catch { /* registry closure still revokes worker access */ }
      }
      connections.delete(sessionId);
      if (options.identityMode === 'stateful') options.registry.closeSession(sessionId);
      else options.registry.closeSingleWorkerConnection();
    })();
    return connection.cleaning;
  }

  async function closeUninitialized(connection: BrokerConnection): Promise<void> {
    connection.closed = true;
    try { await connection.server.close(); } catch { /* no identity has been issued */ }
  }
}

async function readBody(request: IncomingMessage, response: ServerResponse): Promise<Buffer | undefined> {
  const length = request.headers['content-length'];
  if (typeof length === 'string' && (!/^\d+$/.test(length) || Number(length) > MAX_HTTP_BODY_BYTES)) {
    sendJson(response, 413, { error: 'Request body exceeds the broker limit' });
    request.resume();
    return undefined;
  }
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of request) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
      size += buffer.length;
      if (size > MAX_HTTP_BODY_BYTES) {
        sendJson(response, 413, { error: 'Request body exceeds the broker limit' });
        request.destroy();
        return undefined;
      }
      chunks.push(buffer);
    }
  } catch {
    if (!response.headersSent) sendJson(response, 400, { error: 'Request body could not be read' });
    return undefined;
  }
  return Buffer.concat(chunks, size);
}

function isJsonContentType(value: string | string[] | undefined): boolean {
  return typeof value === 'string' && /^application\/json(?:\s*;|\s*$)/i.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function safePolicy(getPolicy: () => BrokerPolicy | undefined): BrokerPolicy | undefined {
  try { return getPolicy(); } catch { return undefined; }
}

function safeErrorCode(error: unknown): string {
  if (!error || typeof error !== 'object') return 'startup failure';
  const code = (error as { code?: unknown }).code;
  return typeof code === 'string' && /^[A-Z0-9_]{1,64}$/.test(code) ? code : 'startup failure';
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  if (response.headersSent || response.destroyed) return;
  const text = JSON.stringify(body);
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Content-Length': Buffer.byteLength(text)
  });
  response.end(text);
}
