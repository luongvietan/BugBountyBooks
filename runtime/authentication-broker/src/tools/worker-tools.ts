import { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import type { MetadataAuditLog } from '../audit/metadata-log.js';
import type { HttpMethod, WorkerToolName } from '../capability/grants.js';
import type { WorkerRequestGuard, WorkerRequestDecision } from '../policy/request-guard.js';
import type { OutputSanitizerOptions } from '../output/sanitize.js';
import { createOutputSanitizer } from '../output/sanitize.js';
import type { AuthorizedApiScope } from '../browser/api-request.js';
import type { SessionManager } from '../session/session-manager.js';

export const WORKER_TOOL_NAMES: readonly WorkerToolName[] = Object.freeze([
  'session_status', 'open_login', 'observe_page', 'navigate', 'act_on_observed_element', 'authorized_request', 'revoke_capability'
]);

export interface WorkerToolDependencies {
  readonly guard: WorkerRequestGuard;
  readonly sessions: Pick<SessionManager,
    'getSnapshot' | 'openLogin' | 'observePage' | 'navigate' | 'clickObservedLink' | 'fillResearcherControlledField' | 'authorizedRequest' | 'revoke'>;
  readonly revokeCapability: (sessionId: string) => boolean;
  readonly audit: Pick<MetadataAuditLog, 'append'>;
  readonly sanitizer?: ReturnType<typeof createOutputSanitizer>;
  readonly sanitizerOptions?: OutputSanitizerOptions;
  readonly nowMs?: () => number;
  readonly onCapabilityContext?: (context: NonNullable<WorkerRequestDecision['context']>) => void;
}

export function registerWorkerTools(server: McpServer, dependencies: WorkerToolDependencies): void {
  const sanitizer = dependencies.sanitizer ?? createOutputSanitizer(dependencies.sanitizerOptions);
  const nowMs = dependencies.nowMs ?? Date.now;

  server.registerTool('session_status', {
    title: 'Session status',
    description: 'Show the current attended session state for this worker capability.',
    inputSchema: z.object({}).strict()
  }, async (_input, context) => execute('session_status', context.sessionId, undefined, async (decision) => {
    const bound = requireContext(decision);
    return dependencies.sessions.getSnapshot(bound.engagementId, bound.accountAlias) ?? { configured: false, state: 'not_configured' };
  }));

  server.registerTool('open_login', {
    title: 'Open attended login',
    description: 'Open a policy-approved sign-in page for the researcher to complete manually.',
    inputSchema: z.object({ origin: z.string().min(1).max(512) }).strict()
  }, async ({ origin }, context) => execute('open_login', context.sessionId, { origin }, async (decision) => {
    const bound = requireContext(decision);
    return dependencies.sessions.openLogin(bound.engagementId, bound.accountAlias, origin);
  }));

  server.registerTool('observe_page', {
    title: 'Observe page',
    description: 'Return sanitized visible page text and observed elements from the approved target.',
    inputSchema: z.object({}).strict()
  }, async (_input, context) => execute('observe_page', context.sessionId, undefined, async (decision) => {
    const bound = requireContext(decision);
    return dependencies.sessions.observePage(bound.engagementId, bound.accountAlias, bound.origins, pageMethods(bound.methods));
  }));

  server.registerTool('navigate', {
    title: 'Navigate',
    description: 'Open a page on an exact origin included in this worker capability.',
    inputSchema: z.object({ url: z.string().min(1).max(8192) }).strict()
  }, async ({ url }, context) => execute('navigate', context.sessionId, { url }, async (decision) => {
    const bound = requireContext(decision);
    const normalized = decision.request?.url;
    if (typeof normalized !== 'string') throw new Error('Navigation was not authorized');
    return dependencies.sessions.navigate(bound.engagementId, bound.accountAlias, normalized, bound.origins, pageMethods(bound.methods));
  }));

  server.registerTool('act_on_observed_element', {
    title: 'Act on an observed element',
    description: 'Follow an observed ordinary link or fill an observed researcher-controlled text field.',
    inputSchema: z.object({
      action: z.enum(['click_link', 'fill_field']),
      id: z.string().uuid(),
      value: z.string().max(4096).optional()
    }).strict()
  }, async ({ action, id, value }, context) => execute('act_on_observed_element', context.sessionId, { action, id, value }, async (decision) => {
    const bound = requireContext(decision);
    if (action === 'click_link') {
      if (value !== undefined) throw new Error('Link action input is invalid');
      return dependencies.sessions.clickObservedLink(bound.engagementId, bound.accountAlias, id, bound.origins, pageMethods(bound.methods));
    }
    if (typeof value !== 'string') throw new Error('Field action input is invalid');
    return dependencies.sessions.fillResearcherControlledField(bound.engagementId, bound.accountAlias, id, value, bound.origins, pageMethods(bound.methods));
  }));

  server.registerTool('authorized_request', {
    title: 'Authorized request',
    description: 'Send one request covered by the active capability and endpoint authorization.',
    inputSchema: z.object({
      url: z.string().min(1).max(8192),
      method: z.enum(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']),
      endpointAuthorizationId: z.string().min(1).max(128),
      body: z.string().max(65_536).optional()
    }).strict()
  }, async (input, context) => execute('authorized_request', context.sessionId, input, async (decision) => {
    const bound = requireContext(decision);
    const normalized = decision.request;
    if (!normalized || typeof normalized.url !== 'string' || typeof normalized.method !== 'string' ||
        typeof normalized.endpointAuthorizationId !== 'string' || typeof decision.authorizeEndpoint !== 'function') {
      throw new Error('Request was not authorized');
    }
    const scope: AuthorizedApiScope = Object.freeze({
      allowedOrigins: bound.origins,
      allowedMethods: bound.methods,
      technique: bound.technique,
      endpointAuthorizationId: normalized.endpointAuthorizationId,
      authorizeEndpoint: decision.authorizeEndpoint
    });
    const request = {
      url: normalized.url,
      method: normalized.method,
      endpointAuthorizationId: normalized.endpointAuthorizationId,
      ...(typeof normalized.body === 'string' ? { body: normalized.body } : {})
    };
    return dependencies.sessions.authorizedRequest(bound.engagementId, bound.accountAlias, request, scope);
  }));

  server.registerTool('revoke_capability', {
    title: 'Revoke this capability',
    description: 'Revoke the shared session for this engagement and account. This stops this worker and interrupts other work using the same account; a researcher must review and grant access again.',
    inputSchema: z.object({}).strict()
  }, async (_input, context) => execute('revoke_capability', context.sessionId, undefined, async (decision) => {
    const sessionId = context.sessionId;
    if (!sessionId) throw new Error('Worker identity is unavailable');
    const revoked = dependencies.revokeCapability(sessionId);
    const bound = decision.context;
    if (revoked && bound) {
      try { await dependencies.sessions.revoke(bound.engagementId, bound.accountAlias, false); } catch { /* capability remains revoked */ }
    }
    return { revoked };
  }));

  async function execute(
    toolName: WorkerToolName,
    sessionId: string | undefined,
    input: unknown,
    dispatch: (decision: WorkerRequestDecision) => Promise<unknown>
  ) {
    const started = nowMs();
    let decision: WorkerRequestDecision;
    try { decision = dependencies.guard.authorize(sessionId, toolName, input); }
    catch { decision = { allowed: false, reason: 'request guard is unavailable' }; }
    if (decision.context) {
      try { dependencies.onCapabilityContext?.(decision.context); } catch { /* diagnostics cannot enlarge a capability */ }
    }
    if (!decision.allowed) {
      try { await appendAudit(decision, 'deny', undefined, started, toolName, sessionId); } catch { /* no dispatch on audit failure */ }
      return toolError(sanitizer.sanitizeText(decision.reason));
    }
    try {
      // An allow record is durable before any page or API operation starts.
      await appendAudit(decision, 'allow', undefined, started, toolName, sessionId);
    } catch {
      decision.release?.();
      return toolError('Metadata audit is unavailable; request was not dispatched.');
    }
    try {
      const value = await dispatch(decision);
      const safe = sanitizer.sanitize(value);
      const status = responseStatus(value);
      await appendAudit(decision, 'result', status, started, toolName, sessionId);
      return toolResult(safe);
    } catch (error) {
      try { await appendAudit(decision, 'unknown', undefined, started, toolName, sessionId); } catch { /* preserve the generic error result */ }
      const message = error instanceof Error ? sanitizer.sanitizeText(error.message) : 'Operation failed';
      return toolError(message || 'Operation failed');
    } finally { decision.release?.(); }
  }

  async function appendAudit(
    decision: WorkerRequestDecision,
    outcome: 'allow' | 'deny' | 'result' | 'unknown',
    status: number | undefined,
    started: number,
    toolName: WorkerToolName,
    sessionId: string | undefined
  ): Promise<void> {
    const bound = decision.context;
    const request = decision.request;
    const category = toolName.replaceAll('_', '-');
    const method = toolName === 'navigate' ? 'GET' : typeof request?.method === 'string' && /^[A-Z]{2,16}$/.test(request.method) ? request.method : 'TOOL';
    const origin = typeof request?.origin === 'string' ? request.origin : undefined;
    await dependencies.audit.append({
      engagementId: bound?.engagementId ?? 'unknown',
      connectionId: bound?.connectionId ?? dependencies.guard.connectionIdForWorker(sessionId) ?? 'unknown',
      accountAlias: bound?.accountAlias ?? 'unknown',
      policyRevision: bound?.policyRevision ?? 'unknown',
      ...(origin ? { origin } : {}),
      method,
      category,
      decision: outcome,
      ...(status !== undefined ? { status } : {}),
      latencyMs: Math.max(0, Math.min(86_400_000, nowMs() - started))
    });
  }
}

function requireContext(decision: WorkerRequestDecision) {
  if (!decision.context) throw new Error('Capability context is unavailable');
  return decision.context;
}

function pageMethods(methods: readonly HttpMethod[]): HttpMethod[] {
  return methods.filter((method) => method === 'GET' || method === 'HEAD');
}

function responseStatus(value: unknown): number | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const status = (value as { status?: unknown }).status;
  return Number.isInteger(status) && Number(status) >= 100 && Number(status) <= 599 ? Number(status) : undefined;
}

function toolResult(value: unknown) {
  let text: string;
  try { text = JSON.stringify(value); } catch { text = '"[omitted]"'; }
  return { content: [{ type: 'text' as const, text }] };
}

function toolError(message: string) {
  return { content: [{ type: 'text' as const, text: JSON.stringify({ ok: false, error: message }) }], isError: true };
}
