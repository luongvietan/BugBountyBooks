import { chromium } from 'playwright';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ConnectionRegistry } from '../capability/connection-registry.js';
import { CapabilityManager } from '../capability/grants.js';
import { MetadataAuditLog } from '../audit/metadata-log.js';
import { createMetadataFileWriter } from '../audit/metadata-file.js';
import { createApiRequestAdapter } from '../browser/api-request.js';
import { createManagedContext } from '../browser/managed-context.js';
import type { ApiCookieJar } from '../browser/api-request.js';
import { createRuntimeDirectories, resolveRuntimePaths } from '../config/paths.js';
import { egressPreflight, managedBrowserNetworkOptions, createCurrentEgressSnapshot, BROKER_PROXY_HOST, BROKER_PROXY_PORT, BROKER_PROXY_URL } from '../network/egress-preflight.js';
import { createOriginProxy } from '../network/origin-proxy.js';
import { ProxyCredentialRegistry } from '../network/proxy-credentials.js';
import { isEndpointAuthorized } from '../policy/endpoint-authorizations.js';
import { createPolicyProvider } from '../policy/policy-provider.js';
import type { BrokerPolicy } from '../policy/schema.js';
import { createOutputSanitizer } from '../output/sanitize.js';
import { SessionManager } from '../session/session-manager.js';
import { createBrokerMcpServer } from '../transport/mcp-server.js';
import { createBrokerLifecycle } from './lifecycle.js';

const MAX_RESPONSE_BYTES = 256 * 1024;

export async function createAuthenticationBroker(options: {
  readonly repositoryRoot?: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly now?: () => Date;
} = {}): Promise<ReturnType<typeof createBrokerLifecycle>> {
  const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const repositoryRoot = options.repositoryRoot ?? path.resolve(packageRoot, '..', '..');
  const env = options.env ?? process.env;
  const now = options.now ?? (() => new Date());
  const paths = resolveRuntimePaths({ repositoryRoot, env });
  createRuntimeDirectories(paths);
  const policyPath = path.join(paths.root, 'broker-policy.json');
  const provider = await createPolicyProvider({ filePath: policyPath, now });
  const initialPolicy = provider.getPolicy();
  if (!initialPolicy || !isProductionPolicy(initialPolicy)) throw new Error('Policy file is unavailable or not safe for runtime use');

  const proxyCredentials = new ProxyCredentialRegistry({ now });
  let lifecycle: ReturnType<typeof createBrokerLifecycle> | undefined;
  let proxyBinding: { address: string; port: number } | undefined;
  const isEgressVerified = (): boolean => lifecycle?.isEgressVerified() === true;
  const proxy = createOriginProxy({
    port: BROKER_PROXY_PORT,
    resolveCapability: (authorization) => {
      if (!isEgressVerified()) return undefined;
      const capability = proxyCredentials.resolveCapability(authorization);
      const policy = capability ? provider.getPolicy(capability.engagementId) : undefined;
      if (!capability || !policy || policy.policySnapshot.revision !== capability.policyRevision) return undefined;
      return capability;
    },
    authorize: (capability, request) => {
      const originAllowed = capability.allowedOrigins.includes(request.origin);
      const methodAllowed = request.method === 'CONNECT'
        ? capability.allowedMethods.some((method) => ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(method))
        : capability.allowedMethods.includes(request.method);
      const isCurrent = (): boolean => {
        if (!isEgressVerified() || !originAllowed || !methodAllowed || !proxyCredentials.isCurrent(capability)) return false;
        const policy = provider.getPolicy(capability.engagementId);
        return Boolean(policy && policy.policySnapshot.revision === capability.policyRevision &&
          Date.parse(capability.expiresAtUtc) > now().getTime());
      };
      return { allowed: isCurrent(), isCurrent };
    }
  });

  const audit = new MetadataAuditLog({
    now,
    retainedRecords: 0,
    write: createMetadataFileWriter({ filePath: path.join(paths.logs, 'audit.jsonl') })
  });
  const sanitizer = createOutputSanitizer();
  const registry = new ConnectionRegistry({ identityMode: 'stateful' });
  let sessions!: SessionManager;
  const capabilities = new CapabilityManager(registry, {
    getPolicy: () => provider.getPolicy(),
    now,
    egressIsVerified: isEgressVerified,
    authorizeEndpoint: (request) => isEndpointAuthorized(provider.getPolicy(request.engagementId), request)
  });

  sessions = new SessionManager({
    profileRoot: paths.profiles,
    getPolicy: (engagementId) => provider.getPolicy(engagementId),
    now,
    createProxyCredentials: ({ engagementId, accountAlias }) => {
      const policy = requirePolicy(provider.getPolicy(engagementId));
      return proxyCredentials.issue(policy, accountAlias);
    },
    createContext: async (contextOptions) => createManagedContext({
      ...contextOptions,
      isEgressVerified,
      sanitizeObservation: (value) => sanitizer.sanitizeText(value),
      onProxyScopeChange: (scope) => proxyCredentials.setScope(contextOptions.proxyCredentials.username, scope),
      onProxyCredentialsClosed: () => proxyCredentials.revoke(contextOptions.proxyCredentials.username),
      createAuthorizedRequest: (browserContext, credentials) => async (input, scope) => {
        const policy = requirePolicy(provider.getPolicy(contextOptions.engagementId));
        if (!scope || !isEgressVerified()) throw new Error('API request scope is unavailable');
        const adapter = createApiRequestAdapter({
          context: browserContext as unknown as ApiCookieJar,
          proxy: { server: BROKER_PROXY_URL, username: credentials.username, password: credentials.password },
          authorize: (request) => scope.authorizeEndpoint({
            ...request,
            endpointAuthorizationId: scope.endpointAuthorizationId
          }),
          allowedOrigins: scope.allowedOrigins,
          allowedMethods: scope.allowedMethods,
          allowedRequestHeaders: [],
          technique: scope.technique,
          endpointAuthorizationId: scope.endpointAuthorizationId,
          maxRequestBodyBytes: policy.limits.maxRequestBodyBytes,
          maxResponseBytes: MAX_RESPONSE_BYTES,
          isEgressVerified
        });
        return adapter.request(input, scope);
      }
    }),
    onAuthorizationStop: ({ engagementId, accountAlias }) => {
      capabilities.revokeAccount(engagementId, accountAlias);
    }
  });

  const createMcp = async () => createBrokerMcpServer({
    identityMode: 'stateful',
    registry,
    capabilities,
    sessions,
    audit,
    getPolicy: () => provider.getPolicy() as BrokerPolicy | undefined,
    sanitizerOptions: {}
  });

  lifecycle = createBrokerLifecycle({
    proxy: {
      start: async () => { const binding = await proxy.start(); proxyBinding = binding; return binding; },
      close: () => proxy.close()
    },
    verifyEgress: async () => {
      if (!proxyBinding || proxyBinding.address !== BROKER_PROXY_HOST || proxyBinding.port !== BROKER_PROXY_PORT) return false;
      const snapshot = await createCurrentEgressSnapshot({
        proxy: { listening: true, host: proxyBinding.address, port: proxyBinding.port },
        browserExecutablePath: chromium.executablePath(),
        launchOptions: managedBrowserNetworkOptions()
      });
      return egressPreflight(snapshot).status === 'verified';
    },
    createMcp,
    recheckIntervalMs: 30_000
  });
  return lifecycle;
}

function isProductionPolicy(policy: BrokerPolicy): boolean {
  if (policy.refreshOrigins.length > 0) return false;
  const origins = [...policy.loginOrigins.map(({ origin }) => origin), ...policy.targetOrigins];
  if (!origins.length) return false;
  return origins.every((origin) => {
    try { return new URL(origin).protocol === 'https:'; } catch { return false; }
  });
}

function requirePolicy(policy: BrokerPolicy | undefined): BrokerPolicy {
  if (!policy) throw new Error('Policy file is unavailable or stale');
  return policy;
}
