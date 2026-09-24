import type { BrokerPolicy } from './schema.js';

export interface EndpointAuthorizationRequest {
  readonly accountAlias: string;
  readonly technique: string;
  readonly policyReference: string;
  readonly endpointAuthorizationId: string;
  readonly origin: string;
  readonly method: string;
  readonly path: string;
}

/** Match one exact researcher-authored endpoint record; absent policy always denies. */
export function isEndpointAuthorized(policy: BrokerPolicy | undefined, request: EndpointAuthorizationRequest): boolean {
  if (!policy || !request || typeof request !== 'object') return false;
  return policy.endpointAuthorizations.some((endpoint) => endpoint.accountAlias === request.accountAlias &&
    endpoint.technique === request.technique && endpoint.policyReference === request.policyReference &&
    endpoint.endpointAuthorizationId === request.endpointAuthorizationId && endpoint.origin === request.origin &&
    endpoint.method === request.method && endpoint.path === request.path);
}
