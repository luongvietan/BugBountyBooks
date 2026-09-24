import { hostHeaderValidation, originValidation } from '@modelcontextprotocol/node';
import type { IncomingMessage, ServerResponse } from 'node:http';

/** Exact-port loopback guard layered over the SDK's hostname/origin checks. */
export function createMcpLoopbackGuard(port: number): (request: IncomingMessage, response: ServerResponse) => boolean {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Loopback port must be between 1 and 65535');
  const sdkHostGuard = hostHeaderValidation(['127.0.0.1']);
  const sdkOriginGuard = originValidation(['127.0.0.1']);
  const expectedHost = `127.0.0.1:${port}`;
  const expectedOrigin = `http://127.0.0.1:${port}`;

  return (request: IncomingMessage, response: ServerResponse): boolean => {
    const rawHost = request.headers.host;
    const rawOrigin = request.headers.origin;
    const host = typeof rawHost === 'string' ? rawHost : undefined;
    const origin = typeof rawOrigin === 'string' ? rawOrigin : undefined;
    if (!host || host !== expectedHost || (rawOrigin !== undefined && origin !== expectedOrigin)) {
      reject(response);
      return false;
    }
    if (!sdkHostGuard(request, response) || !sdkOriginGuard(request, response)) return false;
    return true;
  };
}

function reject(response: ServerResponse): void {
  response.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
  response.end('Forbidden');
}
