import { createConnection, isIP, type Socket } from 'node:net';
import { normalizeOrigin } from '../policy/origin.js';
import { isForbiddenAddress, type PinnedDestination } from './destination-policy.js';

export interface PinnedConnector {
  connect(options: { host: string; port: number; family: 4 | 6 }): Socket;
}

/** Dials only the numeric address that was just validated; it never re-resolves hostname. */
export function connectToPinnedAddress(destination: PinnedDestination, connector: PinnedConnector = { connect: createConnection }): Socket {
  const family = isIP(destination.address);
  if ((family !== 4 && family !== 6) || family !== destination.family || !Number.isInteger(destination.port) || destination.port < 1 || destination.port > 65535) {
    throw new Error('Pinned destination is invalid');
  }
  let parsedOrigin: URL;
  try {
    if (normalizeOrigin(destination.origin) !== destination.origin) throw new Error('non-canonical');
    parsedOrigin = new URL(destination.origin);
  } catch {
    throw new Error('Pinned destination is invalid');
  }
  const expectedPort = Number(parsedOrigin.port) || (parsedOrigin.protocol === 'https:' ? 443 : 80);
  if ((parsedOrigin.protocol !== 'http:' && parsedOrigin.protocol !== 'https:') ||
    parsedOrigin.hostname.toLowerCase() !== destination.hostname || expectedPort !== destination.port ||
    destination.hostname !== destination.hostname.toLowerCase() || !destination.hostname.includes('.') || isIP(destination.hostname) !== 0) {
    throw new Error('Pinned destination is invalid');
  }
  if (isForbiddenAddress(destination.address)) throw new Error('Pinned destination is invalid');
  return connector.connect({ host: destination.address, port: destination.port, family: destination.family });
}
