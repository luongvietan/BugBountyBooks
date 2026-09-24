import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';

const ORIGIN_INPUT = /^(https?):\/\/([^/?#]+)$/i;
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export function normalizeOrigin(input: string): string {
  if (typeof input !== 'string' || /[\u0000-\u0020\u007f%\\]/.test(input)) {
    throw new Error('Origin must be a valid HTTP(S) origin');
  }

  const match = ORIGIN_INPUT.exec(input);
  if (!match) throw new Error('Origin must be a valid HTTP(S) origin');

  const scheme = match[1]!.toLowerCase();
  const authority = match[2]!;
  if (authority.includes('@') || authority.includes('*') || authority.includes('[') || authority.includes(']')) {
    throw new Error('Origin must be a valid HTTP(S) origin');
  }

  const portSeparator = authority.lastIndexOf(':');
  const rawHost = portSeparator < 0 ? authority : authority.slice(0, portSeparator);
  const rawPort = portSeparator < 0 ? undefined : authority.slice(portSeparator + 1);
  if (!rawHost || rawHost.endsWith('.') || rawHost.startsWith('.') || rawHost.includes('..')) {
    throw new Error('Origin must be a valid HTTP(S) origin');
  }
  if (rawPort !== undefined && (!/^\d{1,5}$/.test(rawPort) || (rawPort.length > 1 && rawPort.startsWith('0')))) {
    throw new Error('Origin must be a valid HTTP(S) origin');
  }

  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    throw new Error('Origin must be a valid HTTP(S) origin');
  }

  const host = domainToASCII(parsed.hostname.toLowerCase());
  if (!host || host.length > 253 || host.endsWith('.') || isIP(host) !== 0) {
    throw new Error('Origin must be a valid HTTP(S) origin');
  }
  if (!host.split('.').every((label) => DNS_LABEL.test(label))) {
    throw new Error('Origin must be a valid HTTP(S) origin');
  }

  const port = rawPort === undefined ? (scheme === 'https' ? 443 : 80) : Number(rawPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('Origin must be a valid HTTP(S) origin');
  }

  return `${scheme}://${host}:${port}`;
}
