import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { normalizeOrigin } from '../policy/origin.js';

export interface PinnedDestination {
  readonly origin: string;
  readonly hostname: string;
  readonly port: number;
  readonly address: string;
  readonly family: 4 | 6;
}

export type AddressResolver = (hostname: string) => Promise<readonly string[]>;

const IPV4_DENY_CIDRS: ReadonlyArray<readonly [string, number]> = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
  ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
];
const IPV6_GLOBAL_UNICAST_START = 0x20000000000000000000000000000000n;
const IPV6_GLOBAL_UNICAST_END = 0x3fffffffffffffffffffffffffffffffn;
const IPV6_SPECIAL_DENY = [
  { base: 0x20010000000000000000000000000000n, prefix: 23 }, // protocol assignments and Teredo
  { base: 0x20010db8000000000000000000000000n, prefix: 32 }, // documentation
  { base: 0x20020000000000000000000000000000n, prefix: 16 }, // 6to4
  { base: 0x3fff0000000000000000000000000000n, prefix: 20 }, // documentation
  { base: 0x0064ff9b000000000000000000000000n, prefix: 96 }, // NAT64 well-known prefix
  { base: 0x0064ff9b000100000000000000000000n, prefix: 48 } // NAT64 local-use prefix
];

export async function resolveAndPinDestination(origin: string, resolver: AddressResolver = systemResolve): Promise<PinnedDestination> {
  let normalized: string;
  let url: URL;
  try {
    normalized = normalizeOrigin(origin);
    if (normalized !== origin) throw new Error('non-canonical');
    url = new URL(origin);
  } catch {
    throw new Error('Destination origin is invalid or unsafe');
  }

  const hostname = url.hostname.toLowerCase();
  if (!hostname.includes('.') || isForbiddenHostname(hostname)) throw new Error('Destination origin is invalid or unsafe');
  let answers: readonly string[];
  try {
    answers = await resolver(hostname);
  } catch {
    throw new Error('Destination resolution failed or is unsafe');
  }
  if (!answers.length || answers.some((address) => isForbiddenAddress(address))) throw new Error('Destination resolution failed or is unsafe');
  const address = answers[0]!;
  const family = isIP(address);
  if (family !== 4 && family !== 6) throw new Error('Destination resolution failed or is unsafe');
  return Object.freeze({
    origin: normalized,
    hostname,
    port: Number(url.port) || (url.protocol === 'https:' ? 443 : 80),
    address,
    family
  });
}

export function isForbiddenAddress(address: string): boolean {
  if (typeof address !== 'string' || address.includes('%')) return true;
  const family = isIP(address);
  if (family === 4) return IPV4_DENY_CIDRS.some(([base, prefix]) => inIpv4Cidr(address, base, prefix));
  if (family !== 6) return true;

  const numeric = ipv6ToBigInt(address);
  if (numeric === undefined) return true;
  if ((numeric >> 32n) === 0xffffn) {
    const embeddedIpv4 = Number(numeric & 0xffffffffn);
    const embedded = [24, 16, 8, 0].map((shift) => (embeddedIpv4 >>> shift) & 0xff).join('.');
    return isForbiddenAddress(embedded);
  }
  if (numeric < IPV6_GLOBAL_UNICAST_START || numeric > IPV6_GLOBAL_UNICAST_END) return true;
  return IPV6_SPECIAL_DENY.some(({ base, prefix }) => inIpv6Cidr(numeric, base, prefix));
}

async function systemResolve(hostname: string): Promise<readonly string[]> {
  const answers = await lookup(hostname, { all: true, verbatim: true });
  return answers.map(({ address }) => address);
}

function isForbiddenHostname(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  return lower === 'localhost' || lower === 'metadata' || lower === 'metadata.google.internal' ||
    lower.endsWith('.localhost') || lower.endsWith('.local') || lower.endsWith('.internal') ||
    lower.endsWith('.home') || lower.endsWith('.lan') || lower.endsWith('.test');
}

function inIpv4Cidr(address: string, base: string, prefix: number): boolean {
  const value = ipv4ToBigInt(address);
  const baseValue = ipv4ToBigInt(base);
  if (value === undefined || baseValue === undefined) return true;
  const shift = BigInt(32 - prefix);
  return (value >> shift) === (baseValue >> shift);
}

function ipv4ToBigInt(address: string): bigint | undefined {
  if (isIP(address) !== 4) return undefined;
  const octets = address.split('.').map(Number);
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return undefined;
  return octets.reduce((value, octet) => (value << 8n) | BigInt(octet), 0n);
}

function ipv6ToBigInt(address: string): bigint | undefined {
  if (isIP(address) !== 6) return undefined;
  let input = address.toLowerCase();
  if (input.includes('.')) {
    const lastColon = input.lastIndexOf(':');
    const ipv4 = ipv4ToBigInt(input.slice(lastColon + 1));
    if (ipv4 === undefined) return undefined;
    const high = Number((ipv4 >> 16n) & 0xffffn).toString(16);
    const low = Number(ipv4 & 0xffffn).toString(16);
    input = `${input.slice(0, lastColon + 1)}${high}:${low}`;
  }
  const halves = input.split('::');
  if (halves.length > 2) return undefined;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fillCount = 8 - left.length - right.length;
  if ((halves.length === 1 && fillCount !== 0) || (halves.length === 2 && fillCount < 1)) return undefined;
  const groups = [...left, ...Array.from({ length: fillCount }, () => '0'), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return undefined;
  return groups.reduce((value, group) => (value << 16n) | BigInt(`0x${group}`), 0n);
}

function inIpv6Cidr(value: bigint, base: bigint, prefix: number): boolean {
  const shift = BigInt(128 - prefix);
  return (value >> shift) === (base >> shift);
}
