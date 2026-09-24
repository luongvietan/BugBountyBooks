import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import type { BrokerPolicy } from './schema.js';
import { loadPolicy } from './load-policy.js';

export interface PolicyProvider {
  readonly filePath: string;
  getPolicy(engagementId?: string): BrokerPolicy | undefined;
}

export async function createPolicyProvider(options: {
  readonly filePath: string;
  readonly now?: () => Date;
}): Promise<PolicyProvider> {
  if (!options || typeof options.filePath !== 'string' || !options.filePath) throw new Error('Policy file is unavailable or invalid');
  const now = options.now ?? (() => new Date());
  let initialBytes: Buffer;
  try {
    const info = lstatSync(options.filePath);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error('invalid');
    initialBytes = readFileSync(options.filePath);
  } catch { throw new Error('Policy file is unavailable or invalid'); }
  const policy = await loadPolicy(options.filePath, now());
  const initialDigest = digest(initialBytes);
  let invalidated = false;

  return Object.freeze({
    filePath: options.filePath,
    getPolicy(engagementId?: string): BrokerPolicy | undefined {
      if (invalidated) return undefined;
      let currentBytes: Buffer;
      try {
        const info = lstatSync(options.filePath);
        if (!info.isFile() || info.isSymbolicLink()) { invalidated = true; return undefined; }
        currentBytes = readFileSync(options.filePath);
      } catch { invalidated = true; return undefined; }
      if (digest(currentBytes) !== initialDigest) { invalidated = true; return undefined; }
      if (engagementId !== undefined && engagementId !== policy.engagementId) return undefined;
      return policy as unknown as BrokerPolicy;
    }
  });
}

function digest(value: Buffer): string {
  return createHash('sha256').update(value).digest('hex');
}
