export type AuditDecision = 'allow' | 'deny' | 'result' | 'unknown';

export interface MetadataAuditEvent {
  readonly engagementId: string;
  readonly connectionId: string;
  readonly accountAlias: string;
  readonly policyRevision: string;
  readonly origin?: string;
  readonly method: string;
  readonly category: string;
  readonly decision: AuditDecision;
  readonly status?: number;
  readonly latencyMs?: number;
}

export interface MetadataAuditLogOptions {
  readonly write?: (line: string) => void | Promise<void>;
  readonly now?: () => Date;
}

const ALLOWED_KEYS = new Set(['engagementId', 'connectionId', 'accountAlias', 'policyRevision', 'origin', 'method', 'category', 'decision', 'status', 'latencyMs']);

export class MetadataAuditLog {
  private readonly records: Readonly<Record<string, string | number | undefined>>[] = [];
  private readonly write: NonNullable<MetadataAuditLogOptions['write']>;
  private readonly now: () => Date;

  constructor(options: MetadataAuditLogOptions = {}) {
    this.write = options.write ?? (() => undefined);
    this.now = options.now ?? (() => new Date());
  }

  async append(event: unknown): Promise<void> {
    if (!event || typeof event !== 'object' || Array.isArray(event)) throw new Error('Audit metadata is invalid');
    const candidate = event as Record<string, unknown>;
    let keys: string[];
    try { keys = Object.keys(candidate); } catch { throw new Error('Audit metadata is invalid'); }
    if (keys.some((key) => !ALLOWED_KEYS.has(key))) throw new Error('Audit metadata contains a forbidden field');
    if (!validIdentifier(candidate.engagementId, /^[a-zA-Z0-9][a-zA-Z0-9._-]{2,127}$/) ||
        !validIdentifier(candidate.connectionId, /^[A-Za-z0-9._:-]{1,128}$/) ||
        !validIdentifier(candidate.accountAlias, /^[a-z0-9][a-z0-9._-]{0,63}$/) ||
        !validIdentifier(candidate.policyRevision, /^[A-Za-z0-9._:-]{1,128}$/) ||
        typeof candidate.method !== 'string' || !/^[A-Z]{2,16}$/.test(candidate.method) ||
        typeof candidate.category !== 'string' || !/^[a-z][a-z0-9-]{1,63}$/.test(candidate.category) ||
        !['allow', 'deny', 'result', 'unknown'].includes(String(candidate.decision))) throw new Error('Audit metadata is invalid');
    if (candidate.origin !== undefined && (typeof candidate.origin !== 'string' || candidate.origin.length > 512 || !/^https?:\/\/[^/?#]+$/.test(candidate.origin))) {
      throw new Error('Audit metadata origin is invalid');
    }
    if (candidate.status !== undefined && (!Number.isInteger(candidate.status) || Number(candidate.status) < 100 || Number(candidate.status) > 599)) {
      throw new Error('Audit metadata status is invalid');
    }
    if (candidate.latencyMs !== undefined && (!Number.isFinite(candidate.latencyMs) || Number(candidate.latencyMs) < 0 || Number(candidate.latencyMs) > 86_400_000)) {
      throw new Error('Audit metadata latency is invalid');
    }
    const timestamp = this.now();
    if (!Number.isFinite(timestamp.getTime())) throw new Error('Audit metadata clock is invalid');
    const record = Object.freeze({
      timestampUtc: timestamp.toISOString(),
      engagementId: candidate.engagementId as string,
      connectionId: candidate.connectionId as string,
      accountAlias: candidate.accountAlias as string,
      policyRevision: candidate.policyRevision as string,
      ...(candidate.origin !== undefined ? { origin: candidate.origin as string } : {}),
      method: candidate.method,
      category: candidate.category,
      decision: candidate.decision as AuditDecision,
      ...(candidate.status !== undefined ? { status: candidate.status as number } : {}),
      ...(candidate.latencyMs !== undefined ? { latencyMs: candidate.latencyMs as number } : {})
    });
    try { await this.write(JSON.stringify(record)); } catch { throw new Error('Metadata audit write failed'); }
    this.records.push(record);
  }

  snapshot(): readonly Readonly<Record<string, string | number | undefined>>[] {
    return Object.freeze(this.records.map((record) => Object.freeze({ ...record })));
  }
}

function validIdentifier(value: unknown, pattern: RegExp): value is string {
  return typeof value === 'string' && pattern.test(value);
}
