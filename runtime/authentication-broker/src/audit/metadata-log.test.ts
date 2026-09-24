import assert from 'node:assert/strict';
import test from 'node:test';

type AuditApi = {
  MetadataAuditLog: new (options?: { write?: (line: string) => void | Promise<void>; now?: () => Date }) => {
    append(event: unknown): Promise<void>;
    snapshot(): readonly unknown[];
  };
};

async function getApi(): Promise<AuditApi> {
  let module: AuditApi | undefined;
  try { module = await import('./metadata-log.js') as unknown as AuditApi; } catch { module = undefined; }
  assert.equal(typeof module?.MetadataAuditLog, 'function', 'metadata-only audit log must be implemented');
  return module!;
}

test('records only bounded request metadata and never stores bodies or headers', async () => {
  const { MetadataAuditLog } = await getApi();
  const written: string[] = [];
  const audit = new MetadataAuditLog({ now: () => new Date('2026-09-24T02:00:00.000Z'), write: (line) => { written.push(line); } });
  await audit.append({
    engagementId: 'synthetic-demo-2026-09-24', connectionId: 'opaque-connection-1', accountAlias: 'researcher-a',
    policyRevision: 'rules-r1', origin: 'https://app.example:443', method: 'GET', category: 'page-observation',
    decision: 'allow', status: 200, latencyMs: 13
  });
  assert.equal(written.length, 1);
  assert.deepEqual(JSON.parse(written[0]!), {
    timestampUtc: '2026-09-24T02:00:00.000Z', engagementId: 'synthetic-demo-2026-09-24', connectionId: 'opaque-connection-1',
    accountAlias: 'researcher-a', policyRevision: 'rules-r1', origin: 'https://app.example:443', method: 'GET',
    category: 'page-observation', decision: 'allow', status: 200, latencyMs: 13
  });
});

test('rejects accidental secret, body, header, and unknown metadata before writing', async () => {
  const { MetadataAuditLog } = await getApi();
  const written: string[] = [];
  const audit = new MetadataAuditLog({ write: (line) => { written.push(line); } });
  for (const extra of [
    { body: 'synthetic-body-secret' }, { headers: { authorization: 'Bearer synthetic-token' } },
    { cookie: 'synthetic-cookie-secret' }, { rawResponse: { body: 'secret' } }, { arbitrary: 'unknown' }
  ]) {
    await assert.rejects(audit.append({
      engagementId: 'synthetic-demo-2026-09-24', connectionId: 'opaque-connection-1', accountAlias: 'researcher-a',
      policyRevision: 'rules-r1', method: 'GET', category: 'authorized-request', decision: 'deny', ...extra
    }), /metadata/i);
  }
  assert.equal(written.length, 0);
  assert.deepEqual(audit.snapshot(), []);
});
