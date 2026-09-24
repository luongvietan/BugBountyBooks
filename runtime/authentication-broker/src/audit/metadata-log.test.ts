import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

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

test('bounds in-memory audit retention while continuing to write each record', async () => {
  const { MetadataAuditLog } = await import('./metadata-log.js');
  const written: string[] = [];
  const audit = new MetadataAuditLog({ write: (line) => { written.push(line); }, retainedRecords: 2 });
  const base = { engagementId: 'engagement-a', connectionId: 'connection-a', accountAlias: 'researcher-a', policyRevision: 'rules-a', method: 'GET', category: 'page-observe', latencyMs: 1 };
  await audit.append({ ...base, decision: 'allow' });
  await audit.append({ ...base, decision: 'result' });
  await audit.append({ ...base, decision: 'unknown' });
  assert.equal(written.length, 3);
  assert.deepEqual(audit.snapshot().map((record) => record.decision), ['result', 'unknown']);
});

test('writes bounded JSONL metadata durably and fails closed at the configured size limit', async (t) => {
  const { createMetadataFileWriter } = await import('./metadata-file.js');
  const directory = await mkdtemp(path.join(os.tmpdir(), 'bhs-audit-writer-'));
  t.after(async () => rm(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, 'audit.jsonl');
  const writer = createMetadataFileWriter({ filePath, maxBytes: 2048 });
  await writer('{"decision":"allow"}');
  const before = await readFile(filePath, 'utf8');
  await writer('{"decision":"result"}');
  const after = await readFile(filePath, 'utf8');
  assert.equal(after.split('\n').filter(Boolean).length, 2);
  assert.ok(Buffer.byteLength(before) < Buffer.byteLength(after));

  const small = createMetadataFileWriter({ filePath: path.join(directory, 'small.jsonl'), maxBytes: 1024 });
  await small('{"decision":"allow"}');
  await assert.rejects(small(`{"padding":"${'x'.repeat(1000)}"}`), /Metadata audit capacity is exhausted/);
  assert.equal((await readFile(path.join(directory, 'small.jsonl'), 'utf8')).trim(), '{"decision":"allow"}');
});

test('rejects non-JSON and multiline audit records before writing', async (t) => {
  const { createMetadataFileWriter } = await import('./metadata-file.js');
  const directory = await mkdtemp(path.join(os.tmpdir(), 'bhs-audit-writer-'));
  t.after(async () => rm(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, 'audit.jsonl');
  const writer = createMetadataFileWriter({ filePath, maxBytes: 2048 });
  await assert.rejects(writer('not json'), /Metadata audit record is invalid/);
  await assert.rejects(writer('{"ok":true}\n{"second":true}'), /Metadata audit record is invalid/);
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
