import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

test('serves a validated current policy and revokes it permanently when its file changes', async (t) => {
  const { createPolicyProvider } = await import('./policy-provider.js');
  const directory = await mkdtemp(path.join(os.tmpdir(), 'bhs-policy-provider-'));
  t.after(async () => rm(directory, { recursive: true, force: true }));
  const policyPath = path.join(directory, 'broker-policy.json');
  const examplePath = new URL('../../examples/broker-policy.example.json', import.meta.url);
  const example = JSON.parse(await readFile(examplePath, 'utf8')) as Record<string, unknown>;
  const snapshot = example.policySnapshot as Record<string, unknown>;
  snapshot.capturedAtUtc = '2026-09-24T01:00:00Z';
  snapshot.freshUntilUtc = '2026-09-24T07:00:00Z';
  (example.limits as Record<string, unknown>).expiresAtUtc = '2026-09-24T07:00:00Z';
  await writeFile(policyPath, JSON.stringify(example), 'utf8');
  const provider = await createPolicyProvider({ filePath: policyPath, now: () => new Date('2026-09-24T02:00:00Z') });

  assert.equal(provider.getPolicy('synthetic-demo-2026-09-24')?.policySnapshot.revision, 'synthetic revision');
  assert.equal(provider.getPolicy('other-engagement'), undefined);
  await writeFile(policyPath, `${JSON.stringify(example)}\n`, 'utf8');
  assert.equal(provider.getPolicy('synthetic-demo-2026-09-24'), undefined);
  await writeFile(policyPath, JSON.stringify(example), 'utf8');
  assert.equal(provider.getPolicy('synthetic-demo-2026-09-24'), undefined, 'policy changes require a broker restart');
});

test('fails generically when the policy file is missing or invalid', async (t) => {
  const { createPolicyProvider } = await import('./policy-provider.js');
  const directory = await mkdtemp(path.join(os.tmpdir(), 'bhs-policy-provider-'));
  t.after(async () => rm(directory, { recursive: true, force: true }));
  await assert.rejects(createPolicyProvider({ filePath: path.join(directory, 'missing.json') }), /Policy file is unavailable or invalid/);
  const invalidPath = path.join(directory, 'invalid.json');
  await writeFile(invalidPath, '{invalid', 'utf8');
  await assert.rejects(createPolicyProvider({ filePath: invalidPath }), /Policy file is unavailable or invalid/);
});
