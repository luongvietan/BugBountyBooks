import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

type ProfileLockApi = {
  acquireProfileLock: (options: {
    directory: string;
    profileKey: string;
    pid?: number;
    isProcessAlive?: (pid: number) => boolean;
  }) => Promise<{ release: () => Promise<void> }>;
};

async function getApi(): Promise<ProfileLockApi> {
  let module: ProfileLockApi | undefined;
  try { module = await import('./profile-lock.js') as unknown as ProfileLockApi; } catch { module = undefined; }
  assert.equal(typeof module?.acquireProfileLock, 'function', 'exclusive profile lock must be implemented');
  return module!;
}

async function withLockDirectory(run: (directory: string) => Promise<void>): Promise<void> {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'bhs-auth-broker-lock-'));
  try { await run(directory); } finally { await rm(directory, { recursive: true, force: true }); }
}

test('serializes one owner per engagement/account key and releases only its own lock', async () => {
  const { acquireProfileLock } = await getApi();
  await withLockDirectory(async (directory) => {
    const first = await acquireProfileLock({ directory, profileKey: 'engagement-a\u0000researcher-a', pid: 111, isProcessAlive: () => true });
    await assert.rejects(acquireProfileLock({ directory, profileKey: 'engagement-a\u0000researcher-a', pid: 222, isProcessAlive: () => true }), /already in use/i);
    const otherAccount = await acquireProfileLock({ directory, profileKey: 'engagement-a\u0000researcher-b', pid: 222, isProcessAlive: () => true });
    await first.release();
    const replacement = await acquireProfileLock({ directory, profileKey: 'engagement-a\u0000researcher-a', pid: 333, isProcessAlive: () => true });
    await Promise.all([otherAccount.release(), replacement.release()]);
  });
});

test('recovers a valid stale process lock without reading or changing profile data', async () => {
  const { acquireProfileLock } = await getApi();
  await withLockDirectory(async (directory) => {
    await acquireProfileLock({ directory, profileKey: 'engagement-a\u0000researcher-a', pid: 111, isProcessAlive: (pid) => pid !== 111 });
    const recovered = await acquireProfileLock({ directory, profileKey: 'engagement-a\u0000researcher-a', pid: 222, isProcessAlive: (pid) => pid === 222 });
    await recovered.release();
  });
});

test('fails closed when the owner is live or liveness cannot be verified', async () => {
  const { acquireProfileLock } = await getApi();
  await withLockDirectory(async (directory) => {
    await acquireProfileLock({ directory, profileKey: 'engagement-a\u0000researcher-a', pid: 111, isProcessAlive: () => true });
    await assert.rejects(acquireProfileLock({ directory, profileKey: 'engagement-a\u0000researcher-a', pid: 222, isProcessAlive: () => true }), /already in use/i);
    await assert.rejects(acquireProfileLock({ directory, profileKey: 'engagement-a\u0000researcher-a', pid: 333, isProcessAlive: () => { throw new Error('uncertain'); } }), /already in use/i);
  });
});
