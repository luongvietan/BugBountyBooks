import assert from 'node:assert/strict';
import test from 'node:test';

type ProfileProtectionApi = {
  selectProfileMode: (directory: string, options?: {
    platform?: string;
    inspect?: (directory: string) => Promise<unknown>;
  }) => Promise<{ mode: 'persistent' | 'memory'; reason: string }>;
};

async function getApi(): Promise<ProfileProtectionApi> {
  let module: ProfileProtectionApi | undefined;
  try { module = await import('./profile-protection.js') as unknown as ProfileProtectionApi; } catch { module = undefined; }
  assert.equal(typeof module?.selectProfileMode, 'function', 'profile protection selector must be implemented');
  return module!;
}

test('selects persistent mode only for a fully encrypted volume and an exclusive current-user ACL', async () => {
  const { selectProfileMode } = await getApi();
  const directory = 'C:\\Synthetic\\Broker\\profiles\\account-a';
  const result = await selectProfileMode(directory, {
    platform: 'win32',
    inspect: async (candidate) => {
      assert.equal(candidate, directory);
      return { volumeEncrypted: true, protectionOn: true, encryptionPercent: 100, userOnlyAcl: true };
    }
  });
  assert.deepEqual(result, { mode: 'persistent', reason: 'protection-verified' });
});

test('fails closed to memory mode when any protection evidence is absent, false, or uncertain', async () => {
  const { selectProfileMode } = await getApi();
  const directory = 'C:\\Synthetic\\Broker\\profiles\\account-a';
  for (const evidence of [
    { volumeEncrypted: false, protectionOn: true, encryptionPercent: 100, userOnlyAcl: true },
    { volumeEncrypted: true, protectionOn: false, encryptionPercent: 100, userOnlyAcl: true },
    { volumeEncrypted: true, protectionOn: true, encryptionPercent: 89, userOnlyAcl: true },
    { volumeEncrypted: true, protectionOn: true, encryptionPercent: 100, userOnlyAcl: false },
    { volumeEncrypted: true, protectionOn: true, encryptionPercent: 100 }
  ]) {
    const result = await selectProfileMode(directory, { platform: 'win32', inspect: async () => evidence });
    assert.deepEqual(result, { mode: 'memory', reason: 'protection-unverified' });
  }
  assert.deepEqual(await selectProfileMode(directory, { platform: 'linux' }), { mode: 'memory', reason: 'protection-unverified' });
  assert.deepEqual(await selectProfileMode('\\\\server\\share\\profile', { platform: 'win32', inspect: async () => ({ volumeEncrypted: true, protectionOn: true, encryptionPercent: 100, userOnlyAcl: true }) }), { mode: 'memory', reason: 'protection-unverified' });
  assert.deepEqual(await selectProfileMode(directory, { platform: 'win32', inspect: async () => { throw new Error('secret path or OS detail'); } }), { mode: 'memory', reason: 'protection-unverified' });
});

test('protection decisions never echo the profile path or command output', async () => {
  const { selectProfileMode } = await getApi();
  const directory = 'C:\\Synthetic\\private-account-profile';
  const result = await selectProfileMode(directory, { platform: 'win32', inspect: async () => 'secret command output' });
  assert.equal(JSON.stringify(result).includes('private-account-profile'), false);
  assert.equal(JSON.stringify(result).includes('secret'), false);
});
