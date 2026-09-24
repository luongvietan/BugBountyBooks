import assert from 'node:assert/strict';
import test from 'node:test';
import type { RuntimePaths } from './paths.js';

type PathModule = typeof import('./paths.js');

async function getResolver(): Promise<PathModule['resolveRuntimePaths']> {
  let loaded: PathModule | undefined;
  try {
    loaded = await import('./paths.js');
  } catch {
    loaded = undefined;
  }
  assert.ok(loaded?.resolveRuntimePaths, 'resolveRuntimePaths must be implemented');
  return loaded.resolveRuntimePaths;
}

test('resolves runtime data beneath current-user LocalAppData', async () => {
  const resolveRuntimePaths = await getResolver();
  const paths = resolveRuntimePaths({
    env: { LOCALAPPDATA: 'C:\\Users\\researcher\\AppData\\Local' },
    repositoryRoot: 'C:\\Users\\researcher\\src\\BugBounty',
    oneDriveRoot: 'C:\\Users\\researcher\\OneDrive'
  });

  assert.equal(
    paths.root.toLowerCase(),
    'c:\\users\\researcher\\appdata\\local\\bughuntskills\\authenticationbroker'
  );
  assert.equal(paths.profiles.toLowerCase(), `${paths.root.toLowerCase()}\\profiles`);
  assert.equal(paths.logs.toLowerCase(), `${paths.root.toLowerCase()}\\logs`);
  assert.equal(paths.evidence.toLowerCase(), `${paths.root.toLowerCase()}\\evidence`);
});

test('rejects a LocalAppData root inside the repository', async () => {
  const resolveRuntimePaths = await getResolver();
  assert.throws(() => resolveRuntimePaths({
    env: { LOCALAPPDATA: 'C:\\work\\BugBounty\\.local' },
    repositoryRoot: 'C:\\work\\BugBounty',
    oneDriveRoot: 'C:\\Users\\researcher\\OneDrive'
  }), /outside the repository and OneDrive/);
});

test('rejects LocalAppData traversal into a protected workspace', async () => {
  const resolveRuntimePaths = await getResolver();
  assert.throws(() => resolveRuntimePaths({
    env: { LOCALAPPDATA: 'C:\\Users\\researcher\\AppData\\Local\\..\\..\\OneDrive\\Desktop\\BugBounty' },
    repositoryRoot: 'C:\\Users\\researcher\\OneDrive\\Desktop\\BugBounty',
    oneDriveRoot: 'C:\\Users\\researcher\\OneDrive'
  }), /outside the repository and OneDrive/);
});

test('rejects a LocalAppData root inside OneDrive', async () => {
  const resolveRuntimePaths = await getResolver();
  assert.throws(() => resolveRuntimePaths({
    env: { LOCALAPPDATA: 'C:\\Users\\researcher\\OneDrive\\AppData' },
    repositoryRoot: 'C:\\work\\BugBounty',
    oneDriveRoot: 'C:\\Users\\researcher\\OneDrive'
  }), /outside the repository and OneDrive/);
});

test('rejects a broker root redirected into the repository', async () => {
  const resolveRuntimePaths = await getResolver();
  assert.throws(() => resolveRuntimePaths({
    env: { LOCALAPPDATA: 'C:\\Users\\researcher\\AppData\\Local' },
    repositoryRoot: 'C:\\work\\BugBounty',
    oneDriveRoot: 'C:\\Users\\researcher\\OneDrive',
    canonicalize: (candidate) => candidate.toLowerCase().endsWith('authenticationbroker')
      ? 'C:\\work\\BugBounty\\redirected-broker-root'
      : candidate
  }), /outside the repository and OneDrive/);
});

test('creates only broker-owned directories and applies the private-directory hook', async () => {
  const module = await import('./paths.js') as unknown as Record<string, unknown>;
  assert.equal(typeof module.createRuntimeDirectories, 'function', 'createRuntimeDirectories must be implemented');
  const createRuntimeDirectories = module.createRuntimeDirectories as (
    paths: RuntimePaths,
    adapters: { createDirectory: (directory: string) => void; secureDirectory: (directory: string) => void }
  ) => void;
  const paths = (await getResolver())({
    env: { LOCALAPPDATA: 'C:\\Users\\researcher\\AppData\\Local' },
    repositoryRoot: 'C:\\work\\BugBounty',
    oneDriveRoot: 'C:\\Users\\researcher\\OneDrive'
  });
  const created: string[] = [];
  const secured: string[] = [];

  createRuntimeDirectories(paths, {
    createDirectory: (directory) => created.push(directory),
    secureDirectory: (directory) => secured.push(directory)
  });

  assert.deepEqual(created, [paths.root, paths.profiles, paths.temporary, paths.logs, paths.evidence]);
  assert.deepEqual(secured, created);
});
