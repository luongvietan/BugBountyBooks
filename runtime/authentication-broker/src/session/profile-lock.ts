import { randomUUID, createHash } from 'node:crypto';
import { open, lstat, readFile, rename, rm, mkdir, type FileHandle } from 'node:fs/promises';
import path from 'node:path';

interface LockMetadata {
  readonly version: 1;
  readonly pid: number;
  readonly nonce: string;
  readonly createdAtMs: number;
}

export interface ProfileLockOptions {
  directory: string;
  profileKey: string;
  pid?: number;
  /** Test seam. The default treats permission and query errors as a live owner. */
  isProcessAlive?: (pid: number) => boolean;
}

export interface ProfileLockHandle {
  release(): Promise<void>;
}

export async function acquireProfileLock(options: ProfileLockOptions): Promise<ProfileLockHandle> {
  if (typeof options.directory !== 'string' || !path.isAbsolute(options.directory) ||
      typeof options.profileKey !== 'string' || !options.profileKey || Buffer.byteLength(options.profileKey) > 1024) {
    throw new Error('Profile lock parameters are invalid');
  }
  const pid = options.pid ?? process.pid;
  if (!Number.isInteger(pid) || pid < 1 || pid > 2_147_483_647) throw new Error('Profile lock parameters are invalid');
  const lockPath = path.join(path.resolve(options.directory), `${createHash('sha256').update(options.profileKey).digest('hex')}.lock`);
  const nonce = randomUUID();
  const metadata: LockMetadata = Object.freeze({ version: 1, pid, nonce, createdAtMs: Date.now() });
  await mkdir(path.dirname(lockPath), { recursive: true });

  for (let attempt = 0; attempt < 3; attempt += 1) {
    let handle: FileHandle | undefined;
    try {
      handle = await open(lockPath, 'wx', 0o600);
      await handle.writeFile(JSON.stringify(metadata), 'utf8');
      await handle.sync();
      await handle.close();
      return createHandle(lockPath, nonce);
    } catch (error) {
      try { await handle?.close(); } catch { /* best effort after failed create */ }
      if (errorCode(error) !== 'EEXIST') {
        if (handle) {
          try { await rm(lockPath, { force: true }); } catch { /* cleanup only this process's partially created lock */ }
        }
        throw new Error('Unable to acquire profile lock');
      }
      if (!await recoverStaleLock(lockPath, options.isProcessAlive ?? isProcessAlive)) {
        throw new Error('Profile is already in use or its lock cannot be verified');
      }
    }
  }
  throw new Error('Profile is already in use or its lock cannot be verified');
}

function createHandle(lockPath: string, nonce: string): ProfileLockHandle {
  let released = false;
  return {
    async release(): Promise<void> {
      if (released) return;
      let metadata: unknown;
      try { metadata = JSON.parse(await readFile(lockPath, 'utf8')) as unknown; } catch (error) {
        if (errorCode(error) === 'ENOENT') { released = true; return; }
        throw new Error('Unable to release profile lock');
      }
      if (!isLockMetadata(metadata) || metadata.nonce !== nonce) {
        released = true;
        return;
      }
      try { await rm(lockPath); released = true; } catch (error) {
        if (errorCode(error) === 'ENOENT') { released = true; return; }
        throw new Error('Unable to release profile lock');
      }
    }
  };
}

async function recoverStaleLock(lockPath: string, processAlive: (pid: number) => boolean): Promise<boolean> {
  try {
    const file = await lstat(lockPath);
    if (!file.isFile() || file.isSymbolicLink()) return false;
    const raw: unknown = JSON.parse(await readFile(lockPath, 'utf8'));
    if (!isLockMetadata(raw) || raw.createdAtMs > Date.now() + 60_000) return false;
    let alive = true;
    try { alive = processAlive(raw.pid); } catch { alive = true; }
    if (alive) return false;
    const stalePath = `${lockPath}.stale-${randomUUID()}`;
    try { await rename(lockPath, stalePath); } catch (error) {
      return errorCode(error) === 'ENOENT';
    }
    try { await rm(stalePath, { force: true }); } catch { /* stale metadata is harmless outside the active lock name */ }
    return true;
  } catch (error) {
    return errorCode(error) === 'ENOENT';
  }
}

function isLockMetadata(value: unknown): value is LockMetadata {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const candidate = value as Partial<LockMetadata>;
  return candidate.version === 1 && Number.isInteger(candidate.pid) && (candidate.pid ?? 0) > 0 &&
    typeof candidate.nonce === 'string' && candidate.nonce.length > 0 &&
    typeof candidate.createdAtMs === 'number' && Number.isFinite(candidate.createdAtMs) && candidate.createdAtMs > 0;
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return errorCode(error) !== 'ESRCH';
  }
}

function errorCode(error: unknown): string | undefined {
  return error && typeof error === 'object' && 'code' in error && typeof error.code === 'string' ? error.code : undefined;
}
