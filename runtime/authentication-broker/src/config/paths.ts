import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, realpathSync } from 'node:fs';
import * as path from 'node:path';

export interface RuntimePathOptions {
  env?: NodeJS.ProcessEnv;
  repositoryRoot: string;
  oneDriveRoot?: string;
  canonicalize?: (candidate: string) => string;
}

export interface RuntimePaths {
  root: string;
  profiles: string;
  temporary: string;
  logs: string;
  evidence: string;
}

export interface RuntimeDirectoryAdapters {
  createDirectory?: (directory: string) => void;
  secureDirectory?: (directory: string) => void;
}

export function resolveRuntimePaths(options: RuntimePathOptions): RuntimePaths {
  const env = options.env ?? process.env;
  const localAppData = env.LOCALAPPDATA;
  if (!localAppData || !path.isAbsolute(localAppData)) {
    throw new Error('LOCALAPPDATA must be an absolute path');
  }

  const canonicalize = options.canonicalize ?? canonicalizeExistingPath;
  const root = canonicalize(path.join(localAppData, 'BugHuntSkills', 'AuthenticationBroker'));
  const boundaries = [options.repositoryRoot];
  const configuredOneDrive = [options.oneDriveRoot, env.OneDrive, env.OneDriveCommercial, env.OneDriveConsumer]
    .filter((value): value is string => Boolean(value && path.isAbsolute(value)));
  boundaries.push(...configuredOneDrive);
  const inferredOneDrive = inferOneDriveRoot(options.repositoryRoot);
  if (inferredOneDrive) boundaries.push(inferredOneDrive);

  if (boundaries.some((boundary) => isWithin(canonicalize(boundary), root))) {
    throw new Error('Broker runtime data must be outside the repository and OneDrive');
  }

  return {
    root,
    profiles: path.join(root, 'profiles'),
    temporary: path.join(root, 'temporary'),
    logs: path.join(root, 'logs'),
    evidence: path.join(root, 'evidence')
  };
}

export function createRuntimeDirectories(
  paths: RuntimePaths,
  adapters: RuntimeDirectoryAdapters = {}
): void {
  const directories = [paths.root, paths.profiles, paths.temporary, paths.logs, paths.evidence];
  const createDirectory = adapters.createDirectory ?? ((directory) => mkdirSync(directory, { recursive: true }));
  const secureDirectory = adapters.secureDirectory ?? secureCurrentUserDirectory;

  for (const directory of directories) {
    createDirectory(directory);
    secureDirectory(directory);
  }
}

function isWithin(boundary: string, candidate: string): boolean {
  const relative = path.relative(boundary, candidate);
  return relative === '' || (
    relative !== '..' &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

function inferOneDriveRoot(repositoryRoot: string): string | undefined {
  const resolved = path.resolve(repositoryRoot);
  const { root } = path.parse(resolved);
  const segments = path.relative(root, resolved).split(path.sep).filter(Boolean);
  const index = segments.findIndex((segment) => segment.toLowerCase().startsWith('onedrive'));
  return index < 0 ? undefined : path.join(root, ...segments.slice(0, index + 1));
}

function canonicalizeExistingPath(candidate: string): string {
  let existing = path.resolve(candidate);
  const tail: string[] = [];
  while (!existsSync(existing)) {
    const parent = path.dirname(existing);
    if (parent === existing) {
      throw new Error('Unable to resolve broker runtime path');
    }
    tail.unshift(path.basename(existing));
    existing = parent;
  }

  try {
    return path.resolve(realpathSync.native(existing), ...tail);
  } catch {
    throw new Error('Unable to resolve broker runtime path');
  }
}

function secureCurrentUserDirectory(directory: string): void {
  if (process.platform !== 'win32') return;

  const account = process.env.USERDOMAIN && process.env.USERNAME
    ? `${process.env.USERDOMAIN}\\${process.env.USERNAME}`
    : process.env.USERNAME;
  if (!account) throw new Error('Unable to secure broker runtime directory');

  try {
    execFileSync('icacls.exe', [directory, '/inheritance:r', '/grant:r', `${account}:(OI)(CI)F`], {
      stdio: 'ignore',
      windowsHide: true
    });
  } catch {
    throw new Error('Unable to secure broker runtime directory');
  }
}
