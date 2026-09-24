import { open, lstat } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';

export interface MetadataFileWriter {
  (jsonLine: string): Promise<void>;
}

export function createMetadataFileWriter(options: { filePath: string; maxBytes?: number }): MetadataFileWriter {
  if (!options || typeof options.filePath !== 'string' || !path.isAbsolute(options.filePath)) {
    throw new Error('Metadata audit path is invalid');
  }
  const maxBytes = options.maxBytes ?? 10 * 1024 * 1024;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1024 || maxBytes > 100 * 1024 * 1024) {
    throw new Error('Metadata audit size limit is invalid');
  }
  let queue = Promise.resolve();

  return (jsonLine: string): Promise<void> => {
    let serializedBytes: Buffer;
    try { serializedBytes = validateJsonLine(jsonLine); } catch (error) { return Promise.reject(error); }
    const operation = queue.then(async () => {
      let existingSize = 0;
      try {
        const entry = await lstat(options.filePath);
        if (!entry.isFile() || entry.isSymbolicLink()) throw new Error('Metadata audit file is unavailable');
        existingSize = entry.size;
      } catch (error) {
        if (!isMissingFile(error)) throw new Error('Metadata audit file is unavailable');
      }
      if (existingSize + serializedBytes.length + 1 > maxBytes) throw new Error('Metadata audit capacity is exhausted');

      let handle: Awaited<ReturnType<typeof open>> | undefined;
      try {
        handle = await open(options.filePath, constants.O_CREAT | constants.O_APPEND | constants.O_WRONLY, 0o600);
        const current = await handle.stat();
        if (!current.isFile() || current.size !== existingSize || current.size + serializedBytes.length + 1 > maxBytes) {
          throw new Error('Metadata audit capacity is exhausted');
        }
        await handle.writeFile(Buffer.concat([serializedBytes, Buffer.from('\n', 'utf8')]));
        await handle.sync();
      } catch {
        throw new Error('Metadata audit write failed');
      } finally {
        try { await handle?.close(); } catch { /* audit remains unavailable */ }
      }
    });
    queue = operation.then(() => undefined, () => undefined);
    return operation;
  };
}

function validateJsonLine(value: unknown): Buffer {
  if (typeof value !== 'string' || !value.length || value.length > 32_768 || /[\r\n]/.test(value)) {
    throw new Error('Metadata audit record is invalid');
  }
  try {
    const parsed: unknown = JSON.parse(value);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('invalid');
  } catch { throw new Error('Metadata audit record is invalid'); }
  return Buffer.from(value, 'utf8');
}

function isMissingFile(error: unknown): boolean {
  return Boolean(error && typeof error === 'object' && 'code' in error && (error as { code?: unknown }).code === 'ENOENT');
}
