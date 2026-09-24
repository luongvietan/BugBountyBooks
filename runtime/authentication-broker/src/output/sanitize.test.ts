import assert from 'node:assert/strict';
import test from 'node:test';

type SanitizerApi = {
  createOutputSanitizer: (options?: { secrets?: readonly string[]; maxStringChars?: number; maxDepth?: number }) => {
    sanitize(value: unknown): unknown;
    sanitizeText(value: string): string;
  };
};

async function getApi(): Promise<SanitizerApi> {
  let module: SanitizerApi | undefined;
  try { module = await import('./sanitize.js') as unknown as SanitizerApi; } catch { module = undefined; }
  assert.equal(typeof module?.createOutputSanitizer, 'function', 'central output sanitizer must be implemented');
  return module!;
}

test('redacts credential headers, sensitive fields, secret query values, tokens, and configured researcher values', async () => {
  const { createOutputSanitizer } = await getApi();
  const sanitize = createOutputSanitizer({ secrets: ['synthetic-researcher-secret'], maxStringChars: 2048 });
  const value = {
    headers: {
      authorization: 'Bearer synthetic-bearer-secret',
      COOKIE: 'session=synthetic-cookie-secret',
      'Set-Cookie': 'refresh=synthetic-refresh-secret; HttpOnly',
      'X-Trace': 'safe'
    },
    password: 'synthetic-password-secret',
    researcherNote: 'synthetic-researcher-secret',
    url: 'https://app.example/account?token=synthetic-query-secret&view=compact',
    body: 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.signature synthetic-researcher-secret'
  };
  const result = JSON.stringify(sanitize.sanitize(value));
  for (const canary of ['synthetic-bearer-secret', 'synthetic-cookie-secret', 'synthetic-refresh-secret', 'synthetic-password-secret',
    'synthetic-researcher-secret', 'synthetic-query-secret', 'eyJhbGciOiJIUzI1NiJ9']) {
    assert.equal(result.includes(canary), false, `sanitized result leaked ${canary}`);
  }
  assert.equal(result.includes('safe'), true);
  assert.equal(result.toLowerCase().includes('set-cookie'), false);
});

test('sanitizes errors and evidence with depth and length bounds', async () => {
  const { createOutputSanitizer } = await getApi();
  const sanitize = createOutputSanitizer({ maxStringChars: 32, maxDepth: 2 });
  const error = sanitize.sanitizeText('request failed with password=hunter2 and details '.repeat(10));
  assert.ok(error.length <= 32);
  assert.equal(error.includes('hunter2'), false);
  const result = sanitize.sanitize({ evidence: { nested: { tooDeep: 'do not copy' } } }) as Record<string, unknown>;
  assert.equal(JSON.stringify(result).includes('do not copy'), false);
});
