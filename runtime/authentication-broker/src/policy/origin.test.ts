import assert from 'node:assert/strict';
import test from 'node:test';

async function getNormalizer(): Promise<(origin: string) => string> {
  let module: Record<string, unknown> | undefined;
  try {
    module = await import('./origin.js') as unknown as Record<string, unknown>;
  } catch {
    module = undefined;
  }
  const normalizeOrigin = module?.normalizeOrigin;
  assert.equal(typeof normalizeOrigin, 'function', 'normalizeOrigin must be implemented');
  return normalizeOrigin as (origin: string) => string;
}

test('canonicalizes scheme, host casing, and default ports', async () => {
  const normalizeOrigin = await getNormalizer();
  assert.equal(normalizeOrigin('HTTPS://App.Example'), 'https://app.example:443');
  assert.equal(normalizeOrigin('http://APP.example:80'), 'http://app.example:80');
  assert.equal(normalizeOrigin('https://xn--bcher-kva.example:443'), 'https://xn--bcher-kva.example:443');
});

test('rejects non-origin components, wildcard, IP literals, and ambiguous hosts', async (t) => {
  const normalizeOrigin = await getNormalizer();
  const invalidOrigins = [
    'https://*.app.example:443',
    'https://user@app.example:443',
    'https://app.example/path',
    'https://app.example?query=1',
    'https://app.example#fragment',
    'http://127.0.0.1:80',
    'https://[::1]:443',
    'https://app.example:0',
    'https://app.example:65536',
    'https://app.example.:443',
    'https://%61pp.example:443',
    'https://xn--.example:443',
    'https://app.example\\@evil.example:443',
    'ftp://app.example:21'
  ];
  for (const value of invalidOrigins) {
    await t.test(value, () => assert.throws(() => normalizeOrigin(value)));
  }
});

test('does not turn a hostname suffix into an origin match', async () => {
  const normalizeOrigin = await getNormalizer();
  assert.notEqual(normalizeOrigin('https://evilapp.example:443'), normalizeOrigin('https://app.example:443'));
});
