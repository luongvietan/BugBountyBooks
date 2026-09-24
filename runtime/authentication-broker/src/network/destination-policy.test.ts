import assert from 'node:assert/strict';
import test from 'node:test';

type DestinationApi = {
  resolveAndPinDestination: (origin: string, resolver?: (hostname: string) => Promise<readonly string[]>) => Promise<{
    origin: string; hostname: string; port: number; address: string; family: 4 | 6;
  }>;
  isForbiddenAddress: (address: string) => boolean;
};

async function getDestinationApi(): Promise<DestinationApi> {
  let module: DestinationApi | undefined;
  try { module = await import('./destination-policy.js') as unknown as DestinationApi; } catch { module = undefined; }
  assert.equal(typeof module?.resolveAndPinDestination, 'function', 'destination policy must be implemented');
  assert.equal(typeof module?.isForbiddenAddress, 'function', 'address policy must be implemented');
  return module!;
}

test('resolves once, validates every DNS answer, and returns a pinned public address', async () => {
  const { resolveAndPinDestination } = await getDestinationApi();
  let resolverCalls = 0;
  const result = await resolveAndPinDestination('https://app.example:443', async (hostname) => {
    resolverCalls += 1;
    assert.equal(hostname, 'app.example');
    return ['8.8.8.8', '2001:4860:4860::8888'];
  });
  assert.deepEqual(result, { origin: 'https://app.example:443', hostname: 'app.example', port: 443, address: '8.8.8.8', family: 4 });
  assert.equal(resolverCalls, 1);
});

test('rejects the complete answer set if any DNS answer is private or special-use', async () => {
  const { resolveAndPinDestination } = await getDestinationApi();
  let resolverCalls = 0;
  await assert.rejects(resolveAndPinDestination('https://app.example:443', async () => {
    resolverCalls += 1;
    return ['8.8.8.8', '127.0.0.1'];
  }), /destination/i);
  assert.equal(resolverCalls, 1);
});

test('rejects invalid, local, metadata, and non-canonical origins before DNS lookup', async () => {
  const { resolveAndPinDestination } = await getDestinationApi();
  const inputs = [
    'http://127.0.0.1:80',
    'http://localhost:80',
    'http://service.local:80',
    'http://metadata.google.internal:80',
    'http://single-label:80',
    'https://app.example/path'
  ];
  let resolverCalls = 0;
  for (const input of inputs) {
    await assert.rejects(resolveAndPinDestination(input, async () => { resolverCalls += 1; return ['8.8.8.8']; }), /destination/i);
  }
  assert.equal(resolverCalls, 0);
});

test('rejects IPv4/IPv6 private, loopback, link-local, metadata, multicast, reserved, and documentation ranges', async (t) => {
  const { isForbiddenAddress } = await getDestinationApi();
  const addresses = [
    '0.0.0.0', '10.0.0.1', '100.64.0.1', '127.0.0.1', '169.254.169.254', '172.16.0.1',
    '192.0.2.1', '192.168.1.1', '198.18.0.1', '203.0.113.1', '224.0.0.1', '255.255.255.255',
    '::', '::1', '::ffff:127.0.0.1', 'fc00::1', 'fe80::1', 'ff02::1', '2001:db8::1', '2002::1'
  ];
  for (const address of addresses) {
    await t.test(address, () => assert.equal(isForbiddenAddress(address), true));
  }
});

test('allows representative public IPv4 and IPv6 DNS answers only', async () => {
  const { isForbiddenAddress } = await getDestinationApi();
  assert.equal(isForbiddenAddress('8.8.8.8'), false);
  assert.equal(isForbiddenAddress('1.1.1.1'), false);
  assert.equal(isForbiddenAddress('2001:4860:4860::8888'), false);
});

test('re-resolves on each new connection and rejects a rebinding answer before returning a pin', async () => {
  const { resolveAndPinDestination } = await getDestinationApi();
  let lookupCount = 0;
  const resolver = async () => ++lookupCount === 1 ? ['8.8.8.8'] : ['169.254.169.254'];
  const first = await resolveAndPinDestination('https://app.example:443', resolver);
  assert.equal(first.address, '8.8.8.8');
  await assert.rejects(resolveAndPinDestination('https://app.example:443', resolver), /destination/i);
  assert.equal(lookupCount, 2);
});
