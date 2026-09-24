import assert from 'node:assert/strict';
import type { Socket } from 'node:net';
import test from 'node:test';

type DnsPinApi = {
  connectToPinnedAddress: (destination: { origin: string; hostname: string; address: string; port: number; family: 4 | 6 }, connector?: { connect: (options: { host: string; port: number; family: 4 | 6 }) => Socket }) => Socket;
};

async function getDnsPinApi(): Promise<DnsPinApi> {
  let module: DnsPinApi | undefined;
  try { module = await import('./dns-pin.js') as unknown as DnsPinApi; } catch { module = undefined; }
  assert.equal(typeof module?.connectToPinnedAddress, 'function', 'pinned connector must be implemented');
  return module!;
}

test('connects to the validated numeric pin rather than resolving the hostname again', async () => {
  const { connectToPinnedAddress } = await getDnsPinApi();
  let options: unknown;
  const socket = {} as Socket;
  const returned = connectToPinnedAddress({ origin: 'https://app.example:443', hostname: 'app.example', address: '8.8.8.8', port: 443, family: 4 }, {
    connect: (value) => { options = value; return socket; }
  });
  assert.equal(returned, socket);
  assert.deepEqual(options, { host: '8.8.8.8', port: 443, family: 4 });
});

test('refuses a forged or private numeric pin even when a connector seam is supplied', async () => {
  const { connectToPinnedAddress } = await getDnsPinApi();
  let connectCalls = 0;
  assert.throws(() => connectToPinnedAddress({
    origin: 'https://app.example:443', hostname: 'app.example', address: '127.0.0.1', port: 443, family: 4
  }, {
    connect: () => { connectCalls += 1; return {} as Socket; }
  }), /pinned destination/i);
  assert.equal(connectCalls, 0);
});

test('refuses a forged pin whose origin, hostname, or port do not agree before connecting', async () => {
  const { connectToPinnedAddress } = await getDnsPinApi();
  let connectCalls = 0;
  for (const destination of [
    { origin: 'https://evil.example:443', hostname: 'app.example', address: '8.8.8.8', port: 443, family: 4 as const },
    { origin: 'https://app.example:443', hostname: 'evil.example', address: '8.8.8.8', port: 443, family: 4 as const },
    { origin: 'https://app.example:444', hostname: 'app.example', address: '8.8.8.8', port: 443, family: 4 as const }
  ]) {
    assert.throws(() => connectToPinnedAddress(destination, {
      connect: () => { connectCalls += 1; return {} as Socket; }
    }), /pinned destination/i);
  }
  assert.equal(connectCalls, 0);
});
