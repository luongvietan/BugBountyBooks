import assert from 'node:assert/strict';
import type { IncomingMessage, ServerResponse } from 'node:http';
import test from 'node:test';

type GuardModule = { createMcpLoopbackGuard: (port: number) => (request: IncomingMessage, response: ServerResponse) => boolean };

async function getGuardFactory(): Promise<GuardModule['createMcpLoopbackGuard']> {
  let module: GuardModule | undefined;
  try {
    module = await import('./host-guard.js') as unknown as GuardModule;
  } catch {
    module = undefined;
  }
  assert.equal(typeof module?.createMcpLoopbackGuard, 'function', 'createMcpLoopbackGuard must be implemented');
  return module!.createMcpLoopbackGuard;
}

function fakeExchange(headers: Record<string, string | undefined>): { request: IncomingMessage; response: ServerResponse; status: number | undefined; body: string } {
  let status: number | undefined;
  let body = '';
  const request = { headers } as unknown as IncomingMessage;
  const response = {
    writeHead: (value: number) => { status = value; return response; },
    end: (value?: string) => { body = value ?? ''; return response; }
  } as unknown as ServerResponse;
  return { request, response, get status() { return status; }, get body() { return body; } };
}

test('allows only the bound loopback host and exact browser origin', async () => {
  const createMcpLoopbackGuard = await getGuardFactory();
  const guard = createMcpLoopbackGuard(8765);
  const withoutOrigin = fakeExchange({ host: '127.0.0.1:8765' });
  const withOrigin = fakeExchange({ host: '127.0.0.1:8765', origin: 'http://127.0.0.1:8765' });

  assert.equal(guard(withoutOrigin.request, withoutOrigin.response), true);
  assert.equal(guard(withOrigin.request, withOrigin.response), true);
});

test('rejects remote hosts, wrong ports, and hostile or mismatched origins', async (t) => {
  const createMcpLoopbackGuard = await getGuardFactory();
  const guard = createMcpLoopbackGuard(8765);
  const cases = [
    { host: 'attacker.example:8765' },
    { host: '127.0.0.1:9999' },
    { host: 'localhost:8765' },
    { host: '127.0.0.1:8765', origin: 'http://127.0.0.1:9999' },
    { host: '127.0.0.1:8765', origin: 'https://127.0.0.1:8765' },
    { host: '127.0.0.1:8765', origin: 'null' }
  ];
  for (const headers of cases) {
    await t.test(JSON.stringify(headers), () => {
      const exchange = fakeExchange(headers);
      assert.equal(guard(exchange.request, exchange.response), false);
      assert.equal(exchange.status, 403);
      assert.equal(exchange.body.includes('attacker'), false);
    });
  }
});

test('requires a valid fixed loopback port', async () => {
  const createMcpLoopbackGuard = await getGuardFactory();
  assert.throws(() => createMcpLoopbackGuard(0), /port/);
  assert.throws(() => createMcpLoopbackGuard(65536), /port/);
});
