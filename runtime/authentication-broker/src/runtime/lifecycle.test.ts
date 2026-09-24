import assert from 'node:assert/strict';
import test from 'node:test';

test('does not create or listen to MCP unless the proxy and egress preflight are verified', async () => {
  const { createBrokerLifecycle } = await import('./lifecycle.js');
  let proxyClosed = false;
  let mcpCreated = false;
  const lifecycle = createBrokerLifecycle({
    proxy: { start: async () => ({ address: '127.0.0.1', port: 8766 }), close: async () => { proxyClosed = true; } },
    verifyEgress: async () => false,
    createMcp: async () => { mcpCreated = true; return { listen: async () => ({ host: '127.0.0.1', port: 8765 }), close: async () => undefined }; }
  });
  await assert.rejects(lifecycle.start(), /Egress protection is not verified/);
  assert.equal(proxyClosed, true);
  assert.equal(mcpCreated, false);
  assert.equal(lifecycle.isEgressVerified(), false);
});

test('requires the exact proxy and MCP loopback listeners and disables egress immediately on failed recheck', async (t) => {
  const { createBrokerLifecycle } = await import('./lifecycle.js');
  const states = [true, false, true];
  let checks = 0;
  let appClosed = false;
  let proxyClosed = false;
  const lifecycle = createBrokerLifecycle({
    proxy: { start: async () => ({ address: '127.0.0.1', port: 8766 }), close: async () => { proxyClosed = true; } },
    verifyEgress: async () => states[checks++] === true,
    createMcp: async () => ({ listen: async () => ({ host: '127.0.0.1', port: 8765 }), close: async () => { appClosed = true; } }),
    recheckIntervalMs: 60_000
  });
  await lifecycle.start();
  t.after(async () => { if (lifecycle.isStarted()) await lifecycle.close(); });
  assert.equal(lifecycle.isEgressVerified(), true);
  assert.equal(await lifecycle.refreshEgress(), false);
  assert.equal(lifecycle.isEgressVerified(), false);
  assert.equal(await lifecycle.refreshEgress(), true);
  assert.equal(lifecycle.isEgressVerified(), true);
  await lifecycle.close();
  assert.equal(appClosed, true);
  assert.equal(proxyClosed, true);
});

test('closes the proxy when its listener or MCP binding is not exact loopback', async () => {
  const { createBrokerLifecycle } = await import('./lifecycle.js');
  let proxyClosed = false;
  let mcpCreated = false;
  const badProxy = createBrokerLifecycle({
    proxy: { start: async () => ({ address: '0.0.0.0', port: 8766 }), close: async () => { proxyClosed = true; } },
    verifyEgress: async () => true,
    createMcp: async () => { mcpCreated = true; return { listen: async () => ({ host: '127.0.0.1', port: 8765 }), close: async () => undefined }; }
  });
  await assert.rejects(badProxy.start(), /Broker proxy listener is not exact loopback/);
  assert.equal(proxyClosed, true);
  assert.equal(mcpCreated, false);

  const badMcp = createBrokerLifecycle({
    proxy: { start: async () => ({ address: '127.0.0.1', port: 8766 }), close: async () => undefined },
    verifyEgress: async () => true,
    createMcp: async () => ({ listen: async () => ({ host: '0.0.0.0', port: 8765 }), close: async () => undefined })
  });
  await assert.rejects(badMcp.start(), /MCP listener is not exact loopback/);
  assert.equal(badMcp.isEgressVerified(), false);
});
