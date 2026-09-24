import assert from 'node:assert/strict';
import test from 'node:test';

type RegistryApi = {
  ConnectionRegistry: new (options: { identityMode: 'stateful' | 'single-worker' }) => {
    registerSession(sessionId: string): string;
    registerSingleWorkerConnection(): string;
    resolve(sessionId?: string): string | undefined;
    closeSession(sessionId: string): boolean;
    closeSingleWorkerConnection(): boolean;
    onClosed(listener: (connectionId: string) => void): () => void;
    list(): readonly { connectionId: string; openedAtUtc: string }[];
  };
};

async function getRegistry(): Promise<RegistryApi['ConnectionRegistry']> {
  let module: RegistryApi | undefined;
  try {
    module = await import('./connection-registry.js') as unknown as RegistryApi;
  } catch {
    module = undefined;
  }
  assert.equal(typeof module?.ConnectionRegistry, 'function', 'ConnectionRegistry must be implemented');
  return module!.ConnectionRegistry;
}

test('maps server-issued MCP session IDs to opaque admin connection IDs', async () => {
  const ConnectionRegistry = await getRegistry();
  const registry = new ConnectionRegistry({ identityMode: 'stateful' });
  const mcpSessionId = 'server-issued-mcp-session-secret';
  const connectionId = registry.registerSession(mcpSessionId);

  assert.notEqual(connectionId, mcpSessionId);
  assert.equal(registry.resolve(mcpSessionId), connectionId);
  assert.equal(registry.resolve('caller-supplied-id'), undefined);
  assert.equal(JSON.stringify(registry.list()).includes(mcpSessionId), false);
});

test('revokes and forgets a stateful connection when its MCP session closes', async () => {
  const ConnectionRegistry = await getRegistry();
  const registry = new ConnectionRegistry({ identityMode: 'stateful' });
  const connectionId = registry.registerSession('session-to-close');
  const closed: string[] = [];
  registry.onClosed((id) => closed.push(id));

  assert.equal(registry.closeSession('session-to-close'), true);
  assert.equal(registry.closeSession('session-to-close'), false);
  assert.equal(registry.resolve('session-to-close'), undefined);
  assert.deepEqual(closed, [connectionId]);
});

test('fails closed without stateful identity and limits fallback mode to one connection', async () => {
  const ConnectionRegistry = await getRegistry();
  const stateful = new ConnectionRegistry({ identityMode: 'stateful' });
  assert.equal(stateful.resolve(), undefined);

  const fallback = new ConnectionRegistry({ identityMode: 'single-worker' });
  const connectionId = fallback.registerSingleWorkerConnection();
  assert.equal(fallback.resolve(), connectionId);
  assert.equal(fallback.resolve('untrusted-session-value'), connectionId);
  assert.throws(() => fallback.registerSingleWorkerConnection(), /single worker connection/);
  assert.throws(() => fallback.registerSession('unexpected-session'), /stateful identity mode/);
  assert.equal(fallback.closeSingleWorkerConnection(), true);
  assert.equal(fallback.resolve(), undefined);
});
