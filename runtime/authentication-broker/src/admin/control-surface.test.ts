import assert from 'node:assert/strict';
import test from 'node:test';

type AdminModule = {
  ResearcherControlSurface: new(options: {
    registry: unknown;
    capabilities: unknown;
    closeSession: (connectionId: string) => boolean | Promise<boolean>;
  }) => {
    listConnections(): readonly { connectionId: string; openedAtUtc: string; accountAlias?: string }[];
    grant(input: { connectionId: string; accountAlias: string; role: 'mapper' | 'tester' | 'validator'; tools: string[]; technique: string; policyReference: string; methods: string[]; origins: string[] }): unknown;
    revoke(connectionId: string): boolean;
    closeSession(connectionId: string, confirmed: boolean): Promise<boolean>;
  };
};

async function getAdminSurface(): Promise<AdminModule['ResearcherControlSurface']> {
  let module: AdminModule | undefined;
  try {
    module = await import('./control-surface.js') as unknown as AdminModule;
  } catch {
    module = undefined;
  }
  assert.equal(typeof module?.ResearcherControlSurface, 'function', 'ResearcherControlSurface must be implemented');
  return module!.ResearcherControlSurface;
}

test('researcher surface lists opaque connections and delegates only explicit grant or revoke', async () => {
  const ResearcherControlSurface = await getAdminSurface();
  const opaque = 'server-created-connection-id';
  const calls: unknown[] = [];
  const registry = {
    list: () => [{ connectionId: opaque, openedAtUtc: '2026-09-24T02:00:00.000Z' }],
    closeConnection: (connectionId: string) => connectionId === opaque
  };
  const capabilities = {
    grant: (input: unknown) => { calls.push(['grant', input]); return { ok: true }; },
    revoke: (connectionId: string) => { calls.push(['revoke', connectionId]); return connectionId === opaque; },
    accountAliasFor: () => undefined
  };
  const surface = new ResearcherControlSurface({ registry, capabilities, closeSession: (id) => registry.closeConnection(id) });

  assert.deepEqual(surface.listConnections(), [{ connectionId: opaque, openedAtUtc: '2026-09-24T02:00:00.000Z' }]);
  assert.equal(JSON.stringify(surface.listConnections()).includes('session-token'), false);
  assert.deepEqual(surface.grant({ connectionId: opaque, accountAlias: 'researcher-a', role: 'tester', tools: ['authorized_request'], technique: 'read-only mapping', policyReference: 'Synthetic rules > mapping', methods: ['GET'], origins: ['https://app.example:443'] }), { ok: true });
  assert.equal(surface.revoke(opaque), true);
  assert.equal(calls.length, 2);
});

test('requires deliberate confirmation before closing a session', async () => {
  const ResearcherControlSurface = await getAdminSurface();
  let closeCalls = 0;
  const registry = { list: () => [], closeConnection: () => { closeCalls += 1; return true; } };
  const capabilities = { grant: () => undefined, revoke: () => true, accountAliasFor: () => undefined };
  const surface = new ResearcherControlSurface({ registry, capabilities, closeSession: () => { closeCalls += 1; return true; } });

  assert.equal(await surface.closeSession('opaque-id', false), false);
  assert.equal(closeCalls, 0);
  assert.equal(await surface.closeSession('opaque-id', true), true);
  assert.equal(closeCalls, 1);
});
