import assert from 'node:assert/strict';
import test from 'node:test';

test('counts actual exchanges, releases concurrency slots, and enforces the account budget', async () => {
  const { NetworkRequestBudget } = await import('./network-request-budget.js');
  const budget = new NetworkRequestBudget({ requestsPerSecond: 1, maxConcurrentRequests: 1, maxRequests: 2 });
  const first = await budget.acquire();
  assert.equal(typeof first, 'function');
  assert.deepEqual(budget.snapshot(), { remaining: 1, active: 1, pending: 0 });
  const waiting = budget.acquire();
  first!();
  const second = await waiting;
  assert.equal(typeof second, 'function');
  assert.deepEqual(budget.snapshot(), { remaining: 0, active: 1, pending: 0 });
  second!();
  assert.deepEqual(budget.snapshot(), { remaining: 0, active: 0, pending: 0 });
  assert.equal(await budget.acquire(), undefined);
  budget.close();
});

test('closing the account budget denies and drains requests waiting for the rate token', async () => {
  const { NetworkRequestBudget } = await import('./network-request-budget.js');
  const budget = new NetworkRequestBudget({ requestsPerSecond: 1, maxConcurrentRequests: 1, maxRequests: 3 });
  const first = await budget.acquire();
  assert.equal(typeof first, 'function');
  const pending = budget.acquire();
  budget.close();
  assert.equal(await pending, undefined);
  first!();
  assert.equal(await budget.acquire(), undefined);
  assert.equal(budget.snapshot().active, 0);
});
