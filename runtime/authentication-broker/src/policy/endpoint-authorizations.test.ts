import assert from 'node:assert/strict';
import test from 'node:test';
import type { BrokerPolicy } from './schema.js';
import { isEndpointAuthorized } from './endpoint-authorizations.js';

const policy = {
  endpointAuthorizations: [{
    accountAlias: 'researcher-a', technique: 'read-only mapping', policyReference: 'rules > account read',
    endpointAuthorizationId: 'account-read', origin: 'https://app.example:443', method: 'GET', path: '/account'
  }]
} as BrokerPolicy;

const exact = {
  accountAlias: 'researcher-a', technique: 'read-only mapping', policyReference: 'rules > account read',
  endpointAuthorizationId: 'account-read', origin: 'https://app.example:443', method: 'GET', path: '/account'
};

test('authorizes only the exact policy endpoint, account, method, origin, path, and source reference', () => {
  assert.equal(isEndpointAuthorized(policy, exact), true);
  for (const change of [
    { accountAlias: 'researcher-b' }, { technique: 'other technique' }, { policyReference: 'other rule' },
    { endpointAuthorizationId: 'admin-read' }, { origin: 'https://other.example:443' },
    { method: 'POST' }, { path: '/admin' }
  ]) assert.equal(isEndpointAuthorized(policy, { ...exact, ...change }), false);
  assert.equal(isEndpointAuthorized(undefined, exact), false);
});
