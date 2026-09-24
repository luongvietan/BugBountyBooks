# Authentication Broker

Local runtime for reusing researcher-attended target application sessions through bounded MCP tools. Program policy remains the authority; the broker denies missing or ambiguous grants.

## Development

Use a supported Node.js LTS release, install with `npm ci`, then run `npm run typecheck`, `npm run build`, and `npm test`. Browser binaries are installed separately for local mock verification. No command in this package should contact a bounty target during development validation.

The checked-in `examples/broker-policy.example.json` uses synthetic `.example` origins and aliases only. Real `broker-policy.json` files, browser profiles, logs, and evidence are local runtime data, not repository fixtures.

## Current status

This package is being built in phases. Do not use it for target traffic until the egress fence, policy validation, researcher grant surface, and fail-closed acceptance checks are complete.
