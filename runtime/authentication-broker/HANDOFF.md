# Authentication Broker — handoff status

Updated: 2026-09-24
Working branch: `codex/authentication-broker`

## Completed

- Added the local Authentication Broker runtime, researcher control routes,
  policy/schema validation, metadata-only audit, pinned-origin proxy, isolated
  browser sessions, and seven bounded worker MCP tools.
- Bound grants to one worker per engagement/account. Browser exchanges,
  API calls, and each approved API redirect hop share an account budget that
  persists across profile recreation during the broker process lifetime.
- Added response streaming limits and immediate 401/403/429 handling. A 401
  requires attended sign-in; a 403/429 pauses the session, revokes account
  capabilities, and requires researcher review followed by a fresh grant.
- Updated the local `bug-bounty-hunter` and `computer-use` skill instructions.
  Those files live outside this repository and are not part of the Git push.
- All exercised targets and responses are synthetic. No live program or target
  was contacted.

## Still requires a researcher

- Install and verify the exact Chromium egress firewall fence on the host.
  The runtime intentionally fails closed until current Windows firewall state
  and the exact local proxy listener pass preflight. Review the script's
  `-WhatIf` output before applying firewall changes.
- Create a current `broker-policy.json` from a real program's written rules.
  The checked-in example is synthetic and expired; it does not authorize a
  target.
- Complete the first visible researcher login and any MFA/CAPTCHA, then
  confirm the exact worker connection. Review any 403/429 before resuming.
- Live-host behavior, actual program policy, persistent-profile encryption,
  and real target behavior were not verified in this implementation task.

## Verification

Final local verification used Node 24:

- `npm ci` — completed; 0 vulnerabilities reported.
- `npm run typecheck` — passed.
- `npm run build` — passed.
- `npm test` — 195 passed, 0 failed.
- `git diff --check` — passed (Git printed only line-ending normalization notices).

The feature branch `codex/authentication-broker` has been pushed to the personal
fork remote (`myfork`), and the remote HEAD was verified to match local HEAD.
No pull request has been created.

```powershell
npm ci
npm run typecheck
npm run build
npm test
```

The test suite uses synthetic fixtures and local loopback servers only. Keep
the local skill edits in place when continuing on this same host; on another
host, transfer or reapply those two skill changes separately because they are
outside the repository.
