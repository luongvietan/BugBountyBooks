# Authentication Broker

Local Windows runtime for reusing researcher-attended target application sessions through bounded MCP tools. Program policy remains the authority; the broker denies missing or ambiguous grants.

## Development

Use Windows 11 (build 22000 or newer) and a supported Node.js LTS release. Install with `npm ci`, then run `npm run typecheck`, `npm run build`, and `npm test`. Browser binaries are installed separately for local mock verification. No command in this package should contact a bounty target during development validation.

The checked-in `examples/broker-policy.example.json` uses synthetic `.example` origins and aliases only. Real `broker-policy.json` files, browser profiles, logs, and evidence are local runtime data, not repository fixtures.

## Local operation

The runtime binds the worker MCP endpoint and researcher control routes to `127.0.0.1:8765`; its origin-filtering proxy binds to `127.0.0.1:8766`. It starts only when it finds a valid user-authored policy and the current Windows Firewall state verifies the exact Chromium egress fence. It never installs or changes firewall rules at startup.

Before first start, create the private runtime directories and let the broker apply current-user-only directory ACLs. Start once; without a policy it exits safely after directory setup:

```powershell
npm start
```

Create `%LOCALAPPDATA%\BugHuntSkills\AuthenticationBroker\broker-policy.json` from the schema and current program rules. The checked-in example is synthetic and expired; it is not an engagement policy. Runtime target and login origins must be exact HTTPS origins. During attended login, redirects may return to a policy-listed target origin only for GET/HEAD browser requests; POST-based callbacks such as SAML ACS are unsupported and fail closed. `refreshOrigins` must be empty because automatic refresh is not implemented. Endpoint authorizations must name one exact account, technique, source reference, origin, HTTP method, and canonical path.

Install the egress fence as an explicit researcher action from elevated PowerShell, using the exact Chromium executable returned by Playwright. First review `scripts/install-egress-fence.ps1 -ChromiumPath '<exact path>' -WhatIf`; then run the script without `-WhatIf` and inspect its confirmation. Full firewall requirements and removal steps are in [SECURITY.md](./SECURITY.md).

Start again with `npm start`. If the browser profile cannot be proven encrypted and current-user-only, the broker uses an in-memory profile and requires attended login after every restart. Browser launch, MCP listening, and capability grants remain disabled if firewall preflight is absent or uncertain. The broker rechecks the firewall state every 30 seconds; a failed check immediately disables existing capabilities and proxy tunnels.

### Researcher workflow

1. Connect the intended worker to `http://127.0.0.1:8765/mcp` and initialize its MCP session.
2. Read the worker connection IDs from `GET http://127.0.0.1:8765/researcher/connections`.
3. Review the policy and grant that exact connection an account alias, role, tool set, technique, source reference, methods, and origins using `POST /researcher/grant`. The route requires `Origin: http://127.0.0.1:8765` and JSON.
4. Have the worker call `open_login` for a policy-approved login origin. Complete sign-in, MFA, or CAPTCHA in the visible browser yourself. Then explicitly confirm with `POST /researcher/confirm-login` and `{"connectionId":"<id>","confirmed":true}`.
5. Give each engagement/account one active worker connection; use separate accounts and an independent validator for role or ownership comparisons. The account-wide exchange budget covers target browser requests, API requests, and each authorized API redirect hop. It persists across profile close/recreation within the running broker. Worker tool-call limits are also enforced separately.
6. A 401 pauses the session; use `POST /researcher/require-login`, have the worker reopen attended login, and confirm again. A 403 or 429 pauses the session and revokes all capabilities for that engagement/account. Review the program rules and target response, call `POST /researcher/confirm-authorization-review` with `{"connectionId":"<id>","confirmed":true}`, then issue a fresh capability grant before work resumes.
7. `revoke_capability` revokes the shared session for that engagement/account and interrupts its work. Researchers can revoke with `POST /researcher/revoke`; close a managed session with `POST /researcher/close` and `{"connectionId":"<id>","confirmed":true}`. Stop the runtime with Ctrl+C.

Researcher routes are local control endpoints, not worker MCP tools. Send requests from a local attended shell or same-origin researcher client; do not expose port 8765 beyond loopback. The worker MCP surface contains exactly seven tools: `session_status`, `open_login`, `observe_page`, `navigate`, `act_on_observed_element`, `authorized_request`, and `revoke_capability`.

Policy file changes invalidate the running policy and capabilities. Restart the broker to load a corrected policy. The broker never copies a policy from the example, refreshes credentials automatically, retries unknown requests, or bypasses MFA/CAPTCHA. Audit metadata is appended to `%LOCALAPPDATA%\BugHuntSkills\AuthenticationBroker\logs\audit.jsonl`; it contains no request bodies or headers, is capped at 10 MiB, and reaching the cap stops dispatch until the researcher archives it and restarts.
