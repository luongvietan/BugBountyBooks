# Shared Authentication Broker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` for inline execution. Use `subagent-driven-development` only if the user explicitly selects delegated execution. Do not begin implementation until the user approves this plan and selects an execution method.

**Goal:** Implement a Windows-local broker that lets researcher-approved workers use isolated, researcher-authenticated application sessions through bounded browser and API tools, without exposing credentials or allowing target traffic outside an explicit current policy.

**Architecture:** Add a standalone TypeScript/Node runtime under `runtime/authentication-broker/`. One broker process owns private per-engagement/account Playwright contexts, a strict policy and capability guard, an origin-filtering CONNECT proxy, a loopback MCP server, a researcher-only local control surface, and redacted output/audit paths. Persistent profiles are enabled only when local OS volume protection is verified; otherwise use in-memory contexts and require sign-in after restart. Worker connections start without capability. The hunter skill prepares policy; the computer-use skill only helps the researcher operate the attended sign-in window. If the host cannot prove connection identity or enforce browser egress through the proxy, disable parallel or all target capabilities as appropriate.

**Tech Stack:** Windows 11; Node.js current LTS (confirm the MCP SDK's supported engine at implementation time); TypeScript ESM; official MCP TypeScript server SDK with stateful Streamable HTTP; Playwright Chromium; schema validation with a pinned library; Node `node:test` for local-only unit and integration tests; PowerShell for Windows egress-fence setup and preflight. npm lockfile records exact versions. The mock target is loopback-only and uses synthetic accounts/data.

**Spec:** `docs/superpowers/specs/2026-09-24-authentication-broker-design.md`

The runtime and skill updates stay in one plan because they share the policy schema, tool boundary, and session lifecycle; implementing them as separate plans risks documenting capabilities the runtime does not enforce.

## Global Constraints

- The approved program policy and human-reviewed scope contract are the authority. The broker enforces an explicit, fresh `broker-policy.json`; it never infers authorization from safe harbor, discovery, or a hostname relationship.
- Never make a live bounty-target request, scan, login, or exploit attempt while implementing or validating this package. Use a loopback mock target and synthetic accounts only.
- No password, MFA value, cookie, bearer token, storage state, raw profile file, or secret enters prompts, worker results, evidence, policy files, or ordinary logs. Do not create a `storageState.json` export.
- Use a dedicated browser profile per engagement/account under local application data; never attach the default Chrome profile. Keep profiles, temporary browser data, generated evidence, and runtime logs out of the repository and OneDrive.
- Default deny for missing identity, policy, source reference, account, origin, method, technique, budget, expiry, protection check, or authorization. No capability is granted by default. If MCP connection identity cannot be distinguished, allow only one active worker connection.
- Browser mapping permits only in-scope `GET`/`HEAD` navigation and observed-element operations without submission or unknown side effects. API calls use the broker-only authenticated context and validate every redirect hop. Block service workers, WebSockets, downloads, traces, video, HAR, direct egress, proxy bypass, and UDP/QUIC paths.
- The proxy rejects wildcard/IP-literal/private/loopback/link-local/metadata destinations, resolves names itself, validates and pins the resolution, and permits only exact normalized origins. If the workstation cannot enforce that browser traffic uses the proxy, keep target capabilities disabled.
- `401` expires and pauses a session without replay; `403` is returned without refresh/retry; `429` stops queued work; timeouts are ambiguous and never automatically replayed. Only explicit, official, policy-granted refresh is allowed. CAPTCHA/MFA/legal prompts return control to the researcher.
- Keep the installed skill edits under `C:\Users\luong\.agents\skills\...` outside Git, and identify them explicitly in the final report. Preserve all pre-existing user artifacts. In particular, do not stage, remove, rewrite, or broadly ignore `.playwright-mcp/`, `engagements/`, or `nul`.
- Tests are authorized only against local mocks with synthetic accounts. Do not run tests against any target domain.

## Review Focus

1. **DNS rebinding and mixed DNS answers:** a hostname resolves to a public address during validation and a private/metadata address during connect, or returns both. Tests must reject before opening an upstream socket and prove the validated address is pinned for the connection.
2. **Origin escape through browser/API redirects or proxy bypass:** an allowed page redirects or subresources point off-scope, or Chromium attempts QUIC/direct egress. Tests must show the proxy denies unlisted origins and preflight leaves capabilities disabled when the firewall/proxy guarantee is absent.
3. **Worker identity and capability confusion:** a worker supplies another identity/account, reuses a revoked/expired grant, or calls admin operations. Tests must show identity is server-assigned, cross-account use is denied, revocation is immediate, and ambiguous host identity serializes workers.
4. **Credential or sensitive-data leakage:** adversarial header casing, bearer/JWT forms, secret query parameters, password form values, and researcher-configured test secrets reach results, evidence, audit, or errors. Tests must assert the original values are absent from every outward channel.
5. **Failure handling that causes duplicate or unauthorized requests:** `401`, `403`, `429`, timeout, connection loss, policy revision, MFA/CAPTCHA, and broker/proxy failure. Mock tests must assert stop/pause state and exactly zero automatic replays or refreshes unless the explicit refresh grant applies.

---

### Task 1: Establish the isolated runtime package and safe filesystem layout

**Files:**
- Create `runtime/authentication-broker/package.json`, `package-lock.json`, `tsconfig.json`, and its package `.gitignore`.
- Create `runtime/authentication-broker/src/index.ts` and `src/config/paths.ts`.
- Create `runtime/authentication-broker/README.md`, `SECURITY.md`, and `examples/broker-policy.example.json` using only synthetic hostnames/accounts.
- Create repository `.gitignore` with narrow broker patterns because none exists; do not add an ignore rule for the whole `engagements/` or `.playwright-mcp/` directory.

**Interfaces:**
- Exports an executable local package with `start`, `typecheck`, `build`, and `test` npm scripts.
- Resolves profiles, temporary browser files, logs, and evidence to `%LOCALAPPDATA%\BugHuntSkills\AuthenticationBroker\...` (or the equivalent current-user local app-data directory), never relative to the checkout.
- Declares the minimum Node engine and pins dependency versions in the lockfile. Validate the selected MCP SDK release's official Node compatibility before pinning.
- Documents that only the synthetic example policy is checked in; real engagement policy, profile, and evidence remain researcher-controlled local data.

- [x] **Step 1: Create the standalone ESM package manifest and lockfile.** Add pinned TypeScript, Playwright, the official MCP TypeScript SDK, a schema validator, and the smallest dev dependency needed to run TypeScript tests with Node's test runner. Set scripts `build`, `typecheck`, and `test`; do not add a default live-target command.
- [x] **Step 2: Create TypeScript compiler settings and a minimal entry point.** Compile only `src/` to `dist/`; exclude local state, examples, and engagement data. Set strict type checking and prohibit emitting source maps containing local paths or secrets.
- [x] **Step 3: Implement current-user runtime path resolution.** Add a pure function that derives the application-data root, creates only broker-owned directories, rejects paths that resolve inside the checkout or OneDrive, and applies user-only permissions where Windows supports them. Add tests for normal resolution, path traversal attempts, and a mocked redirected profile root.
- [x] **Step 4: Add narrow repository ignores and synthetic operator documentation.** Ignore only build output, dependencies, broker local state, generated logs/evidence, and per-engagement `broker-policy.json` files. Leave existing engagement and browser artifacts untouched. The example policy must use reserved `.example` hostnames and contain no real account data.
- [x] **Step 5: Run package-only checks.** From `runtime/authentication-broker/`, run `npm ci`, `npm run typecheck`, `npm run build`, and `npm test`. Expected result: clean install, zero TypeScript errors, successful build, and the path-resolution tests pass without creating any files in `engagements/`.

### Task 2: Validate the policy contract and normalize exact origins

**Files:**
- Create `runtime/authentication-broker/src/policy/schema.ts`, `src/policy/load-policy.ts`, `src/policy/origin.ts`, and corresponding `src/policy/*.test.ts` files.
- Create `runtime/authentication-broker/schemas/broker-policy.schema.json` and revise `examples/broker-policy.example.json` to validate against it.

**Interfaces:**
- `loadPolicy(path, now)` returns a typed, immutable validated policy or a redacted fail-closed error; it never silently repairs a missing authorization field.
- `normalizeOrigin(value)` returns canonical `scheme://hostname:port`, rejecting credentials, paths, queries, fragments, wildcards, IP literals, invalid ports, and ambiguous encodings.
- Login origins, refresh origins, and target origins stay separate. A login-origin grant cannot become a worker target grant; refresh is broker-internal and empty by default.

- [x] **Step 1: Define the version-1 schema and typed policy model.** Require engagement ID, fresh policy snapshot/source, account aliases, explicit exact origin lists, per-account method/technique grants with policy references, request/concurrency/body limits, expiry, and stop conditions. Reject unknown fields where practical so misspellings cannot widen access.
- [x] **Step 2: Implement exact origin canonicalization.** Normalize default ports and host casing; reject wildcard, userinfo, path, query, fragment, IP-literal, malformed IDN, control characters, trailing-dot ambiguity, and any scheme outside the supported HTTP(S) origin model. Ensure normalization cannot turn an invalid input into a broader allowed host.
- [x] **Step 3: Implement strict policy loading and freshness checks.** Check schema version, UTC timestamps, freshness at `now`, expiry, unique aliases/origins, positive ceilings no higher than initial defaults, valid references, and the distinction among target/login/refresh origins. Return errors without echoing the full input document.
- [x] **Step 4: Add table-driven policy tests.** Include valid synthetic policy; missing grant/reference/limits; expired or stale snapshot; wildcard/subdomain; duplicate normalized origin; login origin incorrectly used as target; non-empty refresh without documented grant; oversized limits; and malformed timestamps. Expected: only the valid fixture loads; every invalid fixture is rejected before a policy object can issue access.
- [x] **Step 5: Validate the checked-in example and command surface.** Add `npm run validate:example` (or an equivalent test) that loads only the synthetic file. Expected: schema validation succeeds and prints no policy contents, cookies, or tokens.

### Task 3: Bind capabilities to server-created MCP connections and researcher approval

**Files:**
- Create `runtime/authentication-broker/src/capability/connection-registry.ts`, `src/capability/grants.ts`, `src/admin/control-surface.ts`, `src/admin/control-surface.test.ts`, and `src/transport/host-guard.ts`.
- Add contract tests in `runtime/authentication-broker/src/capability/*.test.ts`.

**Interfaces:**
- MCP connection identities are generated and stored by the server from the stateful transport session; no worker-supplied header, tool argument, or prompt string can choose an identity or account.
- Newly connected clients have no grant. A distinct researcher-facing local control surface lists opaque server-created connection IDs and requires a deliberate grant/revoke action. It is not exposed as a worker MCP tool.
- Each capability binds engagement, policy revision, account alias, role, permitted tools/methods/techniques/origins, rate/budget/concurrency ceiling, and expiry to exactly one MCP connection.
- If the deployed MCP host merges workers into one indistinguishable connection, the registry enforces one active worker at a time and never guesses which worker called.

- [x] **Step 1: Verify the pinned MCP SDK's connection/session lifecycle.** Record which server-created session value is stable for a client connection, when it is created and closed, and how the SDK validates Host/Origin for loopback Streamable HTTP. Add an adapter contract so the rest of the broker depends on a narrow `ConnectionId` interface rather than SDK internals.
- [x] **Step 2: Implement the in-memory connection registry.** Generate opaque IDs server-side, register open/close events, revoke grants on connection close, and reject missing/unknown identities. Do not persist connection IDs or capabilities across a broker restart.
- [x] **Step 3: Implement a distinct local researcher control surface.** Show open worker connection IDs and account aliases without secrets; provide grant, revoke, and confirmed close-session actions through the attended local terminal. Keep researcher actions separate from the worker MCP tool list. The terminal has no admin HTTP route; the worker HTTP endpoint is loopback-bound and guarded by exact Host/Origin validation. Never allow a worker tool to grant/reassign another connection.
- [x] **Step 4: Implement capability creation and enforcement.** Require a current policy and explicit researcher action. Compare every operation to the assigned account, policy revision, method, origin, technique, endpoint authorization, expiry, and remaining budgets. Revoke affected capabilities when the policy revision changes.
- [x] **Step 5: Add identity-boundary tests.** Test no-capability default, caller-supplied worker/account ID ignored, account-A versus account-B isolation, connection close, explicit revoke, expiry, stale policy, researcher-surface separation, and indistinguishable host identity. Expected: unauthorized cases deny before endpoint dispatch; ambiguous identity allows only one worker.
- [x] **Step 6: Run the task checks.** Run `npm test` and `npm run typecheck`. Expected: identity/capability tests pass; researcher controls remain in the separate admin module and worker identity fails closed.

### Task 4: Build the origin-filtering proxy and fail-closed Windows egress preflight

**Files:**
- Create `runtime/authentication-broker/src/network/origin-proxy.ts`, `src/network/destination-policy.ts`, `src/network/dns-pin.ts`, and corresponding network tests.
- Create `runtime/authentication-broker/scripts/install-egress-fence.ps1`, `scripts/remove-egress-fence.ps1`, and `src/network/egress-preflight.ts`.
- Add proxy setup, required Windows Firewall behavior, removal/recovery instructions, and preflight limitations to `runtime/authentication-broker/SECURITY.md`.

**Interfaces:**
- A local CONNECT/HTTP proxy permits only exact normalized origins for the active account capability. It resolves names itself, rejects the entire resolution if any address is forbidden, and uses only the validated pinned address for that connection.
- The browser is configured to use this proxy with no bypass list; Chromium QUIC/UDP paths are disabled. A Windows firewall egress fence blocks the managed Chromium executable from direct Internet egress while permitting its loopback proxy connection. The only broker code path that forwards target traffic is the origin-checking proxy; no worker-facing raw client exists.
- `egressPreflight()` returns an explicit verified/unverified result. Any unverified, missing, altered, or unsupported firewall condition leaves target operations disabled; it never falls back to direct browser egress.
- Do not silently install or remove firewall rules at broker startup. The scripts make only named, reversible broker rules, show their effects, and verify exact program paths/rule state.

- [x] **Step 1: Implement exact destination checks.** Validate origin scheme/host/port and all DNS answers; reject loopback, private, link-local, metadata, multicast, unspecified, and IP-literal destinations. Pin the approved address for the connection while preserving TLS hostname verification/SNI.
- [x] **Step 2: Implement the local proxy.** Support HTTP absolute-form requests and HTTPS CONNECT without TLS decryption. Bind only to loopback, cap headers/connection duration, enforce the active origin set per capability, and deny all traffic until a policy-bound proxy context exists.
- [x] **Step 3: Add Windows firewall setup/removal scripts.** Use explicit broker-owned rule names and the exact Chromium executable path; avoid wildcard program paths. Setup must be idempotent and reversible, support `-WhatIf`/dry-run, and removal deletes only those named broker rules. Scripts must require the researcher to run with appropriate privileges and must not run as a side effect of tests.
- [x] **Step 4: Implement egress preflight and browser launch options.** Check supported Windows version, proxy listener, rule direction/action/program/remote address, absence of conflicting rules, and Chromium configuration for no bypass and disabled QUIC. Return `unverified` if any check is unavailable or ambiguous; capability creation consumes this result and denies target access when unverified.
- [x] **Step 5: Test proxy and preflight with an injected resolver and loopback mock.** Cover mixed public/private DNS answers, rebinding, IPv4/IPv6 forbidden ranges, unlisted origin, off-scope redirect destination, wrong port, proxy unavailable, bypass setting, absent/altered firewall rule, and unchanged allowlisted mock origin. Use an injected test-only destination seam for the loopback upstream; production policy must continue rejecting loopback, and there must be no worker-configurable bypass. Expected: forbidden requests never reach the mock upstream and all uncertain host conditions disable capabilities.
- [x] **Step 6: Run the task checks without touching Windows firewall.** Run `npm test` using fake DNS and the test-only loopback seam, run `npm run typecheck`, and invoke the setup script with `-WhatIf` against a synthetic Chromium path. Expected: tests use no admin privileges, dry-run output names only the intended broker rules, and firewall state remains unchanged.

### Task 5: Manage isolated attended browser sessions and safe API cookie reuse

**Files:**
- Create `runtime/authentication-broker/src/session/session-manager.ts`, `src/session/profile-protection.ts`, `src/browser/managed-context.ts`, `src/browser/page-tools.ts`, and corresponding tests.
- Add process/profile lock code in `runtime/authentication-broker/src/session/profile-lock.ts` and tests.

**Interfaces:**
- A session key is `(engagementId, accountAlias)` and resolves to exactly one private profile/context; aliases cannot be overridden by tool arguments.
- Persistent `userDataDir` is available only after the OS protection check verifies an encrypted volume and current-user permissions. Otherwise use a non-persistent in-memory browser context and require user sign-in after daemon restart.
- The visible login window is user-attended. The researcher enters passwords and completes MFA/CAPTCHA; the broker neither reads nor types secrets. Login identity-provider origins are available only during attended bootstrap.
- Context launch disables service workers, downloads, video, traces, HAR, WebSockets, and direct egress. Page mapping allows only approved-origin GET/HEAD; form submission and unknown-effect button actions are blocked.
- Browser-context cookies are never read into worker-visible data. If Playwright's associated API request context cannot prove use of the same proxy, use an internal-only cookie synchronization adapter, test it against the local mock, and keep all values in process memory; if either proxy use or session isolation cannot be proven, disable API capabilities.

- [x] **Step 1: Implement profile protection selection.** Check local app-data path and OS volume encryption without printing sensitive path contents; select persistent or in-memory mode. A failed/unknown protection check selects in-memory mode, never persistent mode.
- [x] **Step 2: Implement a per-engagement/account profile lock.** Create an exclusive process lock, reject a second owner for the same profile, and release on clean shutdown. Test concurrent acquisition and stale-lock recovery without inspecting profile contents.
- [x] **Step 3: Implement session state transitions and attended login.** Track only account alias, engagement ID, policy revision, state, timestamps, and revocation state. Open a visible browser to a policy-allowed login origin; mark active only after a researcher-controlled confirmation or an explicitly authorized read-only status check. After restart, persistent profiles become `login_required`; in-memory profiles are recreated empty.
- [x] **Step 4: Implement guarded page mapping and actions.** Block service workers and WebSockets. Permit exact-origin navigation and sanitized observation. Allow filling only researcher-controlled fields and ordinary links; deny form submit, unknown buttons, arbitrary scripts/evaluate/CDP, downloads, and non-GET/HEAD page requests.
- [x] **Step 5: Implement the internal API request adapter.** Use the context-associated cookie jar only through broker code. Disable automatic redirects and inspect every hop; configure the same origin proxy and TLS checks. Reject caller `Cookie`, `Authorization`, proxy, Host, and equivalent credential/routing headers. Never serialize cookie state.
- [x] **Step 6: Add lifecycle/API tests using two synthetic accounts.** Verify separate profiles, validator isolation, no profile export/read tools, user challenge handoff, 401/403/429/timeout state transitions, no automatic replay, non-persistent restart behavior, and API calls reaching the mock only through the proxy while reusing the correct account's synthetic session cookie. Assert cookie values are absent from every result/log.
- [x] **Step 7: Run task checks against loopback fixtures only.** Run `npm test` and `npm run typecheck`. Expected: all state/isolation cases pass and no network destination outside loopback is contacted.

### Task 6: Assemble the MCP tools, request guard, sanitizer, and metadata-only audit

**Files:**
- Create `runtime/authentication-broker/src/transport/mcp-server.ts`, `src/policy/request-guard.ts`, `src/output/sanitize.ts`, `src/audit/metadata-log.ts`, and `src/tools/*.ts`.
- Add transport and tool integration tests under `runtime/authentication-broker/src/transport/` and `src/tools/`.

**Interfaces:**
- Worker tool names are only `session_status`, `open_login`, `observe_page`, `navigate`, `act_on_observed_element`, `authorized_request`, and `revoke_capability`. `close_session` and grants remain researcher control actions.
- The guard checks server identity, capability, policy freshness/revision, account, exact origin, destination, method, technique, authorized endpoint, body-size ceiling, rate, request budget, concurrency, expiry, and egress-preflight state before dispatch.
- All return values, errors, audit metadata, and opt-in evidence pass through one sanitizer. Audit is metadata-only by default; bodies/headers and raw captures are never logged.
- `401`, `403`, `429`, challenge, timeout, policy change, and broker/proxy failure use the approved stop behavior, without transparent retry or redirect-following.

- [ ] **Step 1: Implement the request guard as a pure pre-dispatch decision layer.** Return a structured allow/deny decision and redacted reason. A denied request must not call the browser, proxy, or upstream adapter.
- [ ] **Step 2: Implement output sanitization.** Remove credential headers (case-insensitive), bearer/JWT-like values, secret query parameters, password fields, configured synthetic secrets, and configured researcher values from tool results, error text, and evidence copies. Bound body sizes and suppress bodies on suspected third-party data.
- [ ] **Step 3: Implement metadata-only audit records.** Record timestamp, engagement, server connection, alias, policy revision, normalized origin, method/category, decision, status, and latency. Reject accidental header/body fields at the audit interface. Ensure errors never attach raw Playwright request/response objects.
- [ ] **Step 4: Assemble the local MCP server.** Register only the approved worker tools, use stateful Streamable HTTP, loopback binding, Host/Origin checks, and the connection registry. Add an independent researcher control interface, not an admin MCP tool. Deny remote host headers and cross-origin browser submissions.
- [ ] **Step 5: Implement failure-state handling centrally.** Ensure `401` pauses/expires and does not replay; `403` returns without refresh; `429` halts queued work; timeout/connection loss marks result unknown and stops; policy revision change revokes affected capabilities; user challenge returns control; proxy/profile failure disables target tools.
- [ ] **Step 6: Add adversarial end-to-end mock tests.** Start a loopback mock web app and two synthetic accounts. Invoke each worker tool through a real local MCP connection. Verify missing capability and every policy limit deny before dispatch, redirects are checked hop-by-hop, page POST/forms are blocked, UI tool schema has no evaluate/cookie/storage/shell methods, and all secret canaries are absent from results, logs, and evidence.
- [ ] **Step 7: Run task checks locally.** Run `npm test`, `npm run typecheck`, and `npm run build`. Expected: local MCP mock flow succeeds only for explicitly granted requests, all stop conditions pass, and no external DNS/network request is made.

### Task 7: Integrate the operator skills and document safe operation

**Files:**
- Modify outside Git: `C:\Users\luong\.agents\skills\bug-bounty-hunter\SKILL.md`.
- Modify outside Git: `C:\Users\luong\.agents\skills\bug-bounty-hunter\chapters\01-phase-map.md`, `02-session-checklist.md`, and `06-authenticated-program-intake.md`.
- Create outside Git: `C:\Users\luong\.agents\skills\bug-bounty-hunter\chapters\07-target-authentication-broker.md`.
- Modify outside Git: `C:\Users\luong\.agents\skills\computer-use\SKILL.md`.
- Modify in Git: `runtime/authentication-broker/README.md`, `SECURITY.md`, and `examples/broker-policy.example.json` only if operator flow or schema changes.

**Interfaces:**
- `bug-bounty-hunter` owns source URL/section/snapshot references, exact target origins, explicit method/technique grant review, account-role separation, policy creation, capability eligibility, and stop/resume decisions. Existing platform intake remains read-only.
- `computer-use` permits the researcher to operate the visible broker login window only; it must not inspect the managed profile, export browser storage, obtain credentials, or drive target actions around the broker.
- The new chapter describes attended setup, local policy validation, worker identity/grants, session states, re-login handoff, revocation, error meanings, and evidence redaction. It must direct uncertainty to pause/researcher review rather than broaden scope.

- [ ] **Step 1: Read current skill entry points and linked chapters before editing.** Preserve existing router paths, platform session boundaries, and skill-specific conventions; do not add a second scope contract or finding lifecycle.
- [ ] **Step 2: Add concise hunter routing.** Link broker use from program intake/session checklist and relevant application-mapping/API-testing phases. Clearly distinguish platform-authenticated program-policy reading from target-app authentication.
- [ ] **Step 3: Create the target broker chapter.** Document policy provenance, exact origins, account separation, no-default capability, local control-surface grant, login/MFA handoff, rate/budget limits, stop conditions, and validator independence. Include no real engagement policy, target, credentials, or saved cookie.
- [ ] **Step 4: Add the computer-use boundary.** Restrict GUI steps to researcher-attended login/challenges and high-impact approvals. Prohibit inspecting profile files, DevTools/storage extraction, arbitrary target actions, and bypassing broker tools.
- [ ] **Step 5: Cross-check skill links and outside-Git edits.** Resolve every referenced file, verify names/headings, compare each instruction against the runtime tool list and policy schema, and record the exact external paths in a change note. Expected: no broken chapter route, and no skill asks a worker to paste or read secrets.

### Task 8: Close with local-only acceptance review and deliverable inventory

**Files:**
- Read all `runtime/authentication-broker/` source, tests, `README.md`, and `SECURITY.md`.
- Read the six edited/created installed skill files listed in Task 7.
- Read repository `.gitignore` and Git status; do not edit existing engagement artifacts.

**Interfaces:**
- Verifies the acceptance criteria in the approved spec using synthetic accounts and the loopback mock only.
- Produces a concise implementation record listing tracked repository changes and installed user-level skill changes outside Git.

- [ ] **Step 1: Run the full mock-only verification suite.** Run `npm ci`, `npm run typecheck`, `npm run build`, and `npm test` from the package. Confirm the mock binds only to loopback and all fixtures use reserved/example names and synthetic accounts. Expected: all tests pass and test logs contain no credentials.
- [ ] **Step 2: Exercise fail-closed startup states.** With mocked preflight results, test missing policy, stale snapshot, absent capability, unsupported host identity, unprotected persistent path, unavailable proxy, and invalid firewall state. Expected: each relevant active capability is disabled and no upstream mock request is sent.
- [ ] **Step 3: Audit the tool and data surface.** Confirm only the seven approved worker tools exist; no worker-facing profile path, cookie/storage/evaluate/CDP/shell/raw HTTP/export or report submission exists; admin actions are separate; all five Review Focus classes have named negative tests.
- [ ] **Step 4: Reconcile acceptance criteria against code and tests.** Record evidence for session reuse/isolation, exact-origin and method enforcement, per-hop redirects, egress failure, stop states, sanitization, metadata-only audit, and optional sanitized evidence. Leave any criterion unsupported by proof explicitly unmet; never soften the guard to make a test pass.
- [ ] **Step 5: Review repository diff and user artifacts.** Use `git status --short` and inspect the exact diff. Do not stage `.playwright-mcp/`, `engagements/`, `nul`, real policy files, or runtime data. Confirm external skill edits remain outside Git.
- [ ] **Step 6: Return a completion summary.** Name repository files and outside-Git skill paths, report exact local commands and results, describe any host limitation that keeps capabilities disabled, and state that no live target was contacted.

## Completion Criteria

- A researcher can complete sign-in in an isolated attended profile and reuse it from separately identified worker connections without exposing credentials or storage state.
- Each engagement/account and validator uses a separate session. A worker cannot choose another account or grant.
- Exact policy, account, origin, method, technique, endpoint, rate, concurrency, body-size, request-budget, expiry, and egress checks happen before dispatch; absent/ambiguous inputs deny.
- Browser page requests are limited to in-scope GET/HEAD and safe observed interactions; service workers, WebSockets, downloads, and arbitrary execution are blocked. API redirects are disabled and checked one hop at a time.
- DNS and proxy checks reject prohibited destinations and pin validated resolutions; if direct egress cannot be ruled out, target capabilities stay disabled.
- Session expiry, authorization responses, rate limits, challenges, timeouts, policy changes, and runtime failures follow the spec with no unsafe replay.
- Secrets are absent from tool results, policy files, default evidence, and audit logs. Persistent profile storage is outside Git/OneDrive and only enabled with verified OS protection.
- Skill edits preserve the distinction between program-platform intake and target-app authentication and route target actions through the broker.
- Every implementation validation uses only loopback mocks and synthetic accounts; no live target is contacted.
