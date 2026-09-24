# Security notes

The broker is intended for authorized, researcher-controlled bug bounty accounts. Its policy file does not create authorization. Missing or stale policy, worker identity, account, origin, method, technique, request limit, expiry, or egress protection must deny target traffic.

Application credentials remain in a broker-owned browser context and local profile. Never copy cookies, tokens, passwords, MFA values, profile files, or Playwright storage state into a prompt, policy, audit log, evidence artifact, or Git. Persistent profiles require verified OS volume encryption and current-user-only access; otherwise use an in-memory context and sign in again after restart.

Development and acceptance verification use loopback mock targets and synthetic accounts only. This package must not bypass MFA, CAPTCHA, legal prompts, rate limits, or program restrictions. See the approved design for the full failure and stop policy.

## Egress fence

The runtime is not ready for target traffic until the managed browser is forced through the exact-origin proxy and the Windows preflight verifies the required firewall boundary. Setup and removal are explicit researcher operations; tests must not change firewall state.
