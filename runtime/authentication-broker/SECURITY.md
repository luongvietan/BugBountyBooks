# Security notes

The broker is intended for authorized, researcher-controlled bug bounty accounts. Its policy file does not create authorization. Missing or stale policy, worker identity, account, origin, method, technique, request limit, expiry, or egress protection must deny target traffic.

Application credentials remain in a broker-owned browser context and local profile. Never copy cookies, tokens, passwords, MFA values, profile files, or Playwright storage state into a prompt, policy, audit log, evidence artifact, or Git. Persistent profiles require verified OS volume encryption and current-user-only access; otherwise use an in-memory context and sign in again after restart.

Development and acceptance verification use loopback mock targets and synthetic accounts only. This package must not bypass MFA, CAPTCHA, legal prompts, rate limits, or program restrictions. See the approved design for the full failure and stop policy.

## Egress fence

Target capabilities remain disabled until the managed browser uses the local proxy and `egressPreflight()` verifies the current Windows state. Missing PowerShell access, an incomplete ActiveStore read, a disabled firewall profile, a mismatched browser path, any conflicting rule for that executable, or any changed broker rule returns `unverified`.

The proxy binds only to `127.0.0.1:8766`. The broker's eight named outbound block rules for the exact Chromium executable block every other IPv4 and IPv6 destination, including private networks, and block UDP to loopback. TCP to `127.0.0.1:8766` is the sole network exception. The rule ranges avoid an overlapping block on that one endpoint; an allow rule cannot safely override an overlapping explicit block because Windows Firewall gives explicit block rules precedence. See [Microsoft's rule precedence documentation](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules).

Install and remove the fence only as explicit researcher actions from an elevated PowerShell window. Review the dry run first with a synthetic path:

```powershell
.\scripts\install-egress-fence.ps1 -ChromiumPath 'C:\Synthetic\chrome.exe' -WhatIf
```

For a real installation, pass the exact managed Chromium `.exe` path returned by the browser runtime. The script prompts before creating only its named rules and refuses to overwrite a same-named rule that differs. It does not change firewall defaults or unrelated rules. To reverse an installation, pass the same exact path to `remove-egress-fence.ps1`; it refuses to remove a rule that no longer matches the broker's expected state. Removal also supports `-WhatIf`.

The browser launch configuration uses the fixed proxy, Chromium's `<-loopback>` subtractive rule to prevent implicit localhost proxy bypass, and `--disable-quic`. Chromium documents the special bypass behavior in its [proxy configuration guide](https://chromium.googlesource.com/chromium/src/+/main/net/docs/proxy.md). Do not add a proxy bypass list or PAC script. If the active firewall policy cannot be read completely, do not substitute assumptions or direct browser egress.

The proxy requires a broker-issued proxy capability, allows only exact canonical origins and authorized methods, resolves all DNS answers itself, rejects the whole set if any address is local or special-use, and connects to a validated numeric pin. HTTP redirects are not followed by the proxy; each subsequent request is checked independently. HTTPS uses CONNECT without TLS decryption, preserving the browser's TLS hostname verification and SNI. Since CONNECT hides the HTTP method and path inside TLS, the managed page adapter must enforce read-only page requests before they reach the tunnel, and the API adapter must enforce endpoint/method authorization before sending requests. A CONNECT tunnel is not a substitute for those request guards.

Firewall state changes are never made by broker startup or tests. The package's local mock tests inject DNS and a test-only loopback connector; production worker inputs cannot configure that connector. No target traffic should be enabled until the remaining session, browser route, and MCP startup checks are implemented and the complete current-state preflight is verified.
