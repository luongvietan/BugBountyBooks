# Bug Bounty Skill Set — Source & Coverage Register

Cutoff: **2026-09-23**. Every version below was verified against the official
page/release feed on this date (not from search snippets). Rolling docs are
labeled rolling; versioned standards get versioned links.

## Verified authorities

| Authority | Current state @ 2026-09-23 | Canonical URL | Notes |
|---|---|---|---|
| OWASP API Security Top 10 | **2023 stable** (rel. 2023-06-05); no newer edition | `https://owasp.org/API-Security/editions/2023/en/0x11-t10/` | API1 BOLA · API2 Broken Auth · API3 **BOPLA** (merges 2019 API3+API6) · API4 Unrestricted Resource Consumption · API5 BFLA · API6 Sensitive Business Flows · API7 SSRF · API8 Misconfiguration · API9 Improper Inventory · API10 Unsafe API Consumption |
| OWASP WSTG | **v4.2 last stable** (2020-12-03); v5.0 in development (master/`latest`) | `https://wstg.owasp.org/v4.2/` versioned · `…/latest/` bleeding-edge | Project rule: link versioned paths, never `stable`/`latest`. Live tree already includes post-4.2 tests (e.g. §4.10.10 BUSL-10, OAuth 4.5.5.x, API headers 4.2.14) |
| FIRST CVSS | **v4.0 current**; v3.1/v3.0/v2 archived | `https://www.first.org/cvss/v4-0/` (spec, calculator, user guide) | v4.0 metric groups: Base (Threat+Environmental+Supplemental optional). Keep v3.x only when a program requires it |
| OWASP GenAI Security Project | **Top 10 for LLM Apps 2025** (v2025); project renamed from "LLM Top 10" | `https://genai.owasp.org/llm-top-10/` | LLM01 prompt injection, LLM02 sensitive info disclosure, LLM05 improper output handling, LLM06 excessive agency, LLM08 vector/embedding weaknesses, LLM10 unbounded consumption — map to T5 LLM chapter |
| OWASP MAS (MASVS/MASTG/MASWE) | Rolling docs at mas.owasp.org; MASWE catalog 0001–0078 live; MASTG-BEST-xxxx series live | `https://mas.owasp.org/` | MASVS has **8** groups incl. PRIVACY (MASWE-0066–0078) — our skill scoped to 7 + documented exclusion. GitHub latest release tag should be re-pinned at review time |
| PortSwigger Web Security Academy | Rolling; "latest topics" banner: request smuggling, web cache deception, Web LLM attacks, API testing, NoSQLi | `https://portswigger.net/web-security/all-materials` | Lab anchors verified per-topic in T7 build; SAML is NOT an Academy topic (404) — keep our noted exception |
| Hacking the Cloud | Rolling (hackingthe.cloud, AWS/GCP/Azure sections) | `https://hackingthe.cloud/` | Content MIT-licensed; techniques skew AWS |
| PayloadsAllTheThings | Rolling master | `https://github.com/swisskyrepo/PayloadsAllTheThings` | Reference library — freshness = spot-check payload families still canonical |
| Jason Haddix TBHM | Rolling repo (methodology v4/v5 era talks) | `https://github.com/jhaddix/tbhm` | Older tool recs already era-marked |

## Tool versions (verified via GitHub releases / vendor pages 2026-09-23)

| Tool | Latest verified | Source | Watch item for T3 |
|---|---|---|---|
| OWASP Amass | **v5.1.1** (2026-04-07) | `github.com/owasp-amass/amass` (repo MOVED from OWASP/Amass) | **v5 = rewrite**: new engine + Asset Database; v4 `amass enum` CLI replaced — every `amass` command in recon-pipeline (20 refs) needs re-verification against v5 docs |
| httpx (pd) | v1.12.0 | `projectdiscovery/httpx` | flag surface stable; verify `-tech-detect` |
| dnsx | v1.3.1 | `projectdiscovery/dnsx` | — |
| trufflehog | v3.97.6 | `trufflesecurity/trufflehog` | v3 confirmed: `--results=verified`, `--json` stdout (no `-o`) — our fix already matches |
| gitleaks | v8.30.1 | `gitleaks/gitleaks` | `--report-path` top-level JSON array — our fix already matches |
| nmap | 7.991 (2026-08-06) | `nmap.org` / `nmap/nmap` mirror | `-Pn` modern syntax (our `-PN` legacy note stands) |
| masscan | 1.3.2 | `robertdavidgraham/masscan` | unchanged; keep behind permission gate per plan |
| gowitness | 3.2.0 | `sensepost/gowitness` | v3 CLI differs from v2 (`scan` subcommands) — verify syntax |

## Per-skill register (17 rows)

| Skill | Current source/version in skill | 2026 authority checked | Files needing substantive review | Disposition |
|---|---|---|---|---|
| `bug-bounty-hunter` | Orchestrator (authored 2026-09-23) | Program-policy-first pattern; all 16 companions | SKILL.md + 3 chapters | UPDATE: scope-first/deny-by-default rewrite (T2) + sources.md |
| `recon-pipeline` | Authored runbook; tools as of build | Amass v5.1.1, httpx v1.12, nmap 7.991, trufflehog v3.97, gitleaks v8.30, masscan 1.3.2, gowitness 3.2 | SKILL.md + 3 chapters | UPDATE: allowlist-derived targets, passive/active split, amass-v5 syntax, masscan behind permission gate, secret-safe artifacts (T3) |
| `report-writing` | Authored; CVSS v3-era vector example, H1/Bugcrowd/Intigriti/YWH bands | CVSS v4.0 spec; platform policy = rolling | SKILL.md + 4 chapters | UPDATE: program-first severity, CVSS v4 optional, evidence minimization (T7) |
| `hacking-the-cloud` | hackingthe.cloud (rolling), 8 chapters | Same rolling source; provider docs for IAM/metadata semantics | SKILL.md + ch01–05,07,08 | UPDATE: credential-validation gate, canary validation, remove default persistence reads (T6) |
| `owasp-mas` | MASTG v2.0.0 release | mas.owasp.org rolling (MASWE-0066–0078 incl. PRIVACY) | SKILL.md + ch01,02,04,05,06,09 | UPDATE: refresh MASWE refs + tool syntax, keep 7-category scope + privacy note (T6) |
| `owasp-wstg` | WSTG v4.2 frozen + BUSL-10 post-4.2 | v4.2 still last stable; v5 dev = latest/master | SKILL.md + ch01,02,05,07,10,11,12 | UPDATE: version-scoped labels (v4.2 IDs stable / latest=draft), light refresh of stale tool notes (T5) |
| `web-app-hackers-handbook` | WAHH ed2 (2011), 20 chapters | Modern equivalents (Academy/WSTG) — mechanics durable | SKILL.md + ch03,05,07,11,13,19,20 | UPDATE: era-label remaining stale spots, route modern classes (T5) |
| `web-security-academy` | PortSwigger topics @ build | Academy rolling; LLM→OWASP GenAI 2025 | SKILL.md + ch01–09,15 | UPDATE: expand LLM to OWASP 2025 risks, lab-vs-bounty-safe split per technique (T5) |
| `payloads-all-the-things` | swisskyrepo rolling master | Same rolling source | SKILL.md + ch01,04,05,06,08,11,14,15 | UPDATE: context-first selection framing, lab-vs-live distinction (T8) |
| `tbhm-methodology` | jhaddix/tbhm + Haddix talks | Recon-stack drift (amass v5 etc.) | SKILL.md + ch02,03,08 mainly | UPDATE: era-mark tool examples, route to recon-pipeline for executable state (T8) |
| `hacking-apis` | Corey Ball book (Early Access) | API Top 10 2023 + vendor docs | SKILL.md + ch00,01,03,04,05,06,07,08,10,11 | UPDATE: 2023 crosswalk, BOPLA rename, low-volume auth checks (T4) |
| `owasp-api-security-top-10` | API Top 10 **2019** | API Top 10 **2023** | all 10 chapters + SKILL.md + cheatsheet/patterns | UPDATE: full 2019→2023 crosswalk; keep 2019 labeled historical (T4) |
| `bug-bounty-bootcamp` | Vickie Li book (2021), 22 chapters | Academy/WSTG modern equivalents | SKILL.md + ch01,03,07,09,10,20,21,22 | UPDATE: annotate dated tools, route modern classes, keep durable loop (T8) |
| `bug-bounty-playbook` | ghostlulz playbook V2 | Safe-validation gates; current technique refs | SKILL.md + ch01,03,04,05,09,10,11,13,14 | UPDATE: brute-force/exploitation examples → theory or permission-gated (T8) |
| `web-hacking-101` | Yaworski (2017) case studies | Historical value only | SKILL.md + ch01,04,10 | UPDATE: explicit historical framing, no payout/severity promises (T8) |
| `xss-cheat-sheet` | Brute Logic cheat sheet | Modern parser/framework behavior (Academy XSS) | SKILL.md + ch01–05 | UPDATE: context-first + harmless-proof framing, maintained-source links (T8) |
| `zseano-methodology` | zseano methodology | Program-selection + first-look durable | SKILL.md + ch01,02,05,06 | UPDATE: authorization assumptions + tool refresh notes (T8) |

## Known gaps / watch items

- **Amass v5 CLI** — biggest tool churn; T3 must re-derive commands from `owasp-amass` v5 docs, not translate v4 flags.
- **WSTG v5.0** — in development; treat `latest` additions as draft; keep v4.2 IDs as stable anchors.
- **MASWE catalog grows** — numbers beyond 0078 may appear; skill ranges documented, not hard-frozen.
- **Platform severity policies** (HackerOne bands, Bugcrowd VRT, Intigriti, YWH) — rolling; date-stamp every platform claim.
- **No live-target testing** performed for this refresh (per spec non-goal).
