# Bug Bounty Skill Set — Source & Coverage Register

Review cutoff: **2026-09-24** for the authorities re-checked in this delta.
Other foundational and rolling entries retain the **2026-09-23** baseline
snapshot unless a newer check date appears in the row. The tool-version table
also retains its **2026-09-23** snapshot. Rolling docs are labeled rolling;
versioned standards get versioned links. Current claims were checked on their
official project pages, not from search snippets.

## Verified authorities

| Authority | Recorded state | Canonical URL | Notes |
|---|---|---|---|
| OWASP API Security Top 10 | **2023 current edition**; project page still identifies 2023 as latest (checked 2026-09-24) | `https://owasp.org/projects/api-security-project` · versioned 2023 contents: `https://owasp.org/API-Security/editions/2023/en/0x11-t10/` | API1 BOLA · API2 Broken Auth · API3 **BOPLA** (merges 2019 API3+API6) · API4 Unrestricted Resource Consumption · API5 BFLA · API6 Sensitive Business Flows · API7 SSRF · API8 Misconfiguration · API9 Improper Inventory · API10 Unsafe API Consumption |
| OWASP WSTG | **v4.2 latest stable** (checked 2026-09-24); v5.0 remains in development | `https://owasp.org/projects/web-security-testing-guide` · versioned v4.2: `https://wstg.owasp.org/v4.2/` | Project says v5 is in development and directs readers to `latest` for development content; stable citations stay on versioned v4.2 paths. |
| FIRST CVSS | **v4.0 current**; v3.1/v3.0/v2 archived | `https://www.first.org/cvss/v4-0/` (spec, calculator, user guide) | v4.0 metric groups: Base (Threat+Environmental+Supplemental optional). Keep v3.x only when a program requires it |
| OWASP ASVS | **5.0.0 latest stable**, as stated by the project guidance page (checked 2026-09-24) | `https://owasp.org/projects/asvs` | The project page's guidance calls 5.0.0 the latest stable version; its separate project-info field appends “Bleeding Edge.” Cite versioned 5.0.0 requirements and re-check that page wording before using unversioned IDs. |
| OWASP GenAI LLM Top 10 | **2026 current edition**, resource page published 2026-08-03 | `https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/` | LLM01 Prompt Injection · LLM02 Sensitive Information Disclosure · LLM03 Excessive Agency · LLM04 Supply Chain · LLM05 Data and Model Poisoning · LLM06 Unbounded Consumption · LLM07 Misinformation · LLM08 Hidden Context Exposure · LLM09 Vector and Embedding Weaknesses · LLM10 Improper Output Handling. The 2025 list is historical: `https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/`. |
| OWASP Top 10 for Agentic Applications | **2026 edition**, announced 2025-12-09 | `https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/` | Use the testable boundaries ASI01 Agent Goal Hijack, ASI02 Tool Misuse and Exploitation, ASI03 Identity and Privilege Abuse, and ASI06 Memory and Context Poisoning where the product exposes them. |
| OWASP AI Testing Guide | **v1 published 2025-11-26**; project is an incubator and its repository is rolling | `https://owasp.org/projects/ai-testing-guide` · official test index: `https://github.com/OWASP/www-project-ai-testing-guide/blob/main/Document/README.md` | Adds test-method IDs beyond a risk taxonomy, including APP-01/02 prompt injection, APP-06 agent behavior limits, APP-08 embedding manipulation, and INF-03/04 plugin-boundary/capability misuse. Use only relevant, authorized product tests; model, training-data, and infrastructure coverage is not a bounty authorization. |
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

The **Files needing substantive review** column records the planned substantive
review surface, not an exhaustive changelog of every modified file. Supporting
artifacts such as `SKILL.md`, `sources.md`, `cheatsheet.md`, and `patterns.md`
may also change during implementation or final-review fixes. Use the Git history
for the authoritative list of files changed by each task/commit.

| Skill | Current source/version in skill | 2026 authority checked | Files needing substantive review | Disposition |
|---|---|---|---|---|
| `bug-bounty-hunter` | Orchestrator (authored 2026-09-23) | Program-policy-first pattern; all 16 companions | SKILL.md + 3 chapters | UPDATE: scope-first/deny-by-default rewrite (T2) + sources.md |
| `recon-pipeline` | Authored runbook; tools as of build | Amass v5.1.1, httpx v1.12, nmap 7.991, trufflehog v3.97, gitleaks v8.30, masscan 1.3.2, gowitness 3.2 | SKILL.md + 3 chapters | UPDATE: allowlist-derived targets, passive/active split, amass-v5 syntax, masscan behind permission gate, secret-safe artifacts (T3) |
| `report-writing` | Authored; CVSS v3-era vector example, H1/Bugcrowd/Intigriti/YWH bands | CVSS v4.0 spec; platform policy = rolling | SKILL.md + 4 chapters | UPDATE: program-first severity, CVSS v4 optional, evidence minimization (T7) |
| `hacking-the-cloud` | hackingthe.cloud (rolling), 8 chapters | Same rolling source; provider docs for IAM/metadata semantics | SKILL.md + ch01–05,07,08 | UPDATE: credential-validation gate, canary validation, remove default persistence reads (T6) |
| `owasp-mas` | MASTG v2.0.0 release | mas.owasp.org rolling (MASWE-0066–0078 incl. PRIVACY) | SKILL.md + ch01,02,04,05,06,09 | UPDATE: refresh MASWE refs + tool syntax, keep 7-category scope + privacy note (T6) |
| `owasp-wstg` | WSTG v4.2 frozen + BUSL-10 post-4.2 | v4.2 still last stable; v5 dev = latest/master | SKILL.md + ch01,02,05,07,10,11,12 | UPDATE: version-scoped labels (v4.2 IDs stable / latest=draft), light refresh of stale tool notes (T5) |
| `web-app-hackers-handbook` | WAHH ed2 (2011), 20 chapters | Modern equivalents (Academy/WSTG) — mechanics durable | SKILL.md + ch03,05,07,11,13,19,20 | UPDATE: era-label remaining stale spots, route modern classes (T5) |
| `web-security-academy` | PortSwigger topics @ build; OWASP GenAI LLM Top 10 2026 | Academy rolling; current LLM + Agentic 2026; selected AI Testing Guide v1 methods | SKILL.md + ch01–09,15 | UPDATE: align chapter 15 with 2026 LLM/Agentic risks and selected AITG test IDs; retain lab-vs-bounty-safe gates (delta 2026-09-24) |
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

## Finalization (2026-09-23, post-implementation)

### Implemented state per skill

All 17 skills now carry: `sources.md` (source/version/review metadata) +
a `sources.md` pointer in `SKILL.md`. Topical refresh commits:
`af73f48` (T2 orchestrator), `d5c87b0` (T3 recon), `80967b6` (T4 API),
`4dec38a` (T5 WSTG/Academy/WAHH), `69daf70` (T6 cloud+mobile),
`2e97973` (T7 reporting), `a6f9297` (T8 seven legacy skills).

- `bug-bounty-hunter`: scope contract deny-by-default, GenAI 2026/Agentic 2026/API-2023/
  severity routing, pressure scenarios; `sources.md` source hierarchy.
- `recon-pipeline`: P/T/I traffic classes, allowlist-derived targets
  (wildcard ≠ apex), Amass-v5 + Gowitness-v3 syntax, masscan exceptional
  path, secret-safe artifacts, dated outputs + diff triage.
- `owasp-api-security-top-10` + `hacking-apis`: 2019→2023 crosswalk per
  chapter, BOPLA read/write split, API6/7/10:2023 coverage, low-volume
  own-account auth checks.
- `web-security-academy`/`owasp-wstg`/`web-app-hackers-handbook`: LLM→
  GenAI 2026 mapping, lab-vs-bounty callouts, version-scoped WSTG labels,
  WAHH era markers.
- `hacking-the-cloud`/`owasp-mas`: creds non-use-by-default, canary-only
  write proofs, MASTG v2.0.0 + MASVS-PRIVACY notes, tool-currency rules.
- `report-writing`: program→platform→CVSS-v4 precedence, scope/asset
  declaration, redaction rules, demonstrated-vs-theoretical split.
- 7 legacy skills: per-chapter ceiling/era/ownership callouts, harmless-
  marker proofs, modern-taxonomy routing, `sources.md` each.

### Unresolved gaps (accepted, watch)

- **Mass-assignment primary** in vuln-class-index still points at the
  2019 ch06 file — intentionally: the file carries the 2023 status line
  and is the write-side of BOPLA. No rename (chapter IDs stable).
- **WSTG v5.0 draft items** (e.g., BUSL-10) live in the skill with
  provenance notes; v4.2 IDs remain the stable quoting anchors.
- **Platform severity policies** are rolling — every platform claim in
  `report-writing` is date-stamped 2026-09-23.
- **No live-target testing** (spec non-goal). All validation was static:
  scanner, validator, link checks, logic tests.

### Next review triggers

- **Amass v5.x**: re-verify `enum`/`subs`/DB-export commands each minor
  release (v5 churn is the highest-volatility surface in the set).
- **WSTG v5.0 stable release**: promote `latest` items to versioned IDs;
  re-run BUSL/checklist parity.
- **OWASP API Top 10 next edition**: re-run the crosswalk; the 2019
  labels stay historical.
- **MASWE catalog > 0078**: extend `owasp-mas` ranges; MASVS-PRIVACY is
  the most likely next category to grow.
- **CVSS v4.x updates** + platform VRT/policy changes: refresh
  `report-writing` severity chapter.
- **OWASP GenAI / Agentic editions and AI Testing Guide test IDs**: check
  the official project pages at each annual review and when a new stable
  edition or distinct application-test method is announced.
- **Tool version drift** (httpx/dnsx/trufflehog/gitleaks/gowitness/nmap):
  annual re-pin or on any command failure report.

## Methodology currency delta (2026-09-24)

The user-shared *BUG BOUNTY METHODOLOGY 2026 v3.0* was read and applied as a
12-activity crosswalk in the existing seven-phase `bug-bounty-hunter` router.
Functional mapping precedes feature-led deep recon; AI assistance remains an
overlay on the existing human-owned hypothesis and authorization gates. No
parallel lifecycle or duplicate validation/monitoring records were added.

Current sources re-checked for this delta: OWASP GenAI LLM Top 10 2026,
OWASP Top 10 for Agentic Applications 2026, selected OWASP AI Testing Guide
v1 procedures, WSTG v4.2 (v5.0 remains in development), API Security Top 10
2023, and ASVS 5.0.0. The ASVS project page still has mixed status language:
its guidance calls 5.0.0 latest stable while its project-info field says
“Bleeding Edge”; use versioned 5.0.0 requirements and re-check before relying
on unversioned status claims. The 2025 LLM list remains historical only.

Delta files changed in the skills repository:

- `bug-bounty-hunter/SKILL.md`
- `bug-bounty-hunter/chapters/01-phase-map.md`
- `bug-bounty-hunter/chapters/02-session-checklist.md`
- `bug-bounty-hunter/chapters/03-vuln-class-index.md`
- `bug-bounty-hunter/sources.md`
- `web-security-academy/SKILL.md`
- `web-security-academy/chapters/ch15-logic-race-api-llm.md`
- `web-security-academy/sources.md`

This register and the historical full-refresh plan were updated in this
workspace; the dated delta plan records the execution steps. Final static
review found all 12 crosswalk activities mapped, the Phase 2/3 session gate
consistent with functional-first ordering, 231 changed-chapter references
resolving, no remaining current-2025 LLM route, and no whitespace errors.
No live-target requests, scans, exploit attempts, or credential checks were
performed. The original plan's generated-skill scanner and pressure-scenario
steps remain open because their run output was not retained; this delta does
not claim those checks passed. Other rolling authorities and tool versions
not named above retain their 2026-09-23 baseline snapshot.
