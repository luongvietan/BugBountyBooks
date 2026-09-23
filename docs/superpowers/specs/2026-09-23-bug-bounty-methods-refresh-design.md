# Design: 2026 Bug Bounty Skills Refresh — Baseline and Delta

Date: 2026-09-24 (delta review)
Status: revised draft, awaiting user review

## Intent

The original refresh of the existing 17 skills in
`C:\Users\luong\.agents\skills\` is recorded as implemented in the source
register. This delta review identifies drift since that refresh, reconciles
the implementation plan with the recorded state, and updates only affected
guidance. Preserve useful foundational material, keep scope control
operationally unambiguous, and do not test any target as part of this work.

## Original full-refresh baseline (2026-09-23)

The sections below preserve the original full-refresh design as context for
the completed work. Their source cutoff and per-skill update scope describe
that baseline; the authoritative follow-up scope and acceptance criteria are
in **Delta review design — 2026-09-24** at the end of this document.

## User-approved direction

Add current methods to the existing 17 skills rather than replacing the corpus
or creating a parallel 2026 skill. Keep existing directory names and skill
loader entry points. Update primary chapters and the `bug-bounty-hunter` router
where methods or source versions have changed. Preserve historical book-based
material where it still explains mechanics well, label its limits, and link it
to current procedures.

## Goals

- Modernize methods across all 17 skills, with explicit source/version/date
  metadata for time-sensitive guidance.
- Make authorization and scope deny-by-default: exact allowlisted assets,
  policy snapshot, technique-specific permission, conservative rate defaults,
  and stop conditions before active traffic.
- Align API coverage with OWASP API Security Top 10 2023 while retaining useful
  2019 crosswalks.
- Update severity guidance for CVSS v4.0 and program-specific taxonomies;
  never imply one score controls every bounty program.
- Add an authorized-testing path for AI/LLM product surfaces (prompt injection,
  sensitive data exposure, unsafe tool/action use, vector/RAG isolation, and
  resource-consumption risks) using current OWASP guidance.
- Refresh modern web, API, mobile, cloud, recon, reporting, and tool workflows
  using primary sources and reproducible references.
- Preserve the seven-phase router and validate every internal skill/chapter
  reference after updates.

## Non-goals

- No active probing, scanning, exploit attempts, or credential validation
  against a bounty program as part of this documentation update.
- No promise to include undisclosed or zero-day techniques; the original
  full-refresh cutoff was 2026-09-23. The delta review uses sources verified
  through 2026-09-24.
- No wholesale re-conversion of the source books and no copying of substantial
  source text. Keep transformed notes, short attributed references, and links.
- No new skills, automated scanner product, or claims that CVSS determines a
  platform's payout.

## Design

### 1. Update in place, with source records

For each skill, inspect the existing `SKILL.md` and supporting chapters. Update
the relevant content in place and add a concise `Sources and currency` section
or a focused source file where it would otherwise make the skill unwieldy.
Record: authority/source, edition or release, canonical URL, access/review date,
and which guidance it supports. Keep old editions explicitly labeled when
retained for historical context. Use versioned links for versioned standards.

Not every source requires a new chapter. Add a chapter only when it provides a
distinct procedure or significant coverage gap; avoid duplicated payload lists
and repeated generic warnings across the set.

### 2. Scope gate and safe operational defaults

Revise `bug-bounty-hunter` and `recon-pipeline` first. The standard workflow
must require a written program policy and an exact asset allowlist before any
target traffic. A discovered hostname or resolved IP is a lead until ownership
and program scope are confirmed. Missing or ambiguous scope, missing permission
for a technique, shared/CDN infrastructure, a service warning, or unexpected
real-user data must stop that stage and trigger policy re-check or program
contact.

Separate passive collection from active requests and from intrusive tests.
Active examples should default to small scope, low rate, short timeouts, and
read-only requests. High-volume scans, brute force, destructive writes,
cross-user access, persistence, exfiltration, and credential use must be
omitted from default quickstarts and described only with explicit policy
authorization, test-owned assets/accounts, and the least-impact proof that
answers the security question. Store credentials in a password manager or
secret store; notes and run logs contain aliases and evidence references only.

### 3. Current-method coverage by skill

| Existing skill | Refresh focus |
|---|---|
| `bug-bounty-hunter` | Router coverage for modern web/API/AI surfaces; scope gates, evidence handling, update/version policy |
| `recon-pipeline` | Deny-by-default allowlist, safe passive/active staging, current tool syntax, scope diffs, secret-safe artifacts |
| `report-writing` | Program-first severity, CVSS v4.0 where useful, reproducible minimal PoCs, evidence/data minimization |
| `hacking-the-cloud` | Current provider docs and safe validation; credential handling, identity/resource policies, cloud service changes |
| `owasp-mas` | Current MASTG/MASVS mappings, Android/iOS platform checks, backend/API boundary, safe device/data handling |
| `owasp-wstg` | Versioned test IDs, current published WSTG release, web/API boundary and version watch |
| `web-app-hackers-handbook` | Retain enduring mechanics; mark legacy assumptions and route modern protocol/browser cases to maintained sources |
| `web-security-academy` | Current request smuggling, HTTP/2, cache, race, WebSocket, OAuth/JWT, browser-side techniques and labs |
| `payloads-all-the-things` | Context-first payload selection, safe test markers, parser/encoding caveats, source freshness |
| `tbhm-methodology` | Reconcile classic recon/mapping with current inventory, platform surfaces, and authorization gates |
| `hacking-apis` | API inventory and authorization matrices, GraphQL and current API protocols, bounded validation |
| `owasp-api-security-top-10` | Add API Top 10 2023 mapping, especially BOPLA, sensitive business flows, SSRF, unsafe API consumption |
| `bug-bounty-bootcamp` | Preserve core web workflow; annotate dated tools/classes and route modern gaps |
| `bug-bounty-playbook` | Reframe high-impact exploitation examples as theory or explicitly gated tests; update current techniques and safe stopping rules |
| `web-hacking-101` | Keep case studies as historical precedent, not current severity or payout guarantees |
| `xss-cheat-sheet` | Modern browser/parser contexts, sanitizer/framework behaviors, safe proof and maintained-source links |
| `zseano-methodology` | Preserve first-look workflow, refresh target selection, recon and authorization assumptions |

### 4. Source hierarchy

Use the following order when guidance conflicts:

1. Current program policy, platform rules, and written authorization.
2. Current official standards and primary project documentation: OWASP WSTG,
   API Security Top 10, MASTG/MASVS, OWASP GenAI/LLM guidance, FIRST CVSS, and
   official provider documentation for cloud behavior.
3. Maintained technical research and lab material from sources such as
   PortSwigger Web Security Academy, with a clear distinction between lab
   demonstration and production-safe bounty validation.
4. Tool vendor documentation for command syntax and version-specific behavior.
5. Existing books and community methodologies for durable concepts; label
   edition/date limits and do not use them as sole authority for current rules.

Initial source anchors for the full refresh (see the delta review below for
current-source updates) included:

- OWASP API Security Top 10 2023:
  `https://api-security.owasp.org/editions/2023/en/0x00-header/`
- OWASP WSTG versioned release:
  `https://wstg.owasp.org/v4.2/` (check official release page for later stable
  versions before finalizing)
- FIRST CVSS v4.0 specification and user guide:
  `https://www.first.org/cvss/v4-0/`
- OWASP Top 10 for LLM Applications 2025 (historical baseline; superseded for
  current guidance by the 2026 edition):
  `https://owasp.org/www-project-top-10-for-large-language-model-applications/`
- PortSwigger Web Security Academy topic index:
  `https://portswigger.net/web-security/all-materials`
- OWASP MASTG/MASVS and official cloud-provider security/testing references;
  exact current URLs/releases to be recorded in the implementation source map.

## Update workflow

1. Inventory all 17 skills, source versions, internal routes, risky claims,
   commands, and existing coverage; record proposed changes by file.
2. Research current primary sources for changed areas and capture edition,
   release/commit, URL, and access date. Do not update from search snippets.
3. Update authorization and source-currency conventions in the router and
   operational skills, then update topical references and cross-links.
4. For each skill, review factual accuracy, scope boundaries, attribution,
   internal links, and duplicated guidance before moving to the next skill.
5. Run structural/link checks and the existing generated-skill scanner where
   available; read every warning in context. Perform scenario-based review of
   the scope gates and retrieval routes before calling the set ready.
6. Produce a change summary and a source/version register with known gaps.

## Acceptance criteria

- All 17 existing skill directories remain discoverable with unchanged names.
- Each skill has either a substantive 2026 update or a documented review note
  explaining why its durable guidance remains current.
- Router entries resolve to existing files and include current AI/LLM, API,
  cloud, mobile, and modern web routes where applicable.
- The recon quickstart cannot imply that discovered assets are automatically
  in scope; no default high-volume or disruptive command is presented as
  routine.
- No instruction recommends storing passwords/tokens in ordinary notes or
  logs, validating third-party credentials, accessing real-user records, or
  continuing after service impact.
- API Top 10 2019 content is labeled historical and mapped to 2023; severity
  guidance defers to the program and supports CVSS v4.0 without making it
  universal.
- Current claims link to source editions or releases and carry a review date.
- All internal skill/chapter references resolve; scanner warnings are
  individually reviewed and dispositions recorded.
- No target has been tested as part of the update.

## Risks and mitigations

- **Moving sources/tool syntax:** pin releases or commits where possible and
  record the access date; keep vendor commands version-scoped.
- **Overstating "2026" completeness:** define the cutoff date and public-source
  basis; document uncovered areas rather than implying exhaustive coverage.
- **Unsafe transfer from lab to production:** state lab-only conditions and
  require a separate policy gate before any real-target validation.
- **Skill duplication and routing drift:** update the router after topical
  edits and validate all referenced paths as a final gate.
- **Copyright/licensing:** synthesize methods, attribute licensed material,
  and link to source documents instead of reproducing chapters.

## Delta review design — 2026-09-24

### Current state and intent

The 2026-09-23 source register records all 17 skills as implemented, including
the scope contract, recon provenance, hypothesis engine, finding lifecycle,
validation gate, evidence hygiene, and monitoring. The implementation plan
still has unchecked task boxes, so it no longer accurately represents the
work state. This follow-up is a targeted currency and plan-reconciliation
pass, not a second full refresh of the 17-skill set.

### Methodology alignment

Keep the existing seven-phase `bug-bounty-hunter` router as the operating
entry point. Cross-map the 12-stage research methodology from program
intelligence through continuous monitoring onto its existing phases and
artifacts. Extend the router only where a real gap remains. Preserve the
existing feature cards, falsifiable hypothesis cards, authorization gates,
independent validation, duplicate/outcome records, and monitoring workflow;
do not create a parallel lifecycle or duplicate the hypothesis engine.

### Source and implementation deltas

- Refresh the source register cutoff and review date to 2026-09-24.
- Replace OWASP GenAI LLM Top 10 2025 as the current AI risk reference with
  the official 2026 edition. Add the OWASP Top 10 for Agentic Applications
  2026 where agent and tool authorization are discussed. Preserve 2025
  references only when they are explicitly historical.
- Verify whether OWASP AI Testing Guide v1 (published in 2025) adds useful,
  testable coverage beyond the two Top 10 references; include it only where
  it contributes a distinct method.
- Keep WSTG v4.2 as the stable versioned baseline while marking v5 material
  as draft until OWASP publishes a stable release. Keep API Security Top 10
  2023 and ASVS 5.0.0 unless the official projects show a newer stable
  edition at implementation time.
- Reconcile the implementation plan against Git history, the source register,
  and the actual skill files. Mark completed work with evidence; retain only
  verified unresolved deltas as tasks.
- Update only the source register, router, AI/LLM skill materials, and any
  directly affected source metadata or links. Leave unrelated skills alone.

### Acceptance criteria for this delta

- The plan's checkboxes and completion notes agree with the implemented state
  and can be traced to files or commits.
- Current AI security references use OWASP's 2026 LLM and agentic editions;
  dated 2025 material is labeled historical where retained.
- The seven-phase router and existing hypothesis engine are mapped to the
  research lifecycle without duplicate stages or a second competing process.
- Stable standards remain version-pinned, draft material is labeled, and all
  changing claims have a review date and canonical source.
- No live-target testing is performed during the documentation update.
