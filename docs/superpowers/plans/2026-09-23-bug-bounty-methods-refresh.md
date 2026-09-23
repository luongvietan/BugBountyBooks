# 2026 Bug Bounty Methods Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Update the 17 existing personal bug bounty skills with current public methods and safe operational defaults as of 2026-09-23.

**Architecture:** Keep the 17 skill names and directories. Add source/version/review metadata in each skill, update the operational safety layer first, refresh topical methods by domain, and finish by reconciling all routes and links. Treat live program policy as the authority for testing; public standards and research inform methods but never grant target authorization.

**Tech Stack:** Markdown skill files, PowerShell/rg for read-only inventory and link checks, official OWASP/FIRST/provider documentation, maintained PortSwigger research/labs, and the existing `scan_generated_skill.py` skill-content scanner when available.

**Spec:** `docs/superpowers/specs/2026-09-23-bug-bounty-methods-refresh-design.md`

## Global Constraints

- Refresh the existing 17 skills in `C:\Users\luong\.agents\skills\` so they teach current, practical methods for authorized bug bounty work as of 2026-09-23.
- Keep existing directory names and skill loader entry points.
- Use a verifiable public-source cutoff of 2026-09-23.
- Current program policy and written authorization outrank all routing and technique guidance.
- A discovered hostname or resolved IP is a lead until ownership and program scope are confirmed.
- Missing or ambiguous scope, missing permission for a technique, shared/CDN infrastructure, a service warning, or unexpected real-user data must stop that stage and trigger policy re-check or program contact.
- High-volume scans, brute force, destructive writes, cross-user access, persistence, exfiltration, and credential use must be omitted from default quickstarts and described only with explicit policy authorization, test-owned assets/accounts, and the least-impact proof that answers the security question.
- Store credentials in a password manager or secret store; notes and run logs contain aliases and evidence references only.
- Use the following source order when guidance conflicts: current program policy and written authorization; official standards and primary documentation; maintained technical research/labs; tool vendor docs; existing books/community methods as foundational context.
- Synthesize and attribute source material; do not reproduce substantial source text.
- No active probing, scanning, exploit attempts, or credential validation against a bounty program as part of this documentation update.

## Review Focus

1. Missing, ambiguous, wildcard, or stale scope must block target traffic; prove the deny-by-default rule in the operational skill review.
2. CDN/shared IPs and third-party services must not inherit authorization from a related hostname; verify recon IP handling and router wording.
3. Found tokens, passwords, and real-user data must not be replayed or copied into notes, logs, or screenshots; verify recon, cloud, and session guidance.
4. Lab-only techniques such as request smuggling, race conditions, brute force, and LLM tool abuse must be distinguishable from safe bounty validation; review each affected chapter and its stop conditions.
5. Standards and severity guidance can be edition- or program-specific; verify API 2019→2023 crosswalks, WSTG versioning, CVSS v4.0 references, and platform-first reporting.

---

### Task 1: Establish the source and coverage register

**Files:**
- Create: `docs/superpowers/2026-09-23-bug-bounty-source-register.md`
- Read: `C:\Users\luong\.agents\skills\bug-bounty-hunter\SKILL.md`, `recon-pipeline\SKILL.md`, `report-writing\SKILL.md`, `hacking-the-cloud\SKILL.md`, `owasp-mas\SKILL.md`, `owasp-wstg\SKILL.md`, `web-app-hackers-handbook\SKILL.md`, `web-security-academy\SKILL.md`, `payloads-all-the-things\SKILL.md`, `tbhm-methodology\SKILL.md`, `hacking-apis\SKILL.md`, `owasp-api-security-top-10\SKILL.md`, `bug-bounty-bootcamp\SKILL.md`, `bug-bounty-playbook\SKILL.md`, `web-hacking-101\SKILL.md`, `xss-cheat-sheet\SKILL.md`, and `zseano-methodology\SKILL.md`; read the supporting Markdown files in those same directories

**Interfaces:**
- Consumes: approved design spec and existing 17-skill tree.
- Produces: source register with one row per skill: current source/version, 2026 source to check, files that need substantive review, and planned disposition.

- [ ] **Step 1: Inventory current skill files** with `Get-ChildItem C:\Users\luong\.agents\skills\bug-bounty-hunter -Recurse -File` and repeat for `recon-pipeline`, `report-writing`, `hacking-the-cloud`, `owasp-mas`, `owasp-wstg`, `web-app-hackers-handbook`, `web-security-academy`, `payloads-all-the-things`, `tbhm-methodology`, `hacking-apis`, `owasp-api-security-top-10`, `bug-bounty-bootcamp`, `bug-bounty-playbook`, `web-hacking-101`, `xss-cheat-sheet`, and `zseano-methodology`; record existing filenames and source labels in the register.
- [ ] **Step 2: Verify current authority pages** from the official source URLs in the spec: OWASP API Top 10, WSTG releases, OWASP GenAI/LLM, FIRST CVSS, OWASP MASTG/MASVS, cloud-provider documentation, PortSwigger topic index, and each recon tool vendor’s official CLI docs.
- [ ] **Step 3: Record exact source versions and access date**; use versioned or commit-pinned links where the source offers them, and label rolling documentation as rolling.
- [ ] **Step 4: Map each authority to skills and chapters**; mark book-derived material as historical/foundational where current guidance differs.
- [ ] **Step 5: Review the register** for every one of the 17 skill names, a 2026 review disposition, and no claim derived only from a search snippet.

### Task 2: Make the orchestrator scope-first and deny-by-default

**Files:**
- Modify: `C:\Users\luong\.agents\skills\bug-bounty-hunter\SKILL.md`
- Modify: `C:\Users\luong\.agents\skills\bug-bounty-hunter\chapters\01-phase-map.md`
- Modify: `C:\Users\luong\.agents\skills\bug-bounty-hunter\chapters\02-session-checklist.md`
- Modify: `C:\Users\luong\.agents\skills\bug-bounty-hunter\chapters\03-vuln-class-index.md`
- Create: `C:\Users\luong\.agents\skills\bug-bounty-hunter\sources.md`

**Interfaces:**
- Consumes: source register from Task 1.
- Produces: policy-first session router with exact asset allowlist, per-technique permission, evidence handling, stop conditions, and an AI/LLM route to maintained guidance.

- [ ] **Step 1: Rewrite session-init requirements** to capture policy URL/revision/date, exact inclusions, exclusions, test-account aliases, allowed methods, limits, reporting path, and stop/contact conditions; remove the instruction to put credentials in notes.
- [ ] **Step 2: Rewrite phase-2 routing** so passive discovery is separated from target traffic and no new hostname or resolved address is treated as in scope automatically.
- [ ] **Step 3: Add a scope decision rule**: if authorization, ownership, asset matching, or technique permission is absent or ambiguous, stop that stage and re-check policy or contact the program.
- [ ] **Step 4: Add/adjust router entries** for current API risks, AI/LLM product surfaces, modern web protocols, and severity sources without adding a new skill.
- [ ] **Step 5: Add focused pressure-review scenarios** for no scope file, discovered-but-unlisted host, shared CDN address, and a found credential; expected behavior is to halt the relevant action and preserve/redact evidence safely.
- [ ] **Step 6: Check every chapter path named in the router** against the target skill directory before considering this task done.

### Task 3: Harden the recon runbook and its artifacts

**Files:**
- Modify: `C:\Users\luong\.agents\skills\recon-pipeline\SKILL.md`
- Modify: `C:\Users\luong\.agents\skills\recon-pipeline\chapters\01-stages.md`
- Modify: `C:\Users\luong\.agents\skills\recon-pipeline\chapters\02-outputs.md`
- Modify: `C:\Users\luong\.agents\skills\recon-pipeline\chapters\03-monitoring.md`
- Create: `C:\Users\luong\.agents\skills\recon-pipeline\sources.md`

**Interfaces:**
- Consumes: the deny-by-default session contract from Task 2 and vendor docs from Task 1.
- Produces: current, version-scoped recon procedures whose target lists are allowlist-derived and whose default settings are low-impact.

- [ ] **Step 1: Replace exclusion-only filtering** with exact allowlist membership and explicit subdomain/wildcard semantics; missing allowlist must yield an empty active-target list, never “all discovered hosts.”
- [ ] **Step 2: Separate stage labels** into third-party passive collection, target HTTP probing, DNS queries, and intrusive/high-volume testing; mark policy permission needed for each.
- [ ] **Step 3: Remove all-ports Masscan and high-rate examples from the normal run path**; if retained as exceptional reference, put behind an explicit program permission gate, strict target file, low configurable rate, and shared-infrastructure exclusion.
- [ ] **Step 4: Refresh command syntax against official vendor docs** for tools retained in the runbook; record tool versions, rate limits, timeout, and user-agent in `run.log`.
- [ ] **Step 5: Update output handling** to redact credentials and personal data, avoid storing full secrets or unnecessary repository clones, and keep sensitive raw results outside normal notes/evidence bundles.
- [ ] **Step 6: Update monitoring** so every newly discovered asset requires ownership, allowlist, exclusion, and method re-check before active follow-up.
- [ ] **Step 7: Review edge scenarios**: no allowlist, empty list, wildcard DNS, CDN resolution, 429/service degradation, and a secret found in public code; expected output must be safe and must not continue testing automatically.

### Task 4: Refresh API coverage and taxonomy

**Files:**
- Modify: `C:\Users\luong\.agents\skills\hacking-apis\SKILL.md`
- Modify: `C:\Users\luong\.agents\skills\hacking-apis\chapters\ch00-approach-and-fundamentals.md`
- Modify: `C:\Users\luong\.agents\skills\hacking-apis\chapters\ch01-insecurity-taxonomy.md`
- Modify: `C:\Users\luong\.agents\skills\hacking-apis\chapters\ch03-discovering-apis.md`
- Modify: `C:\Users\luong\.agents\skills\hacking-apis\chapters\ch04-endpoint-analysis.md`
- Modify: `C:\Users\luong\.agents\skills\hacking-apis\chapters\ch05-attacking-authentication.md`
- Modify: `C:\Users\luong\.agents\skills\hacking-apis\chapters\ch06-fuzzing.md`
- Modify: `C:\Users\luong\.agents\skills\hacking-apis\chapters\ch07-authorization-bola-bfla.md`
- Modify: `C:\Users\luong\.agents\skills\hacking-apis\chapters\ch08-mass-assignment.md`
- Modify: `C:\Users\luong\.agents\skills\hacking-apis\chapters\ch10-evasion-rate-limits.md`
- Modify: `C:\Users\luong\.agents\skills\hacking-apis\chapters\ch11-graphql.md`
- Create: `C:\Users\luong\.agents\skills\hacking-apis\sources.md`
- Modify: `C:\Users\luong\.agents\skills\owasp-api-security-top-10\SKILL.md`, `chapters\ch01-broken-object-level-authorization.md`, `chapters\ch02-broken-user-authentication.md`, `chapters\ch03-excessive-data-exposure.md`, `chapters\ch04-lack-of-resources-rate-limiting.md`, `chapters\ch05-broken-function-level-authorization.md`, `chapters\ch06-mass-assignment.md`, `chapters\ch07-security-misconfiguration.md`, `chapters\ch08-injection.md`, `chapters\ch09-improper-assets-management.md`, `chapters\ch10-insufficient-logging-monitoring.md`, `cheatsheet.md`, `patterns.md`
- Create: `C:\Users\luong\.agents\skills\owasp-api-security-top-10\sources.md`

**Interfaces:**
- Consumes: current OWASP API Security Top 10 2023 source and tool/vendor docs.
- Produces: API discovery and test matrix aligned to API1:2023–API10:2023, with backward mapping to useful 2019 content.

- [ ] **Step 1: Add a 2019→2023 crosswalk** distinguishing old excessive-data-exposure/mass-assignment wording from API3:2023 BOPLA and adding sensitive business flows, SSRF, and unsafe API consumption.
- [ ] **Step 2: Update endpoint inventory and authorization matrices** to cover object, property, function, tenant, and workflow boundaries using only researcher-owned accounts/data.
- [ ] **Step 3: Refresh GraphQL and API discovery guidance** from current primary project/vendor references, preserving bounded introspection and query-cost limits.
- [ ] **Step 4: Reframe authentication/rate-limit examples** around low-volume, account-owned checks; mark brute-force, resource exhaustion, and evasion as requiring explicit permission and omit them from quickstarts.
- [ ] **Step 5: Add source/version/review metadata** to both API skills and update their descriptions/quick references to avoid presenting 2019 categories as current.
- [ ] **Step 6: Review the crosswalk** against the official API Top 10 edition page and verify that every 2023 risk is routed to a method or explicitly marked as a coverage gap.

### Task 5: Refresh WSTG, current web classes, and AI/LLM application testing

**Files:**
- Modify: `C:\Users\luong\.agents\skills\owasp-wstg\SKILL.md`, `chapters\ch01-information-gathering.md`, `chapters\ch02-configuration-deployment.md`, `chapters\ch05-authorization.md`, `chapters\ch07-input-validation.md`, `chapters\ch10-business-logic.md`, `chapters\ch11-client-side.md`, `chapters\ch12-api-testing.md`, `cheatsheet.md`, `patterns.md`
- Create: `C:\Users\luong\.agents\skills\owasp-wstg\sources.md`
- Modify: `C:\Users\luong\.agents\skills\web-security-academy\SKILL.md`, `chapters\ch01-request-smuggling.md`, `chapters\ch02-http2-desync.md`, `chapters\ch03-cache-host.md`, `chapters\ch04-prototype-pollution.md`, `chapters\ch05-dom-attacks.md`, `chapters\ch06-websockets.md`, `chapters\ch07-jwt.md`, `chapters\ch08-oauth.md`, `chapters\ch09-cors-csrf-clickjacking.md`, `chapters\ch15-logic-race-api-llm.md`, `cheatsheet.md`, `patterns.md`
- Create: `C:\Users\luong\.agents\skills\web-security-academy\sources.md`
- Modify: `C:\Users\luong\.agents\skills\web-app-hackers-handbook\SKILL.md`, `chapters\ch03-mapping-application.md`, `chapters\ch05-authentication.md`, `chapters\ch07-access-controls.md`, `chapters\ch11-xss.md`, `chapters\ch13-automating-attacks.md`, `chapters\ch19-hackers-toolkit.md`, `chapters\ch20-methodology.md`, `cheatsheet.md`, `patterns.md`
- Create: `C:\Users\luong\.agents\skills\web-app-hackers-handbook\sources.md`

**Interfaces:**
- Consumes: official current WSTG release page, PortSwigger research/labs, OWASP GenAI/LLM guidance, and the historical WAHH source edition.
- Produces: clear distinction between versioned checklist procedures, maintained modern web research, lab-only methods, and enduring historical mechanics.

- [ ] **Step 1: Verify the latest stable WSTG release** at implementation time; preserve stable versioned test IDs and mark draft/bleeding-edge guidance separately.
- [ ] **Step 2: Update modern web chapters** for request smuggling/HTTP2, cache and host attacks, race conditions, WebSockets, OAuth/JWT, browser parsing/prototype pollution, and API surfaces from maintained first-party materials.
- [ ] **Step 3: Expand the existing LLM material** in `web-security-academy/chapters/ch15-logic-race-api-llm.md` with OWASP LLM application risks: indirect/direct prompt injection, sensitive data exposure, unsafe tool/action calls, RAG/vector-store isolation, output handling, and resource risks.
- [ ] **Step 4: For every protocol/race/LLM technique**, separate lab reproduction from bounty-safe validation; define owned test data, low-impact confirmation, and immediate stop conditions if another user, system, or service could be affected.
- [ ] **Step 5: Mark WAHH edition-dependent advice** as historical, link updated modern procedures, and retain only its durable mechanics/checklists.
- [ ] **Step 6: Review source links and route references** for all modified web chapters; no lab page may be represented as authorization to test a live program.

### Task 6: Refresh cloud and mobile methods

**Files:**
- Modify: `C:\Users\luong\.agents\skills\hacking-the-cloud\SKILL.md`, `chapters\ch01-recon-unauthenticated-enum.md`, `chapters\ch02-metadata-services-ssrf.md`, `chapters\ch03-found-iam-credentials.md`, `chapters\ch04-storage-buckets-snapshots.md`, `chapters\ch05-privesc-misconfigured-policies.md`, `chapters\ch07-exfiltration-detection.md`, `chapters\ch08-multicloud-general.md`, `cheatsheet.md`, `patterns.md`
- Create: `C:\Users\luong\.agents\skills\hacking-the-cloud\sources.md`
- Modify: `C:\Users\luong\.agents\skills\owasp-mas\SKILL.md`, `chapters\ch01-methodology-setup.md`, `chapters\ch02-storage.md`, `chapters\ch04-auth.md`, `chapters\ch05-network.md`, `chapters\ch06-platform-interaction.md`, `chapters\ch09-tools-techniques.md`, `cheatsheet.md`, `patterns.md`
- Create: `C:\Users\luong\.agents\skills\owasp-mas\sources.md`

**Interfaces:**
- Consumes: official provider docs, current OWASP MASTG/MASVS references, and the approved scope/credential rules from Tasks 2–3.
- Produces: current cloud/mobile checks with test-account-only validation and less sensitive data retention.

- [ ] **Step 1: Update cloud service and identity guidance** from official AWS/GCP/Azure docs; record provider/version dependencies and label techniques that require credentialed cloud scope.
- [ ] **Step 2: Replace “verify a found key” defaults** with non-use reporting/redaction by default; allow a single identity check only when the program policy explicitly authorizes credential validation and the key is confirmed to belong to the target program.
- [ ] **Step 3: Update storage/IAM validation** to use metadata/policy evidence or researcher-owned canaries; remove persistence, broad enumeration, and customer-data reads from default procedures.
- [ ] **Step 4: Verify current MASTG/MASVS release references** and update Android/iOS procedures and tool names from official docs; keep backend API testing routed to Task 4.
- [ ] **Step 5: Review cloud/mobile edge scenarios**: third-party cloud account, leaked credential of unclear ownership, public bucket containing personal data, rooted test device with real user data; each must stop or use a safe substitute.

### Task 7: Update severity, reporting, and evidence handling

**Files:**
- Modify: `C:\Users\luong\.agents\skills\report-writing\SKILL.md`
- Modify: `C:\Users\luong\.agents\skills\report-writing\chapters\01-severity.md`
- Modify: `C:\Users\luong\.agents\skills\report-writing\chapters\02-template.md`
- Modify: `C:\Users\luong\.agents\skills\report-writing\chapters\03-impact-library.md`
- Modify: `C:\Users\luong\.agents\skills\report-writing\chapters\04-triage.md`
- Create: `C:\Users\luong\.agents\skills\report-writing\sources.md`

**Interfaces:**
- Consumes: FIRST CVSS v4.0 docs, current program/platform severity policy, source register, and secret-safe evidence rules.
- Produces: platform-first reports with reproducible steps, minimized evidence, and an optional correctly attributed CVSS vector.

- [ ] **Step 1: Reframe severity precedence** as program rubric first, platform policy second, CVSS only where accepted/requested; remove universal HackerOne/Bugcrowd claims and date-stamp changing platform guidance.
- [ ] **Step 2: Add CVSS v4.0 guidance** using FIRST metric names and versioned calculator/spec references; retain v3.x only when a program specifically requires it.
- [ ] **Step 3: Update report template** to require asset/scope match, test account alias, exact impact evidence, minimal PoC, and redaction of tokens/PII.
- [ ] **Step 4: Update impact library and triage guidance** so claims distinguish demonstrated impact from theoretical escalation and do not encourage further exploitation beyond the policy.
- [ ] **Step 5: Review example reports** for reproducibility from clean state and absence of credentials, real personal data, and unsupported severity claims.

### Task 8: Refresh payload, playbook, and legacy methodology skills

**Files:**
- Modify: `C:\Users\luong\.agents\skills\payloads-all-the-things\SKILL.md`, `chapters\ch01-xss.md`, `chapters\ch04-ssti.md`, `chapters\ch05-ssrf.md`, `chapters\ch06-xxe.md`, `chapters\ch08-command-injection.md`, `chapters\ch11-graphql.md`, `chapters\ch14-http-infra.md`, `chapters\ch15-logic-misc.md`, `cheatsheet.md`, `patterns.md`
- Create: `C:\Users\luong\.agents\skills\payloads-all-the-things\sources.md`
- Modify: `C:\Users\luong\.agents\skills\bug-bounty-playbook\SKILL.md`, `chapters\ch01-known-vulnerabilities.md`, `chapters\ch03-github-subdomain-takeover.md`, `chapters\ch04-exposed-databases.md`, `chapters\ch05-brute-force-burp.md`, `chapters\ch09-api-types.md`, `chapters\ch10-api-auth-docs.md`, `chapters\ch11-cache-attacks.md`, `chapters\ch13-osrf-prototype-csti.md`, `chapters\ch14-xxe-csp-rpo.md`, `cheatsheet.md`, `patterns.md`
- Create: `C:\Users\luong\.agents\skills\bug-bounty-playbook\sources.md`
- Modify: `C:\Users\luong\.agents\skills\bug-bounty-bootcamp\SKILL.md`, `chapters\ch01-industry-reports.md`, `chapters\ch03-recon.md`, `chapters\ch07-idor.md`, `chapters\ch09-race-conditions.md`, `chapters\ch10-ssrf.md`, `chapters\ch20-android.md`, `chapters\ch21-api-hacking.md`, `chapters\ch22-fuzzing.md`, `cheatsheet.md`, `patterns.md`
- Create: `C:\Users\luong\.agents\skills\bug-bounty-bootcamp\sources.md`
- Modify: `C:\Users\luong\.agents\skills\web-hacking-101\SKILL.md`, `chapters\ch01-methodology.md`, `chapters\ch04-application-logic.md`, `chapters\ch10-memory-reporting.md`, `cheatsheet.md`, `patterns.md`
- Create: `C:\Users\luong\.agents\skills\web-hacking-101\sources.md`
- Modify: `C:\Users\luong\.agents\skills\xss-cheat-sheet\SKILL.md`, `chapters\ch01-basics.md`, `chapters\ch02-advanced.md`, `chapters\ch03-filter-bypass.md`, `chapters\ch04-exploitation.md`, `chapters\ch05-miscellaneous.md`, `cheatsheet.md`, `patterns.md`
- Create: `C:\Users\luong\.agents\skills\xss-cheat-sheet\sources.md`
- Modify: `C:\Users\luong\.agents\skills\tbhm-methodology\SKILL.md`, `chapters\ch01-philosophy-bounty-model.md`, `chapters\ch02-discovery-recon.md`, `chapters\ch03-mapping-enumeration.md`, `chapters\ch04-auth-session.md`, `chapters\ch05-tactical-fuzzing-xss-sqli.md`, `chapters\ch06-uploads-lfi-redirects.md`, `chapters\ch07-csrf-priv-logic-transport.md`, `chapters\ch08-mobile-aux-checklist.md`, `cheatsheet.md`, `patterns.md`
- Create: `C:\Users\luong\.agents\skills\tbhm-methodology\sources.md`
- Modify: `C:\Users\luong\.agents\skills\zseano-methodology\SKILL.md`, `chapters\ch01-mindset-program-notes.md`, `chapters\ch02-basic-toolkit.md`, `chapters\ch03-common-issues-xss-csrf.md`, `chapters\ch04-common-issues-redirect-ssrf-upload-idor.md`, `chapters\ch05-step-one-first-look.md`, `chapters\ch06-step-two-attack-surface.md`, `chapters\ch07-step-three-findings-resources.md`, `cheatsheet.md`, `patterns.md`
- Create: `C:\Users\luong\.agents\skills\zseano-methodology\sources.md`

**Interfaces:**
- Consumes: current source register and the modern web/API/cloud guidance completed in Tasks 3–6.
- Produces: updated reference methods that preserve useful foundational knowledge while not presenting old payloads, examples, or payouts as current/live-safe.

- [ ] **Step 1: Convert payload guidance to context-first selection**: identify parser/context and safe marker, use a single harmless proof first, and distinguish lab payloads from live-program validation.
- [ ] **Step 2: Review playbook chapters** for brute force, exposed data, cache, SSRF, command execution, and persistence; convert risky actions to theory or explicit permission-gated, test-owned procedures.
- [ ] **Step 3: Review Bootcamp and methodology chapters** for durable concepts, mark tool/platform examples that have changed, and route modern classes to Tasks 4–6.
- [ ] **Step 4: Update Web Hacking 101 case studies** as historical examples with no implied present-day payout or severity promise.
- [ ] **Step 5: Update XSS guidance** against maintained browser/framework/source references; require a harmless proof and avoid session theft or victim delivery.
- [ ] **Step 6: Add sources and review dates** to all seven skills and resolve every new cross-skill route before finishing the task.

### Task 9: Reconcile metadata, descriptions, and the 2026 source index

**Files:**
- Modify: `C:\Users\luong\.agents\skills\bug-bounty-hunter\SKILL.md`, `recon-pipeline\SKILL.md`, `report-writing\SKILL.md`, `hacking-the-cloud\SKILL.md`, `owasp-mas\SKILL.md`, `owasp-wstg\SKILL.md`, `web-app-hackers-handbook\SKILL.md`, `web-security-academy\SKILL.md`, `payloads-all-the-things\SKILL.md`, `tbhm-methodology\SKILL.md`, `hacking-apis\SKILL.md`, `owasp-api-security-top-10\SKILL.md`, `bug-bounty-bootcamp\SKILL.md`, `bug-bounty-playbook\SKILL.md`, `web-hacking-101\SKILL.md`, `xss-cheat-sheet\SKILL.md`, `zseano-methodology\SKILL.md`
- Modify: each of the 17 `sources.md` files created in Tasks 2–8
- Modify: `C:\Users\luong\.agents\skills\bug-bounty-hunter\chapters\01-phase-map.md` and `chapters\03-vuln-class-index.md`
- Modify: `docs/superpowers/2026-09-23-bug-bounty-source-register.md`

**Interfaces:**
- Consumes: all topical task outputs.
- Produces: consistent skill discovery descriptions, per-skill source metadata, and a cross-skill index for maintenance.

- [ ] **Step 1: Add a compact “reviewed to / sources” section** to all 17 SKILL.md files and point each to its `sources.md`.
- [ ] **Step 2: Ensure every skill has a substantive update or a clearly reasoned review disposition** in its source file; record exact source/version/date and affected chapters.
- [ ] **Step 3: Update descriptions and router entries** only where triggers or topical coverage changed; keep the frontmatter name identical to its directory.
- [ ] **Step 4: Reconcile duplicate coverage** so one skill is the primary method source per class and others are explicitly depth/reference/lab supplements.
- [ ] **Step 5: Finalize the central source register** with implemented paths, unresolved gaps, and next review triggers.

### Task 10: Final content and structural review

**Files:**
- Read: all 17 skill trees under `C:\Users\luong\.agents\skills\`
- Read: `docs/superpowers/specs/2026-09-23-bug-bounty-methods-refresh-design.md`
- Read: `docs/superpowers/2026-09-23-bug-bounty-source-register.md`

**Interfaces:**
- Consumes: all preceding task outputs.
- Produces: reviewable updated skill set with source dispositions and no unresolved internal routes.

- [ ] **Step 1: Check skill inventory/frontmatter** for all 17 names and required descriptions.
- [ ] **Step 2: Resolve every local skill/chapter reference** from each SKILL.md and from the bug-bounty-hunter phase/vulnerability routers.
- [ ] **Step 3: Search for stale/hazardous wording** including “no exclusions = all in scope,” credentials in notes, unqualified “almost always in-scope,” high-rate defaults, and universal CVSS/platform claims; manually inspect and fix every occurrence.
- [ ] **Step 4: Run the existing generated-skill scanner** on each modified skill, inspect each warning at the cited line, and record a disposition in the source register.
- [ ] **Step 5: Run the approved scope pressure scenarios** from Tasks 2, 3, and 6 against the updated guidance; record whether the agent halts, narrows, or uses test-owned data as expected.
- [ ] **Step 6: Read the final source register and router once end-to-end**; confirm no undocumented source/version assumptions remain and no live target was tested.
- [ ] **Step 7: Report completion** with skill coverage, source cutoff, check outcomes, warnings/dispositions, and known gaps.

## Self-Review Notes

- Spec coverage: all 17 skills are assigned to topical refresh tasks; router,
  safe recon, API 2023, AI/LLM, CVSS v4, mobile, cloud, source records, and
  final link/scanner review are covered.
- No unsupported implementation symbols are introduced; tasks modify Markdown
  and one documentation source register only.
- The plan preserves unchanged skill names and treats program policy as the
  highest-priority authorization source.
- Task 5 contains both modern web and LLM product testing because the existing
  Web Security Academy set already has an LLM chapter; no new skill is needed.
- Execution approach is not selected yet. The work spans 17 skill directories
  and benefits from independent review, but authoring and router references
  are tightly coupled; recommend native execution in bounded batches followed
  by one independent whole-set review.
