# Bug Bounty Methodology Currency Delta Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` if the user selects native execution. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reconcile the recorded completion of the 17-skill refresh and update only methodology or source references that have drifted as of 2026-09-24.

**Architecture:** First audit the existing skill files and implementation record, then verify current primary sources, update only the AI/security references and methodology crosswalk where needed, and reconcile the original plan with evidence. Keep the existing 17 skills, seven-phase router, and hypothesis engine; do not create a competing lifecycle or retest any bounty target.

**Tech Stack:** Markdown; PowerShell and `rg` for file/reference inventory; official OWASP project pages and primary PortSwigger research for source checks. No target-facing tools or traffic.

**Spec:** `docs/superpowers/specs/2026-09-23-bug-bounty-methods-refresh-design.md`

## Global Constraints

- Use a public-source review cutoff of 2026-09-24 for this delta.
- The current program policy and written authorization outrank all methodology guidance.
- Keep all 17 existing skill names and loader entry points; add no new skill.
- Treat the 12-stage methodology as a crosswalk proposal, not as a standard that overrides the existing seven-phase router.
- Use official primary sources for current editions; label rolling and draft material with its review date.
- Retain 2025 AI references only as historical context after verifying current 2026 references.
- Make no live-target requests, scans, exploit attempts, or credential validation.
- Preserve unrelated user changes, including the existing source-register edit and untracked engagement workspace.

## Review Focus

1. A completion statement in the source register must not close a plan task without evidence in the actual files or commit history.
2. An AI risk source marked current as 2025 must be checked against OWASP's 2026 LLM and Agentic editions.
3. The 12-stage loop must map into existing phases/artifacts without duplicate hypothesis, validation, or monitoring systems.
4. Versioned standards must distinguish stable releases from draft/latest content.
5. Lab or agent-testing guidance must not imply authorization for live bounty targets or actions affecting other users.

---

### Task 1: Reconcile the original refresh plan with the implemented state

**Files:**
- Read: `docs/superpowers/plans/2026-09-23-bug-bounty-methods-refresh.md`
- Read: `docs/superpowers/2026-09-23-bug-bounty-source-register.md`
- Read: `C:\Users\luong\.agents\skills\bug-bounty-hunter\SKILL.md` and `sources.md`; read the same two filenames under `recon-pipeline`, `report-writing`, `hacking-the-cloud`, `owasp-mas`, `owasp-wstg`, `web-app-hackers-handbook`, `web-security-academy`, `payloads-all-the-things`, `tbhm-methodology`, `hacking-apis`, `owasp-api-security-top-10`, `bug-bounty-bootcamp`, `bug-bounty-playbook`, `web-hacking-101`, `xss-cheat-sheet`, and `zseano-methodology`.
- Modify: `docs/superpowers/plans/2026-09-23-bug-bounty-methods-refresh.md`

**Interfaces:**
- Consumes: the source register's implementation summary and the existing 17-skill tree.
- Produces: an evidence-backed execution ledger in the original plan, with verified work closed and any unverified work explicitly left open.

- [x] **Step 1: Enumerate the 17 expected skill directories** and record which contain both `SKILL.md` and `sources.md`.
- [x] **Step 2: Compare each skill's source metadata and router references** with the corresponding row in the source register; record missing or conflicting evidence without changing the skill files yet.
- [x] **Step 3: Reconcile the referenced implementation commits** against available Git history and changed artifacts; a commit hash in the register alone does not prove every acceptance criterion.
- [x] **Step 4: Update the original plan's status**: mark only verified steps complete, label the plan as the historical full-refresh plan, and retain unresolved items as explicit follow-ups.
- [x] **Step 5: Confirm this task preserves the user's pre-existing source-register edit and untracked engagement files.**

### Task 2: Refresh the official source register for current editions

**Files:**
- Read: official OWASP WSTG, API Security, ASVS, GenAI LLM, Agentic Applications, and AI Testing Guide project pages.
- Read: `C:\Users\luong\.agents\skills\web-security-academy\sources.md`
- Read: `C:\Users\luong\.agents\skills\bug-bounty-hunter\sources.md`
- Modify: `docs/superpowers/2026-09-23-bug-bounty-source-register.md`
- Modify: `C:\Users\luong\.agents\skills\web-security-academy\sources.md`
- Modify: `C:\Users\luong\.agents\skills\bug-bounty-hunter\sources.md`

**Interfaces:**
- Consumes: primary project pages verified at implementation time.
- Produces: consistent 2026-09-24 source/version records for current and historical AI guidance and the stable standards relevant to the delta.

Official source anchors to re-check:

- OWASP GenAI LLM Top 10 2026: `https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/`
- OWASP Top 10 for Agentic Applications 2026: `https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/`
- OWASP AI Testing Guide: `https://owasp.org/projects/ai-testing-guide`
- OWASP WSTG stable: `https://wstg.owasp.org/v4.2/`
- OWASP API Security Top 10: `https://owasp.org/projects/api-security-project`
- OWASP ASVS: `https://owasp.org/projects/asvs`

- [x] **Step 1: Verify each official page directly** and record its edition/version, publication or stable status, canonical URL, and check date.
- [x] **Step 2: Confirm whether AI Testing Guide v1 contributes distinct test methods** beyond the current LLM and Agentic Top 10; include it only for distinct coverage.
- [x] **Step 3: Record WSTG v4.2, API Security Top 10 2023, and ASVS 5.0.0 as current only if their official project pages still support those designations; label WSTG development content as draft.**
- [x] **Step 4: Update the source register's cutoff, AI entries, review notes, and next-review triggers** while preserving the existing explanatory paragraph and other user-authored edits.
- [x] **Step 5: Make the two affected skills' `sources.md` files agree with the register**, preserving older AI editions only as dated historical sources.

### Task 3: Update AI routing and map the research loop onto existing phases

**Files:**
- Read: `C:\Users\luong\.agents\skills\bug-bounty-hunter\chapters\01-phase-map.md`
- Read: `C:\Users\luong\.agents\skills\bug-bounty-hunter\chapters\02-session-checklist.md`
- Read: `C:\Users\luong\.agents\skills\bug-bounty-hunter\chapters\03-vuln-class-index.md`
- Read: `C:\Users\luong\.agents\skills\bug-bounty-hunter\chapters\05-hypothesis-engine.md`
- Read: `C:\Users\luong\.agents\skills\web-security-academy\chapters\ch15-logic-race-api-llm.md`
- Modify, only where a source or routing gap is verified:
  - `C:\Users\luong\.agents\skills\bug-bounty-hunter\SKILL.md`
  - `C:\Users\luong\.agents\skills\bug-bounty-hunter\chapters\01-phase-map.md`
  - `C:\Users\luong\.agents\skills\bug-bounty-hunter\chapters\02-session-checklist.md`
  - `C:\Users\luong\.agents\skills\bug-bounty-hunter\chapters\03-vuln-class-index.md`
  - `C:\Users\luong\.agents\skills\web-security-academy\SKILL.md`
  - `C:\Users\luong\.agents\skills\web-security-academy\chapters\ch15-logic-race-api-llm.md`

**Interfaces:**
- Consumes: the updated sources from Task 2 and existing seven-phase router, feature map, hypothesis cards, four authorization gates, finding validation, outcome ledger, and monitoring route.
- Produces: a concise crosswalk and current AI/agent routes without a second process or duplicate records.

Crosswalk to preserve:

| Methodology 2026 stage | Existing router destination |
|---|---|
| 1. Program intelligence and target selection | Phase 1 program dossier and target-fit notes |
| 2. Scope, authorization, and safety | Phase 1 scope contract; re-check exact asset and method gates before each active rung |
| 3. Passive reconnaissance | Phase 2 passive sources and provenance; results remain leads |
| 4. Functional exploration and application mapping | Phase 3 workflows, roles, trust boundaries, and feature cards |
| 5. Deep reconnaissance and attack-surface graph | Re-enter Phase 2 from a mapped Phase 3 feature lead; Phase 3 consumes only scope-confirmed results |
| 6. Threat modeling and hypothesis generation | Phase 4 and the existing Hypothesis Engine |
| 7. Focused testing: web, API, and business logic | Phase 4 and the existing specialist skills, under per-technique gates |
| 8. Modern research: parser, cache, protocol, cloud, and AI | Phase 4 specialist routes; research sources guide hypotheses, not authorization |
| 9. Deterministic validation and impact assessment | Phase 5 and the existing candidate validation gate; controlled evidence only |
| 10. Duplicate analysis and vulnerability reporting | Phase 6, report-writing, and append-only triage/outcome records |
| 11. Controlled AI-assisted automation | Overlay the existing hypothesis and authorization gates; generated ideas remain unvalidated leads and execution remains human-controlled |
| 12. Continuous monitoring and regression hunting | Phase 7 and recon monitoring; policy/surface changes feed Phases 1–4 |

These are crosswalk labels from the user-provided **BUG BOUNTY METHODOLOGY 2026 v3.0** (2026-09-24), not a replacement for the seven-phase router. Stage 5 intentionally re-enters Phase 2 after Phase 3 has produced a feature-led recon question; the router is already a loop, and this handoff preserves the methodology's functional-first ordering without creating a second pipeline.

- [x] **Step 1: Compare the crosswalk with current phase-map headings, exit criteria, and the session checklist**; add only missing handoffs or labels, and do not duplicate the hypothesis engine or finding lifecycle.
- [x] **Step 2: Replace current OWASP GenAI LLM Top 10 2025 routing with the verified 2026 edition** in the router, Web Security Academy description, chapter 15, and source metadata; retain the 2025 edition only when clearly historical.
- [x] **Step 3: Add the Agentic Applications Top 10 2026 route** for agent identity/privilege, memory/context, and tool/action authorization only where the skill explains a testable boundary.
- [x] **Step 4: Keep all live-testing examples bounded by current program policy, researcher-owned accounts/data, least-impact proof, and explicit stop conditions.**
- [x] **Step 5: Re-check every modified router path and source link against files that exist.**

### Task 4: Close the delta with a source and plan reconciliation review

**Files:**
- Modify: `docs/superpowers/2026-09-23-bug-bounty-source-register.md`
- Modify: `docs/superpowers/plans/2026-09-23-bug-bounty-methods-refresh.md`
- Read: all files modified in Tasks 1–3.

**Interfaces:**
- Consumes: evidence-backed audit, source register, and targeted skill updates.
- Produces: a dated delta ledger with remaining watch items and a plan whose open boxes correspond to actual unfinished work.

- [x] **Step 1: Record changed files, source editions, and any accepted unresolved gaps** in the source register; do not claim live-target validation.
- [x] **Step 2: Check each original-plan task against the audit evidence** and make completion labels agree with the skill files and implementation history.
- [x] **Step 3: Review for stale “current” 2025 LLM references**, excluding clearly marked historical discussion.
- [x] **Step 4: Review the seven-phase/12-activity crosswalk** for coverage and duplication; leave the seven-phase entry point intact.
- [x] **Step 5: Read the final diff and confirm no engagement artifacts or unrelated user changes were staged or modified.**

## Completion Criteria

- Every completion mark in the original plan has file/history evidence; unresolved work remains visibly open.
- Current LLM and Agentic guidance points to official 2026 editions, with 2025 retained only as historical material.
- The existing seven-phase router maps all 12 research activities to existing artifacts or routes without creating a parallel workflow.
- WSTG, API Top 10, and ASVS version statements match the official sources checked on the review date.
- No live-target actions are performed; no engagement evidence or unrelated user changes are modified.
- The final update names the files changed and the remaining source-watch items.

## Follow-up review (2026-09-24, after delta closeout)

- The user's consistency review found that `owasp-api-security-top-10/SKILL.md`
  still presented 2019 labels in its Core Testing Model. This was corrected:
  the quick model now uses API1:2023–API10:2023 names, while 2019 chapter IDs
  remain explicitly historical.
- Runtime validation of `Program URL → Scope Contract → Feature Card →
  Hypothesis → Validation → Report` remains open. The design and existing
  pressure scenarios do not prove an end-to-end runtime pass; none was run in
  this delta. A named authorized program, URL, and exact testing limits are
  required before any target-facing step.
- Do not create a separate AI agent/MCP skill before collecting that workflow
  evidence. Reassess the need from observed gaps in tool authorization,
  identity, memory, and retrieved-data boundaries afterward.
- This is a focused currency and consistency delta, not an exhaustive
  chapter-by-chapter audit of all 17 skills.
