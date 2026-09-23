# Design: Complete Bug Bounty Skill Set

Date: 2026-09-23
Status: draft, awaiting user review

## Intent

Build a complete, coherent skill set for bug bounty hunting under
`C:\Users\luong\.agents\skills\`. The existing 7 book-derived skills are
isolated references; the end state is a layered system where one orchestrator
routes a hunting session through phases, two hand-written operational skills
cover the gaps books don't teach (executable recon pipeline, report writing),
and additional sources fill real coverage gaps (modern web attack classes,
cloud, mobile).

Success criteria:

- Starting a hunt, the agent can load `bug-bounty-hunter` and reach the right
  companion skill for any phase/vuln class via its routing table.
- Every major bug-bounty attack surface has at least one dedicated source:
  web vuln classes, APIs, mobile, cloud, modern classes (request smuggling,
  prototype pollution, cache poisoning, WebSockets, HTTP/2).
- Operational phases not covered by books (runbook-style recon, report
  drafting/triage) have dedicated skills.
- All generated skills pass `tools/scan_generated_skill.py` (advisory
  findings reviewed in context, none silently ignored).
- No raw copyrighted text committed; skills contain transformed frameworks,
  checklists, and short excerpts only.

## Topology — 17 skills, 3 layers

Flat namespace in `~/.agents/skills/` (loader scans one level; no nested
collections). Cross-references by skill name in prose only — no hard
dependencies.

### Layer 1 — Orchestration & operations (3, hand-written)

| Skill | Role |
|---|---|
| `bug-bounty-hunter` | Master orchestrator: session checklist, phase map, routing table, vuln-class index |
| `recon-pipeline` | Executable recon runbook: staged commands, output layout, continuous-recon diffing |
| `report-writing` | Report drafting: severity rubric, repro template, impact statements, triage/dispute playbook |

### Layer 2 — Book skills (9)

| Skill | Source | Status |
|---|---|---|
| `xss-cheat-sheet` | Brute Logic, XSS Cheat Sheet | done |
| `owasp-api-security-top-10` | OWASP API Security Top 10 (2019) | done |
| `zseano-methodology` | zseano's methodology | done |
| `bug-bounty-playbook` | Bug Bounty Playbook V2 (ghostlulz) | done |
| `web-hacking-101` | Peter Yaworski | done |
| `hacking-apis` | Corey Ball | done |
| `bug-bounty-bootcamp` | Vickie Li | done |
| `owasp-wstg` | OWASP WSTG v4.2 (PDF in repo) | new |
| `web-app-hackers-handbook` | WAHH 2nd ed (PDF in repo) | new |

Skipped PDFs in repo: OTGv4 (superseded by WSTG v4.2), WAHH ed1 (superseded
by ed2), The Tangled Web (browser internals, low hunt ROI), Advanced SQLi
(SQLi already covered by 3 sources).

### Layer 3 — Free-source gap fillers (5)

| Skill | Source | Format | Gap filled |
|---|---|---|---|
| `web-security-academy` | portswigger.net/web-security (~30 topic guides) | HTML scrape | Request smuggling, prototype pollution, DOM clobbering, cache poisoning, WebSockets, HTTP/2, modern JWT/OAuth/CORS/CSRF |
| `hacking-the-cloud` | github.com/Hacking-the-Cloud/hackingthe.cloud | markdown | AWS/GCP/Azure attack paths beyond SSRF→metadata |
| `owasp-mas` | github.com/OWASP/mastg (MASTG v2.0.0, CC-BY-SA) | markdown | Mobile testing depth (MASVS categories: STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE) |
| `tbhm-methodology` | github.com/jhaddix/tbhm | markdown | Jason Haddix methodology + modern recon stack |
| `payloads-all-the-things` | github.com/swisskyrepo/PayloadsAllTheThings | markdown | Payload library per vuln class (reference, not methodology) |

Not included (commercial, user may supply later): Real-World Bug Hunting,
Black Hat GraphQL, Bug Bounty from Scratch.

## Skill designs

### `bug-bounty-hunter` (orchestrator)

- description: use when starting/running a bug bounty session — phase
  routing, target triage, methodology selection, which companion skill to
  load per task.
- `SKILL.md`: doctrine (scope→recon→hunt→escalate→report→monitor loop),
  session kickoff checklist, compact phase map.
- `phase-map.md`: phases × tasks × which skill to load, with decision rules
  (target is API → `hacking-apis` + `owasp-api-security-top-10`; mobile →
  `owasp-mas` + `bug-bounty-bootcamp` ch20; cloud assets → `hacking-the-cloud`;
  want full test checklist → `owasp-wstg`).
- `vuln-class-index.md`: every vuln class → best skill+chapter, incl. which
  source covers it deepest (e.g. SSTI → bootcamp ch13 for methodology,
  payloads-all-the-things for payloads, academy for labs).
- `session-checklist.md`: policy read, scope capture, test accounts, notes
  layout, recon handoff, hunting loop, escalation review, report, monitoring.

### `recon-pipeline` (ops)

Runbook, not theory: stage-by-stage commands (subdomain enum → live probe →
port scan → dir enum → screenshots → GitHub/pastes → tech fingerprint),
output layout `target/YYYYMMDD/<stage>.txt`, normalization (`sort -u`),
diff vs previous run → "new since last run" lead file, scheduling notes
(cron/Task Scheduler), passive-vs-active gating per program policy.
Explicitly does NOT replace `bug-bounty-bootcamp` ch03 — it operationalizes it.

### `report-writing` (ops)

- Severity rubric: impact × exploitability, mapped to CVSS + platform bands.
- Repro template: numbered steps, copy-pasteable, <5 min triager repro.
- Impact-statement library per vuln class.
- PoC hygiene: test accounts, minimal demonstration, no real-user data.
- Triage playbook: N/A/duplicate/dispute response patterns, mediation
  etiquette, when to escalate.
- Chain reporting: presenting multi-bug chains coherently.

### Book skills (2 new)

Same structure as existing 7: `SKILL.md` (frontmatter + doctrine + routing)
+ `chapters/` + `glossary.md` + `patterns.md` + `cheatsheet.md`.

- `owasp-wstg`: map WSTG v4.2 test categories (~11 files: info gathering,
  config/deploy, identity, authn, authz, session, input validation, error
  handling, crypto, business logic, client-side + AJAX). Each file =
  WSTG test IDs → objective → how to test → interpret results.
- `web-app-hackers-handbook`: ~15-20 files mapped to ed2 chapters; deep
  mechanics + attack techniques + evasion per class. Largest source; read
  selectively per chapter like previous conversions.

### Free-source skills (5)

- `web-security-academy`: scrape ~30 topic guides → chapter files per
  topic class; each: mechanism → detection → exploitation → labs link.
  Emphasis on classes absent from books (smuggling, prototype pollution,
  WebSocket, HTTP/2, cache poisoning).
- `hacking-the-cloud`: clone repo → chapter files by cloud domain
  (enumeration, IAM/creds, metadata, S3/blob, lateral movement, exfil,
  general multi-cloud).
- `owasp-mas`: clone repo → chapter files by MASVS category + platform
  setup/testing sections; CC-BY-SA attribution line in SKILL.md.
- `tbhm-methodology`: clone repo → chapter files per numbered doc
  (Philosophy, Discovery, Mapping, Auth/Session, Tactical fuzzing, …).
- `payloads-all-the-things`: clone repo → chapter files per vuln-class
  directory; reference-style (payload families + when to use which), not
  methodology prose.

## Extraction

- PDFs: `pdftotext` (docling impractical on current network, same as prior
  7 conversions) into `%TEMP%\book_skill_work-*` workspaces.
- GitHub sources: `git clone --depth 1` into `%TEMP%` workspaces; read
  markdown directly.
- PortSwigger: firecrawl/fetch of public topic pages; synthesize per topic.

## Security & ethics

- All skills carry "assume authorized, in-scope testing" framing (matches
  existing set).
- Transformed summaries only — no bulk copyrighted text (books) or bulk
  verbatim copying (CC-BY-SA allows derivative; still synthesize, attribute).
- Payload/technique content is standard published pentest material; scanner
  advisory warnings reviewed individually, disposition documented.

## Validation

- `python tools/scan_generated_skill.py <skill>` on all 10 new skills
  (3 ops + 2 books + 5 free-source).
- Structure check: frontmatter present, chapter links in SKILL.md resolve.
- Final report: skill list, paths, file counts, scan results, warnings with
  dispositions, extraction methods.
- No repo code changes → pytest/ruff gates not applicable (generation only).

## Out of scope

- Converting commercial books not supplied (Tier 3 list above).
- Editing existing 7 book-skills (frozen; orchestrator references by name).
- Changes to `book-to-skill` converter code.
- iOS-specific depth beyond owasp-mas, web3/smart contracts, binary exploit dev.
