# Complete Bug Bounty Skill Set Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a complete 17-skill bug-bounty set under `C:\Users\luong\.agents\skills\` — 3 hand-written operational skills, 2 new book conversions, 5 free-source conversions — layered so the `bug-bounty-hunter` orchestrator routes a session through phases into the right companion skill.

**Architecture:** Flat namespace, 3 layers (ops → books → free sources). Every skill: `SKILL.md` (YAML frontmatter `name`+`description`, doctrine, file routing) + `chapters/` + `glossary.md` + `patterns.md` + `cheatsheet.md`, matching the 7 existing book-skills. Cross-references by skill name in prose only.

**Tech Stack:** `pdftotext` (PDF extraction), `git clone --depth 1` (markdown sources), firecrawl/fetch (PortSwigger pages), `python tools/scan_generated_skill.py` (security scan from `C:\Users\luong\.agents\skills\book-to-skill`).

**Spec:** `C:\Users\luong\OneDrive\Desktop\BugBounty\docs\superpowers\specs\2026-09-23-bug-bounty-skillset-design.md`

## Global Constraints

- Skills root: `C:\Users\luong\.agents\skills\` — create each skill as `<root>\<skill-name>\` with `chapters\` subdir. Use `/c/Users/luong/.agents/skills/` in bash.
- Every skill's `SKILL.md` starts with YAML frontmatter: `---\nname: <skill-name>\ndescription: <one dense paragraph>\n---`. The `name` MUST equal the directory name.
- All content assumes authorized, in-scope testing. Include a scope/ethics note per skill.
- Transformed summaries, frameworks, checklists only — no bulk verbatim copyrighted text. Short quotes/commands are fine.
- `owasp-mas` content is CC-BY-SA → include attribution line in its SKILL.md.
- Do NOT modify the 7 existing skills or `book-to-skill` code. No repo code changes → pytest/ruff not applicable.
- Extraction workspaces under `%TEMP%\book_skill_work-*` (`/c/Users/luong/AppData/Local/Temp/` in bash). Do not commit raw extracted text.
- After each skill: run `cd /c/Users/luong/.agents/skills/book-to-skill && python tools/scan_generated_skill.py ../<skill>`; review EVERY warning individually, document disposition.

## Review Focus

1. **Scanner warnings dismissed without reading the flagged line** — each task's scan step must list flagged file:line and a one-line disposition.
2. **SKILL.md links pointing to non-existent chapter files** — each task ends with a link-resolution check (every `chapters/...` path in SKILL.md must exist on disk).
3. **Malformed frontmatter breaking discovery** — name must equal dir name; description must be a single paragraph inside `---` fences.
4. **Accidental raw-book reproduction** — spot-check: no passage >3 sentences verbatim from source.
5. **Orchestrator referencing skills/chapters that don't exist** — Task 10 has a dedicated resolution check for every route in `vuln-class-index.md` and `phase-map.md`.

---

### Task 1: `owasp-wstg` — WSTG v4.2 conversion

**Files:**
- Create: `/c/Users/luong/.agents/skills/owasp-wstg/SKILL.md`
- Create: `/c/Users/luong/.agents/skills/owasp-wstg/chapters/*.md` (~11 files, one per WSTG category)
- Create: `/c/Users/luong/.agents/skills/owasp-wstg/{glossary,patterns,cheatsheet}.md`
- Source: `/c/Users/luong/OneDrive/Desktop/BugBounty/` WSTG v4.2 PDF (find exact filename in that dir)

**Interfaces:**
- Produces: skill `owasp-wstg` — referenced by orchestrator (`phase-map.md`, `vuln-class-index.md`) as the full-test-checklist authority.

- [ ] **Step 1: Extract PDF to text**

```bash
mkdir -p /c/Users/luong/AppData/Local/Temp/book_skill_work-wstg
ls "/c/Users/luong/OneDrive/Desktop/BugBounty"   # find WSTG file name
pdftotext -layout "/c/Users/luong/OneDrive/Desktop/BugBounty/<WSTG file>.pdf" /c/Users/luong/AppData/Local/Temp/book_skill_work-wstg/full_text.txt
wc -l /c/Users/luong/AppData/Local/Temp/book_skill_work-wstg/full_text.txt
```

Expected: text file >100k chars.

- [ ] **Step 2: Map category boundaries**

Grep for the WSTG test-category headings (Information Gathering, Configuration and Deployment Management, Identity Management, Authentication, Authorization, Session Management, Input Validation, Error Handling, Cryptography, Business Logic, Client-side). Record line offsets for each `4.X`/`WSTG-XXX` section start.

```bash
grep -nE "WSTG-[A-Z]+-[0-9]+|^[0-9]+\.[0-9]+ [A-Z]" /c/Users/luong/AppData/Local/Temp/book_skill_work-wstg/full_text.txt | head -60
```

- [ ] **Step 3: Read selectively**

Read each category's test descriptions (objective, how to test, remediation). ~1-2k lines per category skim; note test IDs and key procedures.

- [ ] **Step 4: Write SKILL.md**

Frontmatter `name: owasp-wstg`; description naming WSTG v4.2 + the categories; body: OWASP testing framework (test-ID-driven checklist methodology), routing table to chapter files, scope note. Pattern after `C:\Users\luong\.agents\skills\bug-bounty-bootcamp\SKILL.md`.

- [ ] **Step 5: Write chapter files** (one per category, `ch01-…` … `ch11-…`)

Each file: category overview → test list (WSTG-XXX ID → objective → test procedure → interpretation) → common findings → escalation notes. Synthesized, not verbatim.

- [ ] **Step 6: Write glossary.md, patterns.md, cheatsheet.md**

- [ ] **Step 7: Structure check**

```bash
ls /c/Users/luong/.agents/skills/owasp-wstg/chapters/ | wc -l
grep -o "chapters/[a-z0-9-]*\.md" /c/Users/luong/.agents/skills/owasp-wstg/SKILL.md | while read f; do [ -f "/c/Users/luong/.agents/skills/owasp-wstg/$f" ] || echo "MISSING: $f"; done
```

Expected: no MISSING output.

- [ ] **Step 8: Security scan + review warnings**

```bash
cd /c/Users/luong/.agents/skills/book-to-skill && python tools/scan_generated_skill.py ../owasp-wstg
```

For each WARN line: open the flagged file:line, confirm it's standard testing content, record disposition in the final report notes.

---

### Task 2: `web-app-hackers-handbook` — WAHH ed2 conversion

**Files:**
- Create: `/c/Users/luong/.agents/skills/web-app-hackers-handbook/SKILL.md`
- Create: `/c/Users/luong/.agents/skills/web-app-hackers-handbook/chapters/*.md` (15-20 files mapped to ed2 chapters)
- Create: `/c/Users/luong/.agents/skills/web-app-hackers-handbook/{glossary,patterns,cheatsheet}.md`
- Source: WAHH ed2 PDF in `/c/Users/luong/OneDrive/Desktop/BugBounty/` (the larger/newer WAHH file — verify by page count/date in text)

**Interfaces:**
- Produces: skill `web-app-hackers-handbook` — the deepest per-class mechanics reference; orchestrator routes "why does this attack work" questions here.

- [ ] **Step 1: Identify correct PDF + extract**

```bash
ls -la "/c/Users/luong/OneDrive/Desktop/BugBounty" | grep -i "hacker\|wahh"
mkdir -p /c/Users/luong/AppData/Local/Temp/book_skill_work-wahh
pdftotext -layout "<ed2 pdf>" /c/Users/luong/AppData/Local/Temp/book_skill_work-wahh/full_text.txt
head -50 /c/Users/luong/AppData/Local/Temp/book_skill_work-wahh/full_text.txt   # confirm 2nd edition
```

Expected: ed2 front matter (2011, Dafydd Stuttard & Marcus Pinto); ~1M+ chars.

- [ ] **Step 2: Map chapter offsets** — grep chapter headings, record line ranges for all ~21 chapters.
- [ ] **Step 3: Read selectively** — prioritize attack chapters (core mechanisms, authn, session, access control, injection, client-side, logic, custom vectors) over intro/defense material.
- [ ] **Step 4-6: Write SKILL.md + chapters + support files** — same pattern as Task 1; chapter files preserve WAHH's signature structure (mechanism → attack → defense/evasion → "questions" checklist where present).
- [ ] **Step 7: Structure check** — same link-resolution command with `web-app-hackers-handbook`.
- [ ] **Step 8: Scan + review** — same scanner command with `../web-app-hackers-handbook`.

---

### Task 3: `hacking-the-cloud` — cloud attack encyclopedia

**Files:**
- Create: `/c/Users/luong/.agents/skills/hacking-the-cloud/SKILL.md`
- Create: `/c/Users/luong/.agents/skills/hacking-the-cloud/chapters/*.md` (~8 files by domain)
- Create: `/c/Users/luong/.agents/skills/hacking-the-cloud/{glossary,patterns,cheatsheet}.md`

**Interfaces:**
- Produces: skill `hacking-the-cloud`; orchestrator routes cloud-asset findings (S3, metadata, IAM) here; complements `bug-bounty-bootcamp` ch10/ch18.

- [ ] **Step 1: Clone source**

```bash
git clone --depth 1 https://github.com/Hacking-the-Cloud/hackingthe.cloud /c/Users/luong/AppData/Local/Temp/book_skill_work-htc
find /c/Users/luong/AppData/Local/Temp/book_skill_work-htc -name "*.md" | head -40
```

- [ ] **Step 2: Map structure** — repo organizes content by technique domain (AWS enum, IAM/credential exposure, metadata services, S3/storage, lateral movement, exfil, multi-cloud/general). List top-level content dirs and pick chapter mapping (~8 files).
- [ ] **Step 3: Read selectively** — skim each domain's articles for technique summaries, commands, detection/impact notes.
- [ ] **Step 4-6: Write files** — same structure; emphasis on hunting-relevant chains (SSRF→metadata→IAM→storage) and bug-bounty-safe validation.
- [ ] **Step 7: Structure check** — same pattern.
- [ ] **Step 8: Scan + review.**

---

### Task 4: `owasp-mas` — MASTG v2.0.0

**Files:**
- Create: `/c/Users/luong/.agents/skills/owasp-mas/SKILL.md`
- Create: `/c/Users/luong/.agents/skills/owasp-mas/chapters/*.md` (~9 files: 7 MASVS categories + setup/tools + platform testing)
- Create: `/c/Users/luong/.agents/skills/owasp-mas/{glossary,patterns,cheatsheet}.md`

**Interfaces:**
- Produces: skill `owasp-mas` — mobile depth reference; orchestrator routes mobile targets here + `bug-bounty-bootcamp` ch20 for methodology.

- [ ] **Step 1: Clone + survey**

```bash
git clone --depth 1 https://github.com/OWASP/mastg /c/Users/luong/AppData/Local/Temp/book_skill_work-mas
ls /c/Users/luong/AppData/Local/Temp/book_skill_work-mas
find /c/Users/luong/AppData/Local/Temp/book_skill_work-mas -name "*.md" -path "*MASTG*" | head -30
```

- [ ] **Step 2: Map MASVS categories** — STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE + tools/techniques sections; pick chapter files (~9).
- [ ] **Step 3: Read selectively** — per category: weakness types (MASWE), test procedures, tools (Frida/Objection/MobSF), platform specifics Android/iOS.
- [ ] **Step 4-6: Write files** — include CC-BY-SA attribution in SKILL.md: `Distilled from OWASP MASTG (mas.owasp.org), CC-BY-SA 4.0`.
- [ ] **Step 7: Structure check.**
- [ ] **Step 8: Scan + review.**

---

### Task 5: `tbhm-methodology` — Jason Haddix methodology

**Files:**
- Create: `/c/Users/luong/.agents/skills/tbhm-methodology/SKILL.md`
- Create: `/c/Users/luong/.agents/skills/tbhm-methodology/chapters/*.md` (~6-8 files per numbered docs)
- Create: `/c/Users/luong/.agents/skills/tbhm-methodology/{glossary,patterns,cheatsheet}.md`

**Interfaces:**
- Produces: skill `tbhm-methodology` — modern recon/methodology; orchestrator routes "wide-scope target" and "recon stack" questions here + `recon-pipeline` for the runbook.

- [ ] **Step 1: Clone**

```bash
git clone --depth 1 https://github.com/jhaddix/tbhm /c/Users/luong/AppData/Local/Temp/book_skill_work-tbhm
ls /c/Users/luong/AppData/Local/Temp/book_skill_work-tbhm
```

- [ ] **Step 2: Read numbered docs** — 01_Philosophy, 02_Discovery, 03_Mapping, 04_Authorization_and_Session, + remaining files; note tool stacks per stage.
- [ ] **Step 3-5: Write files** — chapter per doc group; preserve TBHM's stage model + tool tables.
- [ ] **Step 6: Structure check.**
- [ ] **Step 7: Scan + review.**

---

### Task 6: `payloads-all-the-things` — payload library

**Files:**
- Create: `/c/Users/luong/.agents/skills/payloads-all-the-things/SKILL.md`
- Create: `/c/Users/luong/.agents/skills/payloads-all-the-things/chapters/*.md` (~12-15 files by vuln-class dir)
- Create: `/c/Users/luong/.agents/skills/payloads-all-the-things/{glossary,patterns,cheatsheet}.md`

**Interfaces:**
- Produces: skill `payloads-all-the-things` — payload families + selection guidance; referenced BY vuln-class questions (orchestrator routes "what payload for X context" here + the relevant book skill).

- [ ] **Step 1: Clone + survey dirs**

```bash
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings /c/Users/luong/AppData/Local/Temp/book_skill_work-patt
ls /c/Users/luong/AppData/Local/Temp/book_skill_work-patt
```

- [ ] **Step 2: Pick top dirs** — XSS, SQLi, SSTI, SSRF, XXE, LFI/RFI, command injection, open redirect, CSRF, IDOR-related, upload, deserialization, GraphQL, LDAP/NoSQL — group into ~12-15 chapter files.
- [ ] **Step 3-5: Write files** — reference style: payload families per class, context/encoding variants, when-to-use notes. NOT methodology prose (books cover that).
- [ ] **Step 6: Structure check.**
- [ ] **Step 7: Scan + review** — expect more warnings here (payload text); review each, document.

---

### Task 7: `web-security-academy` — PortSwigger topic guides

**Files:**
- Create: `/c/Users/luong/.agents/skills/web-security-academy/SKILL.md`
- Create: `/c/Users/luong/.agents/skills/web-security-academy/chapters/*.md` (~15 files by topic area)
- Create: `/c/Users/luong/.agents/skills/web-security-academy/{glossary,patterns,cheatsheet}.md`

**Interfaces:**
- Produces: skill `web-security-academy` — the modern-classes authority; orchestrator routes request smuggling, prototype pollution, WebSocket, HTTP/2, cache poisoning here (no other skill covers them).

- [ ] **Step 1: Enumerate topics**

Fetch `https://portswigger.net/web-security` and list all topic links (`/web-security/<topic>`). Expected ~30 topics (sqli, xss, csrf, clickjacking, dom, cors, xxe, ssrf, request-smuggling, command-injection, template-injection, path-traversal, access-control, authentication, websockets, cache-poisoning, prototype-pollution, jwt, oauth, file-upload, race-conditions, deserialization, business-logic, api-testing, graphql, nosql, saml, essential-skills…).

```bash
# via fetch MCP or curl:
curl -s https://portswigger.net/web-security | grep -oE '/web-security/[a-z0-9-]+' | sort -u
```

- [ ] **Step 2: Fetch topic pages** — for each priority topic, fetch the learning page (firecrawl scrape or webfetch). Prioritize gap classes first: request-smuggling (+http2 variants), prototype-pollution, websockets, cache-poisoning, dom, jwt, oauth, cors; then overlap classes for completeness.
- [ ] **Step 3-5: Write files** — chapter per topic group: mechanism → detection signals → exploitation → lab reference link. Emphasis sections mark classes with no book coverage.
- [ ] **Step 6: Structure check.**
- [ ] **Step 7: Scan + review.**

---

### Task 8: `recon-pipeline` — hand-written ops skill

**Files:**
- Create: `/c/Users/luong/.agents/skills/recon-pipeline/SKILL.md`
- Create: `/c/Users/luong/.agents/skills/recon-pipeline/{stages.md,outputs.md,monitoring.md}` — flat supporting files (no chapters/ needed for a runbook skill; use chapters/ only if files grow)

**Interfaces:**
- Consumes: nothing (standalone runbook).
- Produces: output layout convention `recon/<target>/<YYYYMMDD>/<stage>.txt` + `new-since-last-run.txt` — referenced by orchestrator session checklist.

- [ ] **Step 1: Write SKILL.md** — runbook framing: staged pipeline, output layout, diff-first philosophy, passive/active gating.
- [ ] **Step 2: Write stages.md** — per stage: purpose → commands (verbatim, from the established set: amass/sublist3r/gobuster dns → httpx/probing → nmap/masscan → dirsearch/gobuster → eyewitness → github dorks/trufflehog → wappalyzer) → output files → failure notes.
- [ ] **Step 3: Write outputs.md** — directory layout, normalization (`sort -u`, dedupe), diff vs prior run (`comm`, `diff`), lead file format.
- [ ] **Step 4: Write monitoring.md** — scheduling (cron/Task Scheduler examples), diff alerting, continuous-recon cadence, scope-drift cautions.
- [ ] **Step 5: Structure check + scan.**

---

### Task 9: `report-writing` — hand-written ops skill

**Files:**
- Create: `/c/Users/luong/.agents/skills/report-writing/SKILL.md`
- Create: `/c/Users/luong/.agents/skills/report-writing/{severity.md,template.md,impact-library.md,triage.md}`

- [ ] **Step 1: Write SKILL.md** — report as persuasion; structure overview; golden rules (test accounts, minimal PoC, platform channel).
- [ ] **Step 2: Write severity.md** — rubric: impact × exploitability table → platform bands (critical/high/medium/low) → CVSS guidance + when to argue up/down.
- [ ] **Step 3: Write template.md** — full report skeleton (title format, summary, severity, numbered repro, impact, remediation) + worked example (IDOR).
- [ ] **Step 4: Write impact-library.md** — per vuln class: 2-3 sentence impact statements + escalation language + what NOT to claim.
- [ ] **Step 5: Write triage.md** — verdicts (N/A/informative/duplicate/spam) → response playbook, dispute escalation etiquette, mediation.
- [ ] **Step 6: Structure check + scan.**

---

### Task 10: `bug-bounty-hunter` — orchestrator (LAST)

**Files:**
- Create: `/c/Users/luong/.agents/skills/bug-bounty-hunter/SKILL.md`
- Create: `/c/Users/luong/.agents/skills/bug-bounty-hunter/{phase-map.md,vuln-class-index.md,session-checklist.md}`

**Interfaces:**
- Consumes: all 16 other skills by name + their chapter file names (verify against disk).
- Produces: the entry-point skill for sessions.

- [ ] **Step 1: Inventory actual chapter files** — `ls` every skill's `chapters/` to get real filenames for routing (no guessed names).
- [ ] **Step 2: Write phase-map.md** — phases (program selection → recon → hunting → escalation → reporting → monitoring) × tasks × skill routing + decision rules (API target, mobile target, cloud assets, wide scope, checklist need, payload need).
- [ ] **Step 3: Write vuln-class-index.md** — every vuln class across the set → best skill + chapter file; note depth differences (methodology vs payloads vs checklist).
- [ ] **Step 4: Write session-checklist.md** — kickoff → policy/scope → accounts → recon handoff → hunt loop → escalation review → report → monitoring.
- [ ] **Step 5: Write SKILL.md** — doctrine + compact routing; description must trigger on session-start language.
- [ ] **Step 6: Resolution check** — every skill name in the 3 files must exist as a directory; every `chapters/X` reference must exist:

```bash
for s in xss-cheat-sheet owasp-api-security-top-10 zseano-methodology bug-bounty-playbook web-hacking-101 hacking-apis bug-bounty-bootcamp owasp-wstg web-app-hackers-handbook web-security-academy hacking-the-cloud owasp-mas tbhm-methodology payloads-all-the-things recon-pipeline report-writing; do [ -d "/c/Users/luong/.agents/skills/$s" ] || echo "MISSING SKILL: $s"; done
grep -ohE "chapters/[a-z0-9-]+\.md" /c/Users/luong/.agents/skills/bug-bounty-hunter/*.md | sort -u > /tmp/refs.txt
cat /tmp/refs.txt | while read f; do find /c/Users/luong/.agents/skills -path "*/$f" | grep -q . || echo "UNRESOLVED: $f"; done
```

- [ ] **Step 7: Scan + review.**

---

### Task 11: Final validation + report

- [ ] **Step 1: Full-structure sweep** — verify all 17 skill dirs, each with SKILL.md + frontmatter; count files per skill:

```bash
for s in xss-cheat-sheet owasp-api-security-top-10 zseano-methodology bug-bounty-playbook web-hacking-101 hacking-apis bug-bounty-bootcamp owasp-wstg web-app-hackers-handbook web-security-academy hacking-the-cloud owasp-mas tbhm-methodology payloads-all-the-things recon-pipeline report-writing bug-bounty-hunter; do echo "== $s: $(find /c/Users/luong/.agents/skills/$s -type f 2>/dev/null | wc -l) files"; done
```

- [ ] **Step 2: Scan all 10 new skills** — loop scanner over each; collect warnings + dispositions.
- [ ] **Step 3: Spot-check for verbatim text** — pick 3 random chapter files across new skills; confirm synthesized (no >3-sentence verbatim source passages).
- [ ] **Step 4: Final report** — table: skill | files | source | scan warnings + dispositions | extraction method; note limitations (no docling, no Tier-3 books, PortSwigger labs not included).

## Self-Review Notes

- Spec coverage: 3 ops (T8-T10) ✓, 2 books (T1-T2) ✓, 5 free sources (T3-T7) ✓, validation (T11) ✓.
- No placeholders: every step has commands or concrete output specs; chapter counts are ranges because source ToCs are mapped at runtime (Step 2 of each conversion) — this is intentional, not a placeholder.
- Type consistency: skill names identical across spec/plan/routing.
