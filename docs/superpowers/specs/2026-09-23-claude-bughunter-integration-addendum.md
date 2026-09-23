# Claude-BugHunter Integration Addendum

**Purpose:** Add selected organizational patterns and reusable templates from Claude-BugHunter to the existing 17-skill bug-bounty workflow. This is a handoff addendum for the ongoing implementation; it does not replace the approved methods-refresh design or ask for wholesale import of upstream skills.

## Decision

Keep the existing 17-skill architecture and selectively adopt four useful ideas:

1. A repeatable engagement workspace and scope snapshot.
2. A finding lifecycle and report-ready finding template.
3. A pre-report validation gate.
4. Evidence handling and redaction checks.

Preserve the workflow's authorization-first model. Discovered assets remain unverified leads until independently matched to the program's current scope. Do not store secrets in engagement notes or use real third-party data to prove impact. Follow current program rules and platform taxonomies; do not hard-code Claude-BugHunter's older CVSS 3.1 assumptions.

## Integration map for the 17 skills

| Upstream idea | Integrate into | Suggested adaptation |
|---|---|---|
| Per-target engagement scaffold (`scope.md`, notes, findings, evidence, submission tracker) | `bug-bounty-hunter` and `recon-pipeline` | Add an optional workspace template with a dated scope snapshot, rules/source URL, in-scope assets, exclusions, allowed techniques, rate limits, stop conditions, and test-account labels. Do not record passwords, tokens, or recovery secrets. |
| Recon manifest and asset intake | `recon-pipeline` | Store newly discovered hosts in `unverified-leads.md` with source, timestamp, and verification status. Never promote a lead to an active target merely because a tool found it. |
| Finding lifecycle (`lead` → `validated` → `drafted` → `submitted` → `triaged` → `paid`/`closed`) | `bug-bounty-hunter` and `report-writing` | Add explicit status, next action, owner (optional), platform report ID, and timestamps. Keep status tracking separate from sensitive PoC material. |
| Seven-question triage gate | `bug-bounty-hunter` routing into `report-writing` | Use the safe gate below. A failed gate should stop work on that candidate or mark it inconclusive; it should not terminate the whole engagement. |
| Evidence hygiene: screenshot/HAR redaction, evidence index | `report-writing` (and optional companion section in `bug-bounty-hunter`) | Add a pre-attachment checklist for credentials, session material, personal data, and unnecessary response content; verify sanitized exports rather than trusting a redaction command alone. |
| Platform-shaped report templates | `report-writing` | Keep one platform-neutral core template, then apply concise overlays for the active platform's current required fields, taxonomy, and severity policy. |
| Scratchpad sections for leads, hypotheses, dead ends, and tools | `bug-bounty-hunter` | Add these as optional engagement notes to reduce duplicated recon and preserve tested/untested state. Never put raw secrets or unnecessary personal data in notes. |

## Engagement workspace template

```text
engagements/<program-or-alias>/<YYYY-MM-DD>/
  engagement.md          # program link, scope snapshot date, allowed methods, stop conditions
  scope.md               # in-scope, out-of-scope, exclusions, accepted impacts, safe harbor
  recon/
    verified-assets.md
    unverified-leads.md  # discovered != authorized
  findings/
    F-001.md
  evidence/               # restricted local storage; sanitized copies only for sharing
  submissions.md          # platform IDs, dates, state, next follow-up; no credentials/PII
  notes.md                # hypotheses, dead ends, tool/version notes
```

Do not require this exact directory layout when the current workflow has a better normalized output structure. The important properties are separation of scope, verified assets, leads, finding records, evidence, and submission state.

### `scope.md` minimum fields

```markdown
# Program scope snapshot

- Program/platform URL:
- Snapshot captured (UTC):
- Rules/policy URL and revision/date (if shown):
- In-scope assets and qualifying conditions:
- Explicitly out-of-scope assets/features:
- Allowed testing methods:
- Prohibited methods and rate limits:
- Accepted impact categories / exclusions:
- Safe-harbor or disclosure requirements:
- Test-account setup labels (never credentials):
- Stop conditions / emergency contact path:

## Asset verification
| Asset | Evidence it is in scope | Verified at (UTC) | Status |
|---|---|---|---|
```

If scope wording is ambiguous or a policy has changed, pause testing of the affected asset/method until scope is resolved. Keep a dated snapshot; do not treat old scope snapshots as current authorization.

## Candidate validation gate

Before drafting a report, answer all applicable questions with evidence:

1. **Reproduction:** Can the behavior be reproduced with the exact request, response, account role, and preconditions recorded?
2. **Program fit:** Does the current policy accept this vulnerability class and demonstrated impact?
3. **Authorization:** Is the affected asset explicitly in scope, and was the technique permitted? Is any third-party service or tenant involved?
4. **Preconditions:** What access, user interaction, configuration, or role does an attacker need?
5. **Alternative explanation:** Could this be intended behavior, a documented feature, a known issue, or a test artifact? For auth/access-control checks, retry with a minimally valid request so malformed input is not mistaken for an authorization bypass.
6. **Impact proof:** Is impact demonstrated end-to-end with researcher-controlled accounts or synthetic data and the least intrusive proof the program permits? Do not access, retain, or submit real users' data just to strengthen a report.
7. **Submission readiness:** Is the evidence sufficient, sanitized, non-duplicative to the best of available program information, and compatible with platform requirements?

Allowed outcomes: `continue`, `stop candidate`, `needs scope clarification`, or `inconclusive`. A “stop candidate” outcome does not imply stopping unrelated authorized work.

## Finding template (`findings/F-###.md`)

```markdown
# [Asset] | [Bug class] | [Demonstrated impact]

- Status: lead | validated | drafted | submitted | triaged | paid | closed
- First observed (UTC):
- Last reproduced (UTC):
- Program/platform:
- Asset and in-scope evidence:
- Policy/taxonomy reference:
- Severity rationale: use current platform/program method; include vector/version when applicable
- Preconditions / attacker role:
- Test accounts: researcher-controlled labels only; no credentials
- Duplicate/known-issue check:

## Summary
State the root cause and demonstrated impact without speculative chains.

## Reproduction
1. Preconditions and account roles.
2. Exact, minimal request/action using placeholders for secrets.
3. Expected result.
4. Actual result.

## Impact demonstrated
Describe only what was safely observed and reproduced. Identify any synthetic or researcher-owned data used.

## Evidence index
| File | What it proves | Sanitized/checked | Contains third-party data? |
|---|---|---|---|

## Suggested remediation

## Submission / triage history
- Report ID:
- Submitted (UTC):
- Status / response:
- Next action and due date:
```

Never place raw cookies, bearer tokens, API keys, passwords, recovery codes, or unnecessary personal data in this record. Keep secrets out of screenshots, HARs, console output, and tracker fields.

## Evidence checklist

Before storing or attaching evidence:

- Prefer a minimal request/response or screenshot that demonstrates the claim.
- Redact session cookies, `Authorization`, CSRF/session-bound tokens, API keys, and secrets in URLs or bodies.
- Avoid collecting third-party data. If incidental personal data appears, stop further access and minimize exposure; redact it from shared evidence and follow the program's handling/disclosure rules.
- Sanitize HAR request/response headers, cookie arrays, URLs, and bodies. Header-only filters are insufficient; inspect the sanitized artifact for secrets and personal data before attachment.
- Check screenshots at full resolution, including URL bars, side panels, terminal history, and hidden request headers.
- Keep raw captures in restricted local storage only when necessary; exclude evidence and secrets from Git and routine backups where practical. Share only sanitized copies through approved program channels.
- Retain/delete evidence according to program instructions and applicable policy. Rotate a test credential if it was exposed.

## Submission tracker template

```markdown
| Finding | Platform report ID | Submitted (UTC) | Status | Last update (UTC) | Next action |
|---|---|---|---|---|---|
```

Only track administrative metadata here. Do not copy report payloads, credentials, or personal data into the tracker.

## Upstream source notes

These are design references, not instructions to import the repositories wholesale:

- Claude-BugHunter repository and documented structure: https://github.com/elementalsouls/Claude-BugHunter
- Engagement scaffold: https://raw.githubusercontent.com/elementalsouls/Claude-BugHunter/main/scripts/hunt.sh
- Triage gate: https://raw.githubusercontent.com/elementalsouls/Claude-BugHunter/main/skills/triage-validation/SKILL.md
- Evidence hygiene: https://raw.githubusercontent.com/elementalsouls/Claude-BugHunter/main/skills/evidence-hygiene/SKILL.md
- Report-writing templates: https://raw.githubusercontent.com/elementalsouls/Claude-BugHunter/main/skills/report-writing/SKILL.md

Retain required attribution and license notices if any upstream text is copied. Prefer adapting the concepts and writing original templates. Review the repository's current license/NOTICE before copying content.
