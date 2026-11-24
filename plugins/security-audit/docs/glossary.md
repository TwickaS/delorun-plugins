# Security audit glossary

English | [中文](glossary.zh.md)

The words this plugin's documentation, interface text and prompts use, one term per concept, in the form [Delorun's glossary](https://github.com/TwickaS/delorun/blob/main/delorun/docs/reference/glossary.md) uses. Each entry starts with one plain-English sentence, then adds a technical note where the code uses another word. These entries join Delorun's glossary when the plugin's pages are wired into `delorun/docs`.

## Contents

- [The feature](#the-feature)
- [A run](#a-run)
- [Coverage](#coverage)
- [Findings](#findings)
- [The files](#the-files)

## The feature

- **security audit** — a run of Cloudflare's security-audit skill over a repository, which reads the code along its trust boundaries and reports only what a bounded local check supports. Technical note: `@delorun/plugin-security-audit`; the skill is vendored in `skill/`. <a id="security-audit"></a>
- **audit profile** — how broad a run is: **Quick** for a first look, **Standard** as the workflow is written, **Deep** for a release candidate. Breadth and redundancy change with it; the evidence bar does not. Technical note: the `profile` field, `quick`, `standard` or `deep`. <a id="audit-profile"></a>
- **RC profile** — the choice that seeds coverage from one unit for each boundary in [Delorun's threat model](https://github.com/TwickaS/delorun/blob/main/delorun/docs/security/threat-model.md), so a release candidate is audited against everything Delorun claims to protect. <a id="rc-profile"></a>
- **audit budget** — the most agents a run may start, counted in agent invocations across every stage. A run that reaches it stops and calls itself incomplete rather than spend more. <a id="audit-budget"></a>
- **check-in** — when the run reports to the person and waits: never, after reconnaissance, or after every stage. <a id="check-in"></a>

## A run

- **security audit run** — one pass of the skill over one repository at one source reference, which writes its plan, its findings and its report into one folder and ends either complete or incomplete with a stated reason. Technical note: the folder is `<workspace>/.security-audit/run-<N>/`, and its name is the run. <a id="security-audit-run"></a>
- **coordinator** — the chat that runs the audit. It owns the plan, assigns the work, is the only writer of the files the run shares, and writes the report. <a id="coordinator"></a>
- **role** — one delegated agent in a run: a researcher in reconnaissance, a hunter, a candidate verifier, a coverage critic, the final-clean critic, or a record verifier. Each role runs in its own scratch folder, and the agent that validates a candidate never hunted it. <a id="role"></a>
- **hunter** — the role that reads the code for its assigned coverage units and returns one structured result for each. <a id="hunter"></a>
- **critic** — the role that reads the coverage after a wave of hunting and proposes what the plan missed. The final-clean critic is a second, distinct role that must also find nothing before coverage counts as complete. <a id="critic"></a>
- **verifier** — the role that tries to refute one candidate, and the fresh role that checks one final record. <a id="verifier"></a>
- **source reference** — the commit a run audits, and whether its working tree was dirty. A run never treats unreviewed generated or modified files as another revision. <a id="source-reference"></a>

## Coverage

- **coverage unit** — one thing a run promises to check: one entry surface, trust boundary, subsystem and attack class, with the source paths to start from. Technical note: a unit's identifier is derived from its canonical references, so the same source object keeps the same identifier across runs. <a id="coverage-unit"></a>
- **coverage ledger** — the list of coverage units with each one's state, owner and evidence. It is the run's coverage claim: a sentence in the report is not evidence, and a unit closes only from the paths and checks its hunter returned. <a id="coverage-ledger"></a>
- **unit state** — where a unit stands: planned, in progress, covered, holding a candidate, blocked, deferred, out of scope, or not applicable. <a id="unit-state"></a>
- **attack class** — the kind of weakness a unit hunts, such as access control, resource and file handling, or cryptography and secrets, taken from the skill's own list. <a id="attack-class"></a>
- **scoped run** — a run that audits a list of paths or one subsystem. It records everything else as out of scope and presents itself as partial coverage, never as covered. <a id="scoped-run"></a>

## Findings

- **candidate** — something a hunter suspects, which a fresh verifier must either confirm, block or refute. <a id="candidate"></a>
- **confirmed finding** — a candidate that survived its verifier, with a complete trace, a bounded observed result and a severity no higher than that result supports. Only a confirmed finding carries a severity. <a id="confirmed-finding"></a>
- **needs validation** — a specific, source-grounded hypothesis that one missing fact blocks, named with the safe check that settles it. It carries no severity and is never counted as confirmed. <a id="needs-validation"></a>
- **rejected candidate** — a candidate that the source or a local check disproved. It stays in the findings, with what disproved it, so the same claim is not re-investigated from scratch on the next run. <a id="rejected-candidate"></a>
- **fingerprint** — the stable name of one root cause, shared by every state that root cause passes through, so a candidate, its verification and a carried prior record are the same thing rather than three. <a id="fingerprint"></a>
- **bounded local check** — the smallest local run that settles a claim: an existing test, a small fixture, one function harness, a locally rendered policy. It stops at the first result that establishes the boundary and never tests availability against a live service. <a id="bounded-local-check"></a>
- **promotion** — copying one declared file out of a role's scratch into the run's artifacts after the role's processes end, by trusted code that refuses a link, a special file, a changed file or an oversize one. A promoted file is what makes a local check count as evidence. <a id="promotion"></a>

## The files

- **run folder** — `<workspace>/.security-audit/run-<N>/`, which version control must ignore. <a id="run-folder"></a>
- **run metadata** — `run-metadata.json`: the target, source reference, profile, scope, budget, execution policy, prior runs, file owners and run status, with the status's reason when the run is incomplete. <a id="run-metadata"></a>
- **architecture summary** — `architecture.md`: the target's principals, resources, entry surfaces, controls, starting paths and prior gaps, in about 1,000 words. <a id="architecture-summary"></a>
- **findings file** — `findings.json`: every confirmed, needs-validation and rejected record, checked against the skill's schema and validator before any report is written. <a id="findings-file"></a>
- **report files** — `REPORT.md`, `FINDINGS-DETAIL.md` and `NEEDS-VALIDATION.md`, derived only from verified records, and the three files the private export copies out. <a id="report-files"></a>
- **scratch folder** — `agents/<id>/scratch/`: a role's working directory and the only place its commands may write. <a id="scratch-folder"></a>
- **artifacts folder** — `agents/<id>/artifacts/`: the files a run keeps from a role's local checks, written by the coordinator after the role's processes end, never by the role. <a id="artifacts-folder"></a>
- **private export** — the folder the person names, outside the repository, that receives the three report files when the repository has a public remote. <a id="private-export"></a>
