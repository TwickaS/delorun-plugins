---
description: "The Security audit plugin: what it does, how to install and start it, its intake settings, the six phases of a run, the files it writes, the report and its private-export rule, its release-candidate profile seeded from Delorun's threat model, and its honest limits."
kind: "package-reference"
---

# delorun-plugin-security-audit

## Summary

"Security audit" finds security problems in a repository and writes a report whose every finding has a source trace, a bounded local check and a severity that no more than the observed result supports. It runs Cloudflare's MIT-licensed security-audit skill (commit `c1c8a8c`, 2026-09-14) inside Delorun, using Delorun's own confinement for the commands a check runs, its delegation for the agents that hunt and verify, and its studio for the settings and the live view. It is an optional plugin: it does nothing until a person installs it and opens the chat mode.

The plugin carries two profiles. The **general** profile derives its coverage from reconnaissance of the target, as the skill specifies. The **release candidate** (RC) profile seeds one coverage unit for each boundary in [Delorun's threat model](https://github.com/TwickaS/delorun/blob/main/delorun/docs/security/threat-model.md), so an audit of a Delorun release candidate is complete by construction against what Delorun claims to protect.

## Contents

- [Install and start](#install-and-start)
- [Choosing a model per role](#choosing-a-model-per-role)
- [The intake](#the-intake)
- [The six phases](#the-six-phases)
- [What a run writes](#what-a-run-writes)
- [The report](#the-report)
- [The RC profile](#the-rc-profile)
- [Known limitations and deferred work](#known-limitations-and-deferred-work)

## Install and start

Install the plugin and turn it on at the computer that runs Delorun:

```sh
delorun plugin add delorun-plugin-security-audit
```

Then open a chat, choose **Security audit** in the mode list, and pick the workspace that holds the repository to audit. The **Audit settings** bar appears above the message box. Set the profile or turn on the RC profile, the budget, the check-ins and any per-role models, then press **Start audit**: the bar writes a start message into the message box. Read it and send it. The bar never sends a message itself, and it hides **Start audit** while a turn runs so that one audit starts one run.

Every role defaults to this chat's model and effort, and the bar asks rather than assumes. The **Models** menu lists each role with its own model and its own reasoning effort, one **All roles** entry that sets every role at once, and one **Use this chat's model** entry that clears them all. The start message states each role's effective route, so what the run will spend is visible before you send it. A deployment can set defaults for any role in the plugin's configuration, and a run's own choice wins over them field by field.

Four conditions must hold before a run starts. The plugin checks each one and refuses with a message naming the fix:

- The target repository's version control ignores the run directory `<workspace>/.security-audit/`. Add `.security-audit/` to the repository's `.gitignore` when it does not.
- The audit workspace's [network setting](https://github.com/TwickaS/delorun/blob/main/delorun/docs/guide/safety-and-updates/prompt-injection.md#the-network-setting) is **Off**. A run reads the target and needs no network; a setting that admits one would let a target-controlled program send data out, so the plugin refuses rather than assume. Change it in Settings → Safety → Network at the computer.
- The sandbox can express the network rule. Only bubblewrap does, so on Landlock, Seatbelt and Windows a workspace set to Off refuses to run commands. A run on such a machine reports `needs_validation` for every check that needed local execution, and local execution is not attempted.
- The workspace's permission preset is **Workspace Write** or **Read Only**, not full access. A command under full access runs outside the sandbox, so the skill's execution-safety bar does not hold for it.

## Choosing a model per role

A run delegates its work to four kinds of agent, and each can run on a different model and a different reasoning effort:

| Role | What it does | Why you might give it its own model |
| --- | --- | --- |
| reconnaissance | Four agents read the target in parallel and return source facts | It reads the most code, so a cheaper model with a large context is often enough |
| hunters | They hunt one coverage unit each and must show a bounded check | It reads a lot and must be careful, so this is where a stronger model pays |
| verifiers | They try to refute one candidate each, and never hunted it | It reads little and must be strict; a strong model at high effort is the usual choice |
| critics | They judge coverage after each wave and before the run calls itself complete | It reads the ledger and the results, not the target |

Nothing is chosen for you. Every role starts on this chat's model and this chat's effort, and the **Models** menu in the Audit settings bar is where you change that:

- **All roles** sets one model for every role at once, keeping any effort a role already had.
- **Use this chat's model** clears every role's own choice, so all four go back to the chat's route.
- Each role's own row opens its model list, read from the models the Host has loaded, and its **Reasoning effort** row offers **off**, **low**, **high** and **max**, or this chat's effort when unset.

The bar shows how many roles have a choice of their own, and the start message states each role's effective route — provider, model and effort, or "this chat's model" — so what the run will spend is visible before you send it. The run records the same routes in `run-metadata.json`, and each agent's entry in `state.json` records the route it actually ran on.

A deployment can set defaults for any role in the plugin's configuration, which is what a team that always wants a strong verifier should do:

```yaml
- id: security-audit
  config:
    mount: agent
    models:
      hunter: { provider: deepseek, model: deepseek-v4.1-flash, reasoningEffort: low }
      verifier: { provider: deepseek, model: deepseek-v4.1-pro, reasoningEffort: high }
```

A run's own choice wins over a deployment default field by field: a run that sets only a role's effort keeps the deployment's model for that role, and a field neither sets inherits the chat's. The role names are the four in the table above; a configuration or an intake that names any other role is refused with the list of the ones it accepts.

## The intake

The start message carries the intake. Each setting is also a field in the bar.

| Setting | Values | What it decides |
| --- | --- | --- |
| Target | a workspace folder and an optional list of paths | What the run audits. A list of paths makes a scoped run, which presents itself as partial coverage. |
| Profile | `quick`, `standard`, `deep` | Breadth and redundancy, never the evidence bar. `quick` coarsens coverage units to surface × boundary × attack class and runs one hunter wave and one critic pass. `standard` runs the workflow as written. `deep` splits units per subsystem and lifecycle mode and re-passes units a prior run covered from unchanged source. |
| Budget | a number of agent invocations, or unset | The most agents the run may start. Unset means no limit. When the person sets none, the plugin proposes one from the target's size and states the proposal in the start message. |
| Check-ins | `straight_through`, `after_recon`, `every_stage` | When the coordinator reports to the person and waits: never, after reconnaissance (the default), or after each stage. |
| Role models | one model and one reasoning effort per role, or unset | Which model each role runs, and at what effort. Unset inherits the chat's model and effort. **All roles** sets every role at once, and **Use this chat's model** clears them all. |
| RC profile | on or off | Whether coverage starts from the threat model's boundaries instead of reconnaissance. |

The budget gate runs before any reconnaissance agent starts. It reserves the four reconnaissance calls, the critic calls the profile requires and at least one verifier call, and it launches nothing when the budget cannot fund them: the run records `run_status: "incomplete"` with the skill's reason `budget_cannot_fund_reconnaissance_and_reserves` and says that no audit pass ran. A set budget is never exceeded silently. An exhausted budget ends the run as `incomplete` with an exact reason, and the report states which units and candidates the budget left unresolved.

## The six phases

1. **Reconnaissance.** Four research agents read the target in parallel and return source facts to the coordinator. The coordinator writes `architecture.md` and a coverage ledger with one unit for each material combination of entry surface, trust boundary, subsystem and attack class. Each unit has a stable identifier derived from source, so the same source object gets the same identifier in every run.
2. **Coverage-led hunting.** The coordinator assigns units to hunters in priority order: the least-trusted entry surfaces first, the most valuable resources next, prior gaps before re-passes. Each hunter returns one structured result. A fresh coverage critic reads the result after every wave, and in `standard` and `deep` a second, distinct final-clean critic must also find nothing before coverage counts as complete.
3. **Candidate validation.** Every candidate goes to a fresh verifier whose job is to refute it. The agent that validates a candidate never hunted it.
4. **Structured output.** `findings.json` records three verdicts. A `confirmed` record has a complete trace, a bounded observed result and a severity. A `needs_validation` record names the exact fact that is missing and a plan that settles it, and has no severity. A `rejected` record is kept with what disproved it. Two zero-dependency validators gate the ledger and the findings on every write.
5. **Independent record verification.** A fresh agent checks each final record. A record that a verifier replaces goes to another fresh verifier, and so on.
6. **Reporting.** `REPORT.md`, `FINDINGS-DETAIL.md` and `NEEDS-VALIDATION.md` are derived from verified records only, never from a hunter's notes.

## What a run writes

A run lives in `<workspace>/.security-audit/run-<N>/`, where `<N>` is the next unused number. The coordinator is the only writer of the shared files:

| File | Holds |
| --- | --- |
| `run-metadata.json` | The target, source reference, profile, scope, budget, execution policy, prior runs, file owners and run status |
| `architecture.md` | The target's principals, resources, entry surfaces, controls and starting paths, in about 1,000 words |
| `coverage-ledger.json` | One unit per surface × boundary × subsystem × attack class, with its status, owner, reviewed paths, checks, result fingerprints and unresolved facts |
| `findings.json` | Every confirmed, needs-validation and rejected record |
| `denial-tests.json` | The denial test each high or critical finding carries, keyed by fingerprint |
| `REPORT.md` | The report, written last |
| `FINDINGS-DETAIL.md` | One section for each confirmed finding |
| `NEEDS-VALIDATION.md` | One section for each blocked hypothesis and the check that settles it |

Each role also gets `agents/<id>/scratch/`, which is its session's working directory, so the sandbox confines its writes there, and a parent-owned `agents/<id>/artifacts/` that holds the few files a bounded local check leaves behind. Roles read the target; they cannot write it, the shared files, or another role's scratch.

## The report

`REPORT.md` opens with the coverage statement: what the run covered, what it did not, and whether candidate validation completed. It then lists confirmed findings by severity, the needs-validation hypotheses, and the rejected candidates with what disproved them. Each confirmed finding gives the trace from entry point to sink, the conditions, the bounded local check with the input it used, the smallest source change that enforces the invariant, and a regression case.

The report is never offered into a repository with a public remote, because an audit of an unreleased release candidate describes problems that are not yet fixed. The plugin offers a private export instead: it writes the three report files into a folder the person names, outside the repository, and leaves the repository untouched. For Delorun's own repository the report goes to the private `ops/` repository until the findings are fixed, and each finding then becomes an issue.

## The RC profile

The RC profile seeds the coverage ledger from the section "Boundaries and their defences" of Delorun's threat model: one unit for each of its sixteen boundaries, from the confinement of native commands to data sharing. Each unit names the boundary, the Delorun package that implements the defence, the attack class that applies and the threat model's own section as its canonical reference. A hunt then answers one question per boundary: does the code enforce what this page claims, and where does it not?

The seed list is a starting point, not a ceiling. Reconnaissance adds units for combinations the seed does not name, and the coverage critic adds any it finds missing. What the RC profile guarantees is that no boundary Delorun claims to protect is left out of the first wave, whatever the budget: the units are ranked so that a budget cut removes depth, not a whole boundary.

Across runs the profile accumulates. A prior ledger carries a confirmed record into a new run only when its source is unchanged; changed source becomes revalidation work; a prior state never suppresses current coverage.

## Known limitations and deferred work

- **The circularity.** An audit of Delorun runs inside Delorun, so a finding about the sandbox cannot be proved from inside the sandbox it describes. The skill's own rule applies: the record is `needs_validation` with an out-of-band check that the person runs, and the report says so.
- **Resource limits.** The skill requires explicit low CPU, memory, process, file-size, disk and wall-clock limits before a target-controlled program may run. Delorun's sandbox enforces none of them. A check that needs one is recorded as `needs_validation` with that missing capability, and it is never run without it.
- **Network and dialect.** The network rule holds on bubblewrap only. On Landlock, Seatbelt and the Windows access-list runner a workspace set to Off refuses to run commands, so local execution is unavailable there and every check that needed it is `needs_validation` with that reason.
- **Reads on Windows.** The Windows runner confines writes only. A confined command can read the whole home, which weakens the environment control a local check relies on; the run records this in its metadata.
- **The empty environment.** The skill asks for an empty environment filled from an explicit allowlist. Delorun passes the harness's filtered environment, which drops credential-named entries and keeps the rest. A check whose result depends on an inherited variable is `needs_validation`.
- **What `needs_validation` covers.** It is a specific, source-grounded hypothesis blocked by one missing fact, not a low-confidence finding. It carries no severity, and the report never counts it as confirmed. A run with many of them is a run with a weak execution surface, not a lenient one.
- **Promotion.** The skill's artifact promotion procedure, which copies a bounded file out of a role's scratch into the parent's artifacts with no-follow checks, is implemented for the cases the ledger accepts and is not yet exercised on a non-POSIX file system.
- **Deferred.** The catalogue entry, the revocation list's use for this plugin, and the Chinese translation of the interface strings are deferred. A catalogue entry pins an exact published version with its `sha512-` integrity string, and this package is not published yet, so the entry lands with the first release rather than before it. The Chinese entries are English copies so that the typed dictionaries pass, and the [locale list](#translation) names every pair.

## Translation

The plugin's interface strings live in `locale/en.json` and `locale/zh.json`. The Chinese file holds the English strings until a translation pass replaces them. The pair is `locale/en.json` and `locale/zh.json`. The documentation is English only for now: `README.md`, `docs/guide/security-audit.md` and `docs/glossary.md` have no Chinese counterparts yet, and they carry no language switcher until a translation pass writes them.
