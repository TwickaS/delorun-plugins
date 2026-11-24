---
description: "Audit a repository for security problems: choose the profile, set a budget, start the run, watch it in the sidebar, and read the report."
---

# Audit a repository for security problems

English | [中文](security-audit.zh.md)

## Summary

This page helps you run a [security audit run](../../reference/glossary.md#security-audit-run) over a repository and read what it finds. You need Delorun running ([Install and first run](../get-started/install.md)), the **Security audit** plugin installed and turned on at your computer, and a workspace that holds the repository you want audited.

A security audit looks for places where the code lets something happen that its own design says should not. It is not a scan for known bad patterns: an agent reads the code along each trust boundary, proposes candidates, and a second agent tries to refute each one. What survives has a trace from the place input enters to the place it has an effect, a check that ran locally, and a severity no higher than what that check showed. Everything else is either rejected, with what disproved it, or recorded as needing validation, with the fact that is missing.

## What you need first

- The plugin, installed with `delorun plugin add delorun-plugin-security-audit` and turned on in Settings → Plugins. A plugin installed from a folder waits in Changes for you to approve it.
- The repository's version control ignoring `.security-audit/`, which is where the run writes. Add that line to `.gitignore` if it is missing.
- The workspace's network set to **Off** in Settings → Safety → Network. The audit reads the code and runs small local checks; it needs no network, and a setting that allows one would let a checked program send your data out.
- A Linux machine with bubblewrap, which is what runs commands with no network at all. On other systems the audit still reads and reports, and marks every check that needs to run as needing validation.

## Run an audit

1. Open a chat in the workspace that holds the repository, and choose **Security audit** in the mode list.
2. The **Audit settings** bar appears above the message box. Choose a profile: **Quick** for a first look, **Standard** (the usual choice), or **Deep** for a release you are about to publish. Turn on the **RC profile** as well when the target is a Delorun release candidate, so coverage starts from the threat model's boundaries rather than waiting for reconnaissance to find them.
3. Set a budget if you want one: a number of agents the run may start. Left empty, the plugin proposes one from the size of the repository and says so in the start message.
4. Choose when you want to hear from the run: not until the end, after it has read the code (the usual choice), or after every stage.
5. Press **Start audit**. The bar writes a message into the message box saying what will be audited and with which settings. Read it, then send it.

The run then works through six stages: reading the code, hunting along the coverage plan, validating candidates, writing its findings, checking its own records again, and writing the report. How long it takes depends on the profile and the budget, not on the size of the repository alone.

## Watch it work

Open the **Security audit** tab in the sidebar, or the button in the chat's header. The pane follows the run's files as they change, so it shows what is happening rather than a summary written at the end:

- how many coverage units are planned, in progress, covered, holding a candidate, blocked or deferred, and which unit each running agent owns;
- candidates and findings as they appear, with their titles and their state;
- how long the run has been going and how much of its budget it has spent.

The pane keeps a reload button for when the file watch ends, such as after the run finishes or Delorun restarts.

## Read the report

When the run ends, its folder `.security-audit/run-<N>/` in the workspace holds the report. Ask the chat to show it, or open it yourself:

- `REPORT.md` opens with what the run covered and what it did not. Read that first: it says whether every candidate was validated and which areas the budget left out.
- `FINDINGS-DETAIL.md` has one section for each confirmed finding: what goes wrong, the path through the code, the conditions, the check that showed it, the smallest change that fixes it and a test that would have caught it.
- `NEEDS-VALIDATION.md` has one section for each hypothesis that a missing fact blocked, with the check that would settle it. These have no severity; they are leads, not findings.

The report never goes into a repository with a public remote, because it describes problems that are not fixed yet. When the target is public, the plugin offers a private export: you name a folder outside the repository, and it writes the three files there. If you fix the findings, the same audit run again carries them forward only while the code they describe is unchanged.

<details>
<summary>Edge cases</summary>

- If the workspace's network is not Off, then the plugin refuses to start and names the setting — set it in Settings → Safety → Network at the computer, then start the audit again.
- If version control does not ignore `.security-audit/`, then the run refuses and names the file to edit — add the line and start again. Nothing is written until it is ignored.
- If the workspace is on full access, then the plugin refuses, because a command under full access runs outside the sandbox — switch the chat to Workspace Write.
- If your sandbox is Landlock alone, or you are on Windows, then a workspace set to Off refuses to run commands, so the audit reads and reports without running anything and marks each such check as needing validation — run it on a Linux machine with bubblewrap for the checks.
- If the budget runs out mid-run, then the run stops and says so, and the report names the units and candidates it could not finish — raise the budget or narrow the scope with a list of paths.
- If you asked for check-ins after every stage, then each stage ends with a message and a question — answer it to continue; the run waits for you.
- If a turn is already running, then the bar hides **Start audit**, so that one audit starts one run — wait for the turn, or stop it.
- If the sidebar pane is empty, then no run folder exists in that workspace yet, or the run wrote to another workspace — check which workspace the chat is in.

</details>

<details>
<summary>Go further</summary>

- **Audit a Delorun release candidate.** Turn on the RC profile in the Audit settings bar. Coverage then starts from one unit for each boundary in [Delorun's threat model](../../security/threat-model.md), so nothing the project claims to protect is left out of the first wave.
- **Audit only part of a repository.** Name a list of paths in the start message. The run seeds units only for those paths, records the rest as out of scope, and presents itself as partial coverage.
- **Choose a model per role.** Hunters read a lot of code; verifiers read a little and must be strict. A cheaper model for hunters and a stronger one for verifiers and critics is a legitimate mix, and the bar sets each one.
- **Audit again after changes.** A second run in the same workspace reads the prior ledger: a confirmed finding whose source is unchanged is carried forward and re-verified, changed source becomes new work, and nothing is assumed covered because it was covered before.
- **Keep the report out of the repository.** The private export writes the three report files to a folder you name, outside the repository, so a public repository never receives a page describing its own unfixed problems.

</details>

**Next.** Read [What Delorun protects](safety.md) for the confinement the audit's checks rely on, and [Prompt injection and data exfiltration](prompt-injection.md#the-network-setting) for why the audit needs the network Off. If you audit Delorun itself, start with its [threat model](../../security/threat-model.md).

## If something went wrong

- **The mode list has no Security audit.** The plugin is installed but not turned on, or it is turned off in Settings → Plugins. Turn it on at the computer, then reopen the chat.
- **The Audit settings bar does not appear.** The chat is not on the Security audit mode, or a turn is running. Choose the mode; the bar returns when the turn ends.
- **The run refuses before it starts.** Its message names the condition and the fix: the network setting, the ignore line, the permission preset or the sandbox. Fix that one thing; the plugin checks again on the next start.
- **The run stops partway and calls itself incomplete.** Its message names the reason, which is the budget or a missing validator pass. Raise the budget, narrow the scope, or fix what the message names, and start again; the prior run's ledger is read as prior evidence.
- **Every local check is marked as needing validation.** The sandbox cannot enforce what the check needs, usually the network rule or a resource limit. Read the reason in `NEEDS-VALIDATION.md`; run the audit where that control exists, or have the person run the named check out of band.

## For the technically curious

The run directory is `<workspace>/.security-audit/run-<N>/`. The chat's own session is the coordinator and the only writer of the shared files; each role is a delegated agent whose session working directory is its own `<run>/agents/<id>/scratch/`, so the sandbox gives it write isolation with stock tools and no custom command wrapper. A role's structured result is enforced by the harness's `outputSchema` as well as by its prompt. The budget is a count of agent invocations, and the gate that reserves critics and verifiers runs before reconnaissance.

The skill is vendored complete in `skill/`, byte-identical to upstream at commit `c1c8a8c`, with a `NOTICE.md` that names the commit and the licence and `ADAPTER.md` that states, for each of the skill's five execution-safety controls, what Delorun enforces and what it does not.
