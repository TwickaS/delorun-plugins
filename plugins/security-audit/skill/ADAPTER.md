# Adapter: how Delorun's harness fills this skill's terms

Every other file in this directory is Cloudflare's, unchanged (see [NOTICE.md](NOTICE.md)). This one is Delorun's: it maps the skill's platform-neutral terms onto Delorun's harness, and it states control by control what the harness really enforces when an audit runs. Each claim names the package, setting or source file it rests on, so a reader can check it rather than trust it. Written against harness `0.2.2-rc.3`.

The skill's own rules stay the authority on how an audit runs. Where this adapter says a control is missing, the skill's rule applies unchanged: report the missing capability as `needs_validation` with the exact blocker, never work around it.

## Platform terms

| The skill says | In Delorun |
|---|---|
| **Parent** | The chat the person runs in the **Security audit** chat mode. Its preset mounts the coordinator persona and the three audit tools, and it is the only writer of the shared run files. |
| **Task tool** | The `subagent` capability (`@deepseek-ai/dsh-subagent`, the `subagent` and `subagent_fork` tools). The plugin spawns roles through `SubagentStartRequest`. |
| `research` agent (`subagent_type: research`) | A spawned child with its own scratch directory, no preset, a read-focused prompt, and the skill's structured-result schema. |
| `general` agent (`subagent_type: general`) | The same contract, with the bounded local execution section in its prompt. |
| **Skill directory** | This directory. The validators run as `node <this directory>/validate-findings.cjs <path>`. |
| **Target**, **repo name**, **source ref** | The same values, resolved at intake by `audit_init` and recorded in `run-metadata.json`. |
| **Output directory** | `<workspace>/.security-audit/run-<N>/`, where `<N>` is the next unused integer. The plugin verifies that version control ignores the whole directory and refuses to start otherwise, naming the line to add. |
| The seven run files | `run-metadata.json`, `architecture.md`, `coverage-ledger.json`, `findings.json`, `REPORT.md`, `FINDINGS-DETAIL.md` and `NEEDS-VALIDATION.md`, written only by the coordinator through `audit_init`, the ledger operations, `audit_finalize` and `audit_report`. |
| `agents/<agent-id>/scratch/` | `<run>/agents/<agent-id>/scratch/`, and that directory is the role's **session cwd**, so the sandbox makes it the role's only writable root. |
| `agents/<agent-id>/artifacts/` | Coordinator-owned, at `<run>/agents/<agent-id>/artifacts/`. A role never writes there; the coordinator promotes allowlisted files after the role's session ends. |
| Canonical agent ids | `^[a-z0-9][a-z0-9_-]{0,63}$`, refusing the Windows device names the skill lists, enforced by the plugin when it creates a role directory. |
| **Budget**, one agent invocation | One spawn of one role. The plugin counts spawns in the coverage ledger and applies the skill's strict pre-reconnaissance gate before the first one. |
| Per-role model | `agentOptions.model` and `agentOptions.reasoningEffort` on the spawn. Unset inherits the chat's model, which is the default. |
| **Structured result** | The role's JSON schema passed as `outputSchema` on the spawn, on top of the prompt's verbatim copy of the skill's contract. The harness validates the child's return against it, and rejects a schema outside the supported subset at start. |
| `execution_policy` | `"sandboxed-source-and-local-only"`, recorded by `audit_init`. |

A role is a fresh child: the in-process provider reports `inheritsParentContext = false`, so no role sees the chat's conversation, and the agent that validates a candidate is never the agent that hunted it.

## What a run relies on at intake

`audit_init` resolves and records these facts before the first agent is spawned. Each one is checkable, and a run that cannot meet one refuses to start and names the fix.

- **The run directory is ignored by version control.** The plugin reads `.gitignore` (or the effective ignore rules) for `.security-audit/` and refuses with the exact line to add.
- **The audit workspace's network is `off`.** The plugin asks the sandbox policy for the effective network of each role's scratch directory, not the workspace root. With the inheritance change in `@delorun/plugin-permission-defaults` (owner ruling A641), a scratch subdirectory resolves its workspace's setting. Until that change is present, a subdirectory resolves the deployment default, which is `open`; the check then reports `open` and the run refuses to start rather than assuming. That refusal is deliberate.
- **Each role's effective sandbox mode is `workspace-write`.** The composed default is `workspace-write` (`packages/bundle/base/cordis.patch.yml`, `sandbox-policy`), and a role's cwd is a subdirectory, which takes the composed default rather than the audit workspace's full-access consent: the consent store is keyed by the exact workspace directory. The intake still records the mode it found for each role cwd, so the run states its own boundary instead of inheriting an assumption.
- **A `node` executable is on the role's `PATH`.** Both validators are CommonJS files run through `node`; they need nothing else, and the target's own runtime is never required to validate a ledger.

## The execution-safety bar, control by control

The skill lists these controls as one OS-enforced sandbox. Delorun's provider meets three of them fully on Linux with the bubblewrap runner, one through the audit's own command form, and the fifth only in part. This table is the summary; the sections below give the evidence and the gaps.

| Control | Verdict | Enforced by |
|---|---|---|
| No external network, an isolated loopback namespace | Met on Linux with bubblewrap, when the workspace's network is `off` | `@deepseek-ai/dsh-sandbox-local` plus the workspace's network setting |
| An empty environment from an explicit allowlist, with scratch-local `HOME`, temporary directories and caches | Not enforced by the sandbox; met by the role's command form | The role prompt's `env -i` form, recorded with the check |
| A read-only target and toolchain | Met | The per-call sandbox policy, whose writable root is the role's cwd |
| Writes only inside the role's `scratch/` | Met | The same policy, whose root is the role's scratch; the coordinator alone writes the shared files |
| Explicit CPU, memory, process, file-size, disk and wall-clock limits | Partly: wall clock per call, the rest unenforced | The executor's deadline; nothing for the rest |

### 1. No external network, and an isolated loopback namespace

**Met on Linux with the bubblewrap runner.** A workspace's network is a setting in Settings, Network, at the computer that runs Delorun, and it is one of `open` (the default, so a fresh install behaves as stock), `allowlist`, or `off`. The audit requires `off`. Under `off` the provider gives the command a network namespace of its own with a loopback interface and nothing else (`--unshare-net`): no address on the host or beyond it, and neither the host's loopback services nor its abstract Unix sockets are reachable. That is the skill's isolated loopback namespace, so a local client and server can complete a bounded check inside it, and nothing leaves. Delorun also refuses `web_fetch` under `off`, so a role cannot reach the internet through the model's own fetch tool either.

**Only the bubblewrap runner expresses a network rule.** The Landlock, Seatbelt and Windows ACL runners refuse a command whose policy carries a network, with `SANDBOX_UNSUPPORTED_POLICY`, rather than running it with the host's network. On macOS and Windows, therefore, an audit workspace set to `off` runs no command at all: the run is source-only and every execution check is `needs_validation`. That is the fail-closed behaviour and it is correct, but it means an audit that executes target code is a Linux claim. A person who wants execution checks on macOS can set the workspace to `open` and accept the host's network; the run then records that it ran without the network control, which is a weaker claim, not a silent one.

**What the namespace does not cover.** Pathname Unix sockets stay reachable inside the namespace, because no mount rule hides them, and a daemon behind one can act for the command. The provider shadows or hides the default daemons that resolve names or send traffic — the system D-Bus, `tailscaled`, `snapd`, and the directories of systemd-resolved's varlink socket, `nscd`, `avahi` and CUPS — and `delorun start` adds the running profile's channel sockets under the Delorun home. Sockets in the person's runtime directory (the session bus), sockets under their home (an SSH control socket) and a tmux server's `/tmp/tmux-<uid>` stay reachable unless the deployment names them in `escapeSocketDirectories`; through the session bus, `systemd-run --user` starts programs outside the sandbox. Under `workspace-write` the bubblewrap runner mounts an empty `/tmp`, so the host's own `/tmp` sockets, such as an `ssh-agent`'s, are out of reach.

**The harness's own traffic is not in the sandbox.** The model requests the coordinator and its roles make are made by the harness process, not by a confined command, and no sandbox covers them. The sandbox governs target-controlled code, which is what the skill's bar is about.

### 2. An empty environment from an explicit allowlist, with scratch-local `HOME`, temporary directories and caches

**Not enforced by the sandbox, and the harness does not empty the environment.** Each command starts from the harness's own environment, scrubbed of credential-shaped names, credential-shaped values, ambient `DSH_*` values and a denylist of ambient authorities, with the managed `DSH_*` facts rebuilt per call (`scrubbedParentEnv` in `@deepseek-ai/dsh-subprocess`, `@deepseek-ai/dsh-shell-env`). `PATH`, `HOME`, locale and proxy variables survive, on purpose, so ordinary tools run. Three consequences matter to an audit:

- `HOME` is the person's home, not the scratch. Reads are open across the host, so target-controlled code can read the person's dotfiles, `~/.ssh`, `~/.config` and the rest of the tree.
- The only protected directory is the Delorun home, `~/.delorun`, which confined commands cannot read or write except its readable entries `runtimes`, `skills` and `dsh-runtimes` (read and execute only). The file tools refuse it too. That is real protection, but it is narrower than the skill's "never expose the host home directory".
- Under the bubblewrap runner every command gets a private `/tmp` that is discarded when the command ends, so a temporary directory has to be a directory the role creates under its own scratch. The harness tells the model this in its prompt context.

**The control is met by the audit's own command form.** The role prompts tell a role to launch target-controlled processes as `env -i` with an explicit, short allowlist — `PATH`, `HOME` and `TMPDIR` pointing into the role's scratch, plus any named safe value the build needs — and to record those variable names with the check. Inside `bash -c`, `env -i` discards everything the harness handed the shell, so the target process sees exactly the allowlist the skill asks for. `run-metadata.json` records the environment form each recorded check used.

**What remains uncovered.** The host home stays readable to target code, and no setting hides it. A target that reads `HOME` before the role replaces it sees the person's home, so a check that depends on hiding host files is `needs_validation` with that exact reason.

### 3. A read-only target and toolchain

**Met.** The sandbox mode is resolved per call, and the role's session cwd is its scratch directory, so under `workspace-write` the only writable roots are that directory and the private temporary directory. The bubblewrap runner binds a read-only host root, so the target source, the toolchain, the coordinator's run files and the rest of the machine are read-only to the role, while reads stay open everywhere. That is the skill's arrangement: reading the target is the audit's work, and writing to it is a denial.

Enforcement is reported per call as `full` or `partial` rather than promised. Two partial cases are current: the Windows ACL runner (hard links alias one file across paths, and reads stay unconfined) and older Landlock ABIs. On those, the write boundary holds but is weaker than the bubblewrap profile; a run records which runner and which enforcement it got.

The toolchain is read-only for the same reason, and nothing is fetched: under `off` there is no network for a build to install from, so the skill's "use only tools and dependencies already available locally" is a fact of the environment rather than an instruction a role could break.

### 4. Writes only inside the role's `scratch/`

**Met, with one part owned by the coordinator.** The policy's workspace root is the role's cwd, and the same policy fences the role's `write`, `edit` and `bash` calls, so a role that writes to the target source, another role's scratch, or a shared run file is refused by the sandbox and reads the denial marker. The shared files sit outside every role's cwd, so the coordinator's exclusive ownership is a boundary the platform enforces, not a convention.

Two limits belong in the record. Under Landlock and Seatbelt the writable temporary directory is the host's `/tmp`, so "only scratch" is exactly true on bubblewrap and "scratch plus the host's temporary directory" elsewhere. And promotion of a role's files into `artifacts/` is coordinator-side code: the harness gives the model path-based filesystem tools and no descriptor-relative API, so the skill's eleven-step promotion procedure — a retained scratch descriptor, a no-follow walk from it, a single-link regular file, per-file and cumulative byte limits — is implemented by the coordinator's promotion helper, which records any check it cannot make on the record that depends on it. This adapter does not claim the harness supplies those checks; it claims the coordinator owns them.

### 5. Explicit CPU, memory, process, file-size, disk and wall-clock limits

**The weakest control, and the one most often overstated.** The harness applies three bounds and no more:

- **Wall clock per call.** A foreground command has a deadline: 120 seconds by default, and a per-call override capped at 600 seconds (`timeoutMs` and `maxTimeoutMs` in `@deepseek-ai/dsh-bash-local`). A command that outlives its deadline is kept running as a background job rather than killed (`promoteOnTimeout`), and a background job has no deadline at all. So the deadline bounds the wait for a result, not the life of the process. A role bounds its own run with `timeout <seconds> ...` and records the number with the check.
- **Captured output.** 64 kB per stream in memory, spilling to a file capped at 64 MiB per stream. That bounds what the model reads, not what the command writes.
- **Process teardown.** The harness kills the command's process group on timeout, cancellation or session end. It does not cap how many processes the group may have.

There is no `rlimit`, no cgroup and no setting for memory, CPU time, process count, file size or disk use in the sandbox provider. A runaway build can take the host's CPU and memory and fill the role's scratch directory; only the host's own state stops it. The plugin records the practical bound each check ran under, and a check that needs a bound the harness cannot apply is `needs_validation` with the missing bound named — never reported as having run under limits.

## Harness capabilities an audit leans on

These are not part of the skill's bar, and they change what a run can safely do. Each is a stock setting, recorded in `run-metadata.json` rather than rebuilt.

- **The protected home.** Confined commands cannot read or write `~/.delorun` except its readable entries; the file tools refuse it as well. So the harness's own consent stores, secrets and plugin copies are out of reach of the audited code, and remain so for `inputs` beyond the workspace.
- **Denied sockets.** The provider binds `/dev/null` over each denied socket path at each wrap. The default set shadows the system D-Bus, `tailscaled` and `snapd`; `delorun start` adds the running profile's channel sockets. Docker's control socket is denied only where the deployment names it.
- **A private `/tmp` under `workspace-write`.** Files written to `/tmp` are gone when the command ends, which catches a build that expects a temporary directory to persist across calls.
- **Abstract Unix sockets.** No runner can deny a connect to one, because the address lives in memory; with `off` the network namespace removes them instead. This is one more reason the audit needs `off` rather than `open` with the abstract-socket risk accepted.
- **Alias coverage.** On btrfs, bcachefs and overlayfs, another mount of the Delorun home or of a denied socket may go unfound, and `aliasCoverage()` reports `unknown` rather than claiming the rule holds. An audit that depends on the home being hidden records which answer it got.

## What the 2026-11-12 vendoring got wrong

The earlier vendoring, recovered from the V5 skill, is byte-identical to upstream except in two ways this one corrects, and it made one claim this one replaces.

- It dropped `WEB-PROTOCOL-AND-AUTH.md`. This directory keeps all 20 files; [NOTICE.md](NOTICE.md) names the omission so it is not repeated.
- It stored upstream's `SKILL.md` as `references/SKILL-original.md` and served a shortened adapter as the skill's entry point. This directory keeps `SKILL.md` under its own name and file structure, so the roles read the skill's own text. This adapter is a separate document, and nothing in the skill depends on it.
- It stated that "this harness confines file writes only. It does not provide network isolation, an isolated loopback namespace, an empty allowlisted environment, per-agent writable scratch roots, or CPU, memory, process, file-size, disk and wall-clock limits", and concluded that the skill's sandbox requirement was not met at all, so target code must never run. That was true of the harness it was written against and is not true of this one. Network isolation and an isolated loopback namespace exist when the workspace's network is `off`; a read-only target and per-role writable scratch roots exist through the per-call policy and the role's cwd; an empty allowlisted environment exists in the audit's command form but not in the sandbox; and the resource limits are still mostly absent. The table above carries the corrected position, and the run still records every check as `needs_validation` wherever its control is missing.

## What a run may therefore claim

On Linux with the bubblewrap runner and the audit workspace's network set to `off`, an audit executes target code under a read-only target, an isolated loopback network, scratch-only writes and a per-call wall-clock deadline, with the environment emptied by the command form and the resource limits recorded as the weakest part. Elsewhere it is source-only. Either way the report states which of the five controls held, and every check whose control did not hold is `needs_validation` with its exact blocker.

For Delorun's own release candidates the run happens inside Delorun's sandbox, and a control the sandbox provides is exactly the kind of claim the audit is there to test. A finding that the run cannot verify from inside — for instance that the network namespace really refuses a connection, or that the home really is hidden — is `needs_validation` with an out-of-band check, never a confirmed record. The report says so in its own words rather than implying the run proved its own substrate.
