# Provenance and licence

This directory vendors the `security-audit` skill from Cloudflare's repository, complete.

- **Source:** <https://github.com/cloudflare/security-audit-skill>
- **Path in that repository:** `skills/security-audit/`
- **Commit:** `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`
- **Commit date:** 2026-09-14
- **Commit subject:** "Clarify guidance and full audit modes"
- **Vendored:** 2026-11-24, from a fresh clone of that commit. The clone's `git log` shows this commit as the repository's newest, out of fourteen commits in total.

## What is byte-identical

Every file in this table is byte-identical to the file of the same name in `skills/security-audit/` at that commit: no renaming, no reflowing, no edited line, and one trailing newline like upstream's. The digest is the SHA-256 of both copies.

| File | SHA-256 |
|---|---|
| `AI-AND-LLM.md` | `7335a95c43554eadefcf03ece639291bb0e038c398a179299e3887ffe06bd2ef` |
| `ATTACK-CLASSES.md` | `3ee4f00c6e8c9dcf6dd02dd5ac2a4ceb322e2085f3e9fbe79cf0c6330bc7ef83` |
| `CLIENT-SIDE.md` | `613f6b98f86083e045525c5b60154ffdab122bac35f1e05eb17488e6e453370c` |
| `CLOUD-AND-DEPLOYMENT.md` | `3c80f3088be22345e07b057c056d6ed99fe2b0304f794398964f7ccd5a496ca3` |
| `DATA-ISOLATION-AND-LIFECYCLE.md` | `307dcb3e24d292715c4a041190e7bb135646a37eb6187619ae01d000a634a4ad` |
| `DESKTOP-MOBILE-AND-LOCAL-IPC.md` | `58eae8ee0ca6a46611c501ec5a3ab47fdff88dd7db0d8d74789bbf8bb19d8cb2` |
| `HUNTING.md` | `71c121decea1322c47c718f6e110f1a892980bb4266bd7ac55ef043a213ade09` |
| `MEMORY-SAFETY-AND-BINARY.md` | `7c8b0dccfb35315cca2455509674d49632b2fe37e1f3aac16c1a496a7e9924a7` |
| `PROTOCOLS-RPC-AND-MESSAGING.md` | `8b73816fa5b3697c9c40977f0c836b40f01d6e81929ff2720fe83ce089e9a619` |
| `RECONNAISSANCE.md` | `02ca887aca84de8ae137f1891bd2f0a54f28d3fa6da92a27f54734382b3381a2` |
| `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md` | `4326fab5c92a0b4c420a70196254040105cd794026562130b59bf1a6db3e4baa` |
| `SKILL.md` | `5e3e96a1e438d8f35fef0a1e38f02d4f00e2bdf910401b7dfe00e6779c6dac85` |
| `SUPPLY-CHAIN-AND-RELEASE.md` | `f372e919940e335468ba1ae09f99026c3986a345f7fe26f8068f132e199f52a5` |
| `VALIDATION-AND-REPORTING.md` | `b892470cb89bb31f33403e050d4bdfbe2cdaef940ade1496fa65e32b2e129449` |
| `WEB-PROTOCOL-AND-AUTH.md` | `4f3066dffa23c5635859187be9b96c32f2aff29a688186b91ff0c63e47d62b5c` |
| `report-schema.json` | `6575c9de4a62255699ea052ebf9a49ebfb373a32891bcd89af6f55cc84b35519` |
| `validate-coverage-ledger.cjs` | `2eb280bd2e33c002916f86db9b29f9edfedb6454e5db973c766290465b868ac8` |
| `validate-coverage-ledger.test.cjs` | `cfb9df26b03469a4279a70e7664a2a5434dd6f8c2c204e91f9b0aeb9dd71e648` |
| `validate-findings.cjs` | `e85f232e36bfac0f866f244da50376692d6b45c690beadcb00608b0e6c8b5283` |
| `validate-findings.test.cjs` | `b92001117a92c4161d43777a0ba2fa182a8a4d97f2304cc8c0cee5331497b73b` |

## Files that are not upstream

Three files in this directory do not come from `skills/security-audit/`, and none of the 20 files above depends on them:

- `LICENSE` holds Cloudflare's repository-root `LICENSE`, copied unchanged. The skill directory upstream carries no licence file of its own; the repository root states the MIT licence for everything in it.
- `NOTICE.md` is this file.
- `ADAPTER.md` is Delorun's account of how its harness fills the skill's platform-neutral terms, and of what the harness really enforces. It is documentation, not part of the skill's instructions.

## The file an earlier vendoring dropped

The vendoring of 2026-11-12 kept 19 of these files and dropped `WEB-PROTOCOL-AND-AUTH.md`, which carries the attack classes for HTTP framing and caching, browser sessions, federated identity, multi-factor authentication, passkeys and account transition, and API keys and mutual TLS. This vendoring keeps it under its upstream name, along with the 19 others, because the skill's own phase documents load companion classes from the whole set.

Anyone repeating this vendoring takes all 20 files and compares digests. A directory of 19 files, or one holding `SKILL-original.md` instead of `SKILL.md`, is the earlier mistake rather than a deliberate change.

## How to check it

```sh
git clone https://github.com/cloudflare/security-audit-skill /tmp/cloudflare-security-audit
git -C /tmp/cloudflare-security-audit rev-parse HEAD
cd plugins/security-audit/skill
diff -r /tmp/cloudflare-security-audit/skills/security-audit . \
  --exclude=LICENSE --exclude=NOTICE.md --exclude=ADAPTER.md
sha256sum *
```

The `diff -r` prints nothing and exits 0 when every upstream file is present and unchanged, and `sha256sum` then compares with the table above: identical digests, and `git rev-parse` printing the commit named at the top.

## Licence

Upstream's text, unchanged:

```text
MIT License

Copyright (c) 2025-2026 Cloudflare, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
