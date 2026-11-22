# Awesome Delorun

Plugins and the plugin catalogue for [Delorun](https://github.com/TwickaS/delorun).

Delorun is an independent, community-driven continuation of DeepSeek Harness: built on DSH 0.2.2, developed as a product, and invested in the DSH plugin community. Delorun is not a DeepSeek product, and DeepSeek does not endorse it.

This repository holds Delorun's own optional plugins, one catalogue file for each listed plugin, and the list below. A plugin appears in the list once the maintainers have checked that it meets the listing requirements in [CONTRIBUTING.md](CONTRIBUTING.md), which also says how to list one.

## Official plugins

Plugins that Delorun's maintainers build and keep in this repository, in `plugins/`. Official plugins are named `@delorun/plugin-<name>`.

- **Cost meter**: moving here from Delorun's core.
- **Thinking RSVP**: moving here from Delorun's core.

## Community plugins

Plugins that their authors keep in their own repositories. A community plugin appears here once the maintainers have checked that its listing pull request meets the listing requirements: a passing test-bench card, an automatic scan of the exact package, an agent review on the pull request, and an exact version with its integrity hash. To list yours, read [CONTRIBUTING.md](CONTRIBUTING.md).

No community plugins are listed yet.

## Compatible DeepSeek Harness plugins

Plugins written for stock DeepSeek Harness that also run on Delorun. One appears here once the maintainers have checked the version listed against the same listing requirements. Anyone can propose one by following [CONTRIBUTING.md](CONTRIBUTING.md).

No compatible plugins are listed yet.

## Resources

- [Delorun documentation](https://docs.delorun.com)
- [Write a plugin for Delorun](https://docs.delorun.com/guide/plugins)
- [Your first plugin](https://docs.delorun.com/guide/first-plugin)
- [Delorun on GitHub](https://github.com/TwickaS/delorun)
- [CONTRIBUTING.md](CONTRIBUTING.md): how to list a plugin here

## Layout

| Path | What it holds |
| --- | --- |
| `plugins/` | Delorun's own optional plugins. |
| `catalogue/entries/<name>.yml` | One file for each listed plugin. |
| `catalogue/revocations.yml` | Plugin versions to be revoked. Delorun does not read this file yet ([contract C13](https://github.com/TwickaS/delorun/blob/main/delorun/docs/contracts/c13-catalogue-revocation.md)). |
| `catalogue/entry.schema.json` | The schema an entry must match. |
| `corpus/` | Exercises that a listed plugin runs for "Tested with Delorun". |
| `scripts/` | The entry validator and its tests. |

## Licence

[MIT](LICENSE).
