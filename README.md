# Awesome Delorun

Plugins and the plugin catalogue for [Delorun](https://github.com/TwickaS/delorun).

Delorun is an independent, community-driven continuation of DeepSeek Harness: built on DSH 0.2.2, developed as a product, and invested in the DSH plugin community. Delorun is not a DeepSeek product, and DeepSeek does not endorse it.

This repository holds Delorun's own optional plugins, one catalogue file for each listed plugin, and the list below. A plugin appears in the list when it has passed Delorun's checks. [CONTRIBUTING.md](CONTRIBUTING.md) says how to list one.

## Official plugins

Plugins that Delorun's maintainers build and keep in this repository, in `plugins/`. Official plugins are named `@delorun/plugin-<name>`.

- **Cost meter**: moving here from Delorun's core.
- **Thinking RSVP**: moving here from Delorun's core.

## Community plugins

Plugins that their authors keep in their own repositories. A community plugin appears here once it passes Delorun's checks: a passing test-bench card, an automatic scan of the exact package, an agent review on the pull request, and an exact version with its integrity hash. To list yours, read [CONTRIBUTING.md](CONTRIBUTING.md).

No community plugins are listed yet.

## Compatible DeepSeek Harness plugins

Plugins written for stock DeepSeek Harness that also run on Delorun. One appears here once it passes Delorun's checks on the version listed, shown by a passing test-bench card. Anyone can propose one by following [CONTRIBUTING.md](CONTRIBUTING.md).

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
| `catalogue/revocations.yml` | Plugin versions that Delorun disables. |
| `catalogue/entry.schema.json` | The schema an entry must match. |
| `corpus/` | Exercises that a listed plugin runs for "Tested with Delorun". |
| `scripts/` | The entry validator and its tests. |

## Licence

[MIT](LICENSE).
