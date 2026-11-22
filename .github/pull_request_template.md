<!-- Fill this in in plain English. One pull request lists one plugin, adds one version, or makes one change. -->

## What this changes

<!-- For a listing: the plugin's package name, its repository and the exact version. For a new version: the plugin and the version added. For anything else: what changes and why. -->

## Checks

<!-- How you checked it. For a listing, say that `node scripts/validate-entries.mjs` passes. The maintainers run the bench card, the package scan and the agent review. -->

- <!-- Check item. -->

## Checklist

- [ ] Each commit carries a `Signed-off-by` line from `git commit -s`. A pseudonym is accepted.
- [ ] For a listing or a new version: the entry names an exact version with its `sha512-` integrity string, and I left out `addedBy` and the badges.
- [ ] For a listing or a new version: I declared any behaviour a user would want to know about (files, network, credentials, shell), and explained it.
- [ ] The plugin declares `engines.delorun` if it targets Delorun, and the entry copies the ranges.

## AI usage

- **Model and tool:** <!-- e.g. Claude Sonnet 5.5 in Claude Code, or "none". -->
- **What the agent did:** <!-- One or two lines. -->
- **What a person decided or checked:** <!-- One or two lines. -->

The person who opens the pull request is responsible for it, whether or not an AI agent wrote it. A pull request written with an agent gets the same checks and review as any other.
