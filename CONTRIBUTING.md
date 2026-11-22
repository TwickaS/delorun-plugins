# Contributing

This page says how to list a plugin in the catalogue, what a listing needs, and how to report a security problem. Delorun is an independent, community-driven continuation of DeepSeek Harness: built on DSH 0.2.2, developed as a product, and invested in the DSH plugin community. Delorun is not a DeepSeek product, and DeepSeek does not endorse it.

## List a plugin

Your plugin stays in your own repository and package. Listing it means opening a pull request here that adds one file, `catalogue/entries/<name>.yml`.

1. Publish an exact version of your plugin to npm, with a licence and a README.
2. Copy `scripts/fixtures/delorun-plugin-example.yml` to `catalogue/entries/<name>.yml` and fill it in. `<name>` is the package name; a scoped name `@scope/name` is written `@scope__name.yml`.
3. Run `npm install` and `node scripts/validate-entries.mjs`. It checks every entry against `catalogue/entry.schema.json` and checks that the file name matches the package name.
4. Open the pull request. Sign off each commit with `git commit -s`; a pseudonym is accepted.

An entry holds the package name, a title (at most 80 characters) and a description (at most 300), the source repository, the licence, the author's name and GitHub login, and a list of versions. Each version has its exact version number, the npm tarball's `sha512-` integrity string, and the `engines` ranges the package declares. A listing pins exact versions, never ranges. The maintainers fill in who added the entry and the "Tested with Delorun" badges; leave both out.

To list a new version of a plugin that is already listed, open a pull request that adds the version to its entry. Each new version must meet every listing requirement again.

## What a listing needs

These are the listing requirements. The maintainers check all four on every listing pull request, and on every new version of a listed plugin, before it is merged:

- **A passing bench card.** The maintainers run the plugin on the test bench, which installs the plugin in a throwaway Delorun, starts it, draws its screens, uses its main feature once, restarts, updates and removes it, and records what it saw. The card must pass.
- **An automatic scan of the exact package.** The maintainers scan the published package for install scripts, credentials read together with network use, and code fetched at run time.
- **An agent review on the pull request.** The maintainers have an agent read the plugin and post its review there.
- **An exact version with its integrity hash.** The entry names the version and its `integrity` string, and the maintainers check that the string matches the published package.

A plugin that does something risky is listed only if it declares the behaviour and explains it. The finding then appears in plain words on its bench card. Hidden or undeclared behaviour is refused.

A listing means the plugin was checked and tested at that version. It does not mean the plugin is safe, audited or endorsed, and Delorun does not run a plugin audit.

## The privacy markers

Each plugin's bench card shows eight privacy markers:

- Your code
- Your chats
- Model keys
- Other secrets
- Sends out (where it sends, and whether chats, code or keys were in it)
- Acts for you
- Opens a door
- Leaves behind

Each marker reads "not seen", "seen in test" or "declared by author". "Seen in test" means the bench saw it happen in one short run of that exact version. "Declared by author" means you said so in your declaration. The card carries this line: "Plugins run with Delorun's full access. Markers show what it did, not what it could." A marker is a record of what was seen or declared; it does not limit what the plugin does.

## Declare what your plugin reaches (optional)

A plugin may declare what it reaches in an optional `access` block under `dsh` in its `package.json`, explaining each item in a sentence. A declared and explained item is listed as "declared by the author". Behaviour the bench sees that you did not declare is shown as a finding. A plugin without the block can still be listed.

The shape of the block is being finalised.

```jsonc
// package.json: placeholder, the shape is being finalised
{
  "dsh": {
    "access": {}
  }
}
```

## Target Delorun with `engines.delorun`

Declare `engines.delorun` to target Delorun. On Delorun, a plugin that declares `engines.delorun` is checked on that range alone: its `engines.dsh` and `@deepseek-ai/dsh*` peer ranges are not checked. Stock DeepSeek Harness checks `engines.dsh` and ignores `engines.delorun`, so one package can declare both and work on both. A plugin without `engines.delorun` is checked on its `engines.dsh` range against the DSH version Delorun reports.

Copy both ranges into the `engines` field of each version in your entry.

## Report a security problem

Tell the maintainers privately through this repository's private vulnerability reporting: open the Security tab and choose "Report a vulnerability". Do not open a public issue or pull request about it. Maintainers do not publish a weakness in someone else's plugin until its author has been told and 30 days have passed.

## Style

Write British English in plain words and the present tense. Keep a pull request to one plugin.

## Licence

By contributing you agree that your contribution to this repository is licensed under the [MIT licence](LICENSE).
