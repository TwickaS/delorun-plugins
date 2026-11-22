# Catalogue

- `entries/<name>.yml`: one file for each listed plugin. The file name is the package name; a scoped name `@scope/name` is written `@scope__name.yml`.
- `revocations.yml`: the plugin versions that Delorun disables.
- `entry.schema.json` and `revocations.schema.json`: the schemas that `node scripts/validate-entries.mjs` checks both against.
