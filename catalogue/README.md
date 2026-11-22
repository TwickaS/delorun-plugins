# Catalogue

- `entries/<name>.yml`: one file for each listed plugin. The file name is the package name; a scoped name `@scope/name` is written `@scope__name.yml`.
- `revocations.yml`: the plugin versions to be revoked. Delorun does not read this file yet ([contract C13](https://github.com/TwickaS/delorun/blob/main/delorun/docs/contracts/c13-catalogue-revocation.md)).
- `entry.schema.json` and `revocations.schema.json`: the schemas that `node scripts/validate-entries.mjs` checks both against.
