/**
 * Security audit's host half. The audit tools that write the run files and spawn the roles live here; the tools lane
 * replaces this placeholder with them.
 */

/** The plugin's name. */
export const name = '@delorun/plugin-security-audit'

/** The services DSH provides before `apply` runs. */
export const inject = ['tools']

/** Load the plugin. */
export function apply(): void {}
