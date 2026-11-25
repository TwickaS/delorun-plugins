import { readFileSync } from 'node:fs'
import { defineConfig, type UserConfig } from 'tsdown'

/** This package's manifest: its name is the id the studio page loads lib/client.js under. */
const manifest = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as {
  readonly name: string
  readonly dsh: { readonly client: { readonly external?: readonly string[] } }
}

/**
 * The modules the studio page provides to every plugin, and the ones dsh.client.external requests. lib/client.js
 * requires them from the page, so it shares React, Cordis and the slot registry with the page; it carries a copy of
 * every other import.
 */
const PAGE_MODULES = new Set([
  'react',
  'react/jsx-runtime',
  'react-dom',
  'react-dom/client',
  '@deepseek-ai/cordis',
  'zod',
  '@tanstack/react-virtual',
  '@deepseek-ai/dsh-client-store',
  '@deepseek-ai/dsh-client-ui-slots',
  '@deepseek-ai/dsh-client-ui-primitives',
  '@deepseek-ai/dsh-client-ui-dockkit',
  ...manifest.dsh.client.external ?? [],
])

/**
 * Whether the page answers an import.
 * @param id - the import.
 * @returns true for a module the page provides.
 */
const fromPage = (id: string): boolean => PAGE_MODULES.has(id)

// lib/index.js, the module a profile row loads; the studio serves lib/client.js only while that row is loaded.
const host: UserConfig = {
  entry: { index: 'src/index.ts' },
  outDir: 'lib',
  format: 'esm',
  platform: 'node',
  target: 'es2024',
  fixedExtension: false,
  dts: false,
  clean: false,
}

// lib/client.js, the studio half: one script that passes a factory to window.__ModuleLoader__.load. The page calls the
// factory with its own require, which answers PAGE_MODULES, and reads the plugin from the module.exports it returns.
// Limits: no CSS or asset imports, and dynamic import() is inlined rather than split into files.
const client: UserConfig = {
  entry: { client: 'src/client/index.tsx' },
  outDir: 'lib',
  format: 'cjs',
  platform: 'browser',
  target: 'es2022',
  dts: false,
  clean: false,
  deps: { neverBundle: fromPage, alwaysBundle: id => !fromPage(id) },
  define: { 'process.env.NODE_ENV': JSON.stringify('production') },
  plugins: [{
    name: 'page-modules-only',
    resolveId(source: string) {
      if (source.startsWith('@deepseek-ai/') && !fromPage(source)) {
        throw new Error(`${source} is not a module the studio page provides: a copy in lib/client.js would not share the page's state. Import its types with "import type", reach its features through the services on ctx, or request it under dsh.client.external when the page provides it.`)
      }
      return null
    },
  }],
  outputOptions: {
    entryFileNames: 'client.js',
    inlineDynamicImports: true,
    banner: `window.__ModuleLoader__.load({ id: ${JSON.stringify(manifest.name)}, factory: (require) => {`,
    intro: 'var module = { exports: {} }; var exports = module.exports;',
    footer: 'return module.exports; } });',
  },
}

export default defineConfig([host, client])
