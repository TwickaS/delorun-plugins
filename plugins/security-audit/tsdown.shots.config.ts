import { defineConfig } from 'tsdown'

/**
 * The screenshot harness: one self-contained browser bundle plus its stylesheet,
 * so a plain page can render the pane over fixture data.
 */
export default defineConfig({
  entry: { harness: 'scripts/shots/pane-harness.tsx' },
  outDir: 'scripts/shots/out',
  format: 'esm',
  platform: 'browser',
  target: 'es2022',
  dts: false,
  clean: true,
  define: { 'process.env.NODE_ENV': JSON.stringify('production') },
  alias: {
    '@deepseek-ai/dsh-client-ui-primitives': new URL('./scripts/shots/primitives-stub.tsx', import.meta.url).pathname,
  },
})
