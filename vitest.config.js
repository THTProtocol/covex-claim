import { defineConfig } from 'vitest/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// The byte-parity tests import only the pure core of src/covenantRedeemer.js. That file
// also has a DYNAMIC import('@onekeyfe/kaspa-wasm') inside its wasm-backed wrappers, which
// the tests never execute. The published kaspa-wasm package has no resolvable entry point
// (it is a wasm-bindgen --target web build), so we alias it to a no-op stub here just to
// satisfy vite's resolver. The real wasm is inlined into the built tool, not loaded here.
export default defineConfig({
  resolve: {
    alias: {
      '@onekeyfe/kaspa-wasm': path.resolve(__dirname, 'src/__kaspa_wasm_stub.js'),
    },
  },
  test: {
    include: ['src/**/*.test.js'],
    environment: 'node',
  },
});
