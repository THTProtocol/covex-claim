#!/usr/bin/env node
// build-claim-tool.mjs
//
// Inlines @onekeyfe/kaspa-wasm's wasm binary + ESM JS glue into the claim-tool
// template, producing a SINGLE self-contained covex-claim.html that runs from
// file:// with no network dependency. Prints the artifact's SHA-256 so it can be pinned
// in README.md and verified by anyone before they trust the tool.
//
// Run from a checkout that HAS node_modules:
//   npm install            # if needed
//   node tool/build-claim-tool.mjs
//
// HOW THE WASM GETS INLINED (the important part)
// ----------------------------------------------
// kaspa-wasm is wasm-bindgen "--target web" output. Two files matter:
//   - kaspa.js          the ESM glue: `export class PrivateKey ...`, `export function
//                       createInputSignature ...`, and an init footer exporting
//                       `initSync` + a default `__wbg_init`. The default init resolves
//                       the wasm via `new URL('kaspa_bg.wasm', import.meta.url)` (a
//                       NETWORK / module fetch) - which file:// cannot do. We never call
//                       the default with no args; instead the page calls
//                       initSync(compiledModule) with bytes WE inline, exactly as the
//                       app's WalletContext does today.
//   - kaspa_bg.wasm.bin the actual WebAssembly module bytes.
//
// We do TWO substitutions in the template:
//   1. __KASPA_WASM_B64__       -> base64(kaspa_bg.wasm.bin), parked in a
//                                  <script type="text/plain"> so the page can decode it
//                                  to bytes and WebAssembly.compile() it locally.
//   2. __KASPA_WASM_GLUE_MODULE__ -> the body of an inline <script type="module"> that:
//        (a) embeds kaspa.js as a base64 ESM and imports it from a BLOB url. A blob: ESM
//            import works under file:// (it is same-page, not a network fetch), and it
//            keeps `import.meta.url` valid inside the glue. We import the NAMESPACE
//            (`import * as K`), so we get every named export (PrivateKey, Transaction,
//            initSync, createInputSignature, payToScriptHash*, RpcClient, Resolver, ...).
//        (b) assigns that namespace to window.__KASPA_WASM__. The page's initWasm() then
//            calls K.initSync(compiledModule) - so the glue's own network-fetching
//            default init is NEVER invoked. No .wasm sibling fetch, no Covex, no network.
//
// Why a blob ESM import and not just pasting the glue inline: kaspa.js is a real ES
// module (top-level export/import statements) and uses import.meta.url; pasting it raw
// into a classic or even module script and trying to scrape its exports is brittle across
// wasm-bindgen versions. A blob: module URL runs the glue UNMODIFIED as a module and
// gives us its exact export namespace. This is the most version-robust option.

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { createRequire } from 'node:module';

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

const TEMPLATE = join(__dirname, 'covex-claim.template.html');
// Emit the built artifact at the repo root (one level up from tool/) so GitHub Pages
// can serve it directly and a user lands on the working tool.
const OUT = join(__dirname, '..', 'covex-claim.html');

// Resolve the kaspa-wasm package dir. Prefer node's resolver (handles workspaces /
// hoisted node_modules); fall back to a couple of known relative locations.
function resolveKaspaDir() {
  const candidates = [];
  try {
    // package.json may not be in "exports"; resolve a file we KNOW is published.
    const p = require.resolve('@onekeyfe/kaspa-wasm/kaspa.js');
    candidates.push(dirname(p));
  } catch (_) { /* fall through */ }
  // node_modules lives at the repo root (one level up from tool/).
  candidates.push(resolve(__dirname, '..', 'node_modules', '@onekeyfe', 'kaspa-wasm'));
  candidates.push(resolve(__dirname, '..', '..', 'node_modules', '@onekeyfe', 'kaspa-wasm'));
  for (const c of candidates) {
    if (existsSync(join(c, 'kaspa.js'))) return c;
  }
  throw new Error(
    'Could not find @onekeyfe/kaspa-wasm in node_modules. Run `npm install` in this repo ' +
    'first, then re-run the build.',
  );
}

function pickWasmBin(dir) {
  // The published binary is kaspa_bg.wasm.bin; some toolchains emit kaspa_bg.wasm.
  for (const name of ['kaspa_bg.wasm.bin', 'kaspa_bg.wasm']) {
    const p = join(dir, name);
    if (existsSync(p)) return p;
  }
  throw new Error(`No kaspa_bg.wasm(.bin) found in ${dir}`);
}

function main() {
  if (!existsSync(TEMPLATE)) throw new Error(`template missing: ${TEMPLATE}`);
  const kaspaDir = resolveKaspaDir();
  const gluePath = join(kaspaDir, 'kaspa.js');
  const wasmPath = pickWasmBin(kaspaDir);

  const glueSrcRaw = readFileSync(gluePath, 'utf8');
  const wasmBin = readFileSync(wasmPath);

  // (1) base64 of the wasm bytes (parked verbatim in a text/plain script tag).
  const wasmB64 = wasmBin.toString('base64');

  // (1b) PATCH the glue's __wbg_load for the browser single-file context.
  //
  // @onekeyfe/kaspa-wasm ships a glue whose __wbg_load was rewritten for a NODE bundler:
  // it `require("./kaspa_bg.wasm.js")` and the browser instantiate paths are commented
  // out. In a browser that `require` throws "require is not defined", so the default
  // __wbg_init() path is dead here. The named initSync() path is ALSO unusable for this
  // package: it calls `new WebAssembly.Instance(module)` synchronously, which Chrome
  // disallows on the main thread for buffers larger than 8MB (this wasm is ~11MB).
  //
  // The only main-thread-safe instantiation for an 11MB module is ASYNC
  // WebAssembly.instantiate(module, imports). So we replace __wbg_load's body to await
  // exactly that on the WebAssembly.Module the page passes to the default __wbg_init().
  // The page then calls `await K.default(compiledModule)` (async) instead of initSync.
  // Everything else in the glue is untouched; the patch is a single function body.
  const LOAD_NEEDLE =
    'async function __wbg_load(module, imports) {\n' +
    '  const loadWebAssembly = require("./kaspa_bg.wasm.js");\n' +
    '  const bytes = loadWebAssembly();\n' +
    '  return await WebAssembly.instantiate(bytes.buffer, imports);';
  const LOAD_REPLACEMENT =
    'async function __wbg_load(module, imports) {\n' +
    '  // PATCHED by build-claim-tool.mjs for the browser single-file build: instantiate\n' +
    '  // the WebAssembly.Module passed in via async WebAssembly.instantiate (no Node\n' +
    '  // require, no fetch, no >8MB main-thread sync-instance limit).\n' +
    '  if (module instanceof WebAssembly.Module) {\n' +
    '    const instance = await WebAssembly.instantiate(module, imports);\n' +
    '    return { instance, module };\n' +
    '  }\n' +
    '  if (module && typeof module.buffer !== "undefined") {\n' +
    '    return await WebAssembly.instantiate(module.buffer, imports);\n' +
    '  }\n' +
    '  return await WebAssembly.instantiate(module, imports);';
  if (!glueSrcRaw.includes(LOAD_NEEDLE)) {
    throw new Error(
      'glue __wbg_load no longer matches the expected Node-require body; the kaspa-wasm ' +
      'version changed. Re-derive the browser instantiate patch before building.',
    );
  }
  // Also make __wbg_init actually USE the module we pass it (the published body ignores
  // module_or_path and calls __wbg_load(undefined, ...)). Pass it through to __wbg_load.
  const INIT_NEEDLE = 'const { instance, module } = await __wbg_load(undefined, imports);';
  if (!glueSrcRaw.includes(INIT_NEEDLE)) {
    throw new Error(
      'glue __wbg_init no longer matches; the kaspa-wasm version changed. Re-derive the patch.',
    );
  }
  const glueSrc = glueSrcRaw
    .split(LOAD_NEEDLE).join(LOAD_REPLACEMENT)
    .split(INIT_NEEDLE).join('const { instance, module } = await __wbg_load(module_or_path, imports);');

  // (2) base64 of the (patched) glue ESM, imported from a blob: module URL, namespace ->
  // window. We load it as a module so its exports and import.meta.url behave as published
  // (minus the surgical __wbg_load/__wbg_init patch above). The blob URL is same-page
  // (file:// safe). The page initializes it with the inlined wasm bytes via the ASYNC
  // default init, and never triggers any network/module fetch.
  const glueB64 = Buffer.from(glueSrc, 'utf8').toString('base64');
  const glueModule = [
    '// Inlined @onekeyfe/kaspa-wasm ESM glue (with the browser __wbg_load patch), imported',
    '// from a blob: module URL so it runs under file:// without any network/module fetch.',
    '// We expose its namespace on window.__KASPA_WASM__ and resolve window.__KASPA_READY__',
    '// when done; the page awaits that flag (no race) then inits with the inlined wasm bytes',
    '// via the ASYNC default init and never triggers any network fetch.',
    'window.__KASPA_READY__ = new Promise((resolve) => { window.__kaspaResolve__ = resolve; });',
    'const __KASPA_GLUE_SRC__ = atob("' + glueB64 + '");',
    'const __kaspaBlob__ = new Blob([__KASPA_GLUE_SRC__], { type: "text/javascript" });',
    'const __kaspaUrl__ = URL.createObjectURL(__kaspaBlob__);',
    'try {',
    '  const K = await import(__kaspaUrl__);',
    '  window.__KASPA_WASM__ = K;',
    '} catch (e) {',
    '  window.__KASPA_WASM__ = null;',
    '  console.error("kaspa-wasm glue import failed:", e);',
    '} finally {',
    '  URL.revokeObjectURL(__kaspaUrl__);',
    '  if (window.__kaspaResolve__) window.__kaspaResolve__(window.__KASPA_WASM__);',
    '}',
  ].join('\n');

  let html = readFileSync(TEMPLATE, 'utf8');

  // Substitute ONLY the exact injection slots (the script-tag bodies), not the bare
  // placeholder text - the template also mentions the placeholders in a doc comment, and
  // we must not rewrite those (nor any runtime guard). Match the full tag so the swap is
  // unambiguous and idempotent. Use split/join so a literal $ in base64 is never treated
  // as a String.replace replacement pattern.
  const B64_SLOT = '<script id="kaspa-wasm-b64" type="text/plain">__KASPA_WASM_B64__</script>';
  const GLUE_SLOT = '<script type="module">__KASPA_WASM_GLUE_MODULE__</script>';
  if (!html.includes(B64_SLOT)) throw new Error('template lost the wasm-b64 injection slot');
  if (!html.includes(GLUE_SLOT)) throw new Error('template lost the glue-module injection slot');

  html = html.split(B64_SLOT).join(
    '<script id="kaspa-wasm-b64" type="text/plain">' + wasmB64 + '</script>',
  );
  html = html.split(GLUE_SLOT).join(
    '<script type="module">\n' + glueModule + '\n</script>',
  );

  writeFileSync(OUT, html, 'utf8');

  const sha = createHash('sha256').update(readFileSync(OUT)).digest('hex');
  const sizeKb = (Buffer.byteLength(html, 'utf8') / 1024).toFixed(0);

  console.log('Covex claim tool built.');
  console.log('  glue:   ' + gluePath);
  console.log('  wasm:   ' + wasmPath + ' (' + (wasmBin.length / 1024 / 1024).toFixed(2) + ' MB)');
  console.log('  output: ' + OUT + ' (' + sizeKb + ' KB)');
  console.log('  SHA-256: ' + sha);
  console.log('');
  console.log('Pin that SHA-256 in README.md. Verify it before trusting the file:');
  console.log('  sha256sum covex-claim.html   (or: shasum -a 256 / certutil -hashfile / Get-FileHash)');
}

main();
