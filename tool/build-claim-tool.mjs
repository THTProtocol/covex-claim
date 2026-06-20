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

  const glueSrc = readFileSync(gluePath, 'utf8');
  const wasmBin = readFileSync(wasmPath);

  // (1) base64 of the wasm bytes (parked verbatim in a text/plain script tag).
  const wasmB64 = wasmBin.toString('base64');

  // (2) base64 of the glue ESM, imported from a blob: module URL, namespace -> window.
  // We keep the glue UNCHANGED and load it as a module so its exports and import.meta.url
  // behave exactly as published. The blob URL is same-page (file:// safe). We never call
  // the glue's default network init; the page calls K.initSync(compiledModule).
  const glueB64 = Buffer.from(glueSrc, 'utf8').toString('base64');
  const glueModule = [
    '// Inlined @onekeyfe/kaspa-wasm ESM glue, imported from a blob: module URL so it runs',
    '// unmodified under file:// without any network/module fetch. We expose its namespace',
    '// on window.__KASPA_WASM__; the page initializes it with the inlined wasm bytes via',
    '// initSync(compiledModule) and never triggers the glue\'s default network init.',
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
