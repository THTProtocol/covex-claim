# Covex claim (standalone, offline)

Claim or refund your Kaspa covenant funds **directly on Kaspa, with zero Covex
involvement**. This is a single self-contained HTML file. It signs your spend transaction
locally in your own browser and never talks to Covex (hightable.pro) for anything. It
works even if Covex is permanently down.

- Live tool (GitHub Pages): https://thtprotocol.github.io/covex-claim/covex-claim.html
- Built single file in this repo: [`covex-claim.html`](./covex-claim.html)
- The non-custodial claim path is proven on-chain (see [Proof on-chain](#proof-on-chain)).

> Save a copy of `covex-claim.html` now, while you can. It is one file, it runs offline
> from `file://`, and it does not need this website, GitHub, or Covex to function later.

## What this is

When you create a Covex covenant, your funds sit in a pay-to-script-hash (P2SH) address on
Kaspa. The redeem script behind that address defines exactly who can spend the funds and
under what conditions. Releasing the funds means building a spend transaction whose input
satisfies that script, signing it with the right key, and broadcasting it to the network.

This tool does all of that **in your browser**, from a single HTML file:

1. You paste a small "recovery kit" (the public details of your covenant) and your private
   key.
2. The tool assembles the satisfier (the unlocking data the chain checks), signs the
   transaction locally, and shows you the complete signed transaction.
3. You broadcast it, either directly over a public Kaspa node you choose, or by pasting the
   signed transaction into any node or block explorer.

There is no account, no server call to Covex, and no network dependency for the signing
step. The private key is held only in the page, is never transmitted, and is cleared from
the input as soon as it is used.

## Non-custodial security model

- **Your key never leaves the page.** Signing happens entirely in client-side JavaScript +
  WebAssembly inlined into the file. There is no upload, no telemetry, no analytics, and no
  Covex endpoint in the runtime path. You can verify this by reading the file or by running
  it on a machine with networking disabled.
- **No Covex in the loop.** The tool never contacts hightable.pro or any Covex backend.
  The only network step is broadcasting the already-signed, already-public transaction, and
  you pick where: a public Kaspa wRPC node, or any explorer's submit-transaction form.
- **Offline-first.** After you save `covex-claim.html`, you can disconnect from the
  internet, open the file, paste your kit and key, and produce a fully signed transaction.
  Only the final broadcast needs a network, and that can be done from a different, online
  machine using the exported signed-transaction JSON.
- **Self-contained.** The signing library (`@onekeyfe/kaspa-wasm`) and its WebAssembly
  binary are base64-inlined into the one HTML file. There is no sibling `.wasm` fetch, no
  CDN, and no external script.
- **Verifiable.** The single file is content-addressable. Compute its SHA-256 and compare
  it against the published hash (below) before you trust it. If it does not match, do not
  use it; rebuild from source instead.

## Works with Covex fully offline (it talks to a node you pick, never hightable.pro)

The hard requirement this repo exists to satisfy: **claim even if Covex is gone.** That is
why the tool is published here, independently of Covex infrastructure, on GitHub and GitHub
Pages. The runtime contains no reference to hightable.pro or any Covex API. For the one
networked step (broadcast) the tool uses public Kaspa nodes that **you** choose, or you
export the signed bytes and submit them yourself from any node or explorer.

## Byte-parity with the Rust signer (the trust anchor)

The consensus-critical part of any claim tool is the satisfier: the exact bytes pushed to
unlock the script. If those bytes are wrong, the chain rejects the spend (fail-safe), but
if a tool silently produced subtly different bytes you could waste a transaction or, worse,
be tricked. To remove that doubt:

- The pure-core satisfier logic in this tool (`buildSatisfier`, `push65`, `pushData`,
  `parseRedeemPubkeys`, `sigOpCount`) is copied **verbatim** from
  [`src/covenantRedeemer.js`](./src/covenantRedeemer.js).
- That source is CI-gated in the Covex repo to produce bytes **byte-for-byte identical** to
  the Rust `assemble_noncustodial_satisfier` (the same function the Kaspa node already
  validated when these covenants were funded and spent).
- The byte-parity is proven by 23 test vectors covering every kind and branch. The tests
  are included here so you can run them yourself: [`src/covenantRedeemer.test.js`](./src/covenantRedeemer.test.js),
  plus guard and signer tests. See [Run the tests](#run-the-tests).

You can also diff the pure-core block inside `tool/covex-claim.template.html` against
`src/covenantRedeemer.js`; they are the same functions.

## Per-kind self-claimability matrix (honest)

"Offline-claimable" means the Kaspa chain itself (or a revealed public secret plus the
named key's `OpCheckSig`) enforces the spend end to end, so you alone can satisfy it with
no Covex oracle. Where a spend path needs the Covex oracle's signature, it is **not**
offline-claimable here, and the tool says so rather than pretend otherwise.

| kind | offline-claimable? | how |
| --- | --- | --- |
| `singlesig` | yes | named key signs; chain verifies |
| `timelock` | yes | named key signs after `lockTime` (set CLTV) |
| `rcsv` | yes | named key signs after the relative lock (set `sequence`) |
| `hashlock` | yes | reveal preimage + sign |
| `htlc` | yes | claim = receiver sig + preimage; refund = sender sig after `lockTime` |
| `multisig` | yes | gather the required m signatures (set `total` = N) |
| `channel` | yes | cooperative close needs both party sigs; refund = funder sig after `lockTime` |
| `deadman` | yes | owner (IF) any time, or heir (ELSE) after CLTV |
| `binary_oracle_select` | yes | winner reveals the PUBLIC winning preimage + branch-key sig; refund = refund key after lock. The reveal is a hashlock, not an oracle signature. |
| `oracle` | no | win path is a 2-of-2 with the Covex oracle key; needs the oracle half-signature. No chain-enforced refund branch. |
| `oracle_enforced` | no | same as `oracle`: needs the oracle half-signature. No chain-enforced refund branch. |
| `oracle_escrow` | no | payout needs the Covex oracle signature. No chain-enforced refund branch. |
| `oracle_enforced_refundable` | refund branch only | WIN path needs the Covex oracle signature (not offline). REFUND branch (refund key, after `lock_daa`) is offline-claimable. |
| `oracle_escrow_refundable` | refund branch only | WIN path needs the Covex oracle signature (not offline). REFUND branch (refund key, after `lock_daa`) is offline-claimable. |

Plainly: the `oracle_*` win paths depend on Covex oracle **liveness**. If Covex is down,
those winners cannot claim with this tool until the oracle signs, or, for the
`*_refundable` kinds, until the refund timelock elapses and the refund key reclaims the
funds. That is a liveness dependency, not a trustless guarantee, and this tool does not
describe it as trustless. If you need to be able to recover funds unilaterally no matter
what, choose a covenant kind whose row above says "yes".

## What to save as your recovery kit

When a covenant is created and funded, save the JSON "recovery kit" so you can claim later
even if Covex is gone. The Covex app exports the kit in this NESTED, versioned shape (the
covenant fields live under `covenant`, and `redeem_kind` may carry a `:<suffix>` such as
`binary_oracle_select:144` which the tool strips automatically):

```json
{
  "covex_recovery_kit_version": 2,
  "covenant": {
    "network": "mainnet",
    "p2sh_address": "kaspa:....",
    "redeem_kind": "binary_oracle_select:144",
    "redeem_script_hex": "....",
    "lock_daa": null,
    "revealed_secret": null
  }
}
```

Older FLAT kits are still accepted (`{ "kind": "...", "network": "...", "redeem_script_hex":
"...", "p2sh_address": "...", "funding": {...}, "branch": "...", "preimage_hex": "...",
"lock_daa": null }`); a few field aliases are also accepted.

Field by field (under `covenant` for a v2 kit, or top-level for a flat kit):

- `redeem_kind` / `kind` - the covenant kind, with or without a `:<suffix>` (the tool folds
  it to its base kind; see the matrix above).
- `network` - `mainnet`, `testnet-10`, or `testnet-12`. The destination address prefix is
  validated against this.
- `redeem_script_hex` - the full redeem script. This is the source of truth the chain
  enforces; the P2SH address is derived from it.
- `p2sh_address` - the covenant address, for your own cross-check (the tool re-derives the
  P2SH from the redeem script).
- `funding` - OPTIONAL. The v2 kit does not include it. The covenant UTXO you are spending:
  `transactionId`, `index`, and `amount` in sompi. If it is not in the kit, look it up on any
  block explorer for the P2SH address and paste it into the tool as
  `transactionId:index:amount`.
- `branch` - which spend path you intend (see the per-kind notes). You can override it in
  the UI.
- `preimage_hex` - the revealed secret, for `hashlock`, `htlc` claim, and
  `binary_oracle_select` reveal. For `binary_oracle_select` this is the PUBLIC winning
  preimage (it becomes public once the outcome is settled); it is a hashlock secret, not an
  oracle signature.
- `lock_daa` - the lockTime (CLTV) or DAA threshold for timelock and refund branches, if
  the path needs one. Leave null otherwise.
- `total` - the N in an m-of-N `multisig` (or the oracle 2-of-2 total), used to commit the
  correct sig-op count.

You also need, separately and securely, your **private key** for the relevant role (winner
key, branch A/B key, or refund key). Never store the private key in the kit.

## Step-by-step usage

1. Get the tool: either open the live page
   (https://thtprotocol.github.io/covex-claim/covex-claim.html) and save it, or download
   [`covex-claim.html`](./covex-claim.html) from this repo, or build it from source (below).
2. **Verify its SHA-256** against the published hash before trusting it (see
   [Verify before you trust](#verify-before-you-trust)).
3. Move `covex-claim.html` to the machine where you will claim. It can be fully offline for
   the parse and sign steps. Open it in a browser (`file://` works).
4. Wait for the banner to read "Ready and offline."
5. Paste your recovery kit JSON (or Load from file) and click **Parse kit**. The
   Claimability panel tells you whether your kit's path is offline-claimable.
6. Enter the destination address (where the funds go), the fee in sompi, and select the
   branch/outcome if the kit did not specify one.
7. For paths that need extra material, open **Advanced** and fill in: the preimage
   (hashlock / htlc / `binary_oracle_select` reveal), `lockTime`/`sequence` for
   timelock/refund paths, or, only if you legitimately have it, the oracle signature for an
   `oracle_*` win path.
8. Paste your private key and click **Build and sign (local)**. Signing happens entirely in
   the page; the key field is cleared immediately after.
9. Broadcast, either way:
   - **Direct wRPC**: click Broadcast over wRPC. The tool tries public Kaspa nodes and the
     kaspa-wasm public resolver. (A browser opening a WebSocket from a `file://` page can be
     blocked by browser policy; if it fails, use the next option.)
   - **Export signed-tx JSON**: click Export or Copy and submit the JSON from any node CLI
     or a block explorer's submit-transaction endpoint. This always works, because the
     signed transaction is already complete; broadcasting is only relaying public bytes.

### Per-kind notes

- `singlesig` / `timelock` / `rcsv`: choose `claim`. For `timelock` set `lockTime`; for
  `rcsv` set `sequence` to the relative-locktime operand.
- `hashlock`: choose `claim`, provide `preimage_hex`.
- `htlc`: claim = `claim` branch + preimage (receiver key). Refund = `refund` branch +
  `lockTime` (sender key).
- `multisig`: this single-key tool signs your share; for m > 1 you assemble the other
  signatures into the satisfier (or use a co-signing flow). Set `total` = N.
- `channel`: cooperative `close` needs both party signatures; `refund` is the funder key
  after `lockTime`.
- `deadman`: owner uses the IF branch (`claim`); heir uses the ELSE branch (`refund`) after
  the CLTV.
- `binary_oracle_select`: winner uses `revealA` (A key) or `revealB` (B key) plus the
  public winning preimage. Refund uses `refund` (refund key) after the lock; set
  `sequence`/`lockTime` per the kit. Fully offline-claimable once the winning preimage is
  public.
- `oracle_enforced_refundable` / `oracle_escrow_refundable`: if you have the oracle
  signature, paste it in Advanced and use the win branch. Otherwise use `refund` after
  `lock_daa` with the refund key; that branch is chain-enforced and offline-claimable.
- `oracle` / `oracle_enforced` / `oracle_escrow`: the win path needs the Covex oracle
  signature. Without it, these are not claimable by this tool, and they have no
  chain-enforced refund branch.

## Verify before you trust

A tool that signs with your private key must be verified, not trusted on faith. After
downloading or building, compute its SHA-256 and compare it to the value below.

Published SHA-256 of `covex-claim.html`:

```
f0d32c0ca0dbd96790c7939648fc946edaba4754d9399fc55b5c3ea867026bd6
```

Compute it yourself:

- Linux / macOS: `sha256sum covex-claim.html` or `shasum -a 256 covex-claim.html`
- Windows (PowerShell): `Get-FileHash covex-claim.html -Algorithm SHA256`
- Windows (cmd): `certutil -hashfile covex-claim.html SHA256`

If the hash does not match, do not use the file. Rebuild it yourself from this repo and a
known-good `@onekeyfe/kaspa-wasm`. (The hash changes if the pinned kaspa-wasm version
changes; rebuilding from source is the authoritative check.)

## Build from source (auditable)

The repo ships the prebuilt `covex-claim.html` so a user can grab a working file with no
toolchain. To reproduce it yourself:

```sh
git clone https://github.com/THTProtocol/covex-claim
cd covex-claim
npm install
npm run build
```

`npm run build` runs `tool/build-claim-tool.mjs`, which:

1. Reads `@onekeyfe/kaspa-wasm`'s wasm binary (`kaspa_bg.wasm.bin`) from `node_modules`,
   base64-encodes it, and inlines it into a `<script type="text/plain">`. At runtime the
   page decodes those bytes, calls `WebAssembly.compile()` locally, then instantiates the
   module asynchronously. The glue's network-fetching default init is never invoked.
2. Reads the ESM glue (`kaspa.js`) and applies one surgical patch: this kaspa-wasm build
   ships a glue whose loader uses Node's `require(...)` and whose synchronous instantiation
   path (`initSync`) is blocked by Chrome for buffers larger than 8MB (this wasm is ~11MB).
   The patch rewrites the glue's loader to instantiate the passed-in `WebAssembly.Module`
   via async `WebAssembly.instantiate`, which is the only main-thread-safe path for an 11MB
   module. The patched glue is base64-encoded and imported from a `blob:` module URL inside
   an inline `<script type="module">`. A `blob:` ESM import works under `file://` because it
   is a same-page object URL, not a network fetch. The build aborts if the patch points no
   longer match (kaspa-wasm version drift), so it can never emit a silently broken file.

The result is one HTML file with zero external dependencies: no Covex, no CDN, no sibling
`.wasm`. The script prints the output path and the artifact's SHA-256.

## Run the tests

The byte-parity proof is the satisfier test suite. It imports only the pure core, so it
does not load the wasm:

```sh
npm install
npm test
```

This runs the vectors in `src/covenantRedeemer.test.js` (and the guard and signer tests)
that assert the satisfier bytes match the Rust layout for every kind and branch.

## The two broadcast modes, and the file:// limitation

Signing is always local and offline. Broadcasting is the only step that touches the
network, and you have two independent options:

1. **Direct wRPC `submitTransaction`** to a public node. Convenient, but a browser opening
   a WebSocket from a `file://` page to an external `wss://` node may be blocked by the
   browser (opaque-origin / mixed-content policies vary by browser and version). If it
   fails, the tool tells you to use option 2; the signed transaction is still valid.
2. **Export the signed-tx JSON** and submit it from anywhere: a `kaspad` or wallet CLI, or
   a block explorer's submit-transaction form. This always works because you are only
   relaying already-public, already-signed bytes; no key is involved. Use this whenever
   wRPC from `file://` does not connect, or when you want to keep the signing machine fully
   offline and broadcast from a separate networked machine.

## Proof on-chain

The non-custodial claim path this tool produces is proven on Kaspa testnet-12: a covenant
was deployed and then spent by exactly this client-side satisfier logic.

- Deploy transaction: `731c5ea2...`
- Spend (claim) transaction: `f8be3f69...`

## Repository layout

```
covex-claim.html                  the BUILT single-file tool (commit + Pages serve this)
tool/
  covex-claim.template.html       the editable template (UI + the verbatim pure core)
  build-claim-tool.mjs            inlines kaspa-wasm into the template -> covex-claim.html
src/
  covenantRedeemer.js             the source-of-truth redeemer (verbatim from Covex)
  covenantRedeemer.test.js        the 23-vector byte-parity gate vs the Rust signer
  covenantRedeemer.guards.test.js guard tests
  covenantRedeemer.signer.test.js signer-binding tests
package.json
LICENSE                           MIT (bundled kaspa-wasm is ISC)
```

## Honesty notes

- Non-custodial: the private key never leaves the page and is not transmitted anywhere.
- The satisfier bytes this tool produces are byte-for-byte the same the Kaspa node already
  validated for these covenants (the pure core is copied verbatim from the CI-gated source).
- "Trustless / fully offline" is claimed only for the kinds the chain or a revealed public
  secret enforces end to end. The `oracle_*` win paths are oracle-liveness-dependent, not
  trustless, and are labeled as such here and in the tool.
- This tool cannot and does not manufacture an oracle signature.

## License

MIT. See [LICENSE](./LICENSE). The bundled `@onekeyfe/kaspa-wasm` is ISC-licensed,
Copyright (c) 2022-2024 Kaspa developers.
