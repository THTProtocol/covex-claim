// Test-only stub for @onekeyfe/kaspa-wasm.
//
// The byte-parity tests import ONLY the pure core of covenantRedeemer.js (buildSatisfier,
// push65, pushData, parseRedeemPubkeys, sigOpCount), none of which touch the wasm. But the
// module also contains a DYNAMIC `import('@onekeyfe/kaspa-wasm')` inside the wasm-backed
// wrappers. The published kaspa-wasm package is a wasm-bindgen "--target web" build with no
// resolvable package entry, so vite/vitest's static analysis fails to resolve that import
// even though it is never executed in these tests. vitest.config.js aliases the package to
// this stub purely so the resolver is satisfied; the stub is never actually run by the
// pure-core tests. It is NOT used by the built tool, which inlines the real wasm.
export {};
