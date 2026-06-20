// covenantRedeemer.guards.test.js
//
// Fail-closed GUARD tests for the hardening added after the security audit
// (SHIP_WITH_NOTES). These assert the redeemer refuses ambiguous / fund-unsafe inputs
// up front, instead of building something that only fails late at the node.
//
// buildSatisfier guards are pure-core. buildUnsignedSpend / broadcast guards exercise ONLY
// the pre-wasm validation: every case below throws BEFORE the lazy `import('@onekeyfe/
// kaspa-wasm')` is reached, so this file - like covenantRedeemer.test.js - never loads the
// wasm under `npm test`.

import { describe, it, expect } from 'vitest';
import { buildSatisfier, buildUnsignedSpend, broadcast } from './covenantRedeemer.js';

const SIG = new Uint8Array(64).fill(0xa1);
const PRE = new Uint8Array(32).fill(0x5e);

// ---------------------------------------------------------------------------
// buildSatisfier: the "branchy" kinds (two distinct winner keys) must NOT guess
// the A/B outcome - they require branch revealA/revealB or winnerIsA.
// ---------------------------------------------------------------------------
describe('buildSatisfier explicit-outcome guard', () => {
  it('oracle_escrow without winnerIsA or A/B branch throws', () => {
    expect(() => buildSatisfier({ kind: 'oracle_escrow', winnerSig: SIG, oracleSig: SIG })).toThrow(/explicit outcome/);
  });

  it('oracle_escrow_refundable claim without winnerIsA throws (claim alone is ambiguous)', () => {
    expect(() => buildSatisfier({ kind: 'oracle_escrow_refundable', branch: 'claim', winnerSig: SIG, oracleSig: SIG })).toThrow(/explicit outcome/);
  });

  it('binary_oracle_select reveal without winnerIsA or A/B branch throws', () => {
    expect(() => buildSatisfier({ kind: 'binary_oracle_select', winnerSig: SIG, preimageBytes: PRE })).toThrow(/explicit outcome/);
  });

  it('binary_oracle_select revealA via branch label alone (no winnerIsA) is allowed', () => {
    expect(() => buildSatisfier({ kind: 'binary_oracle_select', branch: 'revealA', winnerSig: SIG, preimageBytes: PRE })).not.toThrow();
  });

  it('refund branches do not require an outcome (no A/B key choice)', () => {
    expect(() => buildSatisfier({ kind: 'binary_oracle_select', branch: 'refund', refundSig: SIG })).not.toThrow();
    expect(() => buildSatisfier({ kind: 'oracle_escrow_refundable', branch: 'refund', refundSig: SIG })).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// buildUnsignedSpend: fail-closed input validation (all throw before loadWasm()).
// ---------------------------------------------------------------------------
describe('buildUnsignedSpend fail-closed validation', () => {
  const okUtxo = { transactionId: 'ab'.repeat(32), index: 0, amount: 1_000_000n };
  const base = { utxo: okUtxo, redeemHex: '00', destAddr: 'kaspa:qqexampledest', networkId: 'mainnet', fee: 2000n, kind: 'singlesig' };

  it('missing fee throws', async () => {
    const { fee, ...noFee } = base;
    await expect(buildUnsignedSpend(noFee)).rejects.toThrow(/fee.*required/);
  });

  it('fee >= utxo amount (output below floor) throws', async () => {
    await expect(buildUnsignedSpend({ ...base, utxo: { ...okUtxo, amount: 1500n }, fee: 2000n })).rejects.toThrow(/spendable floor/);
  });

  it('unsupported networkId throws', async () => {
    await expect(buildUnsignedSpend({ ...base, networkId: 'mainnett' })).rejects.toThrow(/unsupported networkId/);
  });

  it('destination address prefix not matching the network throws', async () => {
    await expect(buildUnsignedSpend({ ...base, networkId: 'mainnet', destAddr: 'kaspatest:qqtest' })).rejects.toThrow(/not a mainnet address/);
    await expect(buildUnsignedSpend({ ...base, networkId: 'testnet-10', destAddr: 'kaspa:qqmain' })).rejects.toThrow(/not a testnet-10 address/);
  });

  it('timelock without a lockTime throws (CLTV operand required)', async () => {
    await expect(buildUnsignedSpend({ ...base, kind: 'timelock' })).rejects.toThrow(/lockTime/);
  });

  it('rcsv without a sequence throws (CSV operand required)', async () => {
    await expect(buildUnsignedSpend({ ...base, kind: 'rcsv' })).rejects.toThrow(/sequence/);
  });

  it('binary_oracle_select refund without a sequence throws (CSV refund)', async () => {
    await expect(buildUnsignedSpend({ ...base, kind: 'binary_oracle_select', branch: 'refund' })).rejects.toThrow(/sequence/);
  });

  it('missing utxo throws', async () => {
    const { utxo, ...noUtxo } = base;
    await expect(buildUnsignedSpend(noUtxo)).rejects.toThrow(/utxo/);
  });
});

// ---------------------------------------------------------------------------
// broadcast: network allow-list (throws before loadWasm()).
// ---------------------------------------------------------------------------
describe('broadcast network allow-list', () => {
  it('rejects an unknown networkId before touching the network', async () => {
    await expect(broadcast({}, 'mainnett')).rejects.toThrow(/unsupported networkId/);
    await expect(broadcast({}, '')).rejects.toThrow(/unsupported networkId/);
  });
});
