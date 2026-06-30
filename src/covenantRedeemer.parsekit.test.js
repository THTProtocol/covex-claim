// covenantRedeemer.parsekit.test.js
//
// Regression tests for the P0 funds-recovery fixes:
//   (a) parseKit round-trips the canonical NESTED version-2 kit shape (kind unwrapped from
//       redeem_kind:'<kind>:<suffix>', funding optional), and still accepts older flat kits.
//   (b) sigOpCount('htlc') === 2 (htlc==1 permanently locked HTLC funds).
//   (c) the 4 unsupported kinds (timedecay, winner_bound, escrow_bound, zk_game_settle)
//       produce the honest in-app-flow message instead of a fabricated satisfier.
//   (d) multisig is in SIGNER_INDEX_MAP, so assertSignerForBranch binds an N-of-M co-signer
//       (instead of throwing "unsupported kind").
//
// Pure-core ONLY: never imports the wasm wrappers, so `npm test` stays wasm-free.

import { describe, it, expect } from 'vitest';
import {
  parseKit,
  canonicalKindBase,
  sigOpCount,
  buildSatisfier,
  assertSignerForBranch,
  assertSupportedKind,
  UNSUPPORTED_KINDS,
  bytesToHex,
} from './covenantRedeemer.js';

// ---------------------------------------------------------------------------
// (a) parseKit: the canonical nested version-2 kit shape (the REAL export).
// ---------------------------------------------------------------------------
describe('parseKit accepts the canonical nested version-2 kit', () => {
  // Exactly the shape RecoveryKitModal exports + Recover.normalizeKit consumes: nested under
  // `covenant`, redeem_kind carries a ':<suffix>', NO funding field.
  const v2Kit = {
    covex_recovery_kit_version: 2,
    note: 'Self-custody recovery data...',
    covenant: {
      tx_id: 'aa'.repeat(32),
      network: 'mainnet',
      p2sh_address: 'kaspa:qqexamplep2sh',
      redeem_kind: 'binary_oracle_select:144',
      redeem_script_hex: '20' + '11'.repeat(32) + 'ac',
      lock_daa: null,
      revealed_secret: null,
      oracle_pubkey: null,
    },
  };

  it('unwraps covenant{}, strips the :suffix off redeem_kind, and parses with NO funding', () => {
    const k = parseKit(v2Kit);
    expect(k.kind).toBe('binary_oracle_select'); // suffix stripped
    expect(k.network).toBe('mainnet');
    expect(k.p2sh).toBe('kaspa:qqexamplep2sh');
    expect(k.redeemHex).toBe('20' + '11'.repeat(32) + 'ac');
    expect(k.funding).toBe(null); // funding is OPTIONAL and absent here, must NOT throw
  });

  it('parses the kit from a JSON string too (the textarea path)', () => {
    const k = parseKit(JSON.stringify(v2Kit));
    expect(k.kind).toBe('binary_oracle_select');
    expect(k.funding).toBe(null);
  });

  it('folds the relative_timelock alias to rcsv', () => {
    const k = parseKit({ covenant: { network: 'mainnet', redeem_kind: 'relative_timelock:10', redeem_script_hex: 'ab' } });
    expect(k.kind).toBe('rcsv');
    expect(canonicalKindBase('relative_timelock:10')).toBe('rcsv');
  });

  it('still accepts an older FLAT kit with funding (back-compat)', () => {
    const flat = {
      kind: 'singlesig',
      network: 'testnet-10',
      redeem_script_hex: '20' + '01'.repeat(32) + 'ac',
      p2sh_address: 'kaspatest:qqflat',
      funding: { transactionId: 'bb'.repeat(32), index: 0, amount: '100000000' },
      branch: 'claim',
    };
    const k = parseKit(flat);
    expect(k.kind).toBe('singlesig');
    expect(k.funding.transactionId).toBe('bb'.repeat(32));
    expect(k.funding.index).toBe(0);
    expect(k.funding.amount).toBe('100000000');
  });

  it('validates funding when present: index must be an integer >= 0, amount a positive integer', () => {
    const base = { kind: 'singlesig', network: 'mainnet', redeem_script_hex: 'ab' };
    expect(() => parseKit({ ...base, funding: { transactionId: 't', index: -1, amount: '1' } })).toThrow(/index/);
    expect(() => parseKit({ ...base, funding: { transactionId: 't', index: 1.5, amount: '1' } })).toThrow(/index/);
    expect(() => parseKit({ ...base, funding: { transactionId: 't', index: 0, amount: '0' } })).toThrow(/amount/);
    expect(() => parseKit({ ...base, funding: { transactionId: 't', index: 0, amount: 'x' } })).toThrow(/amount/);
    expect(() => parseKit({ ...base, funding: { index: 0, amount: '1' } })).toThrow(/transactionId/);
    // A valid funding does not throw.
    expect(() => parseKit({ ...base, funding: { transactionId: 't', index: 2, amount: '500' } })).not.toThrow();
  });

  it('throws on a kit missing kind or redeem script', () => {
    expect(() => parseKit({ covenant: { network: 'mainnet', redeem_script_hex: 'ab' } })).toThrow(/kind/);
    expect(() => parseKit({ covenant: { network: 'mainnet', redeem_kind: 'singlesig' } })).toThrow(/redeem_script_hex/);
  });
});

// ---------------------------------------------------------------------------
// (b) htlc sigOpCount is 2.
// ---------------------------------------------------------------------------
describe('htlc sigOpCount', () => {
  it('sigOpCount(htlc) === 2', () => {
    expect(sigOpCount('htlc')).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// (c) unsupported kinds -> honest, actionable message (no fabricated satisfier).
// ---------------------------------------------------------------------------
describe('unsupported kinds fail closed with the in-app-flow message', () => {
  const KINDS = ['timedecay', 'winner_bound', 'escrow_bound', 'zk_game_settle'];

  it('all four are listed in UNSUPPORTED_KINDS', () => {
    for (const k of KINDS) expect(Object.prototype.hasOwnProperty.call(UNSUPPORTED_KINDS, k)).toBe(true);
  });

  it('assertSupportedKind throws the honest message for each', () => {
    for (const k of KINDS) {
      expect(() => assertSupportedKind(k)).toThrow(/not yet supported by the offline claim tool/);
      expect(() => assertSupportedKind(k)).toThrow(/hightable\.pro\/recover/);
    }
  });

  it('buildSatisfier refuses to assemble a satisfier for them (throws the honest message)', () => {
    for (const k of KINDS) {
      expect(() => buildSatisfier({ kind: k, sig65: new Uint8Array(64).fill(1) }))
        .toThrow(/not yet supported by the offline claim tool/);
    }
  });

  it('assertSupportedKind returns false (no throw) for a supported kind', () => {
    expect(assertSupportedKind('singlesig')).toBe(false);
    expect(assertSupportedKind('htlc')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// (d) multisig is now in SIGNER_INDEX_MAP: assertSignerForBranch binds an N-of-M co-signer.
// ---------------------------------------------------------------------------
describe('multisig key-binding pre-check', () => {
  function key(byte) {
    return new Uint8Array(32).fill(byte);
  }
  function cat(...parts) {
    const arrs = parts.map((p) => (p instanceof Uint8Array ? p : Uint8Array.from(p)));
    let total = 0;
    for (const a of arrs) total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrs) { out.set(a, off); off += a.length; }
    return out;
  }
  const p32 = (d) => cat([0x20], d); // OpData32 + 32 bytes
  const K1 = key(0xa1);
  const K2 = key(0xb2);
  const K3 = key(0xc3);
  const FOREIGN = key(0x99);
  // multisig redeem: OP_2 <k1> <k2> <k3> OP_3 OpCheckMultiSig (2-of-3). The keys are inside the
  // CheckMultiSig (NOT each followed by a checksig op), so it must parse with checksigOnly=false.
  const REDEEM_MULTISIG = bytesToHex(cat([0x52], p32(K1), p32(K2), p32(K3), [0x53], [0xae]));

  it('binds any committed key (not "unsupported kind" anymore)', () => {
    // Before the fix this threw /unsupported kind/. Now each committed key binds to its index.
    expect(assertSignerForBranch(REDEEM_MULTISIG, 'multisig', 'claim', bytesToHex(K1)).index).toBe(0);
    expect(assertSignerForBranch(REDEEM_MULTISIG, 'multisig', 'claim', bytesToHex(K2)).index).toBe(1);
    expect(assertSignerForBranch(REDEEM_MULTISIG, 'multisig', 'claim', bytesToHex(K3)).index).toBe(2);
  });

  it('a wholly-foreign key fails closed (NOT one of the committed keys)', () => {
    expect(() => assertSignerForBranch(REDEEM_MULTISIG, 'multisig', 'claim', bytesToHex(FOREIGN)))
      .toThrow(/NOT one of the .* committed multisig keys/);
  });
});
