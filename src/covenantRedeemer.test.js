// covenantRedeemer.test.js
//
// CONSENSUS-CRITICAL GATE. These tests assert the pure-core satisfier bytes are
// byte-for-byte identical to what the Rust `assemble_noncustodial_satisfier`
// (backend/src/covenant_builder.rs:982-1229) produces for each kind+branch. The
// expected vectors are computed HERE from the documented Rust layout (NOT by calling
// buildSatisfier - that would be circular), so a drift in either side fails CI.
//
// IMPORTANT: this file imports ONLY the pure core of covenantRedeemer.js. None of the
// imported symbols touch '@onekeyfe/kaspa-wasm', so `npm test` (vitest run, in node)
// never loads the ~15MB wasm. The wasm-backed wrappers (buildUnsignedSpend, signInput,
// assembleSigScript, broadcast, exportSignedTxJson) are intentionally NOT imported or
// exercised here; they are browser/e2e tested later.

import { describe, it, expect } from 'vitest';
import {
  OPCODES,
  SIG_HASH_ALL,
  pushData,
  push65,
  parseRedeemPubkeys,
  sigOpCount,
  buildSatisfier,
} from './covenantRedeemer.js';

// ---------------------------------------------------------------------------
// Test fixtures: deterministic, non-random byte patterns so every expected
// vector below is hand-verifiable. Signatures are 64 bytes; pubkeys/preimage 32.
// ---------------------------------------------------------------------------
const SIG_A = new Uint8Array(64).fill(0xa1);
const SIG_B = new Uint8Array(64).fill(0xb2);
const SIG_ORACLE = new Uint8Array(64).fill(0x0c);
const SIG_REFUND = new Uint8Array(64).fill(0x4f);
const SIG_P1 = new Uint8Array(64).fill(0x11);
const SIG_P2 = new Uint8Array(64).fill(0x22);
const PREIMAGE = new Uint8Array(32).fill(0x5e);

// Concatenate helper for building expected vectors.
function cat(...parts) {
  const arrs = parts.map((p) => (p instanceof Uint8Array ? p : Uint8Array.from(p)));
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

// Independently-computed expected push65: 0x41 || sig(64) || 0x01. (Rust push65 @968)
function expPush65(sig) {
  return cat([0x41], sig, [SIG_HASH_ALL]);
}

// Independently-computed expected canonical data push for a 32-byte value: 0x20 || data.
function expPush32(data) {
  expect(data.length).toBe(32);
  return cat([0x20], data);
}

const { OpTrue, OpFalse } = OPCODES;

// ---------------------------------------------------------------------------
// push65 wire form: 65-byte payload (0x41 + 64 sig + 0x01 sighashtype).
// ---------------------------------------------------------------------------
describe('push65', () => {
  it('emits OpData65 + 64 sig bytes + SIG_HASH_ALL (66 bytes total on the wire)', () => {
    const got = push65(SIG_A);
    expect(got.length).toBe(66);
    expect(got[0]).toBe(0x41); // OpData65 == 65
    expect(got[65]).toBe(0x01); // SIG_HASH_ALL trailing byte
    expect(Array.from(got.slice(1, 65))).toEqual(Array.from(SIG_A));
    expect(Array.from(got)).toEqual(Array.from(expPush65(SIG_A)));
  });

  it('rejects a non-64-byte signature', () => {
    expect(() => push65(new Uint8Array(63))).toThrow();
    expect(() => push65(new Uint8Array(65))).toThrow();
  });
});

// ---------------------------------------------------------------------------
// pushData canonical encoding (mirrors ScriptBuilder::add_data).
// ---------------------------------------------------------------------------
describe('pushData', () => {
  it('empty -> OpFalse', () => {
    expect(Array.from(pushData(new Uint8Array(0)))).toEqual([OpFalse]);
  });

  it('1..75 bytes -> [len, ...data]', () => {
    const d = new Uint8Array(32).fill(0x5e);
    expect(Array.from(pushData(d))).toEqual(Array.from(cat([0x20], d)));
    const one = Uint8Array.from([0x07]);
    expect(Array.from(pushData(one))).toEqual([0x01, 0x07]); // add_data, NOT OP_7
  });

  it('76..255 bytes -> OpPushData1 + len + data', () => {
    const d = new Uint8Array(80).fill(0xcd);
    const got = pushData(d);
    expect(got[0]).toBe(0x4c);
    expect(got[1]).toBe(80);
    expect(got.length).toBe(82);
  });

  it('256..65535 bytes -> OpPushData2 + LE len + data', () => {
    const d = new Uint8Array(300).fill(0x01);
    const got = pushData(d);
    expect(got[0]).toBe(0x4d);
    expect(got[1]).toBe(300 & 0xff); // 0x2c
    expect(got[2]).toBe((300 >> 8) & 0xff); // 0x01
    expect(got.length).toBe(303);
  });
});

// ---------------------------------------------------------------------------
// buildSatisfier byte-parity per kind + branch.
// Each `expected` is assembled from the documented Rust layout independently.
// ---------------------------------------------------------------------------
describe('buildSatisfier byte parity', () => {
  it('singlesig = push65(sig)', () => {
    const got = buildSatisfier({ kind: 'singlesig', sig65: SIG_A });
    expect(Array.from(got)).toEqual(Array.from(expPush65(SIG_A)));
  });

  it('timelock = push65(sig)', () => {
    const got = buildSatisfier({ kind: 'timelock', sig65: SIG_A });
    expect(Array.from(got)).toEqual(Array.from(expPush65(SIG_A)));
  });

  it('rcsv = push65(sig)', () => {
    const got = buildSatisfier({ kind: 'rcsv', sig65: SIG_A });
    expect(Array.from(got)).toEqual(Array.from(expPush65(SIG_A)));
  });

  it('hashlock = push65(sig) + pushData(preimage)', () => {
    const got = buildSatisfier({ kind: 'hashlock', sig65: SIG_A, preimageBytes: PREIMAGE });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_A), expPush32(PREIMAGE))));
  });

  it('htlc claim = push65(sig) + pushData(preimage) + OP_TRUE', () => {
    const got = buildSatisfier({ kind: 'htlc', branch: 'claim', sig65: SIG_A, preimageBytes: PREIMAGE });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_A), expPush32(PREIMAGE), [OpTrue])));
  });

  it('htlc refund = push65(sig) + OP_FALSE', () => {
    const got = buildSatisfier({ kind: 'htlc', branch: 'refund', sig65: SIG_A });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_A), [OpFalse])));
  });

  it('multisig = push65(sig) per member in order', () => {
    const got = buildSatisfier({ kind: 'multisig', multisigSigs: [SIG_A, SIG_B] });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_A), expPush65(SIG_B))));
  });

  it('multisig with zero sigs throws', () => {
    expect(() => buildSatisfier({ kind: 'multisig', multisigSigs: [] })).toThrow();
  });

  it('channel close = push65(sig_p2) + push65(sig_p1) + OP_TRUE', () => {
    const got = buildSatisfier({ kind: 'channel', branch: 'close', channelSig1: SIG_P1, channelSig2: SIG_P2 });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_P2), expPush65(SIG_P1), [OpTrue])));
  });

  it('channel refund = push65(sig_p1) + OP_FALSE', () => {
    const got = buildSatisfier({ kind: 'channel', branch: 'refund', channelSig1: SIG_P1 });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_P1), [OpFalse])));
  });

  it('deadman owner = push65(sig) + OP_TRUE', () => {
    const got = buildSatisfier({ kind: 'deadman', branch: 'claim', sig65: SIG_A });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_A), [OpTrue])));
  });

  it('deadman heir = push65(sig) + OP_FALSE', () => {
    const got = buildSatisfier({ kind: 'deadman', branch: 'refund', sig65: SIG_A });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_A), [OpFalse])));
  });

  it('oracle_enforced = push65(oracle) + push65(winner)', () => {
    const got = buildSatisfier({ kind: 'oracle_enforced', oracleSig: SIG_ORACLE, winnerSig: SIG_A });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_ORACLE), expPush65(SIG_A))));
  });

  it('oracle (alias) = push65(oracle) + push65(winner)', () => {
    const got = buildSatisfier({ kind: 'oracle', oracleSig: SIG_ORACLE, winnerSig: SIG_A });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_ORACLE), expPush65(SIG_A))));
  });

  it('oracle_escrow A = push65(winner) + OP_TRUE + push65(oracle)', () => {
    const got = buildSatisfier({ kind: 'oracle_escrow', winnerIsA: true, winnerSig: SIG_A, oracleSig: SIG_ORACLE });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_A), [OpTrue], expPush65(SIG_ORACLE))));
  });

  it('oracle_escrow B = push65(winner) + OP_FALSE + push65(oracle)', () => {
    const got = buildSatisfier({ kind: 'oracle_escrow', winnerIsA: false, winnerSig: SIG_B, oracleSig: SIG_ORACLE });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_B), [OpFalse], expPush65(SIG_ORACLE))));
  });

  it('oracle_enforced_refundable IF = push65(oracle) + push65(winner) + OP_TRUE', () => {
    const got = buildSatisfier({ kind: 'oracle_enforced_refundable', branch: 'claim', oracleSig: SIG_ORACLE, winnerSig: SIG_A });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_ORACLE), expPush65(SIG_A), [OpTrue])));
  });

  it('oracle_enforced_refundable ELSE refund = push65(refund) + OP_FALSE', () => {
    const got = buildSatisfier({ kind: 'oracle_enforced_refundable', branch: 'refund', refundSig: SIG_REFUND });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_REFUND), [OpFalse])));
  });

  it('oracle_escrow_refundable IF A = push65(winner) + OP_TRUE + push65(oracle) + OP_TRUE', () => {
    const got = buildSatisfier({ kind: 'oracle_escrow_refundable', branch: 'claim', winnerIsA: true, winnerSig: SIG_A, oracleSig: SIG_ORACLE });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_A), [OpTrue], expPush65(SIG_ORACLE), [OpTrue])));
  });

  it('oracle_escrow_refundable IF B = push65(winner) + OP_FALSE + push65(oracle) + OP_TRUE', () => {
    const got = buildSatisfier({ kind: 'oracle_escrow_refundable', branch: 'closeB', winnerIsA: false, winnerSig: SIG_B, oracleSig: SIG_ORACLE });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_B), [OpFalse], expPush65(SIG_ORACLE), [OpTrue])));
  });

  it('oracle_escrow_refundable ELSE refund = push65(refund) + OP_FALSE', () => {
    const got = buildSatisfier({ kind: 'oracle_escrow_refundable', branch: 'refund', refundSig: SIG_REFUND });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_REFUND), [OpFalse])));
  });

  // binary_oracle_select golden vectors (the consensus-critical parimutuel leg).
  it('binary_oracle_select RevealA = push65(sig_a) + pushData(preimage) + OP_TRUE', () => {
    const got = buildSatisfier({ kind: 'binary_oracle_select', branch: 'revealA', winnerIsA: true, winnerSig: SIG_A, preimageBytes: PREIMAGE });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_A), expPush32(PREIMAGE), [OpTrue])));
  });

  it('binary_oracle_select RevealB = push65(sig_b) + pushData(preimage) + OP_TRUE + OP_FALSE', () => {
    const got = buildSatisfier({ kind: 'binary_oracle_select', branch: 'revealB', winnerIsA: false, winnerSig: SIG_B, preimageBytes: PREIMAGE });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_B), expPush32(PREIMAGE), [OpTrue], [OpFalse])));
  });

  it('binary_oracle_select Refund = push65(sig_refund) + OP_FALSE + OP_FALSE', () => {
    const got = buildSatisfier({ kind: 'binary_oracle_select', branch: 'refund', refundSig: SIG_REFUND });
    expect(Array.from(got)).toEqual(Array.from(cat(expPush65(SIG_REFUND), [OpFalse], [OpFalse])));
  });

  it('unsupported kind throws', () => {
    expect(() => buildSatisfier({ kind: 'totally_made_up', sig65: SIG_A })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// parseRedeemPubkeys against a constructed binary_oracle_select redeem fixture
// (3 keys). Layout (Rust redeem_binary_oracle_select @395):
//   OP_IF OpBlake2b <h_a> OpEqualVerify <winner_a> OpCheckSig
//   OP_ELSE OP_IF OpBlake2b <h_b> OpEqualVerify <winner_b> OpCheckSig
//   OP_ELSE <min_seq> OpCheckSequenceVerify <refund> OpCheckSig OP_ENDIF OP_ENDIF
// With checksigOnly=true the two HASH pushes (followed by OpEqualVerify, 0x88) are
// EXCLUDED and only the three pubkeys (each followed by OpCheckSig 0xac) are returned,
// in script order: [winner_a, winner_b, refund].
// ---------------------------------------------------------------------------
describe('parseRedeemPubkeys', () => {
  const H_A = new Uint8Array(32).fill(0xaa);
  const WIN_A = new Uint8Array(32).fill(0x01);
  const H_B = new Uint8Array(32).fill(0xbb);
  const WIN_B = new Uint8Array(32).fill(0x02);
  const REFUND = new Uint8Array(32).fill(0x03);
  // min_sequence encoded as a small CSV operand push. The exact operand encoding does
  // not matter for the parse (it is not a 0x20+32 push); use a single-byte push.
  const SEQ_PUSH = Uint8Array.from([0x01, 0x90]); // OpData1 + 0x90 (some seq operand)

  function p32(data) {
    return cat([0x20], data);
  }

  const redeem = cat(
    [OPCODES.OpIf],
    [OPCODES.OpBlake2b],
    p32(H_A),
    [OPCODES.OpEqualVerify],
    p32(WIN_A),
    [OPCODES.OpCheckSig],
    [OPCODES.OpElse],
    [OPCODES.OpIf],
    [OPCODES.OpBlake2b],
    p32(H_B),
    [OPCODES.OpEqualVerify],
    p32(WIN_B),
    [OPCODES.OpCheckSig],
    [OPCODES.OpElse],
    SEQ_PUSH,
    [OPCODES.OpCheckSequenceVerify],
    p32(REFUND),
    [OPCODES.OpCheckSig],
    [OPCODES.OpEndIf],
    [OPCODES.OpEndIf],
  );

  it('checksigOnly=true yields [winner_a, winner_b, refund] (hashes excluded)', () => {
    const keys = parseRedeemPubkeys(redeem, true);
    expect(keys.length).toBe(3);
    expect(Array.from(keys[0])).toEqual(Array.from(WIN_A));
    expect(Array.from(keys[1])).toEqual(Array.from(WIN_B));
    expect(Array.from(keys[2])).toEqual(Array.from(REFUND));
  });

  it('checksigOnly=false also picks up the two hash pushes (5 total, script order)', () => {
    const keys = parseRedeemPubkeys(redeem, false);
    expect(keys.length).toBe(5);
    expect(Array.from(keys[0])).toEqual(Array.from(H_A));
    expect(Array.from(keys[1])).toEqual(Array.from(WIN_A));
    expect(Array.from(keys[2])).toEqual(Array.from(H_B));
    expect(Array.from(keys[3])).toEqual(Array.from(WIN_B));
    expect(Array.from(keys[4])).toEqual(Array.from(REFUND));
  });

  it('oracle_escrow redeem: checksigOnly=true yields [oracle, player_a, player_b]', () => {
    // Rust redeem_oracle_escrow @550: <oracle> OpCheckSigVerify OP_IF <a> OpCheckSig
    // OP_ELSE <b> OpCheckSig OP_ENDIF. oracle is followed by OpCheckSigVerify (0xad) so
    // it IS kept; a and b by OpCheckSig (0xac).
    const ORACLE = new Uint8Array(32).fill(0x0c);
    const A = new Uint8Array(32).fill(0x0a);
    const B = new Uint8Array(32).fill(0x0b);
    const esc = cat(
      p32(ORACLE),
      [OPCODES.OpCheckSigVerify],
      [OPCODES.OpIf],
      p32(A),
      [OPCODES.OpCheckSig],
      [OPCODES.OpElse],
      p32(B),
      [OPCODES.OpCheckSig],
      [OPCODES.OpEndIf],
    );
    const keys = parseRedeemPubkeys(esc, true);
    expect(keys.length).toBe(3);
    expect(Array.from(keys[0])).toEqual(Array.from(ORACLE));
    expect(Array.from(keys[1])).toEqual(Array.from(A));
    expect(Array.from(keys[2])).toEqual(Array.from(B));
  });
});

// ---------------------------------------------------------------------------
// sigOpCount per kind (port of SpendKind::sig_op_count).
// ---------------------------------------------------------------------------
describe('sigOpCount', () => {
  it('1 for singlesig/hashlock/timelock/rcsv/htlc', () => {
    for (const k of ['singlesig', 'hashlock', 'timelock', 'rcsv', 'htlc']) {
      expect(sigOpCount(k)).toBe(1);
    }
  });

  it('2 for deadman', () => {
    expect(sigOpCount('deadman')).toBe(2);
  });

  it('3 for channel/oracle_escrow/binary_oracle_select', () => {
    for (const k of ['channel', 'oracle_escrow', 'binary_oracle_select']) {
      expect(sigOpCount(k)).toBe(3);
    }
  });

  it('3 for oracle_enforced_refundable, 4 for oracle_escrow_refundable', () => {
    expect(sigOpCount('oracle_enforced_refundable')).toBe(3);
    expect(sigOpCount('oracle_escrow_refundable')).toBe(4);
  });

  it('multisig = total (the N)', () => {
    expect(sigOpCount('multisig', { total: 5 })).toBe(5);
    expect(() => sigOpCount('multisig')).toThrow();
  });

  it('oracle/oracle_enforced = total (default 2)', () => {
    expect(sigOpCount('oracle_enforced')).toBe(2);
    expect(sigOpCount('oracle')).toBe(2);
    expect(sigOpCount('oracle_enforced', { total: 3 })).toBe(3);
  });

  it('unsupported kind throws', () => {
    expect(() => sigOpCount('nope')).toThrow();
  });
});
