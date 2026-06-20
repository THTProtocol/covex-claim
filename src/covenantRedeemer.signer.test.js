// covenantRedeemer.signer.test.js
//
// Fail-closed NAMED-KEY BINDING tests (security-audit request). assertSignerForBranch is
// pure-core: it parses a redeem script and proves the signer's x-only pubkey is the EXACT key
// the chain will OpCheckSig on the chosen (kind, branch). These build small, hand-verifiable
// redeem fixtures and assert (a) the right key for a branch matches and returns its index, and
// (b) a wrong key (or wrong branch) throws.
//
// IMPORTANT: imports ONLY the pure core of covenantRedeemer.js. None of it touches
// '@onekeyfe/kaspa-wasm', so `npm test` (vitest run, in node) never loads the ~15MB wasm.

import { describe, it, expect } from 'vitest';
import {
  OPCODES,
  bytesToHex,
  assertSignerForBranch,
  claimability,
  KIND_CLAIM_MATRIX,
} from './covenantRedeemer.js';

// ---------------------------------------------------------------------------
// Fixture helpers: deterministic 32-byte keys/hashes so every redeem is exact.
// ---------------------------------------------------------------------------
function k(byte) {
  return new Uint8Array(32).fill(byte);
}
const hx = (bytes) => bytesToHex(bytes);

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
// Canonical 0x20 + 32-byte push (what parseRedeemPubkeys scans for).
function p32(data) {
  return cat([0x20], data);
}

const {
  OpIf, OpElse, OpEndIf, OpBlake2b, OpEqualVerify,
  OpCheckSig, OpCheckSigVerify, OpCheckMultiSig, OpCheckSequenceVerify,
} = OPCODES;

// Deterministic actors.
const KEY = k(0x01);
const RECEIVER = k(0x0a);
const SENDER = k(0x0b);
const OWNER = k(0x0c);
const HEIR = k(0x0d);
const P1 = k(0x11);
const P2 = k(0x22);
const WIN_A = k(0xa1);
const WIN_B = k(0xb2);
const REFUND = k(0x3f);
const ORACLE = k(0x0e);
const WINNER = k(0x0f);
const WRONG = k(0x99);

// ---------------------------------------------------------------------------
// Redeem fixtures. Only the bytes parseRedeemPubkeys reads (0x20+32 + the
// trailing checksig/checksigverify op) matter; surrounding ops are realistic.
// ---------------------------------------------------------------------------

// singlesig: <key> OpCheckSig
const REDEEM_SINGLESIG = hx(cat(p32(KEY), [OpCheckSig]));

// htlc: OP_IF OpBlake2b <hash> OpEqualVerify <receiver> OpCheckSig OP_ELSE <ltv> <sender> OpCheckSig OP_ENDIF
// parseRedeemPubkeys(true) -> [receiver, sender] (the hash push is followed by OpEqualVerify, excluded).
const REDEEM_HTLC = hx(cat(
  [OpIf], [OpBlake2b], p32(k(0xff)), [OpEqualVerify], p32(RECEIVER), [OpCheckSig],
  [OpElse], [0x01, 0x90], p32(SENDER), [OpCheckSig], [OpEndIf],
));

// deadman: <owner> OpCheckSig ... <heir> OpCheckSig -> [owner, heir]
const REDEEM_DEADMAN = hx(cat(
  [OpIf], p32(OWNER), [OpCheckSig],
  [OpElse], [0x01, 0x90], [OpCheckSequenceVerify], p32(HEIR), [OpCheckSig], [OpEndIf],
));

// channel: <p1> OpCheckSig ... <p2> OpCheckSig ... <p1> OpCheckSig -> [p1, p2, p1]
const REDEEM_CHANNEL = hx(cat(
  [OpIf], p32(P2), [OpCheckSig], p32(P1), [OpCheckSig],
  [OpElse], [0x01, 0x90], p32(P1), [OpCheckSig], [OpEndIf],
));
// NOTE: buildRedeem channel script order is [p1, p2, p1]; the close branch needs BOTH p1 and p2,
// so assertSignerForBranch close accepts either index 0 (p1) or 1 (p2). We construct the script
// to that parse order: refund-branch p1 first... but to keep the parse simple and match the doc
// "[p1, p2, p1]", reconstruct deterministically below.
const REDEEM_CHANNEL_DOC = hx(cat(
  p32(P1), [OpCheckSig], p32(P2), [OpCheckSig], p32(P1), [OpCheckSig],
));

// binary_oracle_select: [winner_a, winner_b, refund]
const REDEEM_BOS = hx(cat(
  [OpIf], [OpBlake2b], p32(k(0xaa)), [OpEqualVerify], p32(WIN_A), [OpCheckSig],
  [OpElse], [OpIf], [OpBlake2b], p32(k(0xbb)), [OpEqualVerify], p32(WIN_B), [OpCheckSig],
  [OpElse], [0x01, 0x90], [OpCheckSequenceVerify], p32(REFUND), [OpCheckSig], [OpEndIf], [OpEndIf],
));

// oracle_escrow: <oracle> OpCheckSigVerify OP_IF <a> OpCheckSig OP_ELSE <b> OpCheckSig OP_ENDIF
// parseRedeemPubkeys(true) -> [oracle, a, b]
const REDEEM_ORACLE_ESCROW = hx(cat(
  p32(ORACLE), [OpCheckSigVerify],
  [OpIf], p32(WIN_A), [OpCheckSig],
  [OpElse], p32(WIN_B), [OpCheckSig], [OpEndIf],
));

// oracle_enforced: a 2-of-2 multisig of [oracle, winner]. Keys are NOT each directly followed by a
// checksig (they precede OpCheckMultiSig), so it must be parsed with checksigOnly=false ->
// [oracle, winner]. (Add an unrelated leading byte so indices are exercised, not just luck.)
const REDEEM_ORACLE_ENFORCED = hx(cat(
  [0x52], p32(ORACLE), p32(WINNER), [0x52], [OpCheckMultiSig],
));

// oracle_enforced_refundable: IF <2of2 [oracle, winner]> OP_ELSE <refund> OpCheckSig OP_ENDIF
// parseRedeemPubkeys(false) -> [oracle, winner, refund]
const REDEEM_OEF = hx(cat(
  [OpIf], [0x52], p32(ORACLE), p32(WINNER), [0x52], [OpCheckMultiSig],
  [OpElse], p32(REFUND), [OpCheckSig], [OpEndIf],
));

// ---------------------------------------------------------------------------
// assertSignerForBranch: right key matches, returns the bound index + key.
// ---------------------------------------------------------------------------
describe('assertSignerForBranch matches the named key', () => {
  it('singlesig claim -> index 0 = the key', () => {
    const r = assertSignerForBranch(REDEEM_SINGLESIG, 'singlesig', 'claim', hx(KEY));
    expect(r.index).toBe(0);
    expect(r.namedKeyHex).toBe(hx(KEY));
  });

  it('htlc claim -> receiver (index 0); refund -> sender (index 1)', () => {
    expect(assertSignerForBranch(REDEEM_HTLC, 'htlc', 'claim', hx(RECEIVER)).index).toBe(0);
    expect(assertSignerForBranch(REDEEM_HTLC, 'htlc', 'refund', hx(SENDER)).index).toBe(1);
  });

  it('deadman owner=claim (0), heir=refund (1)', () => {
    expect(assertSignerForBranch(REDEEM_DEADMAN, 'deadman', 'claim', hx(OWNER)).index).toBe(0);
    expect(assertSignerForBranch(REDEEM_DEADMAN, 'deadman', 'refund', hx(HEIR)).index).toBe(1);
  });

  it('channel refund -> p1 (index 0); close accepts either p1 or p2', () => {
    expect(assertSignerForBranch(REDEEM_CHANNEL_DOC, 'channel', 'refund', hx(P1)).index).toBe(0);
    expect(assertSignerForBranch(REDEEM_CHANNEL_DOC, 'channel', 'close', hx(P1)).index).toBe(0);
    expect(assertSignerForBranch(REDEEM_CHANNEL_DOC, 'channel', 'close', hx(P2)).index).toBe(1);
  });

  it('binary_oracle_select revealA=0, revealB=1, refund=2', () => {
    expect(assertSignerForBranch(REDEEM_BOS, 'binary_oracle_select', 'revealA', hx(WIN_A)).index).toBe(0);
    expect(assertSignerForBranch(REDEEM_BOS, 'binary_oracle_select', 'revealB', hx(WIN_B)).index).toBe(1);
    expect(assertSignerForBranch(REDEEM_BOS, 'binary_oracle_select', 'refund', hx(REFUND)).index).toBe(2);
  });

  it('oracle_escrow A=index 1, B=index 2 (oracle is index 0, not a player branch)', () => {
    expect(assertSignerForBranch(REDEEM_ORACLE_ESCROW, 'oracle_escrow', 'revealA', hx(WIN_A)).index).toBe(1);
    expect(assertSignerForBranch(REDEEM_ORACLE_ESCROW, 'oracle_escrow', 'revealB', hx(WIN_B)).index).toBe(2);
  });

  it('oracle_enforced winner=index 1 (parsed with checksigOnly=false)', () => {
    expect(assertSignerForBranch(REDEEM_ORACLE_ENFORCED, 'oracle_enforced', 'claim', hx(WINNER)).index).toBe(1);
  });

  it('oracle_enforced_refundable winner=1, refund=2', () => {
    expect(assertSignerForBranch(REDEEM_OEF, 'oracle_enforced_refundable', 'claim', hx(WINNER)).index).toBe(1);
    expect(assertSignerForBranch(REDEEM_OEF, 'oracle_enforced_refundable', 'refund', hx(REFUND)).index).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// assertSignerForBranch: wrong key / wrong branch / bad input throws (fail-closed).
// ---------------------------------------------------------------------------
describe('assertSignerForBranch fails closed on the wrong key/branch', () => {
  it('wrong key on a valid branch throws and names the expected key', () => {
    expect(() => assertSignerForBranch(REDEEM_SINGLESIG, 'singlesig', 'claim', hx(WRONG)))
      .toThrow(/NOT the singlesig/);
  });

  it('htlc claim with the SENDER key (the refund key) throws (right covenant, wrong branch key)', () => {
    expect(() => assertSignerForBranch(REDEEM_HTLC, 'htlc', 'claim', hx(SENDER))).toThrow(/NOT the htlc/);
  });

  it('binary_oracle_select revealA with the B key throws', () => {
    expect(() => assertSignerForBranch(REDEEM_BOS, 'binary_oracle_select', 'revealA', hx(WIN_B))).toThrow(/NOT the/);
  });

  it('oracle_escrow with the ORACLE key on a player branch throws (oracle is not the player signer)', () => {
    expect(() => assertSignerForBranch(REDEEM_ORACLE_ESCROW, 'oracle_escrow', 'revealA', hx(ORACLE))).toThrow(/NOT the/);
  });

  it('unknown kind throws', () => {
    expect(() => assertSignerForBranch(REDEEM_SINGLESIG, 'made_up', 'claim', hx(KEY))).toThrow(/unsupported kind/);
  });

  it('unknown branch throws', () => {
    expect(() => assertSignerForBranch(REDEEM_HTLC, 'htlc', 'bogus', hx(RECEIVER))).toThrow(/no branch/);
  });

  it('non-32-byte signer pubkey throws', () => {
    expect(() => assertSignerForBranch(REDEEM_SINGLESIG, 'singlesig', 'claim', 'ab')).toThrow(/32 bytes/);
  });

  it('non-hex signer pubkey throws', () => {
    expect(() => assertSignerForBranch(REDEEM_SINGLESIG, 'singlesig', 'claim', 'zz'.repeat(32))).toThrow(/valid hex/);
  });

  it('truncated redeem (too few keys for the index) throws', () => {
    // A redeem with only one key but asking for htlc refund (index 1).
    expect(() => assertSignerForBranch(REDEEM_SINGLESIG, 'htlc', 'refund', hx(SENDER))).toThrow(/need index/);
  });
});

// ---------------------------------------------------------------------------
// claimability matrix: the honest per-kind gating the UI + kit consume.
// ---------------------------------------------------------------------------
describe('claimability honesty matrix', () => {
  it('script-enforced kinds are offline-claimable', () => {
    for (const kk of ['singlesig', 'timelock', 'rcsv', 'hashlock', 'htlc', 'multisig', 'channel', 'deadman']) {
      expect(KIND_CLAIM_MATRIX[kk].offlineClaimable).toBe(true);
      expect(claimability(kk, 'claim').offline).toBe(true);
    }
  });

  it('binary_oracle_select reveal branches are offline-claimable (after the secret is revealed)', () => {
    expect(claimability('binary_oracle_select', 'revealA').offline).toBe(true);
    expect(claimability('binary_oracle_select', 'refund').offline).toBe(true);
  });

  it('oracle_enforced / oracle_escrow WIN path is NOT offline-claimable', () => {
    expect(claimability('oracle_enforced', 'claim').offline).toBe(false);
    expect(claimability('oracle_escrow', 'revealA').offline).toBe(false);
  });

  it('*_refundable kinds: refund branch IS offline-claimable, win path is NOT', () => {
    expect(claimability('oracle_enforced_refundable', 'refund').offline).toBe(true);
    expect(claimability('oracle_enforced_refundable', 'claim').offline).toBe(false);
    expect(claimability('oracle_escrow_refundable', 'refund').offline).toBe(true);
    expect(claimability('oracle_escrow_refundable', 'revealA').offline).toBe(false);
  });

  it('unknown kind -> null (caller falls back conservatively)', () => {
    expect(claimability('totally_unknown', 'claim')).toBe(null);
  });
});
