// covenantRedeemer.js
//
// Client-side, self-custodial covenant redeemer. This is the FOUNDATION of the
// "claim even if Covex is fully down" path: a covenant winner (or refund key holder)
// can assemble and broadcast the spend transaction entirely in their own browser,
// with no Covex frontend or backend in the loop.
//
// This file is published verbatim from the Covex source tree
// (frontend/src/lib/redeemer/covenantRedeemer.js). Its pure-core satisfier bytes are
// CI-gated to byte-match the Rust assemble_noncustodial_satisfier in
// backend/src/covenant_builder.rs. It is mirrored here so the standalone claim tool is
// fully auditable on its own, and so the tool/ template's inlined pure core can be diffed
// against it.
//
// The module is split into two sections:
//
//   (A) PURE CORE   - plain JS over Uint8Array. NO wasm, NO React, NO network, NO
//                     Covex API. This is the consensus-critical part: the satisfier
//                     bytes it produces MUST be byte-for-byte identical to the Rust
//                     `assemble_noncustodial_satisfier` in
//                     backend/src/covenant_builder.rs (lines 982-1229). The
//                     accompanying covenantRedeemer.test.js gates that parity in CI
//                     and imports ONLY this section (so `npm test` never loads wasm).
//
//   (B) WASM WRAPPERS - thin helpers that build/sign/assemble/broadcast a real Kaspa
//                     transaction. Each lazily `await import('@onekeyfe/kaspa-wasm')`
//                     INSIDE the function, so importing the pure core (e.g. from the
//                     CI test) never pulls the ~15MB wasm. These are browser/e2e tested
//                     later, not in CI.
//
// Honesty note: this redeemer only helps for kinds whose redeem script the chain (or a
// revealed public secret + the named key's OpCheckSig) genuinely enforces end to end.
// The oracle_* kinds still need the server-produced oracle half-signature to claim
// (the refund branch of the *_refundable kinds is fully self-claimable). The caller is
// responsible for knowing which branch they can actually satisfy offline.

// ===========================================================================
// (A) PURE CORE - no imports, plain Uint8Array. Byte-parity with the Rust.
// ===========================================================================

// Kaspa txscript opcode bytes. Each constant is the exact byte the Rust
// kaspa_txscript::opcodes::codes emits (cross-checked against
// backend/src/covenant_builder.rs and backend/src/disassembler.rs).
export const OPCODES = Object.freeze({
  OpFalse: 0x00, // pushes an empty value; also the "0"/ELSE branch selector
  OpData1: 0x01, // OpData1..OpData75 (0x01..0x4b): direct N-byte push, opcode == N
  OpData32: 0x20, // canonical push of a 32-byte x-only pubkey or 32-byte hash
  OpData65: 0x41, // canonical push of the 65-byte (64 sig + 1 sighashtype) signature
  OpData75: 0x4b,
  OpPushData1: 0x4c, // 1-byte length prefix, for 76..255 data bytes
  OpPushData2: 0x4d, // 2-byte little-endian length prefix, for 256..65535
  OpPushData4: 0x4e, // 4-byte little-endian length prefix, for >= 65536
  OpTrue: 0x51, // pushes 1; the "1"/IF branch selector
  OpIf: 0x63,
  OpElse: 0x67,
  OpEndIf: 0x68,
  OpEqualVerify: 0x88,
  OpBlake2b: 0xaa,
  OpCheckSig: 0xac,
  OpCheckSigVerify: 0xad,
  OpCheckMultiSig: 0xae,
  OpCheckLockTimeVerify: 0xb0, // Kaspa CLTV; POPS its operand (no OpDrop)
  OpCheckSequenceVerify: 0xb1, // Kaspa CSV;  POPS its operand (no OpDrop)
});

// The sighash-type byte appended after the 64 signature bytes. Kaspa's
// SIG_HASH_ALL.to_u8() == 0x01 (backend/src/covenant_builder.rs:27 imports it; every
// push65 site appends `SIG_HASH_ALL.to_u8()`).
export const SIG_HASH_ALL = 0x01;

/**
 * Concatenate Uint8Arrays / number-arrays into one Uint8Array.
 * @param {...(Uint8Array|number[])} parts
 * @returns {Uint8Array}
 */
function concatBytes(...parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * Hex string -> Uint8Array. Accepts an optional "0x" prefix and is case-insensitive.
 * @param {string} hex
 * @returns {Uint8Array}
 */
export function hexToBytes(hex) {
  let h = String(hex || '').trim();
  if (h.startsWith('0x') || h.startsWith('0X')) h = h.slice(2);
  if (h.length % 2 !== 0) throw new Error(`hex string has odd length: ${h.length}`);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(h.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) throw new Error(`invalid hex at byte ${i}`);
    out[i] = byte;
  }
  return out;
}

/**
 * Uint8Array -> lowercase hex string (no "0x" prefix).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

/**
 * Canonical Kaspa data push, mirroring `ScriptBuilder::add_data` semantics exactly.
 *
 * Layout (matches backend/src/disassembler.rs push_layout @297 and the rusty-kaspa
 * ScriptBuilder::canonical_data_size / add_data):
 *   len == 0           -> [OpFalse]                       (empty value, no data bytes)
 *   1   <= len <= 75   -> [len, ...data]                  (OpData1..OpData75, opcode == len)
 *   76  <= len <= 255  -> [OpPushData1, len, ...data]
 *   256 <= len <= 65535 -> [OpPushData2, len_lo, len_hi, ...data]   (LE length)
 *   len >= 65536       -> [OpPushData4, b0, b1, b2, b3, ...data]    (LE length)
 *
 * NOTE: this is the raw data pusher (add_data), NOT the small-integer pusher
 * (add_i64 / OP_1..OP_16). A single byte 0x01..0x10 is still pushed as
 * [OpData1, byte], exactly as the Rust does for a 1-byte preimage. The covenant
 * builders only ever feed add_data 32-byte pubkeys/hashes and the spend preimage.
 *
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
export function pushData(bytes) {
  const len = bytes.length;
  if (len === 0) return Uint8Array.from([OPCODES.OpFalse]);
  if (len <= 75) return concatBytes([len], bytes);
  if (len <= 255) return concatBytes([OPCODES.OpPushData1, len], bytes);
  if (len <= 65535) return concatBytes([OPCODES.OpPushData2, len & 0xff, (len >> 8) & 0xff], bytes);
  return concatBytes(
    [OPCODES.OpPushData4, len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, (len >>> 24) & 0xff],
    bytes,
  );
}

/**
 * Push a 64-byte BIP340 signature in the exact wire form the Rust `push65` emits.
 *
 * Rust (backend/src/covenant_builder.rs:968-970):
 *   fn push65(sig: &[u8; 64]) -> Vec<u8> {
 *       std::iter::once(65u8).chain(sig.iter().copied()).chain([SIG_HASH_ALL.to_u8()]).collect()
 *   }
 *
 * So the payload is 65 BYTES total: a leading 0x41 (OpData65 == 65, the canonical
 * push-of-65-bytes opcode), then the 64 signature bytes, then ONE sighash-type byte
 * (SIG_HASH_ALL == 0x01). It is push65, not "push 64": the 65-byte value pushed onto
 * the stack is `sig(64) || sighashType(1)`. The same form appears at every other
 * push65 site (lines 454, 670, 674, 698, 744, 807, 855, 927).
 *
 * @param {Uint8Array} sig64 - the 64-byte schnorr signature (exactly 64 bytes)
 * @returns {Uint8Array} 66 bytes on the wire: [0x41, ...sig64, 0x01]
 */
export function push65(sig64) {
  if (sig64.length !== 64) {
    throw new Error(`push65 expects a 64-byte signature, got ${sig64.length}`);
  }
  return concatBytes([OPCODES.OpData65], sig64, [SIG_HASH_ALL]);
}

/**
 * Port of Rust `parse_redeem_pubkeys` (backend/src/covenant_builder.rs:944-966).
 *
 * Scans the redeem script for OpData32 (0x20) + 32-byte pushes. With
 * `checksigOnly === true`, only keep a push whose byte immediately AFTER the 32 data
 * bytes is OpCheckSig (0xac) or OpCheckSigVerify (0xad) - this excludes a
 * hashlock/HTLC hash push (followed by OpEqualVerify) and yields, in SCRIPT order:
 *   htlc                 -> [receiver, sender]
 *   channel              -> [p1, p2, p1]
 *   oracle_escrow        -> [oracle, player_a, player_b]
 *   binary_oracle_select -> [winner_a, winner_b, refund]
 * With `checksigOnly === false`, every 0x20+32 push is returned (used for an N-of-M
 * multisig whose `<m> pk1..pkn <n> OpCheckMultiSig` keys are not each directly followed
 * by a checksig op): oracle_enforced -> [oracle, winner].
 *
 * @param {Uint8Array} redeem
 * @param {boolean} checksigOnly
 * @returns {Uint8Array[]} 32-byte pubkeys in script order
 */
export function parseRedeemPubkeys(redeem, checksigOnly) {
  const out = [];
  let i = 0;
  // Rust loops `while i + 33 <= redeem.len()`.
  while (i + 33 <= redeem.length) {
    if (redeem[i] === OPCODES.OpData32) {
      let isPubkey;
      if (checksigOnly) {
        const next = redeem[i + 33]; // may be undefined at the tail
        isPubkey = next === OPCODES.OpCheckSig || next === OPCODES.OpCheckSigVerify;
      } else {
        isPubkey = true;
      }
      if (isPubkey) {
        out.push(redeem.slice(i + 1, i + 33));
        i += 33;
        continue;
      }
    }
    i += 1;
  }
  return out;
}

/**
 * Port of Rust `SpendKind::sig_op_count` (backend/src/covenant_builder.rs:303-325) for
 * the kinds the non-custodial path supports. This value is committed in the spend
 * input's sighash; too low and the node rejects the tx ("script units exceeded").
 *
 * Kaspa counts a CheckMultiSig as one sig-op per LISTED pubkey, and each
 * CheckSig / CheckSigVerify as one.
 *
 *   singlesig | hashlock | timelock | rcsv | htlc        -> 1
 *   deadman                                              -> 2 (one CheckSig per branch)
 *   channel | oracle_escrow | binary_oracle_select       -> 3
 *   oracle_enforced_refundable                           -> 3 (2 multisig + 1 refund)
 *   oracle_escrow_refundable                             -> 4 (oracle + a + b + refund)
 *   multisig                                             -> `total` (sigOpts.total)
 *   oracle | oracle_enforced                             -> `total` (the 2-of-2 multisig; default 2)
 *
 * @param {string} kind - base kind string (e.g. "singlesig", "binary_oracle_select")
 * @param {{ total?: number }} [opts] - `total` for multisig / oracle_enforced
 * @returns {number}
 */
export function sigOpCount(kind, opts = {}) {
  switch (kind) {
    case 'singlesig':
    case 'hashlock':
    case 'timelock':
    case 'rcsv':
    case 'htlc':
      return 1;
    case 'deadman':
      return 2;
    case 'channel':
    case 'oracle_escrow':
    case 'binary_oracle_select':
      return 3;
    case 'oracle_enforced_refundable':
      return 3;
    case 'oracle_escrow_refundable':
      return 4;
    case 'multisig':
      if (typeof opts.total !== 'number') {
        throw new Error('multisig sigOpCount requires opts.total (the N in m-of-N)');
      }
      return opts.total;
    case 'oracle':
    case 'oracle_enforced':
      // OracleEnforced { total }; default 2 (the [oracle, winner] 2-of-2).
      return typeof opts.total === 'number' ? opts.total : 2;
    default:
      throw new Error(`sigOpCount: unsupported kind '${kind}'`);
  }
}

/**
 * Build the SATISFIER bytes (the input signature_script CONTENT that precedes the
 * trailing redeem-script push) for a non-custodial covenant spend. This is the exact
 * `satisfier` Vec<u8> the Rust `assemble_noncustodial_satisfier` builds up (lines
 * 1008-1224) BEFORE it appends the redeem via pay_to_script_hash_signature_script
 * (line 1227). The wasm wrapper `assembleSigScript` performs that final redeem push.
 *
 * One arm per Rust match arm. The stack-order discipline is: bytes are appended in the
 * SAME order as the Rust `satisfier.extend(...)` / `satisfier.push(...)` calls, so the
 * first-pushed item sits at the BOTTOM of the stack and the last-pushed (a branch
 * selector) sits on TOP - exactly what the redeem's IF/ELSE consumes first.
 *
 * @param {object} args
 * @param {string} args.kind - base kind string
 * @param {('claim'|'refund'|'closeA'|'closeB'|'revealA'|'revealB'|'close'|'refundA'|'refundB')} [args.branch]
 *        High-level branch label; mapped to the Rust (branch_refund, winner_is_a) pair below.
 * @param {Uint8Array} [args.sig65]        - the SOLO 64-byte signature (singlesig-style kinds & branches)
 * @param {Uint8Array} [args.oracleSig]    - the 64-byte server oracle signature (oracle kinds)
 * @param {Uint8Array} [args.winnerSig]    - the 64-byte winner/player browser signature (oracle kinds)
 * @param {Uint8Array} [args.refundSig]    - the 64-byte funder/refund signature (refundable ELSE branches)
 * @param {Uint8Array[]} [args.multisigSigs] - ordered 64-byte sigs for a plain multisig (pubkey/script order)
 * @param {Uint8Array} [args.channelSig1]  - p1 sig for a channel close (members[0])
 * @param {Uint8Array} [args.channelSig2]  - p2 sig for a channel close (members[1])
 * @param {Uint8Array} [args.preimageBytes] - the revealed secret (hashlock / htlc-claim / bos reveal)
 * @param {boolean} [args.winnerIsA]       - escrow/bos: true = A/IF branch, false = B/ELSE branch
 * @returns {Uint8Array} the satisfier bytes (no redeem push appended)
 */
export function buildSatisfier(args) {
  const {
    kind,
    branch,
    sig65: solo,
    oracleSig,
    winnerSig,
    refundSig,
    multisigSigs,
    channelSig1,
    channelSig2,
    preimageBytes,
    winnerIsA,
  } = args || {};

  // Map the high-level branch label to the Rust (branch_refund, winner_is_a) pair.
  // For kinds that read winnerIsA directly (escrow / bos) the explicit arg wins; the
  // branch label is a convenience for callers and for the test vectors.
  const branchRefund = branch === 'refund' || branch === 'refundA' || branch === 'refundB';
  // Resolve the A/B (IF / ELSE) outcome selector. Track whether it was set EXPLICITLY:
  // the "branchy" kinds (oracle_escrow, oracle_escrow_refundable, binary_oracle_select)
  // have two distinct winner keys, so a silent A-vs-B default could assemble the wrong
  // outcome. That still fails on-chain (the named key's OpCheckSig rejects, fail-safe),
  // but we require an explicit outcome and fail fast at build time instead.
  let isA = true; // default only for kinds that ignore the A/B selector (singlesig-style)
  let isAExplicit = false;
  if (winnerIsA !== undefined) {
    isA = !!winnerIsA;
    isAExplicit = true;
  } else if (branch === 'revealA' || branch === 'closeA') {
    isA = true;
    isAExplicit = true;
  } else if (branch === 'revealB' || branch === 'closeB') {
    isA = false;
    isAExplicit = true;
  }

  const need = (v, msg) => {
    if (!v) throw new Error(msg);
    return v;
  };

  // For the branchy kinds, refuse to guess the outcome: an unstated A/B is a fund-path
  // footgun, so require branch 'revealA'/'revealB' (or 'closeA'/'closeB') or winnerIsA.
  const requireExplicitOutcome = () => {
    if (!isAExplicit) {
      throw new Error(
        `${kind} requires an explicit outcome: pass branch 'revealA'/'revealB' (or 'closeA'/'closeB') or winnerIsA`,
      );
    }
  };

  const parts = [];

  switch (kind) {
    // singlesig / timelock / rcsv: just push65(sig). (Rust @1010-1012)
    case 'singlesig':
    case 'timelock':
    case 'rcsv':
      parts.push(push65(need(solo, `${kind} spend needs one signature (sig65)`)));
      break;

    // hashlock: push65(sig) then pushData(preimage). (Rust @1013-1017)
    case 'hashlock':
      parts.push(push65(need(solo, 'hashlock spend needs one signature (sig65)')));
      parts.push(pushData(need(preimageBytes, 'hashlock spend requires preimageBytes')));
      break;

    // htlc: claim = receiver sig + preimage + OP_TRUE; refund = sender sig + OP_FALSE.
    // (Rust @1018-1028)
    case 'htlc':
      parts.push(push65(need(solo, 'htlc spend needs one signature (sig65)')));
      if (branchRefund) {
        parts.push([OPCODES.OpFalse]);
      } else {
        parts.push(pushData(need(preimageBytes, 'HTLC claim requires preimageBytes')));
        parts.push([OPCODES.OpTrue]);
      }
      break;

    // multisig: push each present member's sig in pubkey (script) order. The caller
    // supplies them already ordered. (Rust @1029-1042)
    case 'multisig': {
      const sigs = need(multisigSigs, 'multisig spend needs signatures (multisigSigs[])');
      if (sigs.length === 0) throw new Error('multisig spend needs at least one signature');
      for (const s of sigs) parts.push(push65(s));
      break;
    }

    // channel: refund = p1 sig + OP_FALSE; cooperative close = sig_p2, sig_p1, OP_TRUE.
    // (Rust @1043-1060)
    case 'channel':
      if (branchRefund) {
        const s = channelSig1 || solo;
        parts.push(push65(need(s, 'channel refund needs the funder (player1) signature')));
        parts.push([OPCODES.OpFalse]);
      } else {
        parts.push(push65(need(channelSig2, "channel close needs player2's signature")));
        parts.push(push65(need(channelSig1, "channel close needs player1's signature")));
        parts.push([OPCODES.OpTrue]);
      }
      break;

    // deadman: owner (IF) = sig + OP_TRUE; heir (ELSE) = sig + OP_FALSE. (Rust @1061-1065)
    case 'deadman':
      parts.push(push65(need(solo, 'deadman spend needs one signature (sig65)')));
      parts.push([branchRefund ? OPCODES.OpFalse : OPCODES.OpTrue]);
      break;

    // oracle / oracle_enforced: 2-of-2 [oracle, winner]; OpCheckMultiSig pops sigs in
    // pubkey (script) order, so push oracle FIRST then winner. (Rust @1070-1081)
    case 'oracle':
    case 'oracle_enforced':
      parts.push(push65(need(oracleSig, 'oracle payout needs the server oracle signature')));
      parts.push(push65(need(winnerSig || solo, "oracle payout needs the winner's browser signature")));
      break;

    // oracle_escrow: bottom->top = <winner_sig> <branch_selector> <oracle_sig>.
    // (Rust @1082-1095)
    case 'oracle_escrow':
      requireExplicitOutcome();
      parts.push(push65(need(winnerSig || solo, "oracle_escrow needs the winning player's signature")));
      parts.push([isA ? OPCODES.OpTrue : OPCODES.OpFalse]);
      parts.push(push65(need(oracleSig, 'oracle_escrow payout needs the server oracle signature')));
      break;

    // oracle_enforced_refundable: outer IF = the 2-of-2 [oracle, winner] then OP_TRUE;
    // outer ELSE (refund) = <refund_sig> OP_FALSE. (Rust @1101-1126)
    case 'oracle_enforced_refundable':
      if (branchRefund) {
        parts.push(push65(need(refundSig || solo, 'refund needs the funder/refund key signature')));
        parts.push([OPCODES.OpFalse]);
      } else {
        parts.push(push65(need(oracleSig, 'payout needs the server oracle signature')));
        parts.push(push65(need(winnerSig || solo, "payout needs the winner's browser signature")));
        parts.push([OPCODES.OpTrue]);
      }
      break;

    // oracle_escrow_refundable: outer IF = oracle_escrow layout then OP_TRUE; outer ELSE
    // (refund) = <refund_sig> OP_FALSE. (Rust @1127-1153)
    case 'oracle_escrow_refundable':
      if (branchRefund) {
        parts.push(push65(need(refundSig || solo, 'refund needs the funder/refund key signature')));
        parts.push([OPCODES.OpFalse]);
      } else {
        requireExplicitOutcome();
        parts.push(push65(need(winnerSig || solo, "payout needs the winning player's signature")));
        parts.push([isA ? OPCODES.OpTrue : OPCODES.OpFalse]);
        parts.push(push65(need(oracleSig, 'payout needs the server oracle signature')));
        parts.push([OPCODES.OpTrue]);
      }
      break;

    // binary_oracle_select (the parimutuel-bundle leg), winner-only NON-CUSTODIAL.
    // (Rust @1166-1224). Stack bottom->top:
    //   RevealA = <sig_a> <preimage> OP_TRUE
    //   RevealB = <sig_b> <preimage> OP_TRUE OP_FALSE
    //   Refund  = <sig_refund> OP_FALSE OP_FALSE
    case 'binary_oracle_select':
      if (branchRefund) {
        parts.push(push65(need(refundSig || solo, 'binary_oracle_select refund needs the refund key signature')));
        parts.push([OPCODES.OpFalse]);
        parts.push([OPCODES.OpFalse]);
      } else {
        // RevealA uses the A key, RevealB uses the B key; the caller passes that as
        // winnerSig (or solo) for whichever branch isA selects.
        requireExplicitOutcome();
        parts.push(push65(need(winnerSig || solo, 'binary_oracle_select reveal needs the branch key signature')));
        parts.push(pushData(need(preimageBytes, 'binary_oracle_select reveal requires preimageBytes')));
        parts.push([OPCODES.OpTrue]);
        if (!isA) parts.push([OPCODES.OpFalse]); // outer IF -> ELSE (top of stack)
      }
      break;

    default:
      throw new Error(`buildSatisfier: unsupported kind '${kind}'`);
  }

  // Normalize each part (number[] selector or Uint8Array) and concat in push order.
  return concatBytes(...parts.map((p) => (p instanceof Uint8Array ? p : Uint8Array.from(p))));
}

/**
 * Per-(kind, branch) map of WHICH parsed-pubkey index the chain will OpCheckSig for the
 * signer of that branch, plus how to parse the redeem (checksigOnly) to get that key.
 *
 * The index is into `parseRedeemPubkeys(redeem, checksigOnly)`'s SCRIPT-ORDER output, NOT
 * into the buildSatisfier push order. (For oracle kinds those differ: the satisfier pushes
 * oracle-first, but the parse returns oracle-first too here because the redeem lists oracle
 * first - see parseRedeemPubkeys doc.) Derived from this module's own parseRedeemPubkeys
 * comments and the Rust redeem builders.
 *
 *   parse order per kind (checksigOnly=true unless noted):
 *     singlesig/timelock/rcsv/hashlock -> [key]
 *     htlc                             -> [receiver, sender]
 *     deadman                          -> [owner, heir]
 *     channel                          -> [p1, p2, p1]   (close needs BOTH p1 and p2)
 *     binary_oracle_select             -> [winner_a, winner_b, refund]
 *     oracle_escrow                    -> [oracle, a, b]
 *     oracle_escrow_refundable         -> [oracle, a, b, refund]
 *     oracle_enforced (checksigOnly=false) -> [oracle, winner]
 *     oracle_enforced_refundable (checksigOnly=false) -> [oracle, winner, refund]
 *
 * A value is either a single number (the index the named signer's key sits at) or, for a
 * cooperative-close branch with two required signers, an array of indices (both expected).
 */
const SIGNER_INDEX_MAP = Object.freeze({
  singlesig: { checksigOnly: true, branches: { claim: 0 } },
  timelock: { checksigOnly: true, branches: { claim: 0 } },
  rcsv: { checksigOnly: true, branches: { claim: 0 } },
  hashlock: { checksigOnly: true, branches: { claim: 0 } },
  htlc: { checksigOnly: true, branches: { claim: 0, refund: 1 } },
  deadman: { checksigOnly: true, branches: { claim: 0, refund: 1 } },
  // channel: refund is p1 (index 0); a cooperative close requires BOTH p1 and p2 sigs.
  channel: { checksigOnly: true, branches: { refund: 0, close: [1, 0], closeA: [1, 0], closeB: [1, 0] } },
  binary_oracle_select: { checksigOnly: true, branches: { revealA: 0, revealB: 1, refund: 2 } },
  oracle_escrow: { checksigOnly: true, branches: { revealA: 1, revealB: 2, closeA: 1, closeB: 2 } },
  oracle_escrow_refundable: { checksigOnly: true, branches: { revealA: 1, revealB: 2, closeA: 1, closeB: 2, refund: 3 } },
  // oracle_enforced / oracle: the [oracle, winner] keys live inside an N-of-M multisig, so the
  // winner pubkey is NOT directly followed by a checksig op -> parse with checksigOnly=false.
  oracle: { checksigOnly: false, branches: { claim: 1 } },
  oracle_enforced: { checksigOnly: false, branches: { claim: 1 } },
  oracle_enforced_refundable: { checksigOnly: false, branches: { claim: 1, refund: 2 } },
});

// Aliases so a caller can pass the same branch labels buildSatisfier accepts. 'close' /
// 'reveal' default to the A side; an explicit A/B label is preferred for the branchy kinds.
function normalizeBranchLabel(kind, branch) {
  const b = branch || 'claim';
  const entry = SIGNER_INDEX_MAP[kind];
  if (!entry) return b;
  if (entry.branches[b] !== undefined) return b;
  // Map convenience synonyms to the canonical keys present in the map.
  if (b === 'reveal' || b === 'revealA') return entry.branches.revealA !== undefined ? 'revealA' : (entry.branches.claim !== undefined ? 'claim' : b);
  if (b === 'revealB') return entry.branches.revealB !== undefined ? 'revealB' : b;
  if (b === 'close' || b === 'closeA') return entry.branches.closeA !== undefined ? 'closeA' : (entry.branches.close !== undefined ? 'close' : b);
  if (b === 'closeB') return entry.branches.closeB !== undefined ? 'closeB' : b;
  if (b === 'refundA' || b === 'refundB') return entry.branches.refund !== undefined ? 'refund' : b;
  // 'claim' is the generic single-signer label; fall back to the first non-refund branch.
  if (b === 'claim') {
    if (entry.branches.claim !== undefined) return 'claim';
    if (entry.branches.revealA !== undefined) return 'revealA';
  }
  return b;
}

/**
 * FAIL-CLOSED named-key binding (security-audit request). Before signing, prove that the
 * x-only pubkey the user is about to sign with is the EXACT key the chain will OpCheckSig on
 * the chosen (kind, branch). This catches "right covenant, wrong key/branch" up front, instead
 * of letting it fail late at the node (or, worse, letting a holder waste a fee on a doomed tx).
 *
 * Pure: parses the redeem with parseRedeemPubkeys and compares bytes. No wasm, no network.
 *
 * @param {string} redeemHex          - hex of the covenant redeem script
 * @param {string} kind               - base kind string (e.g. 'htlc', 'binary_oracle_select')
 * @param {string} branch             - branch label ('claim'|'refund'|'revealA'|'revealB'|'closeA'|'closeB'|'close')
 * @param {string} signerXonlyHex     - the signer's 32-byte x-only pubkey, hex (64 chars)
 * @returns {{ index: number, namedKeyHex: string }} the matched index + the named key it bound to.
 *          For a cooperative close (two required signers) `index` is the index the signer matched
 *          and `namedKeyHex` that key; pass each co-signer's pubkey to bind both.
 * @throws if the kind/branch is unknown, the redeem has too few keys, or the signer's pubkey is
 *         not the named key (or, for a close, not EITHER required co-signer key).
 */
export function assertSignerForBranch(redeemHex, kind, branch, signerXonlyHex) {
  const entry = SIGNER_INDEX_MAP[kind];
  if (!entry) {
    throw new Error(`assertSignerForBranch: unsupported kind '${kind}'`);
  }
  const label = normalizeBranchLabel(kind, branch);
  const idxSpec = entry.branches[label];
  if (idxSpec === undefined) {
    throw new Error(`assertSignerForBranch: kind '${kind}' has no branch '${branch}'`);
  }

  let signer;
  try {
    signer = hexToBytes(signerXonlyHex);
  } catch (e) {
    throw new Error(`assertSignerForBranch: signer pubkey is not valid hex (${e.message})`);
  }
  if (signer.length !== 32) {
    throw new Error(`assertSignerForBranch: signer x-only pubkey must be 32 bytes, got ${signer.length}`);
  }

  const redeem = hexToBytes(redeemHex);
  const keys = parseRedeemPubkeys(redeem, entry.checksigOnly);

  const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  const signerArr = Array.from(signer);
  const wantIndices = Array.isArray(idxSpec) ? idxSpec : [idxSpec];
  const maxIdx = Math.max(...wantIndices);
  if (keys.length <= maxIdx) {
    throw new Error(
      `assertSignerForBranch: redeem for '${kind}' parsed ${keys.length} key(s), need index ${maxIdx} (wrong kind, wrong checksigOnly, or truncated redeem)`,
    );
  }

  for (const i of wantIndices) {
    if (eq(Array.from(keys[i]), signerArr)) {
      return { index: i, namedKeyHex: bytesToHex(keys[i]) };
    }
  }

  // Not the named key. Report WHICH key the chain expects so the holder sees they have the
  // wrong key/branch, without leaking anything secret (these pubkeys are public on-chain).
  const expected = wantIndices.map((i) => `#${i}=${bytesToHex(keys[i])}`).join(' or ');
  throw new Error(
    `assertSignerForBranch: your key ${bytesToHex(signer)} is NOT the ${kind} ${label} signer. The chain checks ${expected} on this branch. Use the correct key, or the correct branch.`,
  );
}

/**
 * Honest per-kind offline-claimability matrix (single source of truth shared by the recovery
 * UI and the recovery-kit export). "Offline-claimable" means a holder can satisfy the branch
 * end-to-end with ONLY a revealed-on-chain secret and/or the named key's signature - no Covex
 * oracle co-signature required. Mirrors the module-header honesty note and the memory matrix.
 *
 * Each entry: { offlineClaimable, branches: { <branch>: { offline: bool, role, note } }, liveness }
 *   - branches[].offline: is THAT branch claimable with no Covex involvement?
 *   - branches[].role:    which named key/secret the holder must provide
 *   - liveness:           a plain-language note about what (if anything) still needs the oracle
 */
export const KIND_CLAIM_MATRIX = Object.freeze({
  singlesig: { offlineClaimable: true, branches: { claim: { offline: true, role: 'your key' } }, liveness: 'Fully script-enforced. Claim any time with your key. No oracle.' },
  timelock: { offlineClaimable: true, branches: { claim: { offline: true, role: 'your key (after locktime)' } }, liveness: 'Fully script-enforced. Claim with your key once the locktime / DAA threshold passes. No oracle.' },
  rcsv: { offlineClaimable: true, branches: { claim: { offline: true, role: 'your key (after relative delay)' } }, liveness: 'Fully script-enforced (BIP68 relative locktime). Claim with your key after the relative delay. No oracle.' },
  hashlock: { offlineClaimable: true, branches: { claim: { offline: true, role: 'your key + the revealed preimage' } }, liveness: 'Fully script-enforced. Reveal the preimage and sign with your key. No oracle.' },
  htlc: {
    offlineClaimable: true,
    branches: {
      claim: { offline: true, role: 'receiver key + the revealed preimage' },
      refund: { offline: true, role: 'sender key (after timeout)' },
    },
    liveness: 'Fully script-enforced. Claim by revealing the preimage, or refund after the timeout. No oracle.',
  },
  multisig: { offlineClaimable: true, branches: { claim: { offline: true, role: 'the threshold of committed keys' } }, liveness: 'Fully script-enforced. Collect the required signatures and spend. No oracle.' },
  channel: {
    offlineClaimable: true,
    branches: {
      close: { offline: true, role: 'both participant keys (cooperative close)' },
      refund: { offline: true, role: 'funder (player1) key (after timeout)' },
    },
    liveness: 'Fully script-enforced. Close cooperatively with both keys, or the funder refunds after the timeout. No oracle.',
  },
  deadman: {
    offlineClaimable: true,
    branches: {
      claim: { offline: true, role: 'owner key' },
      refund: { offline: true, role: 'heir key (after the dead-man delay)' },
    },
    liveness: 'Fully script-enforced. Owner spends any time; the heir takes over after the delay. No oracle.',
  },
  binary_oracle_select: {
    offlineClaimable: true,
    branches: {
      revealA: { offline: true, role: 'winner-A key + the revealed secret' },
      revealB: { offline: true, role: 'winner-B key + the revealed secret' },
      refund: { offline: true, role: 'refund key (after the CSV delay)' },
    },
    // The leg becomes self-claimable the moment the secret is public; before that, only the
    // oracle knows it. Honest: the secret-reveal is the oracle liveness dependency.
    liveness: 'Offline-claimable ONCE the outcome secret is revealed on-chain (the disclosed Covex oracle reveals it for the true result). Before reveal, only the oracle can produce the secret. The refund branch is always offline-claimable after the CSV delay.',
  },
  oracle_escrow: {
    offlineClaimable: false,
    branches: {
      revealA: { offline: false, role: 'winning-player key + the Covex oracle co-signature' },
      revealB: { offline: false, role: 'winning-player key + the Covex oracle co-signature' },
    },
    liveness: 'NOT offline-claimable: the winning payout requires the disclosed Covex oracle co-signature. There is no refund branch on this kind, so it depends on oracle liveness. Prefer the *_refundable variant for a self-claimable fallback.',
  },
  oracle_enforced: {
    offlineClaimable: false,
    branches: {
      claim: { offline: false, role: 'winner key + the Covex oracle co-signature' },
    },
    liveness: 'NOT offline-claimable: the winning payout is a 2-of-2 that requires the disclosed Covex oracle co-signature. No refund branch, so it depends on oracle liveness.',
  },
  oracle_enforced_refundable: {
    offlineClaimable: false,
    branches: {
      claim: { offline: false, role: 'winner key + the Covex oracle co-signature' },
      refund: { offline: true, role: 'funder/refund key (after lock_daa)' },
    },
    liveness: 'The WIN path needs the disclosed Covex oracle co-signature (not offline-claimable). The REFUND branch is fully offline-claimable with your refund key after lock_daa.',
  },
  oracle_escrow_refundable: {
    offlineClaimable: false,
    branches: {
      revealA: { offline: false, role: 'winning-player key + the Covex oracle co-signature' },
      revealB: { offline: false, role: 'winning-player key + the Covex oracle co-signature' },
      refund: { offline: true, role: 'funder/refund key (after lock_daa)' },
    },
    liveness: 'The WIN path needs the disclosed Covex oracle co-signature (not offline-claimable). The REFUND branch is fully offline-claimable with your refund key after lock_daa.',
  },
});

/**
 * Resolve the honest claimability of a (kind, branch). Convenience over KIND_CLAIM_MATRIX
 * that normalizes branch synonyms the same way assertSignerForBranch does. Returns null for
 * an unknown kind so a caller can fall back to a conservative "needs the redeem script" message.
 *
 * @param {string} kind
 * @param {string} [branch]
 * @returns {{ offline: boolean, role: string, liveness: string, kindOfflineClaimable: boolean } | null}
 */
export function claimability(kind, branch) {
  const entry = KIND_CLAIM_MATRIX[kind];
  if (!entry) return null;
  const label = normalizeBranchLabel(kind, branch);
  const b = entry.branches[label]
    || entry.branches.claim
    || entry.branches.revealA
    || Object.values(entry.branches)[0]
    || { offline: !!entry.offlineClaimable, role: 'the required key(s)' };
  return {
    offline: !!b.offline,
    role: b.role,
    liveness: entry.liveness,
    kindOfflineClaimable: !!entry.offlineClaimable,
  };
}

// ===========================================================================
// (B) WASM-BACKED WRAPPERS - lazy `import('@onekeyfe/kaspa-wasm')` inside each fn so
//     importing the pure core (section A) never pulls the ~15MB wasm. Browser/e2e
//     tested later, NOT in CI. These build/sign/assemble/broadcast a real spend.
// ===========================================================================

/**
 * Lazily load the kaspa-wasm module. Kept private; every wrapper calls it so the import
 * graph of the pure core stays wasm-free.
 * @returns {Promise<object>} the kaspa-wasm module namespace
 */
async function loadWasm() {
  const k = await import('@onekeyfe/kaspa-wasm');
  return k;
}

/**
 * Build the UNSIGNED spend transaction for a single covenant UTXO -> one destination
 * output. The redeem's P2SH script is set as the input's previous scriptPublicKey so the
 * sighash commits the correct script. `sigOpCount` MUST be the value from the pure-core
 * sigOpCount() for the kind (the node enforces it).
 *
 * @param {object} p
 * @param {{ transactionId: string, index: number, amount: bigint|number, scriptPublicKey?: any }} p.utxo
 * @param {string} p.redeemHex   - hex of the redeem script (used to derive the P2SH spk)
 * @param {string} p.destAddr    - destination Kaspa address (kaspa:/kaspatest: ...)
 * @param {string} p.networkId   - 'mainnet' | 'testnet-10' | 'testnet-12'; the dest address prefix is validated against it
 * @param {bigint|number} p.fee   - fee in sompi (REQUIRED); the sole output value is DERIVED as utxo.amount - fee
 * @param {string} p.kind        - base kind, for sigOpCount
 * @param {string} [p.branch]    - branch label (unused for tx shape, kept for symmetry)
 * @param {bigint|number} [p.lockTime] - tx lockTime (required for timelock/CLTV claims)
 * @param {bigint|number} [p.sequence] - input sequence (required for CSV/rcsv & refund branches)
 * @param {number} [p.total]     - multisig/oracle_enforced N, for sigOpCount
 * @returns {Promise<object>} an unsigned kaspa-wasm Transaction
 */
export async function buildUnsignedSpend(p) {
  // ---- Fail-closed invariants. Run BEFORE loadWasm() so they are unit-testable in CI
  // (vitest) without the wasm, and so a wired UI cannot leak funds via bad inputs. ----
  if (!p || typeof p !== 'object') throw new Error('buildUnsignedSpend: params object required');
  if (!p.utxo || p.utxo.transactionId === undefined || p.utxo.index === undefined || p.utxo.amount === undefined) {
    throw new Error('buildUnsignedSpend: p.utxo {transactionId, index, amount} is required');
  }
  if (!p.redeemHex) throw new Error('buildUnsignedSpend: p.redeemHex is required');
  if (!p.destAddr) throw new Error('buildUnsignedSpend: p.destAddr is required');

  // Destination address prefix MUST match the broadcast network (a kaspatest: address on a
  // mainnet spend, or vice versa, would only fail late at the node).
  const NETWORK_PREFIX = { mainnet: 'kaspa:', 'testnet-10': 'kaspatest:', 'testnet-12': 'kaspatest:' };
  const prefix = NETWORK_PREFIX[p.networkId];
  if (!prefix) {
    throw new Error(`buildUnsignedSpend: unsupported networkId '${p.networkId}' (mainnet | testnet-10 | testnet-12)`);
  }
  if (!String(p.destAddr).startsWith(prefix)) {
    throw new Error(`buildUnsignedSpend: destination ${p.destAddr} is not a ${p.networkId} address (expected ${prefix})`);
  }

  // Fee is REQUIRED and the SOLE output value is derived as utxo.amount - fee (mirrors the
  // backend computing outputs = amount - TX_FEE and rejecting amount <= fee). SIG_HASH_ALL
  // commits this single output, so deriving it here - rather than trusting a caller-passed
  // amount - is what makes the signed spend non-redirectable.
  const utxoAmount = BigInt(p.utxo.amount);
  if (p.fee === undefined) throw new Error('buildUnsignedSpend: p.fee (sompi) is required');
  const fee = BigInt(p.fee);
  if (fee <= 0n) throw new Error('buildUnsignedSpend: fee must be positive');
  const value = utxoAmount - fee;
  const MIN_SPENDABLE = 1000n; // tiny floor; the node enforces the authoritative storage-mass / dust limit
  if (value < MIN_SPENDABLE) {
    throw new Error(`buildUnsignedSpend: output (utxo ${utxoAmount} - fee ${fee} = ${value}) is below the spendable floor`);
  }

  // Couple lockTime / sequence to kind + branch. The backend derives and commits these in
  // the sighash; a missing CLTV/CSV operand otherwise only fails late at the node.
  const isRefundBranch = p.branch === 'refund' || p.branch === 'refundA' || p.branch === 'refundB';
  const needsLockTime = p.kind === 'timelock'
    || (p.kind === 'htlc' && isRefundBranch)
    || (p.kind === 'channel' && isRefundBranch)
    || (p.kind === 'deadman' && isRefundBranch); // heir / ELSE is the CLTV branch
  const needsSequence = p.kind === 'rcsv'
    || (p.kind === 'binary_oracle_select' && isRefundBranch);
  if (needsLockTime && (p.lockTime === undefined || BigInt(p.lockTime) <= 0n)) {
    throw new Error(`buildUnsignedSpend: ${p.kind} ${p.branch || ''} requires a positive lockTime (CLTV)`);
  }
  if (needsSequence && (p.sequence === undefined || BigInt(p.sequence) <= 0n)) {
    throw new Error(`buildUnsignedSpend: ${p.kind} ${p.branch || ''} requires a positive sequence (CSV)`);
  }

  const k = await loadWasm();
  const { Transaction, payToScriptHashScript, addressToScriptPublicKey } = k;

  const redeem = hexToBytes(p.redeemHex);
  // P2SH script the UTXO is locked to (what the sighash must commit as the input's spk).
  const p2sh = payToScriptHashScript(redeem);

  const ops = sigOpCount(p.kind, { total: p.total });
  const seq = p.sequence !== undefined ? BigInt(p.sequence) : 0n;

  const input = {
    previousOutpoint: {
      transactionId: p.utxo.transactionId,
      index: p.utxo.index >>> 0,
    },
    signatureScript: new Uint8Array(0), // filled by assembleSigScript after signing
    sequence: seq,
    sigOpCount: ops,
    // The previous output's value+script: required so the wasm can compute the sighash.
    utxo: {
      address: undefined,
      amount: BigInt(p.utxo.amount),
      scriptPublicKey: p.utxo.scriptPublicKey || p2sh,
      blockDaaScore: 0n,
      isCoinbase: false,
    },
  };

  const outputScript = addressToScriptPublicKey(p.destAddr);
  const output = { value, scriptPublicKey: outputScript };

  const tx = new Transaction({
    version: 0,
    inputs: [input],
    outputs: [output],
    lockTime: p.lockTime !== undefined ? BigInt(p.lockTime) : 0n,
    subnetworkId: new Uint8Array(20),
    gas: 0n,
    payload: new Uint8Array(0),
  });
  return tx;
}

/**
 * Produce the 64-byte BIP340 signature for input `idx` over the tx's sighash, using a
 * private key held entirely in the browser. Uses kaspa-wasm's createInputSignature with
 * the default SIG_HASH_ALL. The key never leaves this function.
 *
 * @param {object} tx     - the unsigned Transaction (or SignableTransaction) from buildUnsignedSpend
 * @param {number} idx    - input index to sign
 * @param {string} privKeyHex - 32-byte secret key hex (browser-held; never transmitted)
 * @returns {Promise<Uint8Array>} the 64-byte schnorr signature (feed to buildSatisfier)
 */
export async function signInput(tx, idx, privKeyHex) {
  const k = await loadWasm();
  const { PrivateKey, createInputSignature, SighashType } = k;
  const pk = new PrivateKey(privKeyHex);
  try {
    // createInputSignature(tx, inputIndex, privateKey, sighashType) -> hex/bytes.
    const sighashAll = SighashType ? SighashType.All : undefined;
    const sigRaw = createInputSignature(tx, idx, pk, sighashAll);
    let sig = typeof sigRaw === 'string' ? hexToBytes(sigRaw) : new Uint8Array(sigRaw);
    // kaspa-wasm may return 64 bytes (raw) or 65 (sig||sighashtype). Normalize to 64;
    // push65() re-appends the sighash-type byte to match the Rust wire form.
    if (sig.length === 65) sig = sig.slice(0, 64);
    if (sig.length !== 64) throw new Error(`unexpected signature length ${sig.length}`);
    return sig;
  } finally {
    if (pk && typeof pk.free === 'function') pk.free();
  }
}

/**
 * Assemble the final input signature_script: the satisfier bytes (from the pure-core
 * buildSatisfier) followed by the canonical redeem-script push, exactly as the Rust
 * pay_to_script_hash_signature_script does (backend/src/covenant_builder.rs:1227). We
 * delegate to the wasm so the redeem push and any length encoding are produced by the
 * same library the node validates against.
 *
 * @param {string} redeemHex      - hex of the redeem script
 * @param {Uint8Array} satisfierBytes - output of buildSatisfier()
 * @returns {Promise<Uint8Array>} the full signature_script for the input
 */
export async function assembleSigScript(redeemHex, satisfierBytes) {
  const k = await loadWasm();
  const { payToScriptHashSignatureScript } = k;
  const redeem = hexToBytes(redeemHex);
  const script = payToScriptHashSignatureScript(redeem, satisfierBytes);
  return typeof script === 'string' ? hexToBytes(script) : new Uint8Array(script);
}

/**
 * Broadcast a fully-signed transaction to the Kaspa network via a public node. Uses
 * kaspa-wasm's Resolver to find a node for `networkId` (so no Covex infrastructure is
 * required - this is the "Covex is down" path). Returns the accepted txid.
 *
 * @param {object} signedTx   - a Transaction whose input signatureScripts are assembled
 * @param {string} networkId  - 'mainnet' | 'testnet-10' | 'testnet-12'
 * @param {{ nodeUrl?: string }} [opts] - pin a specific wRPC node URL (for the "Covex is down"
 *        scenario, or to avoid the public Resolver); otherwise a public Resolver node is used
 * @returns {Promise<string>} the broadcast transaction id
 */
export const BROADCAST_NETWORKS = Object.freeze(['mainnet', 'testnet-10', 'testnet-12']);

export async function broadcast(signedTx, networkId, opts = {}) {
  if (!BROADCAST_NETWORKS.includes(networkId)) {
    throw new Error(`broadcast: unsupported networkId '${networkId}' (expected one of ${BROADCAST_NETWORKS.join(', ')})`);
  }
  const k = await loadWasm();
  const { RpcClient, Resolver } = k;
  // A caller-pinned node URL takes precedence; otherwise discover a public node via Resolver.
  // Only the fully-signed tx is sent (its sig + any revealed preimage are public on-chain
  // anyway); the private key never touches this path.
  const rpc = opts && opts.nodeUrl
    ? new RpcClient({ url: opts.nodeUrl, networkId })
    : new RpcClient({ resolver: new Resolver(), networkId });
  await rpc.connect();
  try {
    const res = await rpc.submitTransaction({ transaction: signedTx, allowOrphan: false });
    return res.transactionId || res.txId || res;
  } finally {
    try {
      await rpc.disconnect();
    } catch (_) {
      /* best effort */
    }
  }
}

/**
 * Export a signed transaction as JSON for the cold/offline tool (broadcast elsewhere).
 * Falls back gracefully across the kaspa-wasm serialization API surface.
 *
 * @param {object} signedTx
 * @returns {Promise<string>} a JSON string the standalone cold tool can submit
 */
export async function exportSignedTxJson(signedTx) {
  await loadWasm(); // ensure wasm types are initialized for any lazy getters
  if (signedTx && typeof signedTx.serializeToSafeJSON === 'function') {
    return signedTx.serializeToSafeJSON();
  }
  if (signedTx && typeof signedTx.toJSON === 'function') {
    return JSON.stringify(signedTx.toJSON());
  }
  return JSON.stringify(signedTx);
}
