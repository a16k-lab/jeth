// Phase 4d scenario "intN-signext-elements": signed-integer element validation in
// fixed-array and struct calldata params. Arrays int8[4], int16[3], int64[2],
// int128[2], int256[2], plus a struct {int8 a; int128 b; int256 c}. For each signed
// leaf we probe: a valid positive value, a valid NEGATIVE value (canonical two's-
// complement sign-extension into the full 256-bit ABI word), the type MIN and MAX,
// and a DIRTY non-canonical encoding (wrong high bits, not a sign-extension) expecting
// an EMPTY revert (lazy per-access validation). Every probe must be byte-identical to
// Solidity (the oracle): success + the full 32-byte returndata word (so a returned
// negative is the exact 0xfff...sign-extended word), '0x' for empty reverts, and
// 0x4e487b71 + 0x32 for runtime OOB panics. We also confirm that an UNREAD dirty
// element is ignored (lazy), and that a clean read of one element does not trip on a
// dirty sibling.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
// Encode a (possibly negative) integer into its canonical 256-bit ABI word (two's
// complement, sign-extended to 256 bits). This is what solc emits for an intN value.
function pad(v: bigint): string {
  return (((v % M) + M) % M).toString(16).padStart(64, '0');
}

// JETH source: signed fixed-array getters + a signed-struct getter set.
const JETH = `// generated: signed element validation in array & struct params
@struct class Tri { a: i8; b: i128; c: i256; }
@contract
class SignExt {
  // signed fixed-array params, returned with a runtime index
  @external @pure i8at(a: Arr<i8, 4>, i: u256): i8 { return a[i]; }
  @external @pure i16at(a: Arr<i16, 3>, i: u256): i16 { return a[i]; }
  @external @pure i64at(a: Arr<i64, 2>, i: u256): i64 { return a[i]; }
  @external @pure i128at(a: Arr<i128, 2>, i: u256): i128 { return a[i]; }
  @external @pure i256at(a: Arr<i256, 2>, i: u256): i256 { return a[i]; }

  // signed struct fields {int8 a; int128 b; int256 c}
  @external @pure triA(t: Tri): i8 { return t.a; }
  @external @pure triB(t: Tri): i128 { return t.b; }
  @external @pure triC(t: Tri): i256 { return t.c; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract SignExt {
  struct Tri { int8 a; int128 b; int256 c; }
  function i8at(int8[4] calldata a, uint256 i) external pure returns (int8){ return a[i]; }
  function i16at(int16[3] calldata a, uint256 i) external pure returns (int16){ return a[i]; }
  function i64at(int64[2] calldata a, uint256 i) external pure returns (int64){ return a[i]; }
  function i128at(int128[2] calldata a, uint256 i) external pure returns (int128){ return a[i]; }
  function i256at(int256[2] calldata a, uint256 i) external pure returns (int256){ return a[i]; }
  function triA(Tri calldata t) external pure returns (int8){ return t.a; }
  function triB(Tri calldata t) external pure returns (int128){ return t.b; }
  function triC(Tri calldata t) external pure returns (int256){ return t.c; }
}`;

// Per-type canonical bounds and a DIRTY (non-canonical) 256-bit word that is NOT a
// sign-extension of its low N bits, so reading it must EMPTY-revert.
interface SignedType {
  bits: number;
  min: bigint; // -(2^(bits-1))
  max: bigint; // 2^(bits-1) - 1
  dirty: bigint; // a non-canonical ABI word for intN (wrong high bits)
}
function mk(bits: number, dirty: bigint): SignedType {
  return { bits, min: -(1n << BigInt(bits - 1)), max: (1n << BigInt(bits - 1)) - 1n, dirty };
}
// Dirty words: high bits set that do NOT match the sign-extension of the low N bits.
// i8:  0x000000ff...ff in the low byte but bit 8 set (0x1ff) -> low byte 0xff would
//       sign-extend to all-ones, but high bits are 0, so non-canonical.
// i16: 0x18000 (bit 16 set, low 16 bits = 0x8000) -> not a sign-extension.
const SIGNED: Record<string, SignedType> = {
  i8: mk(8, 0x1ffn),
  i16: mk(16, 0x18000n),
  i64: mk(64, 1n << 64n),
  i128: mk(128, 1n << 128n),
  i256: mk(256, 0n), // i256 has no high bits to dirty; every 256-bit word is canonical
};

describe('intN sign-extension in array & struct params vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);

  function raw(selSig: string, words: bigint[]): string {
    return '0x' + sel(selSig) + words.map(pad).join('');
  }
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  // Assert JETH == Solidity byte-for-byte (success + full returndata word).
  async function eq(label: string, data: string) {
    const { j, s } = await both(data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'SignExt.jeth' });
    const sb = compileSolidity(SOL, 'SignExt');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  // ---- fixed-array params: one block per element type ------------------------------

  it('int8[4]: positive, negative, min, max byte-identical', async () => {
    const t = SIGNED.i8!;
    // a = [ +5, -1, MIN(-128), MAX(127) ]
    const a = [5n, -1n, t.min, t.max];
    for (const i of [0n, 1n, 2n, 3n]) {
      const r = await eq(`i8at[${i}]`, raw('i8at(int8[4],uint256)', [...a, i]));
      // returned word must equal the canonical sign-extension of the input element.
      expect(r.j.returnHex).toBe('0x' + pad(a[Number(i)]!));
    }
    // runtime OOB -> Panic(0x32)
    const oob = await eq('i8at OOB', raw('i8at(int8[4],uint256)', [...a, 4n]));
    expect(oob.j.success).toBe(false);
    expect(oob.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
  });

  it('int8[4]: dirty element read -> EMPTY revert; unread dirty ignored', async () => {
    const t = SIGNED.i8!;
    // a[1] dirty (0x1ff): low byte 0xff would mean -1 sign-extended, but high bits 0.
    const a = [1n, t.dirty, 2n, 3n];
    const bad = await eq('i8at dirty read i=1', raw('i8at(int8[4],uint256)', [...a, 1n]));
    expect(bad.j.success).toBe(false);
    expect(bad.j.returnHex).toBe('0x');
    // read a CLEAN sibling i=0 -> OK (lazy: dirty sibling ignored)
    const ok = await eq('i8at dirty-unread i=0', raw('i8at(int8[4],uint256)', [...a, 0n]));
    expect(ok.j.success).toBe(true);
    expect(ok.j.returnHex).toBe('0x' + pad(1n));
  });

  it('int16[3]: positive, negative, min/max + dirty', async () => {
    const t = SIGNED.i16!;
    const a = [t.max, -1n, t.min]; // [32767, -1, -32768]
    for (const i of [0n, 1n, 2n]) {
      const r = await eq(`i16at[${i}]`, raw('i16at(int16[3],uint256)', [...a, i]));
      expect(r.j.returnHex).toBe('0x' + pad(a[Number(i)]!));
    }
    // dirty 0x18000 at index 0, read it -> EMPTY revert
    const bad = await eq('i16at dirty i=0', raw('i16at(int16[3],uint256)', [t.dirty, -1n, t.min, 0n]));
    expect(bad.j.success).toBe(false);
    expect(bad.j.returnHex).toBe('0x');
    // OOB
    const oob = await eq('i16at OOB', raw('i16at(int16[3],uint256)', [...a, 3n]));
    expect(oob.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
  });

  it('int64[2]: positive, negative, min/max + dirty', async () => {
    const t = SIGNED.i64!;
    for (const [a, label] of [
      [[7n, -7n], 'small'],
      [[t.max, t.min], 'bounds'],
    ] as [bigint[], string][]) {
      for (const i of [0n, 1n]) {
        const r = await eq(`i64at ${label}[${i}]`, raw('i64at(int64[2],uint256)', [...a, i]));
        expect(r.j.returnHex).toBe('0x' + pad(a[Number(i)]!));
      }
    }
    // dirty high bit 64 set on a[1]; reading it reverts empty, reading a[0] is fine.
    const aDirty = [3n, t.dirty];
    const bad = await eq('i64at dirty i=1', raw('i64at(int64[2],uint256)', [...aDirty, 1n]));
    expect(bad.j.success).toBe(false);
    expect(bad.j.returnHex).toBe('0x');
    const ok = await eq('i64at dirty-unread i=0', raw('i64at(int64[2],uint256)', [...aDirty, 0n]));
    expect(ok.j.success).toBe(true);
  });

  it('int128[2]: positive, negative, min/max + dirty', async () => {
    const t = SIGNED.i128!;
    const a = [t.min, t.max];
    for (const i of [0n, 1n]) {
      const r = await eq(`i128at[${i}]`, raw('i128at(int128[2],uint256)', [...a, i]));
      expect(r.j.returnHex).toBe('0x' + pad(a[Number(i)]!));
    }
    // also a plain negative
    const neg = await eq('i128at neg', raw('i128at(int128[2],uint256)', [-42n, 42n, 0n]));
    expect(neg.j.returnHex).toBe('0x' + pad(-42n));
    // dirty: bit 128 set on a[0]
    const bad = await eq('i128at dirty i=0', raw('i128at(int128[2],uint256)', [t.dirty, 1n, 0n]));
    expect(bad.j.success).toBe(false);
    expect(bad.j.returnHex).toBe('0x');
  });

  it('int256[2]: positive, negative, min/max (no dirty form possible)', async () => {
    const t = SIGNED.i256!;
    const a = [t.min, t.max]; // every 256-bit word is canonical for int256
    for (const i of [0n, 1n]) {
      const r = await eq(`i256at[${i}]`, raw('i256at(int256[2],uint256)', [...a, i]));
      expect(r.j.returnHex).toBe('0x' + pad(a[Number(i)]!));
    }
    const neg = await eq('i256at neg', raw('i256at(int256[2],uint256)', [-1n, 1n, 0n]));
    expect(neg.j.returnHex).toBe('0x' + 'f'.repeat(64));
  });

  // ---- struct param {int8 a; int128 b; int256 c} -----------------------------------

  it('struct {int8 a; int128 b; int256 c}: clean positives/negatives/bounds', async () => {
    // Tri head is flat & unpacked: [a, b, c] = 3 words.
    const cases: [bigint, bigint, bigint][] = [
      [5n, 9n, 13n],
      [-1n, -1n, -1n],
      [SIGNED.i8!.min, SIGNED.i128!.min, SIGNED.i256!.min],
      [SIGNED.i8!.max, SIGNED.i128!.max, SIGNED.i256!.max],
    ];
    for (const [a, b, c] of cases) {
      const head = [a, b, c];
      const ra = await eq(`triA a=${a}`, raw('triA((int8,int128,int256))', head));
      expect(ra.j.returnHex).toBe('0x' + pad(a));
      const rb = await eq(`triB b=${b}`, raw('triB((int8,int128,int256))', head));
      expect(rb.j.returnHex).toBe('0x' + pad(b));
      const rc = await eq(`triC c=${c}`, raw('triC((int8,int128,int256))', head));
      expect(rc.j.returnHex).toBe('0x' + pad(c));
    }
  });

  it('struct {int8 a; int128 b}: dirty leaf read -> EMPTY; unread dirty ignored', async () => {
    // dirty a (int8 0x1ff), clean b, clean c.
    let bad = await eq('triA dirty a', raw('triA((int8,int128,int256))', [SIGNED.i8!.dirty, 1n, 2n]));
    expect(bad.j.success).toBe(false);
    expect(bad.j.returnHex).toBe('0x');
    // but reading b (clean) ignores the dirty a (lazy per-access).
    const ok = await eq('triB clean (dirty a unread)', raw('triB((int8,int128,int256))', [SIGNED.i8!.dirty, 7n, 0n]));
    expect(ok.j.success).toBe(true);
    expect(ok.j.returnHex).toBe('0x' + pad(7n));
    // dirty b (int128 bit128 set), read b -> EMPTY; read a (clean) -> OK.
    bad = await eq('triB dirty b', raw('triB((int8,int128,int256))', [1n, SIGNED.i128!.dirty, 0n]));
    expect(bad.j.success).toBe(false);
    expect(bad.j.returnHex).toBe('0x');
    const ok2 = await eq(
      'triA clean (dirty b unread)',
      raw('triA((int8,int128,int256))', [3n, SIGNED.i128!.dirty, 0n]),
    );
    expect(ok2.j.success).toBe(true);
    expect(ok2.j.returnHex).toBe('0x' + pad(3n));
  });

  it('short calldata for struct/array reverts empty identically', async () => {
    // triC needs 3 head words; supply only 2.
    const short = '0x' + sel('triC((int8,int128,int256))') + pad(1n) + pad(2n);
    const r = await eq('triC short', short);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // i256at needs 2 elems + index = 3 words; supply 2.
    const short2 = '0x' + sel('i256at(int256[2],uint256)') + pad(1n) + pad(2n);
    const r2 = await eq('i256at short', short2);
    expect(r2.j.success).toBe(false);
    expect(r2.j.returnHex).toBe('0x');
  });
});
