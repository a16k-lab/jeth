// Phase 4d scenario "deep-nested-aggregates": deeply nested STATIC aggregate
// calldata params, byte-identical to Solidity. Exercises:
//  (1) array-of-struct-with-array-field: Big[2] arr, Big{uint64 id; uint128[3] xs}
//      -> arr[i].id, arr[i].xs[j]; OOB on i and on j -> Panic(0x32).
//  (2) struct-with-array-of-struct: S{uint64 h; Pt[2] pts}, Pt{uint128 x;uint128 y}
//      -> s.pts[i].y; OOB on i -> Panic(0x32).
//  (3) three-level struct A{B b} B{C c} C{uint128 v} -> a.b.c.v.
// Confirms the FLAT/UNPACKED ABI head offsets and LAZY dirty-leaf reverts (empty).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

// ---- JETH source (inline, self-contained) ----
const JETH = `// deep-nested-aggregates
@struct class Pt { x: u128; y: u128; }
@struct class Big { id: u64; xs: Arr<u128, 3>; }
@struct class S { h: u64; pts: Arr<Pt, 2>; }
@struct class C { v: u128; }
@struct class B { c: C; }
@struct class A { b: B; }

@contract
class DeepNested {
  // (1) array-of-struct-with-array-field
  @external @pure bigId(arr: Arr<Big, 2>, i: u256): u64 { return arr[i].id; }
  @external @pure bigXs(arr: Arr<Big, 2>, i: u256, j: u256): u128 { return arr[i].xs[j]; }
  // constant-index variants (compile-time addressing)
  @external @pure bigId0(arr: Arr<Big, 2>): u64 { return arr[0n].id; }
  @external @pure bigXs1_2(arr: Arr<Big, 2>): u128 { return arr[1n].xs[2n]; }

  // (2) struct-with-array-of-struct
  @external @pure sPtsY(s: S, i: u256): u128 { return s.pts[i].y; }
  @external @pure sH(s: S): u64 { return s.h; }
  @external @pure sPtsX0(s: S): u128 { return s.pts[0n].x; }

  // (3) three-level struct
  @external @pure abcV(a: A): u128 { return a.b.c.v; }
}`;

// ---- Solidity mirror ----
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract DeepNested {
  struct Pt  { uint128 x; uint128 y; }
  struct Big { uint64 id; uint128[3] xs; }
  struct S   { uint64 h; Pt[2] pts; }
  struct C   { uint128 v; }
  struct B   { C c; }
  struct A   { B b; }
  function bigId(Big[2] calldata arr, uint256 i) external pure returns (uint64){ return arr[i].id; }
  function bigXs(Big[2] calldata arr, uint256 i, uint256 j) external pure returns (uint128){ return arr[i].xs[j]; }
  function bigId0(Big[2] calldata arr) external pure returns (uint64){ return arr[0].id; }
  function bigXs1_2(Big[2] calldata arr) external pure returns (uint128){ return arr[1].xs[2]; }
  function sPtsY(S calldata s, uint256 i) external pure returns (uint128){ return s.pts[i].y; }
  function sH(S calldata s) external pure returns (uint64){ return s.h; }
  function sPtsX0(S calldata s) external pure returns (uint128){ return s.pts[0].x; }
  function abcV(A calldata a) external pure returns (uint128){ return a.b.c.v; }
}`;

const M = 1n << 256n;
function pad(v: bigint): string {
  return (((v % M) + M) % M).toString(16).padStart(64, '0');
}

describe('deep-nested-aggregates vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  function raw(selSig: string, words: bigint[]): string {
    return '0x' + sel(selSig) + words.map(pad).join('');
  }
  async function both(data: string) {
    return { j: await jeth.call(aj, data), s: await sol.call(as, data) };
  }
  // assert JETH matches Solidity byte-for-byte (returndata + success).
  async function eq(label: string, data: string) {
    const { j, s } = await both(data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'DeepNested.jeth' });
    const sb = compileSolidity(SOL, 'DeepNested');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  // ---------------------------------------------------------------------------
  // (1) array-of-struct-with-array-field: Big[2] arr, Big{u64 id; u128[3] xs}
  //     ABI head: Big = id(1) + xs(3) = 4 words; Big[2] = 8 words.
  //     arr[0] = words[0..3] = {id0, x00, x01, x02}
  //     arr[1] = words[4..7] = {id1, x10, x11, x12}
  //     i appended at word 8.
  // ---------------------------------------------------------------------------
  const SIG_ID = 'bigId((uint64,uint128[3])[2],uint256)';
  const SIG_XS = 'bigXs((uint64,uint128[3])[2],uint256,uint256)';
  // arr leaves: id0=0xa0, xs0=[1,2,3]; id1=0xb0, xs1=[4,5,6]
  const ARR = [0xa0n, 1n, 2n, 3n, 0xb0n, 4n, 5n, 6n];

  it('(1) array-of-struct-with-array-field: id and xs reads + head offsets', async () => {
    // arr[0].id and arr[1].id
    expect(decodeUint((await eq('bigId i=0', raw(SIG_ID, [...ARR, 0n]))).j.returnHex)).toBe(0xa0n);
    expect(decodeUint((await eq('bigId i=1', raw(SIG_ID, [...ARR, 1n]))).j.returnHex)).toBe(0xb0n);
    // arr[i].xs[j] across both i and all j
    for (const [i, j, exp] of [
      [0n, 0n, 1n], [0n, 1n, 2n], [0n, 2n, 3n],
      [1n, 0n, 4n], [1n, 1n, 5n], [1n, 2n, 6n],
    ] as [bigint, bigint, bigint][]) {
      expect(decodeUint((await eq(`bigXs i=${i} j=${j}`, raw(SIG_XS, [...ARR, i, j]))).j.returnHex)).toBe(exp);
    }
  });

  it('(1) constant-index variants address the same flat head', async () => {
    expect(decodeUint((await eq('bigId0', raw('bigId0((uint64,uint128[3])[2])', ARR))).j.returnHex)).toBe(0xa0n);
    // arr[1].xs[2] -> word 7 = 6
    expect(decodeUint((await eq('bigXs1_2', raw('bigXs1_2((uint64,uint128[3])[2])', ARR))).j.returnHex)).toBe(6n);
  });

  it('(1) OOB on outer index i -> Panic(0x32)', async () => {
    const r = await eq('bigId i=2 OOB', raw(SIG_ID, [...ARR, 2n]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
    const r2 = await eq('bigXs i=2 OOB', raw(SIG_XS, [...ARR, 2n, 0n]));
    expect(r2.j.success).toBe(false);
    expect(r2.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
  });

  it('(1) OOB on inner array index j -> Panic(0x32)', async () => {
    const r = await eq('bigXs j=3 OOB', raw(SIG_XS, [...ARR, 0n, 3n]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
    // i=1, j=3 OOB too
    const r2 = await eq('bigXs i=1 j=3 OOB', raw(SIG_XS, [...ARR, 1n, 3n]));
    expect(r2.j.success).toBe(false);
    expect(r2.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
  });

  it('(1) lazy dirty-leaf reads: dirty u64 id and dirty u128 element revert EMPTY; unread dirty ignored', async () => {
    // dirty id1 (bit64 set) read via bigId i=1 -> revert empty
    const dirtyId = [...ARR]; dirtyId[4] = (1n << 64n) | 0xb0n; // word 4 = id1
    let r = await eq('bigId dirty id1', raw(SIG_ID, [...dirtyId, 1n]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // same dirty id1 but read id0 (i=0) -> clean -> OK (lazy)
    r = await eq('bigId dirty id1 unread', raw(SIG_ID, [...dirtyId, 0n]));
    expect(r.j.success).toBe(true);
    expect(decodeUint(r.j.returnHex)).toBe(0xa0n);
    // dirty xs[0][2] (bit128 set) read via bigXs i=0 j=2 -> revert empty
    const dirtyXs = [...ARR]; dirtyXs[3] = (1n << 128n) | 3n; // word 3 = xs0[2]
    r = await eq('bigXs dirty xs0[2]', raw(SIG_XS, [...dirtyXs, 0n, 2n]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // same dirty xs0[2] but read xs0[0] (j=0) -> clean -> OK (lazy)
    r = await eq('bigXs dirty xs0[2] unread', raw(SIG_XS, [...dirtyXs, 0n, 0n]));
    expect(r.j.success).toBe(true);
    expect(decodeUint(r.j.returnHex)).toBe(1n);
  });

  // ---------------------------------------------------------------------------
  // (2) struct-with-array-of-struct: S{u64 h; Pt[2] pts}, Pt{u128 x;u128 y}
  //     ABI head: h(1) + Pt[2](2*2=4) = 5 words.
  //     word0 = h; word1=pts[0].x; word2=pts[0].y; word3=pts[1].x; word4=pts[1].y
  // ---------------------------------------------------------------------------
  const SIG_SY = 'sPtsY((uint64,(uint128,uint128)[2]),uint256)';
  // h=0x55; pts[0]={0x10,0x11}; pts[1]={0x20,0x21}
  const SVAL = [0x55n, 0x10n, 0x11n, 0x20n, 0x21n];

  it('(2) struct-with-array-of-struct: s.pts[i].y + s.h head offsets', async () => {
    expect(decodeUint((await eq('sH', raw('sH((uint64,(uint128,uint128)[2]))', SVAL))).j.returnHex)).toBe(0x55n);
    expect(decodeUint((await eq('sPtsY i=0', raw(SIG_SY, [...SVAL, 0n]))).j.returnHex)).toBe(0x11n);
    expect(decodeUint((await eq('sPtsY i=1', raw(SIG_SY, [...SVAL, 1n]))).j.returnHex)).toBe(0x21n);
    expect(decodeUint((await eq('sPtsX0', raw('sPtsX0((uint64,(uint128,uint128)[2]))', SVAL))).j.returnHex)).toBe(0x10n);
  });

  it('(2) OOB on pts index i -> Panic(0x32)', async () => {
    const r = await eq('sPtsY i=2 OOB', raw(SIG_SY, [...SVAL, 2n]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x4e487b71' + pad(0x32n));
  });

  it('(2) lazy dirty-leaf: dirty pts[1].y read reverts empty; unread dirty ignored', async () => {
    const dirty = [...SVAL]; dirty[4] = (1n << 128n) | 0x21n; // word4 = pts[1].y dirty
    let r = await eq('sPtsY dirty pts1.y', raw(SIG_SY, [...dirty, 1n]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // read pts[0].y (i=0) with same dirty pts[1].y -> OK
    r = await eq('sPtsY dirty unread', raw(SIG_SY, [...dirty, 0n]));
    expect(r.j.success).toBe(true);
    expect(decodeUint(r.j.returnHex)).toBe(0x11n);
  });

  // ---------------------------------------------------------------------------
  // (3) three-level struct A{B b} B{C c} C{u128 v}. ABI head: 1 word (v).
  //     Sig: abcV((((uint128))))
  // ---------------------------------------------------------------------------
  it('(3) three-level struct: a.b.c.v single-word head', async () => {
    expect(decodeUint((await eq('abcV', raw('abcV((((uint128))))', [0xdeadn]))).j.returnHex)).toBe(0xdeadn);
  });

  it('(3) lazy dirty-leaf on three-level v: dirty high bits revert EMPTY', async () => {
    const r = await eq('abcV dirty v', raw('abcV((((uint128))))', [(1n << 128n) | 0xdeadn]));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
  });

  it('short calldata reverts empty identically', async () => {
    // sPtsY needs 5+1=6 head words; supply 5.
    const short = '0x' + sel(SIG_SY) + SVAL.map(pad).join('');
    const r = await eq('sPtsY short', short);
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // bigId needs 8+1=9 head words; supply 8.
    const short2 = '0x' + sel(SIG_ID) + ARR.map(pad).join('');
    const r2 = await eq('bigId short', short2);
    expect(r2.j.success).toBe(false);
    expect(r2.j.returnHex).toBe('0x');
  });
});
