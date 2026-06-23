// Phase 4e-1 scenario "nested-struct-element": a DYNAMIC ARRAY of a STATIC struct
// that itself contains a NESTED static struct field, as a calldata param.
//   Inner { uint128 a; uint128 b; }
//   Outer { uint64 p; Inner inner; uint64 q; }   // ABI leaves flatten inline:
//     element head = [p][a][b][q]  => stride = 4 words (4*32 = 128 bytes)
// Selector expands the element struct to a nested tuple:
//   echoOuters((uint64,(uint128,uint128),uint64)[])
// Differential vs Solidity (the oracle), byte-for-byte on:
//   - whole-array echo (head/tail round-trip; dirty leaf -> EMPTY revert, because a
//     STRUCT-element echo reads/validates EVERY leaf, including the inner ones),
//   - element value-field reads ps[i].p, ps[i].q (lazy dirty validation),
//   - nested-struct field chain ps[i].inner.a / ps[i].inner.b (leaf at the inline
//     accumulated head word), with OOB Panic(0x32) and lazy dirty validation,
//   - OOB index -> Panic(0x32), length, truncated payload -> EMPTY.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

// JETH surface: Outer[] echo + element value-field reads + length.
const JETH = `
@struct class Inner { a: u128; b: u128; }
@struct class Outer { p: u64; inner: Inner; q: u64; }

@contract
class NestedStructElem {
  @external @pure echoOuters(ps: Outer[]): Outer[] { return ps; }
  @external @pure outerP(ps: Outer[], i: u256): u64 { return ps[i].p; }
  @external @pure outerQ(ps: Outer[], i: u256): u64 { return ps[i].q; }
  @external @pure len(ps: Outer[]): u256 { return ps.length; }
  @external @pure innerA(ps: Outer[], i: u256): u128 { return ps[i].inner.a; }
  @external @pure innerB(ps: Outer[], i: u256): u128 { return ps[i].inner.b; }
}`;

// Faithful Solidity mirror (the oracle).
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract NestedStructElem {
  struct Inner { uint128 a; uint128 b; }
  struct Outer { uint64 p; Inner inner; uint64 q; }
  function echoOuters(Outer[] calldata ps) external pure returns (Outer[] memory){ return ps; }
  function outerP(Outer[] calldata ps, uint256 i) external pure returns (uint64){ return ps[i].p; }
  function outerQ(Outer[] calldata ps, uint256 i) external pure returns (uint64){ return ps[i].q; }
  function len(Outer[] calldata ps) external pure returns (uint256){ return ps.length; }
  function innerA(Outer[] calldata ps, uint256 i) external pure returns (uint128){ return ps[i].inner.a; }
  function innerB(Outer[] calldata ps, uint256 i) external pure returns (uint128){ return ps[i].inner.b; }
}`;

const T = '(uint64,(uint128,uint128),uint64)'; // element tuple form

describe('nested-struct-element: Outer[] (uint64,(uint128,uint128),uint64)[] vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);

  // Element leaves (inline, unpacked): one 32-byte word per leaf -> stride 4 words.
  const outer = (p: bigint, a: bigint, b: bigint, q: bigint) => [p, a, b, q];

  // sole dynamic-array param: head = [offset=0x20], then [len][flat element words].
  const arr1 = (selSig: string, flat: bigint[], len: number) =>
    '0x' + sel(selSig) + pad(0x20n) + pad(BigInt(len)) + flat.map(pad).join('');
  // (dynamic-array, uint256 i): head = [offset=0x40][i], then [len][flat words].
  const arr2 = (selSig: string, flat: bigint[], len: number, i: bigint) =>
    '0x' + sel(selSig) + pad(0x40n) + pad(i) + pad(BigInt(len)) + flat.map(pad).join('');

  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
    return { j, s };
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'NestedStructElem.jeth' });
    const sb = compileSolidity(SOL, 'NestedStructElem');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('compile contract: abiLeaves flatten the inner struct inline (stride 4)', () => {
    // sanity: it compiled (beforeAll did not throw); selector expands nested tuple.
    expect(sel(`echoOuters(${T}[])`)).toHaveLength(8);
  });

  it('echoes Outer[] byte-identically (head/tail round-trip, inner flattened)', async () => {
    // 2 Outers: O0{p=1, inner{a=2,b=3}, q=4}, O1{p=5, inner{a=6,b=7}, q=8}
    const flat = [...outer(1n, 2n, 3n, 4n), ...outer(5n, 6n, 7n, 8n)];
    await eq('echoOuters n=2', arr1(`echoOuters(${T}[])`, flat, 2));
    await eq('echoOuters n=0', arr1(`echoOuters(${T}[])`, [], 0));
    await eq('echoOuters n=1', arr1(`echoOuters(${T}[])`, outer(9n, 10n, 11n, 12n), 1));
    // larger array (3) to exercise multi-element tail re-encode
    const flat3 = [
      ...outer(0x10n, 0x11n, 0x12n, 0x13n),
      ...outer(0x20n, 0x21n, 0x22n, 0x23n),
      ...outer(0x30n, 0x31n, 0x32n, 0x33n),
    ];
    await eq('echoOuters n=3', arr1(`echoOuters(${T}[])`, flat3, 3));
  });

  it('whole-array echo VALIDATES every leaf, INCLUDING inner ones (dirty -> EMPTY revert)', async () => {
    // For each of the 4 leaves (p, inner.a, inner.b, q), dirtying it must make BOTH
    // revert EMPTY on the whole-array copy (struct-element echo reads all leaves).
    const dirtyOuter = (slot: 0 | 1 | 2 | 3) => {
      const o = outer(1n, 2n, 3n, 4n);
      if (slot === 0 || slot === 3)
        o[slot] = (1n << 64n) | o[slot]!; // u64 leaf: bit64 dirty
      else o[slot] = (1n << 128n) | o[slot]!; // u128 leaf: bit128 dirty
      return o;
    };
    for (const slot of [0, 1, 2, 3] as const) {
      const r = await eq(`echoOuters dirty leaf#${slot}`, arr1(`echoOuters(${T}[])`, dirtyOuter(slot), 1));
      expect(r.j.success).toBe(false);
      expect(r.j.returnHex).toBe('0x');
    }
    // control: same array but CLEAN -> success (and identical returndata)
    const r = await eq('echoOuters clean control', arr1(`echoOuters(${T}[])`, outer(1n, 2n, 3n, 4n), 1));
    expect(r.j.success).toBe(true);
  });

  it('reads ps[i].p and ps[i].q with lazy dirty validation + OOB Panic', async () => {
    const flat = [...outer(0xa1n, 0xa2n, 0xa3n, 0xa4n), ...outer(0xb1n, 0xb2n, 0xb3n, 0xb4n)];
    // ps[1].p
    let r = await eq('outerP i=1', arr2(`outerP(${T}[],uint256)`, flat, 2, 1n));
    expect(decodeUint(r.j.returnHex)).toBe(0xb1n);
    // ps[0].q
    r = await eq('outerQ i=0', arr2(`outerQ(${T}[],uint256)`, flat, 2, 0n));
    expect(decodeUint(r.j.returnHex)).toBe(0xa4n);
    // ps[1].q
    r = await eq('outerQ i=1', arr2(`outerQ(${T}[],uint256)`, flat, 2, 1n));
    expect(decodeUint(r.j.returnHex)).toBe(0xb4n);

    // OOB i=2 (len 2) -> Panic(0x32)
    r = await eq('outerP OOB i=2', arr2(`outerP(${T}[],uint256)`, flat, 2, 2n));
    expect(r.j.success).toBe(false);

    // lazy dirty validation on a single read:
    // dirty p (read by outerP) -> EMPTY revert
    const dp = outer((1n << 64n) | 0x5n, 0x6n, 0x7n, 0x8n);
    r = await eq('outerP dirty-p', arr2(`outerP(${T}[],uint256)`, dp, 1, 0n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // dirty q (read by outerQ) -> EMPTY revert
    const dq = outer(0x5n, 0x6n, 0x7n, (1n << 64n) | 0x8n);
    r = await eq('outerQ dirty-q', arr2(`outerQ(${T}[],uint256)`, dq, 1, 0n));
    expect(r.j.success).toBe(false);
    // dirty INNER leaf (a) but read p (unread by outerP) -> OK (lazy)
    const du = outer(0x5n, (1n << 128n) | 0x6n, 0x7n, 0x8n);
    r = await eq('outerP dirty-unread-inner.a', arr2(`outerP(${T}[],uint256)`, du, 1, 0n));
    expect(r.j.success).toBe(true);
    expect(decodeUint(r.j.returnHex)).toBe(0x5n);
    // dirty q (unread by outerP) -> OK (lazy)
    const dqu = outer(0x5n, 0x6n, 0x7n, (1n << 64n) | 0x8n);
    r = await eq('outerP dirty-unread-q', arr2(`outerP(${T}[],uint256)`, dqu, 1, 0n));
    expect(r.j.success).toBe(true);
    expect(decodeUint(r.j.returnHex)).toBe(0x5n);
  });

  it('length and truncated payload', async () => {
    const flat = [...outer(1n, 2n, 3n, 4n), ...outer(5n, 6n, 7n, 8n)];
    const r = await eq('len', arr1(`len(${T}[])`, flat, 2));
    expect(decodeUint(r.j.returnHex)).toBe(2n);
    // declares len=2 but only 1 element (4 words) of payload -> EMPTY revert
    const bad = '0x' + sel(`echoOuters(${T}[])`) + pad(0x20n) + pad(2n) + outer(1n, 2n, 3n, 4n).map(pad).join('');
    const rb = await eq('echoOuters truncated payload', bad);
    expect(rb.j.success).toBe(false);
    // offset past calldata -> EMPTY revert
    const off = '0x' + sel(`len(${T}[])`) + pad(0x1000n);
    const ro = await eq('len bad offset', off);
    expect(ro.j.success).toBe(false);
  });

  it('reads ps[i].inner.a / ps[i].inner.b (nested-struct field chain) byte-identically', async () => {
    const flat = [...outer(0xa1n, 0xa2n, 0xa3n, 0xa4n), ...outer(0xb1n, 0xb2n, 0xb3n, 0xb4n)];
    const IA = `innerA(${T}[],uint256)`;
    const IB = `innerB(${T}[],uint256)`;
    // ps[i].inner.a is element head word 1; ps[i].inner.b is word 2
    let r = await eq('innerA i=0', arr2(IA, flat, 2, 0n));
    expect(decodeUint(r.j.returnHex)).toBe(0xa2n);
    r = await eq('innerA i=1', arr2(IA, flat, 2, 1n));
    expect(decodeUint(r.j.returnHex)).toBe(0xb2n);
    r = await eq('innerB i=0', arr2(IB, flat, 2, 0n));
    expect(decodeUint(r.j.returnHex)).toBe(0xa3n);
    r = await eq('innerB i=1', arr2(IB, flat, 2, 1n));
    expect(decodeUint(r.j.returnHex)).toBe(0xb3n);
    // OOB i=2 (len 2) -> Panic(0x32), byte-identical revert
    r = await eq('innerA OOB i=2', arr2(IA, flat, 2, 2n));
    expect(r.j.success).toBe(false);
    // lazy dirty validation: dirty inner.a (read by innerA) -> EMPTY revert
    const da = outer(0x5n, (1n << 128n) | 0x6n, 0x7n, 0x8n);
    r = await eq('innerA dirty inner.a', arr2(IA, da, 1, 0n));
    expect(r.j.success).toBe(false);
    expect(r.j.returnHex).toBe('0x');
    // dirty inner.b but read inner.a (unread) -> OK (lazy), byte-identical value
    const db = outer(0x5n, 0x6n, (1n << 128n) | 0x7n, 0x8n);
    r = await eq('innerA dirty-unread inner.b', arr2(IA, db, 1, 0n));
    expect(r.j.success).toBe(true);
    expect(decodeUint(r.j.returnHex)).toBe(0x6n);
  });
});
