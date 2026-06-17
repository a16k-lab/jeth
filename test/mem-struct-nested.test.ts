// G9: nested-struct field access on memory struct locals (p.inner.x read/write, deeper chains),
// plus passing/returning structs that contain nested structs through internal helpers. vs solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);

const JETH = `@struct class Inner { a: u256; b: i64; }
@struct class Outer { tag: u8; inner: Inner; z: u256; }
@struct class Deep { o: Outer; w: u256; }
@contract class C {
  // read nested value fields
  @external @pure rd(t: u8, a: u256, b: i64, z: u256): u256 {
    let p: Outer = Outer(t, Inner(a, b), z);
    return u256(p.tag) * 1000000n + p.inner.a + u256(u64(p.inner.b)) + p.z;
  }
  // write nested value fields, then return the whole struct
  @external @pure wr(a: u256, b: i64): Outer {
    let p: Outer = Outer(0n, Inner(0n, 0n), 0n);
    p.tag = 9n; p.inner.a = a; p.inner.b = b; p.inner.a += 1n; p.z = a * 2n;
    return p;
  }
  // 2-level deep chain p.o.inner.a
  @external @pure deep(a: u256, b: i64): Deep {
    let d: Deep = Deep(Outer(1n, Inner(a, b), 7n), 0n);
    d.o.inner.a = d.o.inner.a + 100n; d.o.inner.b = -5n; d.w = 42n;
    return d;
  }
  // pass a nested-struct memory struct to a helper that mutates a deep field (by ref)
  @internal bumpInner(p: Outer): void { p.inner.a = p.inner.a + 1n; p.inner.b = p.inner.b - 1n; }
  @external @pure viaHelper(a: u256, b: i64): Outer {
    let p: Outer = Outer(3n, Inner(a, b), 5n);
    this.bumpInner(p); this.bumpInner(p);
    return p;
  }
  // return a nested struct constructed by a helper
  @internal @pure mkOuter(t: u8, a: u256, b: i64): Outer { return Outer(t, Inner(a, b), 0n); }
  @external @pure mkE(t: u8, a: u256, b: i64): Outer { return this.mkOuter(t, a, b); }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Inner { uint256 a; int64 b; }
  struct Outer { uint8 tag; Inner inner; uint256 z; }
  struct Deep { Outer o; uint256 w; }
  function rd(uint8 t, uint256 a, int64 b, uint256 z) external pure returns (uint256){
    Outer memory p = Outer(t, Inner(a, b), z);
    return uint256(p.tag) * 1000000 + p.inner.a + uint256(uint64(p.inner.b)) + p.z;
  }
  function wr(uint256 a, int64 b) external pure returns (Outer memory){
    Outer memory p = Outer(0, Inner(0, 0), 0);
    p.tag = 9; p.inner.a = a; p.inner.b = b; p.inner.a += 1; p.z = a * 2;
    return p;
  }
  function deep(uint256 a, int64 b) external pure returns (Deep memory){
    Deep memory d = Deep(Outer(1, Inner(a, b), 7), 0);
    d.o.inner.a = d.o.inner.a + 100; d.o.inner.b = -5; d.w = 42;
    return d;
  }
  function bumpInner(Outer memory p) internal pure { p.inner.a = p.inner.a + 1; p.inner.b = p.inner.b - 1; }
  function viaHelper(uint256 a, int64 b) external pure returns (Outer memory){
    Outer memory p = Outer(3, Inner(a, b), 5);
    bumpInner(p); bumpInner(p);
    return p;
  }
  function mkOuter(uint8 t, uint256 a, int64 b) internal pure returns (Outer memory){ return Outer(t, Inner(a, b), 0); }
  function mkE(uint8 t, uint256 a, int64 b) external pure returns (Outer memory){ return mkOuter(t, a, b); }
}`;

describe('nested-struct memory field access (G9) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  it('read/write nested value fields + deep chains', async () => {
    for (const [a, b] of [[1n, 2n], [0n, -1n], [M - 1n, (1n << 63n) - 1n], [123n, M - (1n << 63n)]] as [bigint, bigint][]) {
      await eq(`rd(7,${a},${b})`, encodeCall(sel('rd(uint8,uint256,int64,uint256)'), [7n, a, b, 50n]));
      await eq(`wr(${a},${b})`, encodeCall(sel('wr(uint256,int64)'), [a, b]));
      await eq(`deep(${a},${b})`, encodeCall(sel('deep(uint256,int64)'), [a, b]));
    }
  });
  it('nested struct through internal helpers (by-ref mutate + construct-return)', async () => {
    for (const [a, b] of [[10n, 3n], [0n, -7n], [M - 5n, -1n]] as [bigint, bigint][]) {
      await eq(`viaHelper(${a},${b})`, encodeCall(sel('viaHelper(uint256,int64)'), [a, b]));
      await eq(`mkE(5,${a},${b})`, encodeCall(sel('mkE(uint8,uint256,int64)'), [5n, a, b]));
    }
  });
});
