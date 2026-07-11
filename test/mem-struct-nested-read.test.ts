// G9: reading a WHOLE nested struct field of a memory struct (return p.inner; let q = p.inner).
// A nested struct field is a sub-pointer into the parent image: `let q = p.inner` ALIASES it
// (a write through q is visible through p), matching Solidity memory references. vs solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);

const JETH = `type Inner = { a: u256; b: i64; };
type Outer = { tag: u256; inner: Inner; z: u8; };
class C {
  // return a whole nested struct field
  get getInner(t: u256, a: u256, b: i64): External<Inner> {
    let p: Outer = Outer(t, Inner(a, b), 0n);
    return p.inner;
  }
  // alias: q = p.inner; mutating q is visible through p (return whole p)
  get aliasMutate(a: u256, b: i64): External<Outer> {
    let p: Outer = Outer(9n, Inner(a, b), 5n);
    let q: Inner = p.inner;
    q.a = q.a + 1000n; q.b = -3n;
    return p;
  }
  // bind nested field, read its value fields
  get readVia(a: u256, b: i64): External<u256> {
    let p: Outer = Outer(0n, Inner(a, b), 0n);
    let q: Inner = p.inner;
    return q.a + u256(u64(q.b));
  }
  // pass a nested field (by ref) to an internal helper that mutates it
  bump(i: Inner): void { i.a = i.a + 1n; }
  get passInner(a: u256, b: i64): External<Outer> {
    let p: Outer = Outer(7n, Inner(a, b), 2n);
    this.bump(p.inner);
    return p;
  }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Inner { uint256 a; int64 b; }
  struct Outer { uint256 tag; Inner inner; uint8 z; }
  function getInner(uint256 t, uint256 a, int64 b) external pure returns (Inner memory){
    Outer memory p = Outer(t, Inner(a, b), 0);
    return p.inner;
  }
  function aliasMutate(uint256 a, int64 b) external pure returns (Outer memory){
    Outer memory p = Outer(9, Inner(a, b), 5);
    Inner memory q = p.inner;
    q.a = q.a + 1000; q.b = -3;
    return p;
  }
  function readVia(uint256 a, int64 b) external pure returns (uint256){
    Outer memory p = Outer(0, Inner(a, b), 0);
    Inner memory q = p.inner;
    return q.a + uint256(uint64(q.b));
  }
  function bump(Inner memory i) internal pure { i.a = i.a + 1; }
  function passInner(uint256 a, int64 b) external pure returns (Outer memory){
    Outer memory p = Outer(7, Inner(a, b), 2);
    bump(p.inner);
    return p;
  }
}`;

describe('whole nested-struct-field read on a memory struct (G9) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('return p.inner / alias-mutate / read-via / pass-by-ref', async () => {
    for (const [a, b] of [
      [1n, 2n],
      [0n, -1n],
      [M - 1n, (1n << 63n) - 1n],
      [42n, M - (1n << 63n)],
    ] as [bigint, bigint][]) {
      await eq('getInner', encodeCall(sel('getInner(uint256,uint256,int64)'), [9n, a, b]));
      await eq('aliasMutate', encodeCall(sel('aliasMutate(uint256,int64)'), [a, b]));
      await eq('readVia', encodeCall(sel('readVia(uint256,int64)'), [a, b]));
      await eq('passInner', encodeCall(sel('passInner(uint256,int64)'), [a, b]));
    }
  });
});
