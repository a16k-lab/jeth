// G8 + G9 synergy: internal/private functions taking and returning STATIC structs as memory
// (pass-by-reference). Construct, pass to a helper that reads/mutates it (mutation visible to
// the caller), return a struct from a helper, chain calls, recursion over a struct. vs solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);

const JETH = `@struct class P { a: u256; b: u256; }
@contract class C {
  // read a struct param (by reference)
  @internal @pure sum(p: P): u256 { return p.a + p.b; }
  @external @pure sumE(a: u256, b: u256): u256 { let p: P = P(a, b); return this.sum(p); }
  // MUTATE a struct param in place: the change is visible to the caller (memory is by-ref)
  @internal scale(p: P, k: u256): void { p.a = p.a * k; p.b = p.b * k; }
  @external scaleE(a: u256, b: u256, k: u256): u256 { let p: P = P(a, b); this.scale(p, k); return p.a + p.b; }
  // RETURN a struct from a helper; caller returns it
  @internal @pure make(a: u256, b: u256): P { return P(a, b); }
  @external @pure makeE(a: u256, b: u256): P { return this.make(a, b); }
  // bind a struct-returning call to a local, then read it
  @external @pure bindRead(a: u256, b: u256): u256 { let p: P = this.make(a, b); return p.a * 1000n + p.b; }
  // chain: outer(inner(...)) passing a struct through
  @internal @pure addOne(p: P): P { return P(p.a + 1n, p.b + 1n); }
  @external @pure chainE(a: u256, b: u256): P { return this.addOne(this.make(a, b)); }
  // recursion building a struct
  @internal @pure climb(p: P, n: u256): P { if (n == 0n) { return p; } return this.climb(P(p.a + 1n, p.b + 2n), n - 1n); }
  @external @pure climbE(a: u256, b: u256, n: u256): P { return this.climb(P(a, b), n); }
  // a helper that both takes and returns a struct, used statefully
  @state acc: P;
  @internal addTo(p: P): void { this.acc.a = this.acc.a + p.a; this.acc.b = this.acc.b + p.b; }
  @external feed(a: u256, b: u256): void { let p: P = P(a, b); this.addTo(p); }
  @view getAcc(): P { return this.acc; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 a; uint256 b; }
  function sum(P memory p) internal pure returns (uint256){ return p.a + p.b; }
  function sumE(uint256 a, uint256 b) external pure returns (uint256){ P memory p = P(a, b); return sum(p); }
  function scale(P memory p, uint256 k) internal pure { p.a = p.a * k; p.b = p.b * k; }
  function scaleE(uint256 a, uint256 b, uint256 k) external pure returns (uint256){ P memory p = P(a, b); scale(p, k); return p.a + p.b; }
  function make(uint256 a, uint256 b) internal pure returns (P memory){ return P(a, b); }
  function makeE(uint256 a, uint256 b) external pure returns (P memory){ return make(a, b); }
  function bindRead(uint256 a, uint256 b) external pure returns (uint256){ P memory p = make(a, b); return p.a * 1000 + p.b; }
  function addOne(P memory p) internal pure returns (P memory){ return P(p.a + 1, p.b + 1); }
  function chainE(uint256 a, uint256 b) external pure returns (P memory){ return addOne(make(a, b)); }
  function climb(P memory p, uint256 n) internal pure returns (P memory){ if (n == 0) { return p; } return climb(P(p.a + 1, p.b + 2), n - 1); }
  function climbE(uint256 a, uint256 b, uint256 n) external pure returns (P memory){ return climb(P(a, b), n); }
  P acc;
  function addTo(P memory p) internal { acc.a = acc.a + p.a; acc.b = acc.b + p.b; }
  function feed(uint256 a, uint256 b) external { P memory p = P(a, b); addTo(p); }
  function getAcc() external view returns (P memory){ return acc; }
}`;

describe('internal-function struct params/returns (G8+G9) vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function send(data: string) { const j = await jeth.call(aj, data); const s = await sol.call(as, data); expect(j.success, `${j.exceptionError}`).toBe(s.success); }
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

  it('pass / mutate-by-ref / return / bind / chain', async () => {
    for (const [a, b] of [[1n, 2n], [0n, 0n], [M - 1n, 5n], [100n, 200n]] as [bigint, bigint][]) {
      await eq(`sumE(${a},${b})`, encodeCall(sel('sumE(uint256,uint256)'), [a, b]));
      await eq(`makeE(${a},${b})`, encodeCall(sel('makeE(uint256,uint256)'), [a, b]));
      await eq(`bindRead(${a},${b})`, encodeCall(sel('bindRead(uint256,uint256)'), [a, b]));
      await eq(`chainE(${a},${b})`, encodeCall(sel('chainE(uint256,uint256)'), [a, b]));
      for (const k of [0n, 1n, 3n]) await eq(`scaleE(${a},${b},${k})`, encodeCall(sel('scaleE(uint256,uint256,uint256)'), [a, b, k]));
    }
  });
  it('recursion building a struct', async () => {
    for (const n of [0n, 1n, 5n, 20n]) await eq(`climbE(${n})`, encodeCall(sel('climbE(uint256,uint256,uint256)'), [1n, 2n, n]));
  });
  it('stateful struct-arg helper', async () => {
    for (const [a, b] of [[1n, 2n], [10n, 20n]] as [bigint, bigint][]) await send(encodeCall(sel('feed(uint256,uint256)'), [a, b]));
    await eq('getAcc', encodeCall(sel('getAcc()'), []));
  });
});
