// A2: whole fixed-array return (return this.fa) and a static struct with a fixed-array
// field (return this.s). Encoded inline from storage. Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const JETH = `@struct class P { x: u128; y: u128; }
@struct class WithArr { p: u256; xs: Arr<u256, 3>; q: u256; }
@struct class Nest { a: u256; pt: P; b: u256; }
@contract class FA {
  @state nums: Arr<u256, 4>;
  @state pts: Arr<P, 3>;
  @state wa: WithArr;
  @state ns: Nest;
  @external setNum(i: u256, v: u256): void { this.nums[i] = v; }
  @external setPt(i: u256, x: u128, y: u128): void { this.pts[i] = P(x, y); }
  @external setWa(p: u256, a: u256, b: u256, c: u256, q: u256): void { this.wa.p = p; this.wa.xs[0n] = a; this.wa.xs[1n] = b; this.wa.xs[2n] = c; this.wa.q = q; }
  @external setNs(a: u256, x: u128, y: u128, b: u256): void { this.ns.a = a; this.ns.pt = P(x, y); this.ns.b = b; }
  @view getNums(): Arr<u256, 4> { return this.nums; }
  @view getPts(): Arr<P, 3> { return this.pts; }
  @view getWa(): WithArr { return this.wa; }
  @view getNs(): Nest { return this.ns; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract FA {
  struct P { uint128 x; uint128 y; }
  struct WithArr { uint256 p; uint256[3] xs; uint256 q; }
  struct Nest { uint256 a; P pt; uint256 b; }
  uint256[4] nums;
  P[3] pts;
  WithArr wa;
  Nest ns;
  function setNum(uint256 i, uint256 v) external { nums[i] = v; }
  function setPt(uint256 i, uint128 x, uint128 y) external { pts[i] = P(x, y); }
  function setWa(uint256 p, uint256 a, uint256 b, uint256 c, uint256 q) external { wa.p = p; wa.xs[0]=a; wa.xs[1]=b; wa.xs[2]=c; wa.q = q; }
  function setNs(uint256 a, uint128 x, uint128 y, uint256 b) external { ns.a = a; ns.pt = P(x, y); ns.b = b; }
  function getNums() external view returns (uint256[4] memory){ return nums; }
  function getPts() external view returns (P[3] memory){ return pts; }
  function getWa() external view returns (WithArr memory){ return wa; }
  function getNs() external view returns (Nest memory){ return ns; }
}`;

describe('whole fixed-array & struct-with-fixed-array return vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function send(data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `send success (jeth err=${j.exceptionError})`).toBe(s.success);
  }
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'FA.jeth' });
    const sb = compileSolidity(SOL, 'FA');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('return this.nums (uint256[4]) default + populated', async () => {
    await eq('getNums default', encodeCall(sel('getNums()'), []));
    await send(encodeCall(sel('setNum(uint256,uint256)'), [0n, 11n]));
    await send(encodeCall(sel('setNum(uint256,uint256)'), [3n, 44n]));
    await eq('getNums populated', encodeCall(sel('getNums()'), []));
  });

  it('return this.pts (P[3], static struct elements)', async () => {
    await send(encodeCall(sel('setPt(uint256,uint128,uint128)'), [1n, 0xcafen, 0xbeefn]));
    await eq('getPts', encodeCall(sel('getPts()'), []));
  });

  it('return this.wa (struct with a fixed-array field)', async () => {
    await send(encodeCall(sel('setWa(uint256,uint256,uint256,uint256,uint256)'), [7n, 1n, 2n, 3n, 9n]));
    await eq('getWa', encodeCall(sel('getWa()'), []));
  });

  it('return this.ns (struct with a nested static struct field)', async () => {
    await send(encodeCall(sel('setNs(uint256,uint128,uint128,uint256)'), [4n, 0x11n, 0x22n, 8n]));
    await eq('getNs', encodeCall(sel('getNs()'), []));
  });
});
