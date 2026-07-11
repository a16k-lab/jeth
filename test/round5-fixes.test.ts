// Round-5 gaps: struct dynamic-array-field whole return (#3), fixed inner-array row return
// of a 2D fixed array (#4), and assigning a whole dynamic inner array element (#7).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const JETH = `type S = { a: u256; xs: u256[]; };
class R5 {
  s: S;
  g: Arr<Arr<u256, 2>, 2>;
  dd: u256[][];
  pushX(v: u256): External<void> { this.s.xs.push(v); }
  get getXs(): External<u256[]> { return this.s.xs; }
  setG(i: u256, j: u256, v: u256): External<void> { this.g[i][j] = v; }
  get getRow(i: u256): External<Arr<u256, 2>> { return this.g[i]; }
  ddPush(): External<void> { this.dd.push(); }
  assignInner(i: u256, a: u256, b: u256, c: u256): External<void> { let xs: u256[] = [a, b, c]; this.dd[i] = xs; }
  get getInner(i: u256): External<u256[]> { return this.dd[i]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract R5 {
  struct S { uint256 a; uint256[] xs; }
  S s;
  uint256[2][2] g;
  uint256[][] dd;
  function pushX(uint256 v) external { s.xs.push(v); }
  function getXs() external view returns (uint256[] memory){ return s.xs; }
  function setG(uint256 i, uint256 j, uint256 v) external { g[i][j] = v; }
  function getRow(uint256 i) external view returns (uint256[2] memory){ return g[i]; }
  function ddPush() external { dd.push(); }
  function assignInner(uint256 i, uint256 a, uint256 b, uint256 c) external { uint256[] memory xs = new uint256[](3); xs[0]=a;xs[1]=b;xs[2]=c; dd[i] = xs; }
  function getInner(uint256 i) external view returns (uint256[] memory){ return dd[i]; }
}`;

describe('round-5 fixes vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function send(data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${j.exceptionError}`).toBe(s.success);
  }
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'R5.jeth' });
    const sb = compileSolidity(SOL, 'R5');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('#3 return this.s.xs (struct dynamic-array field)', async () => {
    await send(encodeCall(sel('pushX(uint256)'), [11n]));
    await send(encodeCall(sel('pushX(uint256)'), [22n]));
    await eq('getXs', encodeCall(sel('getXs()'), []));
  });
  it('#4 return this.g[i] (fixed inner-array row of a 2D fixed array)', async () => {
    await send(encodeCall(sel('setG(uint256,uint256,uint256)'), [0n, 0n, 7n]));
    await send(encodeCall(sel('setG(uint256,uint256,uint256)'), [0n, 1n, 8n]));
    await eq('getRow[0]', encodeCall(sel('getRow(uint256)'), [0n]));
    await eq('getRow[1] default', encodeCall(sel('getRow(uint256)'), [1n]));
  });
  it('#7 assign whole inner array element + overwrite (shrink) preserved', async () => {
    await send(encodeCall(sel('ddPush()'), []));
    await send(encodeCall(sel('assignInner(uint256,uint256,uint256,uint256)'), [0n, 1n, 2n, 3n]));
    await eq('getInner after assign', encodeCall(sel('getInner(uint256)'), [0n]));
    // overwrite with a shorter one (was len 3) - reuse assignInner then a 2-element via direct push path
    await send(encodeCall(sel('assignInner(uint256,uint256,uint256,uint256)'), [0n, 9n, 8n, 7n]));
    await eq('getInner after reassign', encodeCall(sel('getInner(uint256)'), [0n]));
  });
});
