// Round-6: memory-array -> storage assignment (this.a = xs), and whole fixed-array leaf
// return at depth (return this.g3[i][j]). Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const JETH = `@contract class R6 {
  @state a: u256[];
  @state g3: Arr<Arr<Arr<u256, 2>, 3>, 2>;
  @external pushA(v: u256): void { this.a.push(v); }
  @external assignMem(x: u256, y: u256, z: u256): void { let xs: u256[] = [x, y, z]; this.a = xs; }
  @external @view getA(): u256[] { return this.a; }
  @external setG3(i: u256, j: u256, k: u256, v: u256): void { this.g3[i][j][k] = v; }
  @external @view row(i: u256, j: u256): Arr<u256, 2> { return this.g3[i][j]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract R6 {
  uint256[] a;
  uint256[2][3][2] g3;
  function pushA(uint256 v) external { a.push(v); }
  function assignMem(uint256 x, uint256 y, uint256 z) external { uint256[] memory xs = new uint256[](3); xs[0]=x;xs[1]=y;xs[2]=z; a = xs; }
  function getA() external view returns (uint256[] memory){ return a; }
  function setG3(uint256 i, uint256 j, uint256 k, uint256 v) external { g3[i][j][k] = v; }
  function row(uint256 i, uint256 j) external view returns (uint256[2] memory){ return g3[i][j]; }
}`;

describe('round-6 fixes vs Solidity', () => {
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
    const jb = compile(JETH, { fileName: 'R6.jeth' });
    const sb = compileSolidity(SOL, 'R6');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('memory array -> storage assign (overwrite a pre-filled longer array, tail clear)', async () => {
    for (const v of [9n, 8n, 7n, 6n, 5n]) await send(encodeCall(sel('pushA(uint256)'), [v]));
    await send(encodeCall(sel('assignMem(uint256,uint256,uint256)'), [1n, 2n, 3n]));
    await eq('getA after mem-assign (shrink 5->3)', encodeCall(sel('getA()'), []));
  });
  it('whole fixed-array leaf return at depth (return this.g3[i][j])', async () => {
    await send(encodeCall(sel('setG3(uint256,uint256,uint256,uint256)'), [0n, 1n, 0n, 42n]));
    await send(encodeCall(sel('setG3(uint256,uint256,uint256,uint256)'), [0n, 1n, 1n, 43n]));
    await eq('row[0][1]', encodeCall(sel('row(uint256,uint256)'), [0n, 1n]));
    await eq('row[1][2] default', encodeCall(sel('row(uint256,uint256)'), [1n, 2n]));
  });
});
