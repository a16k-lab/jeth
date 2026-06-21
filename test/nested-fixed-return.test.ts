// Critical fix: structStorageLeaves now flattens a NESTED fixed-array element. Whole returns
// of Arr<Arr<u256,2>,2>, 3D fixed arrays, single-index rows, and structs with a 2D fixed
// field were silently zeroing the deeper elements. Byte-identical to Solidity now.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const JETH = `@struct class W { tag: u256; grid: Arr<Arr<u256, 2>, 2>; }
@contract class NF {
  @state g: Arr<Arr<u256, 2>, 2>;
  @state g3: Arr<Arr<Arr<u256, 2>, 3>, 2>;
  @state w: W;
  @external setG(i: u256, j: u256, v: u256): void { this.g[i][j] = v; }
  @external setG3(i: u256, j: u256, k: u256, v: u256): void { this.g3[i][j][k] = v; }
  @external setW(t: u256, i: u256, j: u256, v: u256): void { this.w.tag = t; this.w.grid[i][j] = v; }
  @external @view whole(): Arr<Arr<u256, 2>, 2> { return this.g; }
  @external @view row(i: u256): Arr<u256, 2> { return this.g[i]; }
  @external @view whole3(): Arr<Arr<Arr<u256, 2>, 3>, 2> { return this.g3; }
  @external @view plane(i: u256): Arr<Arr<u256, 2>, 3> { return this.g3[i]; }
  @external @view wstruct(): W { return this.w; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract NF {
  struct W { uint256 tag; uint256[2][2] grid; }
  uint256[2][2] g;
  uint256[2][3][2] g3;
  W w;
  function setG(uint256 i, uint256 j, uint256 v) external { g[i][j] = v; }
  function setG3(uint256 i, uint256 j, uint256 k, uint256 v) external { g3[i][j][k] = v; }
  function setW(uint256 t, uint256 i, uint256 j, uint256 v) external { w.tag = t; w.grid[i][j] = v; }
  function whole() external view returns (uint256[2][2] memory){ return g; }
  function row(uint256 i) external view returns (uint256[2] memory){ return g[i]; }
  function whole3() external view returns (uint256[2][3][2] memory){ return g3; }
  function plane(uint256 i) external view returns (uint256[2][3] memory){ return g3[i]; }
  function wstruct() external view returns (W memory){ return w; }
}`;

describe('nested fixed-array whole returns vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function send(data: string) { const j = await jeth.call(aj, data); const s = await sol.call(as, data); expect(j.success).toBe(s.success); }
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'NF.jeth' });
    const sb = compileSolidity(SOL, 'NF');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  it('2D fixed array: whole return + single-index row (no zeroing)', async () => {
    for (const [i, j, v] of [[0n,0n,1n],[0n,1n,2n],[1n,0n,3n],[1n,1n,4n]] as [bigint,bigint,bigint][])
      await send(encodeCall(sel('setG(uint256,uint256,uint256)'), [i, j, v]));
    await eq('whole', encodeCall(sel('whole()'), []));
    await eq('row[0]', encodeCall(sel('row(uint256)'), [0n]));
    await eq('row[1]', encodeCall(sel('row(uint256)'), [1n]));
  });
  it('3D fixed array: whole + single-index plane', async () => {
    await send(encodeCall(sel('setG3(uint256,uint256,uint256,uint256)'), [0n, 1n, 0n, 11n]));
    await send(encodeCall(sel('setG3(uint256,uint256,uint256,uint256)'), [0n, 1n, 1n, 12n]));
    await send(encodeCall(sel('setG3(uint256,uint256,uint256,uint256)'), [1n, 2n, 1n, 99n]));
    await eq('whole3', encodeCall(sel('whole3()'), []));
    await eq('plane[0]', encodeCall(sel('plane(uint256)'), [0n]));
  });
  it('struct with a 2D fixed-array field', async () => {
    await send(encodeCall(sel('setW(uint256,uint256,uint256,uint256)'), [7n, 0n, 1n, 88n]));
    await eq('wstruct', encodeCall(sel('wstruct()'), []));
  });
});
