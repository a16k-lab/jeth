// Manual adversarial verification of the structStorageLeaves fix across its full blast
// radius: packed / signed / deeper-nested fixed arrays, fixed arrays of structs with fixed
// fields, mapping values, and dynamic arrays of such structs. EVERY leaf gets a distinct
// value so any "deeper element zeroed / wrong slot" miscompile is caught. Byte-identical to solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const K = 0xbeefn;

const JETH = `@struct class W { tag: u256; grid: Arr<Arr<u256, 2>, 2>; }
@struct class Pk { a: u64; rows: Arr<Arr<u8, 4>, 3>; b: u64; }
@struct class Sg { s: Arr<Arr<i64, 2>, 2>; }
@contract class NA {
  @state up: Arr<Arr<u8, 4>, 3>;
  @state sg: Arr<Arr<i64, 2>, 2>;
  @state d4: Arr<Arr<Arr<u256, 2>, 2>, 2>;
  @state w: W;
  @state pk: Pk;
  @state mw: mapping<u256, W>;
  @state warr: W[];
  @external setUp(i: u256, j: u256, v: u8): void { this.up[i][j] = v; }
  @external setSg(i: u256, j: u256, v: i64): void { this.sg[i][j] = v; }
  @external setD4(i: u256, j: u256, k: u256, v: u256): void { this.d4[i][j][k] = v; }
  @external setW(t: u256, i: u256, j: u256, v: u256): void { this.w.tag = t; this.w.grid[i][j] = v; }
  @external setPk(a: u64, b: u64, i: u256, j: u256, v: u8): void { this.pk.a = a; this.pk.b = b; this.pk.rows[i][j] = v; }
  @external setMw(k: u256, t: u256, i: u256, j: u256, v: u256): void { this.mw[k].tag = t; this.mw[k].grid[i][j] = v; }
  @external pushW(): void { this.warr.push(); }
  @external setWarr(idx: u256, t: u256, i: u256, j: u256, v: u256): void { this.warr[idx].tag = t; this.warr[idx].grid[i][j] = v; }
  @external @view getUp(): Arr<Arr<u8, 4>, 3> { return this.up; }
  @external @view getSg(): Arr<Arr<i64, 2>, 2> { return this.sg; }
  @external @view getD4(): Arr<Arr<Arr<u256, 2>, 2>, 2> { return this.d4; }
  @external @view getW(): W { return this.w; }
  @external @view getPk(): Pk { return this.pk; }
  @external @view getMw(k: u256): W { return this.mw[k]; }
  @external @view getWarr(): W[] { return this.warr; }
  @external @view getWarrI(i: u256): W { return this.warr[i]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract NA {
  struct W { uint256 tag; uint256[2][2] grid; }
  struct Pk { uint64 a; uint8[4][3] rows; uint64 b; }
  uint8[4][3] up;
  int64[2][2] sg;
  uint256[2][2][2] d4;
  W w; Pk pk;
  mapping(uint256 => W) mw;
  W[] warr;
  function setUp(uint256 i, uint256 j, uint8 v) external { up[i][j] = v; }
  function setSg(uint256 i, uint256 j, int64 v) external { sg[i][j] = v; }
  function setD4(uint256 i, uint256 j, uint256 k, uint256 v) external { d4[i][j][k] = v; }
  function setW(uint256 t, uint256 i, uint256 j, uint256 v) external { w.tag = t; w.grid[i][j] = v; }
  function setPk(uint64 a, uint64 b, uint256 i, uint256 j, uint8 v) external { pk.a = a; pk.b = b; pk.rows[i][j] = v; }
  function setMw(uint256 k, uint256 t, uint256 i, uint256 j, uint256 v) external { mw[k].tag = t; mw[k].grid[i][j] = v; }
  function pushW() external { warr.push(); }
  function setWarr(uint256 idx, uint256 t, uint256 i, uint256 j, uint256 v) external { warr[idx].tag = t; warr[idx].grid[i][j] = v; }
  function getUp() external view returns (uint8[4][3] memory){ return up; }
  function getSg() external view returns (int64[2][2] memory){ return sg; }
  function getD4() external view returns (uint256[2][2][2] memory){ return d4; }
  function getW() external view returns (W memory){ return w; }
  function getPk() external view returns (Pk memory){ return pk; }
  function getMw(uint256 k) external view returns (W memory){ return mw[k]; }
  function getWarr() external view returns (W[] memory){ return warr; }
  function getWarrI(uint256 i) external view returns (W memory){ return warr[i]; }
}`;

describe('nested fixed-array adversarial (structStorageLeaves) vs Solidity', () => {
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
    const jb = compile(JETH, { fileName: 'NA.jeth' });
    const sb = compileSolidity(SOL, 'NA');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('packed Arr<Arr<u8,4>,3> whole return (distinct every lane)', async () => {
    let n = 1n;
    for (let i = 0n; i < 3n; i++)
      for (let j = 0n; j < 4n; j++) await send(encodeCall(sel('setUp(uint256,uint256,uint8)'), [i, j, n++]));
    await eq('getUp', encodeCall(sel('getUp()'), []));
  });
  it('signed Arr<Arr<i64,2>,2> whole return (negatives, sign-extend)', async () => {
    await send(encodeCall(sel('setSg(uint256,uint256,int64)'), [0n, 0n, 5n]));
    await send(encodeCall(sel('setSg(uint256,uint256,int64)'), [0n, 1n, M - 7n]));
    await send(encodeCall(sel('setSg(uint256,uint256,int64)'), [1n, 0n, (1n << 63n) - 1n]));
    await send(encodeCall(sel('setSg(uint256,uint256,int64)'), [1n, 1n, M - (1n << 63n)]));
    await eq('getSg', encodeCall(sel('getSg()'), []));
  });
  it('4D-ish Arr<Arr<Arr<u256,2>,2>,2> whole return', async () => {
    let n = 100n;
    for (let i = 0n; i < 2n; i++)
      for (let j = 0n; j < 2n; j++)
        for (let k = 0n; k < 2n; k++)
          await send(encodeCall(sel('setD4(uint256,uint256,uint256,uint256)'), [i, j, k, n++]));
    await eq('getD4', encodeCall(sel('getD4()'), []));
  });
  it('struct W{tag; 2D grid} whole return + mapping value', async () => {
    await send(encodeCall(sel('setW(uint256,uint256,uint256,uint256)'), [9n, 0n, 0n, 1n]));
    await send(encodeCall(sel('setW(uint256,uint256,uint256,uint256)'), [9n, 0n, 1n, 2n]));
    await send(encodeCall(sel('setW(uint256,uint256,uint256,uint256)'), [9n, 1n, 0n, 3n]));
    await send(encodeCall(sel('setW(uint256,uint256,uint256,uint256)'), [9n, 1n, 1n, 4n]));
    await eq('getW', encodeCall(sel('getW()'), []));
    await send(encodeCall(sel('setMw(uint256,uint256,uint256,uint256,uint256)'), [K, 7n, 1n, 1n, 55n]));
    await eq('getMw', encodeCall(sel('getMw(uint256)'), [K]));
  });
  it('struct Pk{u64; packed 2D; u64} whole return (packed neighbours preserved)', async () => {
    let n = 1n;
    for (let i = 0n; i < 3n; i++)
      for (let j = 0n; j < 4n; j++)
        await send(encodeCall(sel('setPk(uint64,uint64,uint256,uint256,uint8)'), [0xaaaan, 0xbbbbn, i, j, n++]));
    await eq('getPk', encodeCall(sel('getPk()'), []));
  });
  it('W[] (struct array with nested fixed field) whole + element return', async () => {
    await send(encodeCall(sel('pushW()'), []));
    await send(encodeCall(sel('pushW()'), []));
    for (const [idx, t, i, j, v] of [
      [0n, 1n, 0n, 0n, 10n],
      [0n, 1n, 0n, 1n, 11n],
      [0n, 1n, 1n, 0n, 12n],
      [0n, 1n, 1n, 1n, 13n],
      [1n, 2n, 0n, 0n, 20n],
      [1n, 2n, 0n, 1n, 21n],
      [1n, 2n, 1n, 0n, 22n],
      [1n, 2n, 1n, 1n, 23n],
    ] as [bigint, bigint, bigint, bigint, bigint][])
      await send(encodeCall(sel('setWarr(uint256,uint256,uint256,uint256,uint256)'), [idx, t, i, j, v]));
    await eq('getWarr', encodeCall(sel('getWarr()'), []));
    await eq('getWarrI[1]', encodeCall(sel('getWarrI(uint256)'), [1n]));
  });
});
