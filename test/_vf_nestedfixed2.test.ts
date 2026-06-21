// AREA: nestedfixed (part 2) - deeper/odder nests the first probe did not cover:
// 5D arrays, signed i8/i128/i256 nested returns, fixed array of structs that have a
// 2D fixed field as a STRUCT FIELD (Arr<Pk,2> whole return), partial-write zero-init
// parity, mixed packed-width struct elements in a nested grid, bytes32 grid, and a
// struct holding Arr<Arr<Struct,2>,2> of a struct that itself holds a 2D fixed field.
// Byte-identical to solc (0.8.x, cancun, optimizer).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const JETH = `@struct class Pk { a: u64; rows: Arr<Arr<u8, 4>, 3>; b: u64; }
@struct class Cell { lo: u128; hi: i128; }
@struct class Deep { head: u256; inner: Arr<Pk, 2>; foot: u256; }
@contract class C {
  @state d5: Arr<Arr<Arr<Arr<Arr<u256, 2>, 2>, 2>, 2>, 2>;
  @state s8: Arr<Arr<i8, 3>, 2>;
  @state s128: Arr<Arr<i128, 2>, 2>;
  @state s256: Arr<Arr<i256, 2>, 2>;
  @state b32: Arr<Arr<bytes32, 2>, 2>;
  @state cells: Arr<Arr<Cell, 2>, 2>;
  @state pkgrid: Arr<Pk, 2>;
  @state deep: Deep;
  @state part: Arr<Arr<u256, 3>, 3>;
  @state sentinel: u256;

  @external setSentinel(v: u256): void { this.sentinel = v; }
  @external setD5(i: u256, j: u256, k: u256, l: u256, m: u256, v: u256): void { this.d5[i][j][k][l][m] = v; }
  @external setS8(i: u256, j: u256, v: i8): void { this.s8[i][j] = v; }
  @external setS128(i: u256, j: u256, v: i128): void { this.s128[i][j] = v; }
  @external setS256(i: u256, j: u256, v: i256): void { this.s256[i][j] = v; }
  @external setB32(i: u256, j: u256, v: bytes32): void { this.b32[i][j] = v; }
  @external setCell(i: u256, j: u256, lo: u128, hi: i128): void { this.cells[i][j].lo = lo; this.cells[i][j].hi = hi; }
  @external setPkgrid(idx: u256, a: u64, b: u64, i: u256, j: u256, v: u8): void { this.pkgrid[idx].a = a; this.pkgrid[idx].b = b; this.pkgrid[idx].rows[i][j] = v; }
  @external setDeep(head: u256, foot: u256, idx: u256, a: u64, b: u64, i: u256, j: u256, v: u8): void { this.deep.head = head; this.deep.foot = foot; this.deep.inner[idx].a = a; this.deep.inner[idx].b = b; this.deep.inner[idx].rows[i][j] = v; }
  @external setPart(i: u256, j: u256, v: u256): void { this.part[i][j] = v; }

  @external @view getD5(): Arr<Arr<Arr<Arr<Arr<u256, 2>, 2>, 2>, 2>, 2> { return this.d5; }
  @external @view elemD5(i: u256, j: u256, k: u256, l: u256, m: u256): u256 { return this.d5[i][j][k][l][m]; }
  @external @view getS8(): Arr<Arr<i8, 3>, 2> { return this.s8; }
  @external @view rowS8(i: u256): Arr<i8, 3> { return this.s8[i]; }
  @external @view getS128(): Arr<Arr<i128, 2>, 2> { return this.s128; }
  @external @view getS256(): Arr<Arr<i256, 2>, 2> { return this.s256; }
  @external @view getB32(): Arr<Arr<bytes32, 2>, 2> { return this.b32; }
  @external @view getCells(): Arr<Arr<Cell, 2>, 2> { return this.cells; }
  @external @view rowCells(i: u256): Arr<Cell, 2> { return this.cells[i]; }
  @external @view getPkgrid(): Arr<Pk, 2> { return this.pkgrid; }
  @external @view elemPkgrid(idx: u256): Pk { return this.pkgrid[idx]; }
  @external @view getDeep(): Deep { return this.deep; }
  @external @view getPart(): Arr<Arr<u256, 3>, 3> { return this.part; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Pk { uint64 a; uint8[4][3] rows; uint64 b; }
  struct Cell { uint128 lo; int128 hi; }
  struct Deep { uint256 head; Pk[2] inner; uint256 foot; }
  uint256[2][2][2][2][2] d5;
  int8[3][2] s8;
  int128[2][2] s128;
  int256[2][2] s256;
  bytes32[2][2] b32;
  Cell[2][2] cells;
  Pk[2] pkgrid;
  Deep deep;
  uint256[3][3] part;
  uint256 sentinel;

  function setSentinel(uint256 v) external { sentinel = v; }
  function setD5(uint256 i, uint256 j, uint256 k, uint256 l, uint256 m, uint256 v) external { d5[i][j][k][l][m] = v; }
  function setS8(uint256 i, uint256 j, int8 v) external { s8[i][j] = v; }
  function setS128(uint256 i, uint256 j, int128 v) external { s128[i][j] = v; }
  function setS256(uint256 i, uint256 j, int256 v) external { s256[i][j] = v; }
  function setB32(uint256 i, uint256 j, bytes32 v) external { b32[i][j] = v; }
  function setCell(uint256 i, uint256 j, uint128 lo, int128 hi) external { cells[i][j].lo = lo; cells[i][j].hi = hi; }
  function setPkgrid(uint256 idx, uint64 a, uint64 b, uint256 i, uint256 j, uint8 v) external { pkgrid[idx].a = a; pkgrid[idx].b = b; pkgrid[idx].rows[i][j] = v; }
  function setDeep(uint256 head, uint256 foot, uint256 idx, uint64 a, uint64 b, uint256 i, uint256 j, uint8 v) external { deep.head = head; deep.foot = foot; deep.inner[idx].a = a; deep.inner[idx].b = b; deep.inner[idx].rows[i][j] = v; }
  function setPart(uint256 i, uint256 j, uint256 v) external { part[i][j] = v; }

  function getD5() external view returns (uint256[2][2][2][2][2] memory){ return d5; }
  function elemD5(uint256 i, uint256 j, uint256 k, uint256 l, uint256 m) external view returns (uint256){ return d5[i][j][k][l][m]; }
  function getS8() external view returns (int8[3][2] memory){ return s8; }
  function rowS8(uint256 i) external view returns (int8[3] memory){ return s8[i]; }
  function getS128() external view returns (int128[2][2] memory){ return s128; }
  function getS256() external view returns (int256[2][2] memory){ return s256; }
  function getB32() external view returns (bytes32[2][2] memory){ return b32; }
  function getCells() external view returns (Cell[2][2] memory){ return cells; }
  function rowCells(uint256 i) external view returns (Cell[2] memory){ return cells[i]; }
  function getPkgrid() external view returns (Pk[2] memory){ return pkgrid; }
  function elemPkgrid(uint256 idx) external view returns (Pk memory){ return pkgrid[idx]; }
  function getDeep() external view returns (Deep memory){ return deep; }
  function getPart() external view returns (uint256[3][3] memory){ return part; }
}`;

describe('nestedfixed probe part 2', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;
  async function eq(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success || j.returnHex !== s.returnHex)
      mism.push(label + ': jeth{ok=' + j.success + ',ret=' + j.returnHex + ',err=' + j.exceptionError + '} sol{ok=' + s.success + ',ret=' + s.returnHex + '}');
  }
  function raw(sig: string, words: bigint[]): string {
    return '0x' + functionSelector(sig) + words.map(pad).join('');
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('runs', async () => {
    await eq('setSentinel', raw('setSentinel(uint256)', [0xc0ffeen]));

    // ---- 5D array: write a SPARSE set of corners + a couple of interior cells ----
    const d5cells: [bigint, bigint, bigint, bigint, bigint, bigint][] = [
      [0n,0n,0n,0n,0n, 1n], [1n,1n,1n,1n,1n, M - 1n], [0n,1n,0n,1n,0n, 0xabcn],
      [1n,0n,1n,0n,1n, 1n << 255n], [0n,0n,1n,1n,0n, 0xdeadn], [1n,1n,0n,0n,1n, M - 0x100n],
    ];
    for (const [i,j,k,l,m,v] of d5cells)
      await eq(`setD5[${i}${j}${k}${l}${m}]`, raw('setD5(uint256,uint256,uint256,uint256,uint256,uint256)', [i,j,k,l,m,v]));
    await eq('getD5', encodeCall(sel('getD5()')));
    for (const [i,j,k,l,m] of d5cells)
      await eq(`elemD5[${i}${j}${k}${l}${m}]`, raw('elemD5(uint256,uint256,uint256,uint256,uint256)', [i,j,k,l,m]));
    // a few zero cells (never written) - prove zero-init parity in whole return
    await eq('elemD5-zero', raw('elemD5(uint256,uint256,uint256,uint256,uint256)', [0n,1n,1n,0n,1n]));

    // ---- i8 grid: INT8_MIN/MAX, -1, sign-extend on whole + row return ----
    const i8vals = [127n, M - 128n, M - 1n, 0n, 42n, M - 100n];
    let n = 0;
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 3n; j++)
      await eq(`setS8[${i}][${j}]`, raw('setS8(uint256,uint256,int8)', [i, j, i8vals[n++]!]));
    await eq('getS8', encodeCall(sel('getS8()')));
    await eq('rowS8[0]', raw('rowS8(uint256)', [0n]));
    await eq('rowS8[1]', raw('rowS8(uint256)', [1n]));

    // ---- i128 grid ----
    const i128vals = [(1n << 127n) - 1n, M - (1n << 127n), M - 1n, 0x1234567890n];
    n = 0;
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++)
      await eq(`setS128[${i}][${j}]`, raw('setS128(uint256,uint256,int128)', [i, j, i128vals[n++]!]));
    await eq('getS128', encodeCall(sel('getS128()')));

    // ---- i256 grid: full-width INT256_MIN/MAX ----
    const i256vals = [(1n << 255n) - 1n, 1n << 255n, M - 1n, 0n];
    n = 0;
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++)
      await eq(`setS256[${i}][${j}]`, raw('setS256(uint256,uint256,int256)', [i, j, i256vals[n++]!]));
    await eq('getS256', encodeCall(sel('getS256()')));

    // ---- bytes32 grid ----
    const b32vals = [M - 1n, 0n, 0xdeadbeefn << 224n, 0x0123456789abcdefn];
    n = 0;
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++)
      await eq(`setB32[${i}][${j}]`, raw('setB32(uint256,uint256,bytes32)', [i, j, b32vals[n++]!]));
    await eq('getB32', encodeCall(sel('getB32()')));

    // ---- Cell grid (struct with u128 + i128 packed in one slot) ----
    const cellPairs: [bigint, bigint][] = [
      [(1n << 128n) - 1n, (1n << 127n) - 1n], [1n, M - 1n], [0xaan, M - (1n << 127n)], [0n, 5n],
    ];
    n = 0;
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++) {
      const [lo, hi] = cellPairs[n++]!;
      await eq(`setCell[${i}][${j}]`, raw('setCell(uint256,uint256,uint128,int128)', [i, j, lo, hi]));
    }
    await eq('getCells', encodeCall(sel('getCells()')));
    await eq('rowCells[0]', raw('rowCells(uint256)', [0n]));
    await eq('rowCells[1]', raw('rowCells(uint256)', [1n]));

    // ---- pkgrid: fixed array of struct-with-packed-2D-field ----
    for (const idx of [0n, 1n]) {
      let m = 1n;
      for (let i = 0n; i < 3n; i++) for (let j = 0n; j < 4n; j++)
        await eq(`setPkgrid[${idx}][${i}][${j}]`, raw('setPkgrid(uint256,uint64,uint64,uint256,uint256,uint8)', [idx, 0xa0n + idx, 0xb0n + idx, i, j, m++]));
    }
    await eq('getPkgrid', encodeCall(sel('getPkgrid()')));
    await eq('elemPkgrid[0]', raw('elemPkgrid(uint256)', [0n]));
    await eq('elemPkgrid[1]', raw('elemPkgrid(uint256)', [1n]));

    // ---- deep: struct{u256; Arr<Pk,2>; u256} - struct holding fixed array of struct w/ 2D field ----
    for (const idx of [0n, 1n]) {
      let m = 1n;
      for (let i = 0n; i < 3n; i++) for (let j = 0n; j < 4n; j++)
        await eq(`setDeep[${idx}][${i}][${j}]`, raw('setDeep(uint256,uint256,uint256,uint64,uint64,uint256,uint256,uint8)', [0x111n, 0x222n, idx, 0xc0n + idx, 0xd0n + idx, i, j, m++]));
    }
    await eq('getDeep', encodeCall(sel('getDeep()')));

    // ---- part: partial-write zero-init parity (write only the diagonal of a 3x3) ----
    for (let d = 0n; d < 3n; d++)
      await eq(`setPart[${d}][${d}]`, raw('setPart(uint256,uint256,uint256)', [d, d, 0x1000n + d]));
    await eq('getPart-partial', encodeCall(sel('getPart()')));
    // overwrite one diagonal cell to 0 then read whole (clearing parity)
    await eq('setPart-clear', raw('setPart(uint256,uint256,uint256)', [1n, 1n, 0n]));
    await eq('getPart-after-clear', encodeCall(sel('getPart()')));

    // ---- OOB on the deeper dims ----
    await eq('oob-d5-m', raw('elemD5(uint256,uint256,uint256,uint256,uint256)', [0n,0n,0n,0n,2n]));
    await eq('oob-d5-i', raw('elemD5(uint256,uint256,uint256,uint256,uint256)', [2n,0n,0n,0n,0n]));
    await eq('oob-pkgrid', raw('elemPkgrid(uint256)', [2n]));
    await eq('oob-cells-row', raw('rowCells(uint256)', [2n]));
    await eq('oob-s8-i', raw('rowS8(uint256)', [2n]));

    // dirty input validation on small signed/packed values
    await eq('dirty-i8', raw('setS8(uint256,uint256,int8)', [0n, 0n, 200n])); // 200 > int8 dirty -> revert
    await eq('dirty-i128', raw('setS128(uint256,uint256,int128)', [0n, 0n, 1n << 128n]));
    await eq('dirty-u128-cell', raw('setCell(uint256,uint256,uint128,int128)', [0n, 0n, 1n << 128n, 1n]));

    if (mism.length) { console.log('MISMATCHES ' + mism.length + '/' + count); for (const m of mism.slice(0, 40)) console.log(m); }
    else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
