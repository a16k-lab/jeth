// AREA: nestedfixed - adversarial differential probe for nested/multi-dimensional
// FIXED arrays Arr<Arr<T,N>,M> and deeper. Element types: u256, packed u8, signed
// i64, bytesN, bool, struct. Whole-array returns, single-index row/plane returns,
// element read/write at every index, fixed-array fields in structs, fixed array of
// structs that themselves have a 2D fixed field. This area had a real miscompile
// before (deeper elements zeroed). Byte-identical to solc (0.8.x, cancun, optimizer).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

// JETH and SOL mirror each other exactly.
const JETH = `@struct class G2 { tag: u256; grid: Arr<Arr<u256, 2>, 2>; }
@struct class Pk { a: u64; rows: Arr<Arr<u8, 4>, 3>; b: u64; }
@struct class Sg { lead: i32; s: Arr<Arr<i64, 2>, 3>; tail: i32; }
@struct class Bz { h: bytes8; m: Arr<Arr<bytes4, 2>, 2>; }
@struct class Bl { p: bool; flags: Arr<Arr<bool, 5>, 2>; q: bool; }
@struct class Inner { x: u32; y: u32; }
@struct class StructGrid { lead: u256; cells: Arr<Arr<Inner, 2>, 2>; trail: u256; }
@contract class C {
  @state u2: Arr<Arr<u256, 3>, 2>;
  @state u3: Arr<Arr<Arr<u256, 2>, 2>, 2>;
  @state u4: Arr<Arr<Arr<Arr<u256, 2>, 2>, 2>, 2>;
  @state p2: Arr<Arr<u8, 4>, 3>;
  @state p3: Arr<Arr<Arr<u8, 5>, 3>, 2>;
  @state s2: Arr<Arr<i64, 2>, 3>;
  @state b2: Arr<Arr<bytes4, 2>, 2>;
  @state bl2: Arr<Arr<bool, 5>, 2>;
  @state g2: G2;
  @state pk: Pk;
  @state sg: Sg;
  @state bz: Bz;
  @state bl: Bl;
  @state sgr: StructGrid;
  @state g2arr: G2[];
  @state pkarr: Pk[];
  @state sentBefore: u256;
  @state sentAfter: u256;

  @external setSent(b4: u256, aft: u256): void { this.sentBefore = b4; this.sentAfter = aft; }
  @external setU2(i: u256, j: u256, v: u256): void { this.u2[i][j] = v; }
  @external setU3(i: u256, j: u256, k: u256, v: u256): void { this.u3[i][j][k] = v; }
  @external setU4(i: u256, j: u256, k: u256, l: u256, v: u256): void { this.u4[i][j][k][l] = v; }
  @external setP2(i: u256, j: u256, v: u8): void { this.p2[i][j] = v; }
  @external setP3(i: u256, j: u256, k: u256, v: u8): void { this.p3[i][j][k] = v; }
  @external setS2(i: u256, j: u256, v: i64): void { this.s2[i][j] = v; }
  @external setB2(i: u256, j: u256, v: bytes4): void { this.b2[i][j] = v; }
  @external setBl2(i: u256, j: u256, v: bool): void { this.bl2[i][j] = v; }
  @external setG2(t: u256, i: u256, j: u256, v: u256): void { this.g2.tag = t; this.g2.grid[i][j] = v; }
  @external setPk(a: u64, b: u64, i: u256, j: u256, v: u8): void { this.pk.a = a; this.pk.b = b; this.pk.rows[i][j] = v; }
  @external setSg(lead: i32, tail: i32, i: u256, j: u256, v: i64): void { this.sg.lead = lead; this.sg.tail = tail; this.sg.s[i][j] = v; }
  @external setBz(h: bytes8, i: u256, j: u256, v: bytes4): void { this.bz.h = h; this.bz.m[i][j] = v; }
  @external setBl(p: bool, q: bool, i: u256, j: u256, v: bool): void { this.bl.p = p; this.bl.q = q; this.bl.flags[i][j] = v; }
  @external setSgr(lead: u256, trail: u256, i: u256, j: u256, x: u32, y: u32): void { this.sgr.lead = lead; this.sgr.trail = trail; this.sgr.cells[i][j].x = x; this.sgr.cells[i][j].y = y; }
  @external pushG2(): void { this.g2arr.push(); }
  @external setG2arr(idx: u256, t: u256, i: u256, j: u256, v: u256): void { this.g2arr[idx].tag = t; this.g2arr[idx].grid[i][j] = v; }
  @external pushPk(): void { this.pkarr.push(); }
  @external setPkarr(idx: u256, a: u64, b: u64, i: u256, j: u256, v: u8): void { this.pkarr[idx].a = a; this.pkarr[idx].b = b; this.pkarr[idx].rows[i][j] = v; }

  @view getU2(): Arr<Arr<u256, 3>, 2> { return this.u2; }
  @view rowU2(i: u256): Arr<u256, 3> { return this.u2[i]; }
  @view elemU2(i: u256, j: u256): u256 { return this.u2[i][j]; }
  @view getU3(): Arr<Arr<Arr<u256, 2>, 2>, 2> { return this.u3; }
  @view planeU3(i: u256): Arr<Arr<u256, 2>, 2> { return this.u3[i]; }
  @view rowU3(i: u256, j: u256): Arr<u256, 2> { return this.u3[i][j]; }
  @view elemU3(i: u256, j: u256, k: u256): u256 { return this.u3[i][j][k]; }
  @view getU4(): Arr<Arr<Arr<Arr<u256, 2>, 2>, 2>, 2> { return this.u4; }
  @view cubeU4(i: u256): Arr<Arr<Arr<u256, 2>, 2>, 2> { return this.u4[i]; }
  @view elemU4(i: u256, j: u256, k: u256, l: u256): u256 { return this.u4[i][j][k][l]; }
  @view getP2(): Arr<Arr<u8, 4>, 3> { return this.p2; }
  @view rowP2(i: u256): Arr<u8, 4> { return this.p2[i]; }
  @view elemP2(i: u256, j: u256): u8 { return this.p2[i][j]; }
  @view getP3(): Arr<Arr<Arr<u8, 5>, 3>, 2> { return this.p3; }
  @view planeP3(i: u256): Arr<Arr<u8, 5>, 3> { return this.p3[i]; }
  @view elemP3(i: u256, j: u256, k: u256): u8 { return this.p3[i][j][k]; }
  @view getS2(): Arr<Arr<i64, 2>, 3> { return this.s2; }
  @view rowS2(i: u256): Arr<i64, 2> { return this.s2[i]; }
  @view elemS2(i: u256, j: u256): i64 { return this.s2[i][j]; }
  @view getB2(): Arr<Arr<bytes4, 2>, 2> { return this.b2; }
  @view rowB2(i: u256): Arr<bytes4, 2> { return this.b2[i]; }
  @view elemB2(i: u256, j: u256): bytes4 { return this.b2[i][j]; }
  @view getBl2(): Arr<Arr<bool, 5>, 2> { return this.bl2; }
  @view rowBl2(i: u256): Arr<bool, 5> { return this.bl2[i]; }
  @view elemBl2(i: u256, j: u256): bool { return this.bl2[i][j]; }
  @view getG2(): G2 { return this.g2; }
  @view getPk(): Pk { return this.pk; }
  @view getSg(): Sg { return this.sg; }
  @view getBz(): Bz { return this.bz; }
  @view getBl(): Bl { return this.bl; }
  @view getSgr(): StructGrid { return this.sgr; }
  @view getG2arr(): G2[] { return this.g2arr; }
  @view getG2arrI(i: u256): G2 { return this.g2arr[i]; }
  @view getPkarr(): Pk[] { return this.pkarr; }
  @view getPkarrI(i: u256): Pk { return this.pkarr[i]; }
  @view getSentBefore(): u256 { return this.sentBefore; }
  @view getSentAfter(): u256 { return this.sentAfter; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct G2 { uint256 tag; uint256[2][2] grid; }
  struct Pk { uint64 a; uint8[4][3] rows; uint64 b; }
  struct Sg { int32 lead; int64[2][3] s; int32 tail; }
  struct Bz { bytes8 h; bytes4[2][2] m; }
  struct Bl { bool p; bool[5][2] flags; bool q; }
  struct Inner { uint32 x; uint32 y; }
  struct StructGrid { uint256 lead; Inner[2][2] cells; uint256 trail; }
  uint256[3][2] u2;
  uint256[2][2][2] u3;
  uint256[2][2][2][2] u4;
  uint8[4][3] p2;
  uint8[5][3][2] p3;
  int64[2][3] s2;
  bytes4[2][2] b2;
  bool[5][2] bl2;
  G2 g2;
  Pk pk;
  Sg sg;
  Bz bz;
  Bl bl;
  StructGrid sgr;
  G2[] g2arr;
  Pk[] pkarr;
  uint256 sentBefore;
  uint256 sentAfter;

  function setSent(uint256 b4, uint256 aft) external { sentBefore = b4; sentAfter = aft; }
  function setU2(uint256 i, uint256 j, uint256 v) external { u2[i][j] = v; }
  function setU3(uint256 i, uint256 j, uint256 k, uint256 v) external { u3[i][j][k] = v; }
  function setU4(uint256 i, uint256 j, uint256 k, uint256 l, uint256 v) external { u4[i][j][k][l] = v; }
  function setP2(uint256 i, uint256 j, uint8 v) external { p2[i][j] = v; }
  function setP3(uint256 i, uint256 j, uint256 k, uint8 v) external { p3[i][j][k] = v; }
  function setS2(uint256 i, uint256 j, int64 v) external { s2[i][j] = v; }
  function setB2(uint256 i, uint256 j, bytes4 v) external { b2[i][j] = v; }
  function setBl2(uint256 i, uint256 j, bool v) external { bl2[i][j] = v; }
  function setG2(uint256 t, uint256 i, uint256 j, uint256 v) external { g2.tag = t; g2.grid[i][j] = v; }
  function setPk(uint64 a, uint64 b, uint256 i, uint256 j, uint8 v) external { pk.a = a; pk.b = b; pk.rows[i][j] = v; }
  function setSg(int32 lead, int32 tail, uint256 i, uint256 j, int64 v) external { sg.lead = lead; sg.tail = tail; sg.s[i][j] = v; }
  function setBz(bytes8 h, uint256 i, uint256 j, bytes4 v) external { bz.h = h; bz.m[i][j] = v; }
  function setBl(bool p, bool q, uint256 i, uint256 j, bool v) external { bl.p = p; bl.q = q; bl.flags[i][j] = v; }
  function setSgr(uint256 lead, uint256 trail, uint256 i, uint256 j, uint32 x, uint32 y) external { sgr.lead = lead; sgr.trail = trail; sgr.cells[i][j].x = x; sgr.cells[i][j].y = y; }
  function pushG2() external { g2arr.push(); }
  function setG2arr(uint256 idx, uint256 t, uint256 i, uint256 j, uint256 v) external { g2arr[idx].tag = t; g2arr[idx].grid[i][j] = v; }
  function pushPk() external { pkarr.push(); }
  function setPkarr(uint256 idx, uint64 a, uint64 b, uint256 i, uint256 j, uint8 v) external { pkarr[idx].a = a; pkarr[idx].b = b; pkarr[idx].rows[i][j] = v; }

  function getU2() external view returns (uint256[3][2] memory){ return u2; }
  function rowU2(uint256 i) external view returns (uint256[3] memory){ return u2[i]; }
  function elemU2(uint256 i, uint256 j) external view returns (uint256){ return u2[i][j]; }
  function getU3() external view returns (uint256[2][2][2] memory){ return u3; }
  function planeU3(uint256 i) external view returns (uint256[2][2] memory){ return u3[i]; }
  function rowU3(uint256 i, uint256 j) external view returns (uint256[2] memory){ return u3[i][j]; }
  function elemU3(uint256 i, uint256 j, uint256 k) external view returns (uint256){ return u3[i][j][k]; }
  function getU4() external view returns (uint256[2][2][2][2] memory){ return u4; }
  function cubeU4(uint256 i) external view returns (uint256[2][2][2] memory){ return u4[i]; }
  function elemU4(uint256 i, uint256 j, uint256 k, uint256 l) external view returns (uint256){ return u4[i][j][k][l]; }
  function getP2() external view returns (uint8[4][3] memory){ return p2; }
  function rowP2(uint256 i) external view returns (uint8[4] memory){ return p2[i]; }
  function elemP2(uint256 i, uint256 j) external view returns (uint8){ return p2[i][j]; }
  function getP3() external view returns (uint8[5][3][2] memory){ return p3; }
  function planeP3(uint256 i) external view returns (uint8[5][3] memory){ return p3[i]; }
  function elemP3(uint256 i, uint256 j, uint256 k) external view returns (uint8){ return p3[i][j][k]; }
  function getS2() external view returns (int64[2][3] memory){ return s2; }
  function rowS2(uint256 i) external view returns (int64[2] memory){ return s2[i]; }
  function elemS2(uint256 i, uint256 j) external view returns (int64){ return s2[i][j]; }
  function getB2() external view returns (bytes4[2][2] memory){ return b2; }
  function rowB2(uint256 i) external view returns (bytes4[2] memory){ return b2[i]; }
  function elemB2(uint256 i, uint256 j) external view returns (bytes4){ return b2[i][j]; }
  function getBl2() external view returns (bool[5][2] memory){ return bl2; }
  function rowBl2(uint256 i) external view returns (bool[5] memory){ return bl2[i]; }
  function elemBl2(uint256 i, uint256 j) external view returns (bool){ return bl2[i][j]; }
  function getG2() external view returns (G2 memory){ return g2; }
  function getPk() external view returns (Pk memory){ return pk; }
  function getSg() external view returns (Sg memory){ return sg; }
  function getBz() external view returns (Bz memory){ return bz; }
  function getBl() external view returns (Bl memory){ return bl; }
  function getSgr() external view returns (StructGrid memory){ return sgr; }
  function getG2arr() external view returns (G2[] memory){ return g2arr; }
  function getG2arrI(uint256 i) external view returns (G2 memory){ return g2arr[i]; }
  function getPkarr() external view returns (Pk[] memory){ return pkarr; }
  function getPkarrI(uint256 i) external view returns (Pk memory){ return pkarr[i]; }
  function getSentBefore() external view returns (uint256){ return sentBefore; }
  function getSentAfter() external view returns (uint256){ return sentAfter; }
}`;

describe('nestedfixed probe', () => {
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
  // raw calldata with a dirty index word (high bits) to test calldata cleaning
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
    // sentinels
    await eq('setSent', raw('setSent(uint256,uint256)', [0xdeadbeefn, 0xfeedfacen]));

    // ---- u2: Arr<Arr<u256,3>,2> : write every cell distinct, then whole/row/elem ----
    let n = 1n;
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 3n; j++)
      await eq(`setU2[${i}][${j}]`, raw('setU2(uint256,uint256,uint256)', [i, j, (0xa11ce000n << 8n) | n++]));
    await eq('getU2', encodeCall(sel('getU2()')));
    for (let i = 0n; i < 2n; i++) await eq(`rowU2[${i}]`, raw('rowU2(uint256)', [i]));
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 3n; j++)
      await eq(`elemU2[${i}][${j}]`, raw('elemU2(uint256,uint256)', [i, j]));

    // ---- u3: Arr<Arr<Arr<u256,2>,2>,2> : boundary values at corners ----
    n = 0n;
    const u3vals = [0n, M - 1n, 1n << 255n, (1n << 255n) - 1n, 0xffn, M - 0x100n, 1n, M - 1n];
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++) for (let k = 0n; k < 2n; k++)
      await eq(`setU3[${i}][${j}][${k}]`, raw('setU3(uint256,uint256,uint256,uint256)', [i, j, k, u3vals[Number(n++)]!]));
    await eq('getU3', encodeCall(sel('getU3()')));
    for (let i = 0n; i < 2n; i++) await eq(`planeU3[${i}]`, raw('planeU3(uint256)', [i]));
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++)
      await eq(`rowU3[${i}][${j}]`, raw('rowU3(uint256,uint256)', [i, j]));
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++) for (let k = 0n; k < 2n; k++)
      await eq(`elemU3[${i}][${j}][${k}]`, raw('elemU3(uint256,uint256,uint256)', [i, j, k]));

    // ---- u4: Arr deep 4D, all 16 cells distinct ----
    n = 100n;
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++) for (let k = 0n; k < 2n; k++) for (let l = 0n; l < 2n; l++)
      await eq(`setU4[${i}][${j}][${k}][${l}]`, raw('setU4(uint256,uint256,uint256,uint256,uint256)', [i, j, k, l, n++]));
    await eq('getU4', encodeCall(sel('getU4()')));
    for (let i = 0n; i < 2n; i++) await eq(`cubeU4[${i}]`, raw('cubeU4(uint256)', [i]));
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++) for (let k = 0n; k < 2n; k++) for (let l = 0n; l < 2n; l++)
      await eq(`elemU4[${i}][${j}][${k}][${l}]`, raw('elemU4(uint256,uint256,uint256,uint256)', [i, j, k, l]));

    // ---- p2: packed Arr<Arr<u8,4>,3> : distinct each lane (1..12), then whole/row/elem ----
    n = 1n;
    for (let i = 0n; i < 3n; i++) for (let j = 0n; j < 4n; j++)
      await eq(`setP2[${i}][${j}]`, raw('setP2(uint256,uint256,uint8)', [i, j, n++]));
    await eq('getP2', encodeCall(sel('getP2()')));
    for (let i = 0n; i < 3n; i++) await eq(`rowP2[${i}]`, raw('rowP2(uint256)', [i]));
    for (let i = 0n; i < 3n; i++) for (let j = 0n; j < 4n; j++)
      await eq(`elemP2[${i}][${j}]`, raw('elemP2(uint256,uint256)', [i, j]));
    // overwrite a packed lane then re-read (no neighbor corruption)
    await eq('setP2-overwrite', raw('setP2(uint256,uint256,uint8)', [1n, 2n, 0xffn]));
    await eq('getP2-after-ow', encodeCall(sel('getP2()')));
    await eq('elemP2-after-ow', raw('elemP2(uint256,uint256)', [1n, 2n]));

    // ---- p3: packed 3D u8 Arr<Arr<Arr<u8,5>,3>,2> : 30 lanes distinct ----
    n = 1n;
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 3n; j++) for (let k = 0n; k < 5n; k++)
      await eq(`setP3[${i}][${j}][${k}]`, raw('setP3(uint256,uint256,uint256,uint8)', [i, j, k, n++]));
    await eq('getP3', encodeCall(sel('getP3()')));
    for (let i = 0n; i < 2n; i++) await eq(`planeP3[${i}]`, raw('planeP3(uint256)', [i]));
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 3n; j++) for (let k = 0n; k < 5n; k++)
      await eq(`elemP3[${i}][${j}][${k}]`, raw('elemP3(uint256,uint256,uint256)', [i, j, k]));

    // ---- s2: signed Arr<Arr<i64,2>,3> : negatives + INT_MIN/MAX, sign-extend on return ----
    const i64vals = [5n, M - 7n, (1n << 63n) - 1n, M - (1n << 63n), 0n, M - 1n];
    n = 0n;
    for (let i = 0n; i < 3n; i++) for (let j = 0n; j < 2n; j++)
      await eq(`setS2[${i}][${j}]`, raw('setS2(uint256,uint256,int64)', [i, j, i64vals[Number(n++)]!]));
    await eq('getS2', encodeCall(sel('getS2()')));
    for (let i = 0n; i < 3n; i++) await eq(`rowS2[${i}]`, raw('rowS2(uint256)', [i]));
    for (let i = 0n; i < 3n; i++) for (let j = 0n; j < 2n; j++)
      await eq(`elemS2[${i}][${j}]`, raw('elemS2(uint256,uint256)', [i, j]));

    // ---- b2: Arr<Arr<bytes4,2>,2> left-aligned bytesN ----
    const b4vals = [0xdeadbeefn << 224n, 0x11223344n << 224n, 0xffffffffn << 224n, 0n];
    n = 0n;
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++)
      await eq(`setB2[${i}][${j}]`, raw('setB2(uint256,uint256,bytes4)', [i, j, b4vals[Number(n++)]!]));
    await eq('getB2', encodeCall(sel('getB2()')));
    for (let i = 0n; i < 2n; i++) await eq(`rowB2[${i}]`, raw('rowB2(uint256)', [i]));
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++)
      await eq(`elemB2[${i}][${j}]`, raw('elemB2(uint256,uint256)', [i, j]));

    // ---- bl2: Arr<Arr<bool,5>,2> packed bools ----
    const blvals = [1n, 0n, 1n, 1n, 0n, 0n, 1n, 0n, 1n, 1n];
    n = 0n;
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 5n; j++)
      await eq(`setBl2[${i}][${j}]`, raw('setBl2(uint256,uint256,bool)', [i, j, blvals[Number(n++)]!]));
    await eq('getBl2', encodeCall(sel('getBl2()')));
    for (let i = 0n; i < 2n; i++) await eq(`rowBl2[${i}]`, raw('rowBl2(uint256)', [i]));
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 5n; j++)
      await eq(`elemBl2[${i}][${j}]`, raw('elemBl2(uint256,uint256)', [i, j]));

    // ---- structs with nested fixed-array fields ----
    for (const [i, j, v] of [[0n,0n,1n],[0n,1n,2n],[1n,0n,3n],[1n,1n,4n]] as [bigint,bigint,bigint][])
      await eq(`setG2[${i}][${j}]`, raw('setG2(uint256,uint256,uint256,uint256)', [9n, i, j, v]));
    await eq('getG2', encodeCall(sel('getG2()')));

    // Pk: u64; packed 2D u8; u64 - packed neighbours preserved
    n = 1n;
    for (let i = 0n; i < 3n; i++) for (let j = 0n; j < 4n; j++)
      await eq(`setPk[${i}][${j}]`, raw('setPk(uint64,uint64,uint256,uint256,uint8)', [0xaaaan, 0xbbbbn, i, j, n++]));
    await eq('getPk', encodeCall(sel('getPk()')));

    // Sg: i32; 2D i64 negatives; i32
    n = 0n;
    for (let i = 0n; i < 3n; i++) for (let j = 0n; j < 2n; j++)
      await eq(`setSg[${i}][${j}]`, raw('setSg(int32,int32,uint256,uint256,int64)', [M - 5n, 7n, i, j, i64vals[Number(n++)]!]));
    await eq('getSg', encodeCall(sel('getSg()')));

    // Bz: bytes8; 2D bytes4; left-aligned
    n = 0n;
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++)
      await eq(`setBz[${i}][${j}]`, raw('setBz(bytes8,uint256,uint256,bytes4)', [0xcafebabecafebaben << 192n, i, j, b4vals[Number(n++)]!]));
    await eq('getBz', encodeCall(sel('getBz()')));

    // Bl: bool; 2D bool; bool
    n = 0n;
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 5n; j++)
      await eq(`setBl[${i}][${j}]`, raw('setBl(bool,bool,uint256,uint256,bool)', [1n, 1n, i, j, blvals[Number(n++)]!]));
    await eq('getBl', encodeCall(sel('getBl()')));

    // StructGrid: lead; Arr<Arr<Inner,2>,2> of struct elements; trail
    n = 1n;
    for (let i = 0n; i < 2n; i++) for (let j = 0n; j < 2n; j++) {
      await eq(`setSgr[${i}][${j}]`, raw('setSgr(uint256,uint256,uint256,uint256,uint32,uint32)', [0x1111n, 0x2222n, i, j, n, n + 1000n]));
      n++;
    }
    await eq('getSgr', encodeCall(sel('getSgr()')));

    // ---- fixed array of structs that themselves have a 2D fixed field (dynamic array) ----
    await eq('pushG2-a', encodeCall(sel('pushG2()')));
    await eq('pushG2-b', encodeCall(sel('pushG2()')));
    for (const [idx, t, i, j, v] of [
      [0n,1n,0n,0n,10n],[0n,1n,0n,1n,11n],[0n,1n,1n,0n,12n],[0n,1n,1n,1n,13n],
      [1n,2n,0n,0n,20n],[1n,2n,0n,1n,21n],[1n,2n,1n,0n,22n],[1n,2n,1n,1n,23n],
    ] as [bigint,bigint,bigint,bigint,bigint][])
      await eq(`setG2arr[${idx}]`, raw('setG2arr(uint256,uint256,uint256,uint256,uint256)', [idx, t, i, j, v]));
    await eq('getG2arr', encodeCall(sel('getG2arr()')));
    await eq('getG2arrI[0]', raw('getG2arrI(uint256)', [0n]));
    await eq('getG2arrI[1]', raw('getG2arrI(uint256)', [1n]));

    // Pk[] : packed 2D field through a dynamic-array element
    await eq('pushPk-a', encodeCall(sel('pushPk()')));
    await eq('pushPk-b', encodeCall(sel('pushPk()')));
    for (const idx of [0n, 1n]) {
      let m = 1n;
      for (let i = 0n; i < 3n; i++) for (let j = 0n; j < 4n; j++)
        await eq(`setPkarr[${idx}][${i}][${j}]`, raw('setPkarr(uint256,uint64,uint64,uint256,uint256,uint8)', [idx, 0x1234n + idx, 0x5678n + idx, i, j, m++]));
    }
    await eq('getPkarr', encodeCall(sel('getPkarr()')));
    await eq('getPkarrI[0]', raw('getPkarrI(uint256)', [0n]));
    await eq('getPkarrI[1]', raw('getPkarrI(uint256)', [1n]));

    // ---- OOB on EVERY dimension for each array (read + write) -> Panic(0x32) ----
    await eq('oob-u2-i', raw('elemU2(uint256,uint256)', [2n, 0n]));
    await eq('oob-u2-j', raw('elemU2(uint256,uint256)', [0n, 3n]));
    await eq('oob-u2-row', raw('rowU2(uint256)', [2n]));
    await eq('oob-u2-set-i', raw('setU2(uint256,uint256,uint256)', [2n, 0n, 1n]));
    await eq('oob-u2-set-j', raw('setU2(uint256,uint256,uint256)', [0n, 3n, 1n]));
    await eq('oob-u3-i', raw('elemU3(uint256,uint256,uint256)', [2n, 0n, 0n]));
    await eq('oob-u3-j', raw('elemU3(uint256,uint256,uint256)', [0n, 2n, 0n]));
    await eq('oob-u3-k', raw('elemU3(uint256,uint256,uint256)', [0n, 0n, 2n]));
    await eq('oob-u3-plane', raw('planeU3(uint256)', [2n]));
    await eq('oob-u4-i', raw('elemU4(uint256,uint256,uint256,uint256)', [2n, 0n, 0n, 0n]));
    await eq('oob-u4-l', raw('elemU4(uint256,uint256,uint256,uint256)', [0n, 0n, 0n, 2n]));
    await eq('oob-u4-cube', raw('cubeU4(uint256)', [2n]));
    await eq('oob-p2-i', raw('elemP2(uint256,uint256)', [3n, 0n]));
    await eq('oob-p2-j', raw('elemP2(uint256,uint256)', [0n, 4n]));
    await eq('oob-p3-k', raw('elemP3(uint256,uint256,uint256)', [0n, 0n, 5n]));
    await eq('oob-s2-i', raw('elemS2(uint256,uint256)', [3n, 0n]));
    await eq('oob-b2-j', raw('elemB2(uint256,uint256)', [0n, 2n]));
    await eq('oob-bl2-j', raw('elemBl2(uint256,uint256)', [0n, 5n]));
    await eq('oob-g2arr-idx', raw('getG2arrI(uint256)', [2n]));
    await eq('oob-g2arr-set', raw('setG2arr(uint256,uint256,uint256,uint256,uint256)', [2n, 1n, 0n, 0n, 1n]));

    // huge index (high bits) on each dimension
    await eq('oob-u2-huge-i', raw('elemU2(uint256,uint256)', [M - 1n, 0n]));
    await eq('oob-u3-huge-k', raw('elemU3(uint256,uint256,uint256)', [0n, 0n, M - 1n]));
    await eq('oob-u4-huge-mid', raw('elemU4(uint256,uint256,uint256,uint256)', [0n, M - 5n, 0n, 0n]));

    // ---- dirty-high-bits calldata on packed/small element setters (cleaning parity) ----
    // u8 value with dirty upper bits -> solc reverts (input validation)
    await eq('dirty-u8-val', raw('setP2(uint256,uint256,uint8)', [0n, 0n, 0x1ffn]));
    await eq('dirty-i64-val', raw('setS2(uint256,uint256,int64)', [0n, 0n, (1n << 64n) | 5n]));
    await eq('dirty-bool-val', raw('setBl2(uint256,uint256,bool)', [0n, 0n, 2n]));
    await eq('dirty-bytes4-val', raw('setB2(uint256,uint256,bytes4)', [0n, 0n, 0xdeadbeefn])); // not left-aligned -> dirty low bits
    await eq('dirty-u64-val', raw('setPk(uint64,uint64,uint256,uint256,uint8)', [(1n << 64n) | 1n, 2n, 0n, 0n, 1n]));

    // sentinels still untouched + getters
    await eq('getSentBefore', encodeCall(sel('getSentBefore()')));
    await eq('getSentAfter', encodeCall(sel('getSentAfter()')));

    if (mism.length) { console.log('MISMATCHES ' + mism.length + '/' + count); for (const m of mism.slice(0, 40)) console.log(m); }
    else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
