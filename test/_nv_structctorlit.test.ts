import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);

// AREA: structctorlit
// Struct construction with nested fixed-array-field literals and nested struct-literal
// fields. Constructions exercised:
//   W(t, [[a,b],[c,d]])             W{tag; grid: Arr<Arr<u256,2>,2>}  -> store + whole-return
//   M(t, [Row(x0,y0), Row(x1,y1)])  struct-array literal, PURE return only (solc legacy cannot
//                                   copy struct-array literal to storage)
//   D3(t, [[[..]]])                 deeper nest Arr<Arr<Arr<u256,2>,2>,2>
//   Pk(t, [[..]],...)              packed element grid Arr<Arr<u8,4>,2>
//   Sg(t, [[..]])                  signed element grid Arr<Arr<i64,2>,2> / i8 / i128
//   Bg(t, [[..]])                  bytesN element grid
//   Mix(scalar, grid)              struct with both a scalar field and a 2D grid field
// All compared whole-struct / whole-array byte-for-byte against solc.

const JETH = `@struct class W { tag: u256; grid: Arr<Arr<u256, 2>, 2>; }
@struct class Row { x: u256; y: u256; }
@struct class M { tag: u256; rows: Arr<Row, 2>; }
@struct class M3 { tag: u256; rows: Arr<Row, 3>; }
@struct class D3 { tag: u256; cube: Arr<Arr<Arr<u256, 2>, 2>, 2>; }
@struct class Pk { tag: u64; rows: Arr<Arr<u8, 4>, 2>; tail: u64; }
@struct class Sg { tag: i256; grid: Arr<Arr<i64, 2>, 2>; }
@struct class Sg8 { grid: Arr<Arr<i8, 2>, 2>; }
@struct class Sg128 { grid: Arr<Arr<i128, 2>, 2>; }
@struct class Bg { tag: u256; grid: Arr<Arr<bytes4, 2>, 2>; }
@struct class Bg32 { grid: Arr<Arr<bytes32, 2>, 2>; }
@struct class Mix { scalar: u256; grid: Arr<Arr<u256, 2>, 2>; extra: u256; }
@struct class Pt { a: u8; b: u8; }
@struct class MP { tag: u256; pts: Arr<Pt, 2>; }
@struct class WideRow { x: i128; y: i128; }
@struct class MW { tag: u256; rows: Arr<WideRow, 2>; }

@contract class SC {
  @state w: W;
  @state d3: D3;
  @state pk: Pk;
  @state sg: Sg;
  @state mix: Mix;
  @state bg: Bg;

  // ----- W: store then whole-return, and pure return -----
  @external setW(t: u256, a: u256, b: u256, c: u256, d: u256): void { this.w = W(t, [[a, b], [c, d]]); }
  @view getW(): W { return this.w; }
  @view mkW(t: u256, a: u256, b: u256, c: u256, d: u256): W { return W(t, [[a, b], [c, d]]); }

  // ----- M: struct-array literal, PURE return only -----
  @view mkM(t: u256, x0: u256, y0: u256, x1: u256, y1: u256): M { return M(t, [Row(x0, y0), Row(x1, y1)]); }
  @view mkM3(t: u256, x0: u256, y0: u256, x1: u256, y1: u256, x2: u256, y2: u256): M3 { return M3(t, [Row(x0, y0), Row(x1, y1), Row(x2, y2)]); }
  @view mkMW(t: u256, x0: i128, y0: i128, x1: i128, y1: i128): MW { return MW(t, [WideRow(x0, y0), WideRow(x1, y1)]); }
  @view mkMP(t: u256, a0: u8, b0: u8, a1: u8, b1: u8): MP { return MP(t, [Pt(a0, b0), Pt(a1, b1)]); }

  // ----- D3: deeper nest, store + pure (cube values via fixed-array param to dodge stack-too-deep) -----
  @external setD3(t: u256, v: Arr<u256, 8>): void {
    this.d3 = D3(t, [[[v[0n], v[1n]], [v[2n], v[3n]]], [[v[4n], v[5n]], [v[6n], v[7n]]]]);
  }
  @view getD3(): D3 { return this.d3; }
  @view mkD3(t: u256, v: Arr<u256, 8>): D3 {
    return D3(t, [[[v[0n], v[1n]], [v[2n], v[3n]]], [[v[4n], v[5n]], [v[6n], v[7n]]]]);
  }

  // ----- Pk: packed u8 grid with scalar neighbours, store + pure -----
  @external setPk(t: u64, tail: u64, a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8): void {
    this.pk = Pk(t, [[a, b, c, d], [e, f, g, h]], tail);
  }
  @view getPk(): Pk { return this.pk; }
  @view mkPk(t: u64, tail: u64, a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8): Pk {
    return Pk(t, [[a, b, c, d], [e, f, g, h]], tail);
  }

  // ----- Sg: signed grid, store + pure -----
  @external setSg(t: i256, a: i64, b: i64, c: i64, d: i64): void { this.sg = Sg(t, [[a, b], [c, d]]); }
  @view getSg(): Sg { return this.sg; }
  @view mkSg(t: i256, a: i64, b: i64, c: i64, d: i64): Sg { return Sg(t, [[a, b], [c, d]]); }
  @view mkSg8(a: i8, b: i8, c: i8, d: i8): Sg8 { return Sg8([[a, b], [c, d]]); }
  @view mkSg128(a: i128, b: i128, c: i128, d: i128): Sg128 { return Sg128([[a, b], [c, d]]); }

  // ----- Bg: bytesN grid, store + pure -----
  @external setBg(t: u256, a: bytes4, b: bytes4, c: bytes4, d: bytes4): void { this.bg = Bg(t, [[a, b], [c, d]]); }
  @view getBg(): Bg { return this.bg; }
  @view mkBg(t: u256, a: bytes4, b: bytes4, c: bytes4, d: bytes4): Bg { return Bg(t, [[a, b], [c, d]]); }
  @view mkBg32(a: bytes32, b: bytes32, c: bytes32, d: bytes32): Bg32 { return Bg32([[a, b], [c, d]]); }

  // ----- Mix: scalar + 2D grid + trailing scalar, store + pure -----
  @external setMix(s: u256, e: u256, a: u256, b: u256, c: u256, d: u256): void { this.mix = Mix(s, [[a, b], [c, d]], e); }
  @view getMix(): Mix { return this.mix; }
  @view mkMix(s: u256, e: u256, a: u256, b: u256, c: u256, d: u256): Mix { return Mix(s, [[a, b], [c, d]], e); }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract SC {
  struct W { uint256 tag; uint256[2][2] grid; }
  struct Row { uint256 x; uint256 y; }
  struct M { uint256 tag; Row[2] rows; }
  struct M3 { uint256 tag; Row[3] rows; }
  struct D3 { uint256 tag; uint256[2][2][2] cube; }
  struct Pk { uint64 tag; uint8[4][2] rows; uint64 tail; }
  struct Sg { int256 tag; int64[2][2] grid; }
  struct Sg8 { int8[2][2] grid; }
  struct Sg128 { int128[2][2] grid; }
  struct Bg { uint256 tag; bytes4[2][2] grid; }
  struct Bg32 { bytes32[2][2] grid; }
  struct Mix { uint256 scalar; uint256[2][2] grid; uint256 extra; }
  struct Pt { uint8 a; uint8 b; }
  struct MP { uint256 tag; Pt[2] pts; }
  struct WideRow { int128 x; int128 y; }
  struct MW { uint256 tag; WideRow[2] rows; }

  W w; D3 d3; Pk pk; Sg sg; Mix mix; Bg bg;

  function setW(uint256 t, uint256 a, uint256 b, uint256 c, uint256 d) external { w = W(t, [[a, b], [c, d]]); }
  function getW() external view returns (W memory){ return w; }
  function mkW(uint256 t, uint256 a, uint256 b, uint256 c, uint256 d) external pure returns (W memory){ return W(t, [[a, b], [c, d]]); }

  function mkM(uint256 t, uint256 x0, uint256 y0, uint256 x1, uint256 y1) external pure returns (M memory){ return M(t, [Row(x0, y0), Row(x1, y1)]); }
  function mkM3(uint256 t, uint256 x0, uint256 y0, uint256 x1, uint256 y1, uint256 x2, uint256 y2) external pure returns (M3 memory){ return M3(t, [Row(x0, y0), Row(x1, y1), Row(x2, y2)]); }
  function mkMW(uint256 t, int128 x0, int128 y0, int128 x1, int128 y1) external pure returns (MW memory){ return MW(t, [WideRow(x0, y0), WideRow(x1, y1)]); }
  function mkMP(uint256 t, uint8 a0, uint8 b0, uint8 a1, uint8 b1) external pure returns (MP memory){ return MP(t, [Pt(a0, b0), Pt(a1, b1)]); }

  function setD3(uint256 t, uint256[8] calldata v) external {
    d3 = D3(t, [[[v[0], v[1]], [v[2], v[3]]], [[v[4], v[5]], [v[6], v[7]]]]);
  }
  function getD3() external view returns (D3 memory){ return d3; }
  function mkD3(uint256 t, uint256[8] calldata v) external pure returns (D3 memory){
    return D3(t, [[[v[0], v[1]], [v[2], v[3]]], [[v[4], v[5]], [v[6], v[7]]]]);
  }

  function setPk(uint64 t, uint64 tail, uint8 a, uint8 b, uint8 c, uint8 d, uint8 e, uint8 f, uint8 g, uint8 h) external {
    pk = Pk(t, [[a, b, c, d], [e, f, g, h]], tail);
  }
  function getPk() external view returns (Pk memory){ return pk; }
  function mkPk(uint64 t, uint64 tail, uint8 a, uint8 b, uint8 c, uint8 d, uint8 e, uint8 f, uint8 g, uint8 h) external pure returns (Pk memory){
    return Pk(t, [[a, b, c, d], [e, f, g, h]], tail);
  }

  function setSg(int256 t, int64 a, int64 b, int64 c, int64 d) external { sg = Sg(t, [[a, b], [c, d]]); }
  function getSg() external view returns (Sg memory){ return sg; }
  function mkSg(int256 t, int64 a, int64 b, int64 c, int64 d) external pure returns (Sg memory){ return Sg(t, [[a, b], [c, d]]); }
  function mkSg8(int8 a, int8 b, int8 c, int8 d) external pure returns (Sg8 memory){ return Sg8([[a, b], [c, d]]); }
  function mkSg128(int128 a, int128 b, int128 c, int128 d) external pure returns (Sg128 memory){ return Sg128([[a, b], [c, d]]); }

  function setBg(uint256 t, bytes4 a, bytes4 b, bytes4 c, bytes4 d) external { bg = Bg(t, [[a, b], [c, d]]); }
  function getBg() external view returns (Bg memory){ return bg; }
  function mkBg(uint256 t, bytes4 a, bytes4 b, bytes4 c, bytes4 d) external pure returns (Bg memory){ return Bg(t, [[a, b], [c, d]]); }
  function mkBg32(bytes32 a, bytes32 b, bytes32 c, bytes32 d) external pure returns (Bg32 memory){ return Bg32([[a, b], [c, d]]); }

  function setMix(uint256 s, uint256 e, uint256 a, uint256 b, uint256 c, uint256 d) external { mix = Mix(s, [[a, b], [c, d]], e); }
  function getMix() external view returns (Mix memory){ return mix; }
  function mkMix(uint256 s, uint256 e, uint256 a, uint256 b, uint256 c, uint256 d) external pure returns (Mix memory){ return Mix(s, [[a, b], [c, d]], e); }
}`;

describe('probe', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = []; let count = 0;
  async function eq(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    if (j.success !== s.success || j.returnHex !== s.returnHex)
      mism.push(label + ': jeth{ok=' + j.success + ',ret=' + j.returnHex + ',err=' + j.exceptionError + '} sol{ok=' + s.success + ',ret=' + s.returnHex + '}');
  }
  // raw calldata builder allowing dirty high bits (for u8/u64/bytes4 etc.)
  function rawCall(sig: string, words: bigint[]): string {
    let h = '0x' + sel(sig);
    for (const w of words) { let x = ((w % M) + M) % M; h += x.toString(16).padStart(64, '0'); }
    return h;
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'SC.jeth' });
    const sb = compileSolidity(SOL, 'SC');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  it('runs', async () => {
    const MAX = M - 1n;
    const HALF = 1n << 255n;
    // interesting u256 corpus
    const U: bigint[] = [0n, 1n, 2n, 255n, 256n, 0xffffn, MAX, MAX - 1n, HALF, HALF - 1n, HALF + 1n, 0xdeadbeefn, 12345678901234567890n];

    // ---- W: store then whole-return, and pure return ----
    for (let i = 0; i < U.length; i++) {
      const t = U[i]!, a = U[(i + 1) % U.length]!, b = U[(i + 2) % U.length]!, c = U[(i + 3) % U.length]!, d = U[(i + 4) % U.length]!;
      await eq('setW#' + i, encodeCall(sel('setW(uint256,uint256,uint256,uint256,uint256)'), [t, a, b, c, d]));
      await eq('getW#' + i, encodeCall(sel('getW()'), []));
      await eq('mkW#' + i, encodeCall(sel('mkW(uint256,uint256,uint256,uint256,uint256)'), [t, a, b, c, d]));
    }

    // ---- M: struct-array literal pure return ----
    for (let i = 0; i < U.length; i++) {
      const t = U[i]!, x0 = U[(i + 1) % U.length]!, y0 = U[(i + 2) % U.length]!, x1 = U[(i + 3) % U.length]!, y1 = U[(i + 4) % U.length]!;
      await eq('mkM#' + i, encodeCall(sel('mkM(uint256,uint256,uint256,uint256,uint256)'), [t, x0, y0, x1, y1]));
    }
    // M3
    for (let i = 0; i < U.length; i++) {
      const v = (k: number) => U[(i + k) % U.length]!;
      await eq('mkM3#' + i, encodeCall(sel('mkM3(uint256,uint256,uint256,uint256,uint256,uint256,uint256)'), [v(0), v(1), v(2), v(3), v(4), v(5), v(6)]));
    }

    // ---- D3: deeper nest store + pure. Cube via uint256[8] inline static param. ----
    for (let i = 0; i < U.length; i++) {
      const v = (k: number) => U[(i + k) % U.length]!;
      // args = [t, then 8 cube words inline]
      const args = [v(0), v(1), v(2), v(3), v(4), v(5), v(6), v(7), v(8)];
      await eq('setD3#' + i, encodeCall(sel('setD3(uint256,uint256[8])'), args));
      await eq('getD3#' + i, encodeCall(sel('getD3()'), []));
      await eq('mkD3#' + i, encodeCall(sel('mkD3(uint256,uint256[8])'), args));
    }

    // ---- Pk: packed u8 grid, store + pure. Use dirty high bits in u8/u64 slots. ----
    const U8: bigint[] = [0n, 1n, 127n, 128n, 255n];
    const U64: bigint[] = [0n, 1n, (1n << 64n) - 1n, 0xdeadn];
    // dirty: high bits set above the type width to test masking on construction
    const DIRTY8 = (1n << 250n) | 0x5an; // should mask to 0x5a
    const DIRTY64 = (1n << 200n) | 0xcafen;
    for (let i = 0; i < 8; i++) {
      const t = U64[i % U64.length]!, tail = U64[(i + 1) % U64.length]!;
      const g = (k: number) => U8[(i + k) % U8.length]!;
      const sig = 'setPk(uint64,uint64,uint8,uint8,uint8,uint8,uint8,uint8,uint8,uint8)';
      const msig = 'mkPk(uint64,uint64,uint8,uint8,uint8,uint8,uint8,uint8,uint8,uint8)';
      const args = [t, tail, g(0), g(1), g(2), g(3), g(4), g(5), g(6), g(7)];
      await eq('setPk#' + i, rawCall(sig, args));
      await eq('getPk#' + i, encodeCall(sel('getPk()'), []));
      await eq('mkPk#' + i, rawCall(msig, args));
    }
    // dirty-high-bit cases for Pk (solc masks function-param inputs; both should agree)
    await eq('mkPk-dirty', rawCall('mkPk(uint64,uint64,uint8,uint8,uint8,uint8,uint8,uint8,uint8,uint8)',
      [DIRTY64, DIRTY64, DIRTY8, DIRTY8, DIRTY8, DIRTY8, DIRTY8, DIRTY8, DIRTY8, DIRTY8]));
    await eq('setPk-dirty', rawCall('setPk(uint64,uint64,uint8,uint8,uint8,uint8,uint8,uint8,uint8,uint8)',
      [DIRTY64, DIRTY64, DIRTY8, DIRTY8, DIRTY8, DIRTY8, DIRTY8, DIRTY8, DIRTY8, DIRTY8]));
    await eq('getPk-dirty', encodeCall(sel('getPk()'), []));

    // ---- Sg: signed grid (i256 tag, i64 grid). negatives / INT_MIN / INT_MAX ----
    const I64MAX = (1n << 63n) - 1n, I64MIN = -(1n << 63n);
    const I256MAX = (1n << 255n) - 1n, I256MIN = -(1n << 255n);
    const Scorp: bigint[] = [0n, 1n, -1n, 7n, -7n, I64MAX, I64MIN, I64MAX - 1n, I64MIN + 1n, 42n, -42n];
    for (let i = 0; i < Scorp.length; i++) {
      const t = [0n, -1n, I256MAX, I256MIN, 12345n][i % 5]!;
      const a = Scorp[i]!, b = Scorp[(i + 1) % Scorp.length]!, c = Scorp[(i + 2) % Scorp.length]!, d = Scorp[(i + 3) % Scorp.length]!;
      await eq('setSg#' + i, encodeCall(sel('setSg(int256,int64,int64,int64,int64)'), [t, a, b, c, d]));
      await eq('getSg#' + i, encodeCall(sel('getSg()'), []));
      await eq('mkSg#' + i, encodeCall(sel('mkSg(int256,int64,int64,int64,int64)'), [t, a, b, c, d]));
    }
    // i8 grid
    const I8: bigint[] = [0n, 1n, -1n, 127n, -128n, 42n, -42n, 100n, -100n];
    for (let i = 0; i < I8.length; i++) {
      const a = I8[i]!, b = I8[(i + 1) % I8.length]!, c = I8[(i + 2) % I8.length]!, d = I8[(i + 3) % I8.length]!;
      await eq('mkSg8#' + i, encodeCall(sel('mkSg8(int8,int8,int8,int8)'), [a, b, c, d]));
    }
    // i128 grid
    const I128MAX = (1n << 127n) - 1n, I128MIN = -(1n << 127n);
    const I128: bigint[] = [0n, 1n, -1n, I128MAX, I128MIN, I128MAX - 1n, I128MIN + 1n, 999n, -999n];
    for (let i = 0; i < I128.length; i++) {
      const a = I128[i]!, b = I128[(i + 1) % I128.length]!, c = I128[(i + 2) % I128.length]!, d = I128[(i + 3) % I128.length]!;
      await eq('mkSg128#' + i, encodeCall(sel('mkSg128(int128,int128,int128,int128)'), [a, b, c, d]));
    }

    // ---- Bg: bytesN grid (left-aligned). store + pure ----
    // bytes4 values occupy top 4 bytes of the word.
    const B4: bigint[] = [
      0n,
      0xdeadbeefn << 224n,
      0x11223344n << 224n,
      0xffffffffn << 224n,
      0x00000001n << 224n,
      0x80000000n << 224n,
    ];
    for (let i = 0; i < B4.length; i++) {
      const t = U[i % U.length]!;
      const a = B4[i]!, b = B4[(i + 1) % B4.length]!, c = B4[(i + 2) % B4.length]!, d = B4[(i + 3) % B4.length]!;
      await eq('setBg#' + i, rawCall('setBg(uint256,bytes4,bytes4,bytes4,bytes4)', [t, a, b, c, d]));
      await eq('getBg#' + i, encodeCall(sel('getBg()'), []));
      await eq('mkBg#' + i, rawCall('mkBg(uint256,bytes4,bytes4,bytes4,bytes4)', [t, a, b, c, d]));
    }
    // dirty low bits in bytes4 slots: bytes4 only takes top 4 bytes; low bytes dirty -> both mask
    await eq('mkBg-dirty', rawCall('mkBg(uint256,bytes4,bytes4,bytes4,bytes4)',
      [7n, (0x11223344n << 224n) | 0xabcdefn, (0xaabbccddn << 224n) | 0x123n, 0xffffffffffffffffn << 192n, 0n]));
    // bytes32 grid
    const B32: bigint[] = [0n, MAX, 1n, HALF, 0xdeadbeefn, M - 12345n];
    for (let i = 0; i < B32.length; i++) {
      const a = B32[i]!, b = B32[(i + 1) % B32.length]!, c = B32[(i + 2) % B32.length]!, d = B32[(i + 3) % B32.length]!;
      await eq('mkBg32#' + i, rawCall('mkBg32(bytes32,bytes32,bytes32,bytes32)', [a, b, c, d]));
    }

    // ---- Mix: scalar + 2D grid + trailing scalar ----
    for (let i = 0; i < U.length; i++) {
      const s = U[i]!, e = U[(i + 1) % U.length]!, a = U[(i + 2) % U.length]!, b = U[(i + 3) % U.length]!, c = U[(i + 4) % U.length]!, d = U[(i + 5) % U.length]!;
      await eq('setMix#' + i, encodeCall(sel('setMix(uint256,uint256,uint256,uint256,uint256,uint256)'), [s, e, a, b, c, d]));
      await eq('getMix#' + i, encodeCall(sel('getMix()'), []));
      await eq('mkMix#' + i, encodeCall(sel('mkMix(uint256,uint256,uint256,uint256,uint256,uint256)'), [s, e, a, b, c, d]));
    }

    // ---- MW: struct-array literal with packed i128 fields, pure return ----
    for (let i = 0; i < I128.length; i++) {
      const x0 = I128[i]!, y0 = I128[(i + 1) % I128.length]!, x1 = I128[(i + 2) % I128.length]!, y1 = I128[(i + 3) % I128.length]!;
      await eq('mkMW#' + i, encodeCall(sel('mkMW(uint256,int128,int128,int128,int128)'), [U[i % U.length]!, x0, y0, x1, y1]));
    }
    // ---- MP: struct-array literal with packed u8 fields, pure return ----
    for (let i = 0; i < U8.length; i++) {
      const a0 = U8[i]!, b0 = U8[(i + 1) % U8.length]!, a1 = U8[(i + 2) % U8.length]!, b1 = U8[(i + 3) % U8.length]!;
      await eq('mkMP#' + i, rawCall('mkMP(uint256,uint8,uint8,uint8,uint8)', [U[i % U.length]!, a0, b0, a1, b1]));
    }
    // dirty MP
    await eq('mkMP-dirty', rawCall('mkMP(uint256,uint8,uint8,uint8,uint8)',
      [9n, (1n << 100n) | 0x12n, (1n << 80n) | 0x34n, 0xffn, (1n << 9n) | 0x56n]));

    if (mism.length) { console.log('MISMATCHES ' + mism.length + '/' + count); for (const m of mism.slice(0, 40)) console.log(m); }
    else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});

// ===========================================================================
// Wave 2: harder shapes -- address grids, asymmetric dims, 1x1, struct-array
// elements that contain fixed-array fields, ternary/cast subexpressions inside
// grid literals, struct with two grid fields + a nested struct field.
// ===========================================================================
const JETH2 = `@struct class Ag { tag: u256; grid: Arr<Arr<address, 2>, 2>; }
@struct class As { tag: u256; grid: Arr<Arr<u256, 3>, 2>; }
@struct class On { tag: u256; grid: Arr<Arr<u256, 1>, 1>; }
@struct class RA { id: u64; data: Arr<u256, 2>; }
@struct class MM { tag: u256; rows: Arr<RA, 2>; }
@struct class P2 { a: u128; b: u128; }
@struct class Two { g1: Arr<Arr<u256, 2>, 2>; pt: P2; g2: Arr<Arr<u8, 2>, 2>; }
@struct class W { tag: u256; grid: Arr<Arr<u256, 2>, 2>; }

@contract class D {
  @state ag: Ag;
  @state asym: As;
  @state two: Two;

  // address grid: 20-byte right-aligned masking
  @external setAg(t: u256, a: address, b: address, c: address, d: address): void { this.ag = Ag(t, [[a, b], [c, d]]); }
  @view getAg(): Ag { return this.ag; }
  @view mkAg(t: u256, a: address, b: address, c: address, d: address): Ag { return Ag(t, [[a, b], [c, d]]); }

  // asymmetric 3x2 grid
  @external setAsym(t: u256, a: u256, b: u256, c: u256, d: u256, e: u256, f: u256): void { this.asym = As(t, [[a, b, c], [d, e, f]]); }
  @view getAsym(): As { return this.asym; }
  @view mkAsym(t: u256, a: u256, b: u256, c: u256, d: u256, e: u256, f: u256): As { return As(t, [[a, b, c], [d, e, f]]); }

  // 1x1 grid (degenerate)
  @view mkOne(t: u256, a: u256): On { return On(t, [[a]]); }

  // struct-array literal where each element struct has a fixed-array field (pure return)
  @view mkMM(t: u256, i0: u64, a0: u256, b0: u256, i1: u64, a1: u256, b1: u256): MM {
    return MM(t, [RA(i0, [a0, b0]), RA(i1, [a1, b1])]);
  }

  // ternary + cast subexpressions inside the grid literal
  @view mkWtern(t: u256, f: bool, a: u256, b: u256): W { return W(t, [[f ? a : b, b], [a, f ? b : a]]); }
  @view mkWcast(t: u256, a: u8, b: u16): W { return W(t, [[u256(a), u256(b)], [u256(a) + u256(b), u256(a) * 2n]]); }

  // struct with two grid fields and a nested packed struct field between them.
  // NOTE: the construct-and-RETURN path (mkTwo) hits JETH900 -- the encodeStructReturn
  // lowering cannot encode a nested-struct-literal field that sits alongside an
  // array-literal field. The STORE path (writeStruct) handles it, so we exercise
  // store + whole-read here (byte-identical to solc at runtime).
  @external setTwo(a: u256, b: u256, c: u256, d: u256, px: u128, py: u128, e: u8, f: u8, g: u8, h: u8): void {
    this.two = Two([[a, b], [c, d]], P2(px, py), [[e, f], [g, h]]);
  }
  @view getTwo(): Two { return this.two; }
}`;

const SOL2 = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract D {
  struct Ag { uint256 tag; address[2][2] grid; }
  struct As { uint256 tag; uint256[3][2] grid; }
  struct On { uint256 tag; uint256[1][1] grid; }
  struct RA { uint64 id; uint256[2] data; }
  struct MM { uint256 tag; RA[2] rows; }
  struct P2 { uint128 a; uint128 b; }
  struct Two { uint256[2][2] g1; P2 pt; uint8[2][2] g2; }
  struct W { uint256 tag; uint256[2][2] grid; }

  Ag ag; As asym; Two two;

  function setAg(uint256 t, address a, address b, address c, address d) external { ag = Ag(t, [[a, b], [c, d]]); }
  function getAg() external view returns (Ag memory){ return ag; }
  function mkAg(uint256 t, address a, address b, address c, address d) external pure returns (Ag memory){ return Ag(t, [[a, b], [c, d]]); }

  function setAsym(uint256 t, uint256 a, uint256 b, uint256 c, uint256 d, uint256 e, uint256 f) external { asym = As(t, [[a, b, c], [d, e, f]]); }
  function getAsym() external view returns (As memory){ return asym; }
  function mkAsym(uint256 t, uint256 a, uint256 b, uint256 c, uint256 d, uint256 e, uint256 f) external pure returns (As memory){ return As(t, [[a, b, c], [d, e, f]]); }

  function mkOne(uint256 t, uint256 a) external pure returns (On memory){ return On(t, [[a]]); }

  function mkMM(uint256 t, uint64 i0, uint256 a0, uint256 b0, uint64 i1, uint256 a1, uint256 b1) external pure returns (MM memory){
    return MM(t, [RA(i0, [a0, b0]), RA(i1, [a1, b1])]);
  }

  function mkWtern(uint256 t, bool f, uint256 a, uint256 b) external pure returns (W memory){ return W(t, [[f ? a : b, b], [a, f ? b : a]]); }
  function mkWcast(uint256 t, uint8 a, uint16 b) external pure returns (W memory){ return W(t, [[uint256(a), uint256(b)], [uint256(a) + uint256(b), uint256(a) * 2]]); }

  function setTwo(uint256 a, uint256 b, uint256 c, uint256 d, uint128 px, uint128 py, uint8 e, uint8 f, uint8 g, uint8 h) external {
    two = Two([[a, b], [c, d]], P2(px, py), [[e, f], [g, h]]);
  }
  function getTwo() external view returns (Two memory){ return two; }
}`;

describe('probe2', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = []; let count = 0;
  async function eq(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    if (j.success !== s.success || j.returnHex !== s.returnHex)
      mism.push(label + ': jeth{ok=' + j.success + ',ret=' + j.returnHex + ',err=' + j.exceptionError + '} sol{ok=' + s.success + ',ret=' + s.returnHex + '}');
  }
  function rawCall(sig: string, words: bigint[]): string {
    let h = '0x' + sel(sig);
    for (const w of words) { let x = ((w % M) + M) % M; h += x.toString(16).padStart(64, '0'); }
    return h;
  }
  beforeAll(async () => {
    const jb = compile(JETH2, { fileName: 'D.jeth' });
    const sb = compileSolidity(SOL2, 'D');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  it('runs', async () => {
    const MAX = M - 1n;
    const U: bigint[] = [0n, 1n, 255n, MAX, 1n << 255n, 0xdeadbeefn, 12345n];
    // address corpus: includes a full 20-byte value, and a value with dirty high bits above 160
    const ADDR: bigint[] = [
      0n, 1n,
      BigInt('0x' + 'ab'.repeat(20)),         // full 20 bytes
      BigInt('0x' + 'ff'.repeat(20)),
      0x00112233445566778899aabbccddeeff00112233n,
      (1n << 200n) | 0x1234n,                  // dirty high bits -> solc masks to 160; both should mask
    ];

    // ---- address grid ----
    for (let i = 0; i < ADDR.length; i++) {
      const t = U[i % U.length]!;
      const a = ADDR[i]!, b = ADDR[(i + 1) % ADDR.length]!, c = ADDR[(i + 2) % ADDR.length]!, d = ADDR[(i + 3) % ADDR.length]!;
      await eq('setAg#' + i, rawCall('setAg(uint256,address,address,address,address)', [t, a, b, c, d]));
      await eq('getAg#' + i, encodeCall(sel('getAg()'), []));
      await eq('mkAg#' + i, rawCall('mkAg(uint256,address,address,address,address)', [t, a, b, c, d]));
    }

    // ---- asymmetric 3x2 grid ----
    for (let i = 0; i < U.length; i++) {
      const v = (k: number) => U[(i + k) % U.length]!;
      const args = [v(0), v(1), v(2), v(3), v(4), v(5), v(6)];
      await eq('setAsym#' + i, encodeCall(sel('setAsym(uint256,uint256,uint256,uint256,uint256,uint256,uint256)'), args));
      await eq('getAsym#' + i, encodeCall(sel('getAsym()'), []));
      await eq('mkAsym#' + i, encodeCall(sel('mkAsym(uint256,uint256,uint256,uint256,uint256,uint256,uint256)'), args));
    }

    // ---- 1x1 degenerate grid ----
    for (let i = 0; i < U.length; i++) {
      await eq('mkOne#' + i, encodeCall(sel('mkOne(uint256,uint256)'), [U[i % U.length]!, U[(i + 3) % U.length]!]));
    }

    // ---- struct-array literal with element having a fixed-array field ----
    const U64: bigint[] = [0n, 1n, (1n << 64n) - 1n, 0xcafen];
    for (let i = 0; i < U.length; i++) {
      const v = (k: number) => U[(i + k) % U.length]!;
      const id0 = U64[i % U64.length]!, id1 = U64[(i + 1) % U64.length]!;
      await eq('mkMM#' + i, encodeCall(sel('mkMM(uint256,uint64,uint256,uint256,uint64,uint256,uint256)'),
        [v(0), id0, v(1), v(2), id1, v(3), v(4)]));
    }

    // ---- ternary + cast subexpressions inside grid literal ----
    for (let i = 0; i < U.length; i++) {
      const a = U[i]!, b = U[(i + 2) % U.length]!;
      await eq('mkWtern-T#' + i, rawCall('mkWtern(uint256,bool,uint256,uint256)', [U[(i + 1) % U.length]!, 1n, a, b]));
      await eq('mkWtern-F#' + i, rawCall('mkWtern(uint256,bool,uint256,uint256)', [U[(i + 1) % U.length]!, 0n, a, b]));
    }
    const SMALL_A: bigint[] = [0n, 1n, 255n];
    const SMALL_B: bigint[] = [0n, 1n, 65535n, 1000n];
    for (let i = 0; i < SMALL_A.length; i++) for (let k = 0; k < SMALL_B.length; k++) {
      await eq(`mkWcast#${i}_${k}`, rawCall('mkWcast(uint256,uint8,uint16)', [7n, SMALL_A[i]!, SMALL_B[k]!]));
    }

    // ---- struct with two grids + nested packed struct field (STORE path; the
    //      construct-and-return path is rejected by JETH900, documented in notes) ----
    const U128: bigint[] = [0n, 1n, (1n << 128n) - 1n, 0xdeadn];
    const U8: bigint[] = [0n, 1n, 127n, 255n];
    for (let i = 0; i < U.length; i++) {
      const v = (k: number) => U[(i + k) % U.length]!;
      const px = U128[i % U128.length]!, py = U128[(i + 1) % U128.length]!;
      const e = U8[i % U8.length]!, f = U8[(i + 1) % U8.length]!, g = U8[(i + 2) % U8.length]!, h = U8[(i + 3) % U8.length]!;
      const sig = 'setTwo(uint256,uint256,uint256,uint256,uint128,uint128,uint8,uint8,uint8,uint8)';
      const args = [v(0), v(1), v(2), v(3), px, py, e, f, g, h];
      await eq('setTwo#' + i, rawCall(sig, args));
      await eq('getTwo#' + i, encodeCall(sel('getTwo()'), []));
    }

    if (mism.length) { console.log('W2 MISMATCHES ' + mism.length + '/' + count); for (const m of mism.slice(0, 40)) console.log(m); }
    else console.log('W2 ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});

// ===========================================================================
// A nested struct-literal (structNew) appearing as a struct FIELD or as a struct-array
// -literal element's SUBFIELD, when the construction is RETURNED directly (pure/view), is
// now encoded byte-identically to solc (encodeStructReturn flattens a nested struct field
// via staticNewLeaves; encodeArrayLitHead recurses into a struct element's nested struct
// subfield). These were previously a documented JETH900 gap; now runtime-parity cases.
// ===========================================================================
describe('nested struct-literal field in RETURN position vs solc (byte-identical)', () => {
  async function sameReturn(J: string, S: string, sig: string, args: bigint[]): Promise<void> {
    const jb = compile(J, { fileName: 'D.jeth' });
    const sb = compileSolidity(S, 'D');
    const hj = await Harness.create(); const hs = await Harness.create();
    const aj = await hj.deploy(jb.creationBytecode); const as = await hs.deploy(sb.creation);
    const data = '0x' + sel(sig) + args.map((w) => ((w % M + M) % M).toString(16).padStart(64, '0')).join('');
    const rj = await hj.call(aj, data); const rs = await hs.call(as, data);
    expect(rj.success, `jeth err=${rj.exceptionError}`).toBe(rs.success);
    expect(rj.returnHex).toBe(rs.returnHex);
  }

  it('nested struct field returned: M(Pt(x,y), z)', () =>
    sameReturn(
      `@struct class Pt { x: u256; y: u256; }
@struct class M { p: Pt; z: u256; }
@contract class D { @external @view f(x: u256, y: u256, z: u256): M { return M(Pt(x, y), z); } }`,
      `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract D { struct Pt { uint256 x; uint256 y; } struct M { Pt p; uint256 z; }
  function f(uint256 x, uint256 y, uint256 z) external pure returns (M memory){ return M(Pt(x, y), z); } }`,
      'f(uint256,uint256,uint256)', [7n, 8n, 9n]));

  it('struct field + array-literal sibling returned: T2(P2(px,py), [[..]])', () =>
    sameReturn(
      `@struct class P2 { a: u128; b: u128; }
@struct class T2 { pt: P2; g: Arr<Arr<u256, 2>, 2>; }
@contract class D { @external @view f(px: u128, py: u128, a: u256, b: u256, c: u256, d: u256): T2 { return T2(P2(px, py), [[a, b], [c, d]]); } }`,
      `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract D { struct P2 { uint128 a; uint128 b; } struct T2 { P2 pt; uint256[2][2] g; }
  function f(uint128 px, uint128 py, uint256 a, uint256 b, uint256 c, uint256 d) external pure returns (T2 memory){ return T2(P2(px, py), [[a, b], [c, d]]); } }`,
      'f(uint128,uint128,uint256,uint256,uint256,uint256)', [3n, 4n, 10n, 11n, 12n, 13n]));

  it('struct-array literal element with nested struct subfield returned: M(t,[Row(Pt(..),z),..])', () =>
    sameReturn(
      `@struct class Pt { x: u8; y: u8; }
@struct class Row { p: Pt; z: u256; }
@struct class M { tag: u256; rows: Arr<Row, 2>; }
@contract class D { @external @view f(t: u256, x0: u8, y0: u8, z0: u256, x1: u8, y1: u8, z1: u256): M {
  return M(t, [Row(Pt(x0, y0), z0), Row(Pt(x1, y1), z1)]); } }`,
      `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract D { struct Pt { uint8 x; uint8 y; } struct Row { Pt p; uint256 z; } struct M { uint256 tag; Row[2] rows; }
  function f(uint256 t, uint8 x0, uint8 y0, uint256 z0, uint8 x1, uint8 y1, uint256 z1) external pure returns (M memory){
    return M(t, [Row(Pt(x0, y0), z0), Row(Pt(x1, y1), z1)]); } }`,
      'f(uint256,uint8,uint8,uint256,uint8,uint8,uint256)', [99n, 1n, 2n, 100n, 3n, 4n, 200n]));

  it('CONTROL: the identical struct stored to state IS byte-identical at runtime', async () => {
    // construct-and-store compiles; verify runtime parity for M(Pt(x,y), z) via the STORE path.
    const J = `@struct class Pt { x: u256; y: u256; }
@struct class M { p: Pt; z: u256; }
@contract class D { @state m: M;
  @external set(x: u256, y: u256, z: u256): void { this.m = M(Pt(x, y), z); }
  @view get(): M { return this.m; } }`;
    const S = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract D { struct Pt { uint256 x; uint256 y; } struct M { Pt p; uint256 z; } M m;
  function set(uint256 x, uint256 y, uint256 z) external { m = M(Pt(x, y), z); }
  function get() external view returns (M memory){ return m; } }`;
    const jb = compile(J, { fileName: 'D.jeth' });
    const sb = compileSolidity(S, 'D');
    const hj = await Harness.create(); const hs = await Harness.create();
    const aj = await hj.deploy(jb.creationBytecode); const as = await hs.deploy(sb.creation);
    const data = '0x' + sel('set(uint256,uint256,uint256)') +
      [7n, 8n, 9n].map((w) => w.toString(16).padStart(64, '0')).join('');
    const j1 = await hj.call(aj, data); const s1 = await hs.call(as, data);
    expect(j1.success, `set jeth err=${j1.exceptionError}`).toBe(s1.success);
    const g = '0x' + sel('get()');
    const j2 = await hj.call(aj, g); const s2 = await hs.call(as, g);
    expect(j2.success).toBe(s2.success);
    expect(j2.returnHex).toBe(s2.returnHex);
  });
});
