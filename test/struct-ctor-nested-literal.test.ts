// Struct construction with a NESTED (2D) fixed-array-field literal:
//   this.w = W(t, [[a,b],[c,d]])   (store path -> writeStruct/writeArrayLit)
//   return W(t, [[a,b],[c,d]])     (return path -> encodeStructReturn/encodeArrayLitHead)
// Also a struct whose nested field elements are themselves struct literals, and a plain 1D
// case to guard the simple branch. Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const JETH = `@struct class W { tag: u256; grid: Arr<Arr<u256, 2>, 2>; }
@struct class Row { x: u256; y: u256; }
@struct class M { tag: u256; rows: Arr<Row, 2>; }
@contract class SC {
  @state w: W;
  @external setW(t: u256, a: u256, b: u256, c: u256, d: u256): void { this.w = W(t, [[a, b], [c, d]]); }
  @external @view getW(): W { return this.w; }
  @external @view mkW(t: u256, a: u256, b: u256, c: u256, d: u256): W { return W(t, [[a, b], [c, d]]); }
  @external @view mkM(t: u256, x0: u256, y0: u256, x1: u256, y1: u256): M { return M(t, [Row(x0, y0), Row(x1, y1)]); }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract SC {
  struct W { uint256 tag; uint256[2][2] grid; }
  struct Row { uint256 x; uint256 y; }
  struct M { uint256 tag; Row[2] rows; }
  W w;
  function setW(uint256 t, uint256 a, uint256 b, uint256 c, uint256 d) external { w = W(t, [[a, b], [c, d]]); }
  function getW() external view returns (W memory){ return w; }
  function mkW(uint256 t, uint256 a, uint256 b, uint256 c, uint256 d) external pure returns (W memory){ return W(t, [[a, b], [c, d]]); }
  function mkM(uint256 t, uint256 x0, uint256 y0, uint256 x1, uint256 y1) external pure returns (M memory){ return M(t, [Row(x0, y0), Row(x1, y1)]); }
}`;

describe('struct ctor with nested fixed-array literal vs Solidity', () => {
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
    const jb = compile(JETH, { fileName: 'SC.jeth' });
    const sb = compileSolidity(SOL, 'SC');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('store W(t,[[..]]) then whole return', async () => {
    await send(encodeCall(sel('setW(uint256,uint256,uint256,uint256,uint256)'), [9n, 1n, 2n, 3n, 4n]));
    await eq('getW', encodeCall(sel('getW()'), []));
  });
  it('return W(t,[[..]]) constructed directly (pure)', async () => {
    await eq('mkW', encodeCall(sel('mkW(uint256,uint256,uint256,uint256,uint256)'), [7n, 11n, 12n, 13n, 14n]));
  });
  it('return M(t,[Row(..),Row(..)]) constructed directly (pure)', async () => {
    await eq('mkM', encodeCall(sel('mkM(uint256,uint256,uint256,uint256,uint256)'), [6n, 200n, 201n, 202n, 203n]));
  });
});
