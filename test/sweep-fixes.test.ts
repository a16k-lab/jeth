// Final-sweep fixes: unchecked signed-div overflow (#1), @pure memory-array RMW (#2/#6),
// struct ctor with fixed-array field (#5), ++/-- in value position (#3), ternary over
// memory arrays (#4). All byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const JETH = `@struct class D { id: u256; data: Arr<u256, 3>; }
@contract class SW {
  @state s: D;
  @external @pure uDivI256(a: i256, b: i256): i256 { unchecked: { return a / b; } }
  @external @pure pureRMW(a: u8): u8 { let xs: u8[] = [a, a]; xs[0n]++; xs[0n] = xs[0n] + 1n; return xs[0n]; }
  @external setS(id: u256, a: u256, b: u256, c: u256): void { this.s = D(id, [a, b, c]); }
  @external @view getId(): u256 { return this.s.id; }
  @external @view getData(i: u256): u256 { return this.s.data[i]; }
  @external @pure ctorReturn(id: u256, a: u256, b: u256, c: u256): D { return D(id, [a, b, c]); }
  @external @pure postInc(x: u256): u256 { let a: u256 = x; let p: u256 = a++; return p + a; }
  @external @pure preInc(x: u256): u256 { let a: u256 = x; let p: u256 = ++a; return p + a; }
  @external @pure ternMem(c: bool, x: u256, y: u256): u256[] {
    let xs: u256[] = [x, x];
    let ys: u256[] = [y, y, y];
    return c ? xs : ys;
  }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract SW {
  struct D { uint256 id; uint256[3] data; }
  D s;
  function uDivI256(int256 a, int256 b) external pure returns (int256){ unchecked { return a / b; } }
  function pureRMW(uint8 a) external pure returns (uint8){ uint8[] memory xs = new uint8[](2); xs[0]=a; xs[1]=a; xs[0]++; xs[0] = xs[0] + 1; return xs[0]; }
  function setS(uint256 id, uint256 a, uint256 b, uint256 c) external { s = D(id, [a, b, c]); }
  function getId() external view returns (uint256){ return s.id; }
  function getData(uint256 i) external view returns (uint256){ return s.data[i]; }
  function ctorReturn(uint256 id, uint256 a, uint256 b, uint256 c) external pure returns (D memory){ return D(id, [a, b, c]); }
  function postInc(uint256 x) external pure returns (uint256){ uint256 a = x; uint256 p = a++; return p + a; }
  function preInc(uint256 x) external pure returns (uint256){ uint256 a = x; uint256 p = ++a; return p + a; }
  function ternMem(bool c, uint256 x, uint256 y) external pure returns (uint256[] memory){
    uint256[] memory xs = new uint256[](2); xs[0]=x; xs[1]=x;
    uint256[] memory ys = new uint256[](3); ys[0]=y; ys[1]=y; ys[2]=y;
    return c ? xs : ys;
  }
}`;

describe('final-sweep fixes vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function eq(label: string, sig: string, args: bigint[]) {
    const data = '0x' + sel(sig) + args.map(pad).join('');
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'SW.jeth' });
    const sb = compileSolidity(SOL, 'SW');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('#1 unchecked signed div: INT_MIN/-1 wraps (no Panic), and /0 still panics', async () => {
    await eq('INT_MIN / -1', 'uDivI256(int256,int256)', [1n << 255n, M - 1n]);
    await eq('div by zero', 'uDivI256(int256,int256)', [5n, 0n]);
    await eq('normal -10/3', 'uDivI256(int256,int256)', [M - 10n, 3n]);
  });
  it('#2/#6 @pure memory-array RMW compiles + runs', async () => {
    await eq('pureRMW', 'pureRMW(uint8)', [40n]);
  });
  it('#5 struct ctor with fixed-array field (store + read + return)', async () => {
    {
      const data = encodeCall(sel('setS(uint256,uint256,uint256,uint256)'), [7n, 1n, 2n, 3n]);
      const j = await jeth.call(aj, data);
      const s = await sol.call(as, data);
      expect(j.success).toBe(s.success);
    }
    await eq('getId', 'getId()', []);
    await eq('getData[1]', 'getData(uint256)', [1n]);
    await eq('ctorReturn', 'ctorReturn(uint256,uint256,uint256,uint256)', [9n, 4n, 5n, 6n]);
  });
  it('#3 ++/-- in value position (post + pre)', async () => {
    await eq('postInc', 'postInc(uint256)', [10n]);
    await eq('preInc', 'preInc(uint256)', [10n]);
  });
  it('#4 ternary over memory arrays', async () => {
    await eq('ternMem true', 'ternMem(bool,uint256,uint256)', [1n, 7n, 9n]);
    await eq('ternMem false', 'ternMem(bool,uint256,uint256)', [0n, 7n, 9n]);
  });
});
