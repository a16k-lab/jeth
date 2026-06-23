// Phase 4: UNBOUNDED nested dynamic arrays (u256[][][], u256[][][][], string[][])
// as calldata param + return, byte-identical to Solidity. Strategy: let solc encode
// a known deep value (make*), then feed those exact ABI bytes to BOTH echoes and to
// the element accessors, comparing returndata byte-for-byte.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, decodeUint } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const JETH = `@contract class Deep {
  @external @pure echo3(m: u256[][][]): u256[][][] { return m; }
  @external @pure at3(m: u256[][][], i: u256, j: u256, k: u256): u256 { return m[i][j][k]; }
  @external @pure echo4(m: u256[][][][]): u256[][][][] { return m; }
  @external @pure echoS(a: string[][]): string[][] { return a; }
  @external @pure atS(a: string[][], i: u256, j: u256): string { return a[i][j]; }
  @external @pure echo5(m: u256[][][][][]): u256[][][][][] { return m; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Deep {
  function make3() external pure returns (uint256[][][] memory m) {
    m = new uint256[][][](2);
    m[0] = new uint256[][](2);
    m[0][0] = new uint256[](2); m[0][0][0] = 1; m[0][0][1] = 2;
    m[0][1] = new uint256[](1); m[0][1][0] = 3;
    m[1] = new uint256[][](1);
    m[1][0] = new uint256[](3); m[1][0][0] = 4; m[1][0][1] = 5; m[1][0][2] = 6;
  }
  function make4() external pure returns (uint256[][][][] memory m) {
    m = new uint256[][][][](2);
    m[0] = new uint256[][][](1); m[0][0] = new uint256[][](1); m[0][0][0] = new uint256[](2);
    m[0][0][0][0] = 7; m[0][0][0][1] = 8;
    m[1] = new uint256[][][](1); m[1][0] = new uint256[][](2);
    m[1][0][0] = new uint256[](0);
    m[1][0][1] = new uint256[](1); m[1][0][1][0] = 9;
  }
  function makeS() external pure returns (string[][] memory a) {
    a = new string[][](2);
    a[0] = new string[](2); a[0][0] = "ab"; a[0][1] = "this string is definitely longer than thirty-two bytes for padding";
    a[1] = new string[](1); a[1][0] = "";
  }
  function echo3(uint256[][][] calldata m) external pure returns (uint256[][][] memory) { return m; }
  function at3(uint256[][][] calldata m, uint256 i, uint256 j, uint256 k) external pure returns (uint256){ return m[i][j][k]; }
  function echo4(uint256[][][][] calldata m) external pure returns (uint256[][][][] memory) { return m; }
  function echoS(string[][] calldata a) external pure returns (string[][] memory) { return a; }
  function atS(string[][] calldata a, uint256 i, uint256 j) external pure returns (string memory){ return a[i][j]; }
  function make5() external pure returns (uint256[][][][][] memory m) {
    m = new uint256[][][][][](1); m[0] = new uint256[][][][](2);
    m[0][0] = new uint256[][][](1); m[0][0][0] = new uint256[][](1); m[0][0][0][0] = new uint256[](2);
    m[0][0][0][0][0] = 11; m[0][0][0][0][1] = 22;
    m[0][1] = new uint256[][][](0);
  }
  function echo5(uint256[][][][][] calldata m) external pure returns (uint256[][][][][] memory) { return m; }
}`;

describe('unbounded nested dynamic arrays vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function makeData(maker: string): Promise<string> {
    const r = await sol.call(as, '0x' + sel(maker));
    return r.returnHex; // [0x20][value encoding]
  }
  async function echoBoth(echoSig: string, valueRet: string) {
    // echo(x) calldata for a sole dynamic param == [0x20][value] == the maker returndata.
    const data = '0x' + sel(echoSig) + valueRet.slice(2);
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${echoSig} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${echoSig} returndata`).toBe(s.returnHex);
    expect(j.returnHex, `${echoSig} identity`).toBe(valueRet); // echo is the identity
    return { j, s };
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'Deep.jeth' });
    const sb = compileSolidity(SOL, 'Deep');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('u256[][][] echo (3 levels) byte-identical', async () => {
    await echoBoth('echo3(uint256[][][])', await makeData('make3()'));
  });
  it('u256[][][][] echo (4 levels) byte-identical incl empty inner array', async () => {
    await echoBoth('echo4(uint256[][][][])', await makeData('make4()'));
  });
  it('string[][] echo (nested array of dynamic) byte-identical incl empty + long', async () => {
    await echoBoth('echoS(string[][])', await makeData('makeS()'));
  });
  it('u256[][][][][] echo (5 levels) byte-identical incl empty branch', async () => {
    await echoBoth('echo5(uint256[][][][][])', await makeData('make5()'));
  });
  it('string[][] element access a[i][j] (string leaf) byte-identical + OOB', async () => {
    const rs = await makeData('makeS()');
    const adata = rs.slice(2 + 64); // drop leading 0x20
    for (const [i, j] of [
      [0n, 0n],
      [0n, 1n],
      [1n, 0n],
    ] as [bigint, bigint][]) {
      const data = '0x' + sel('atS(string[][],uint256,uint256)') + pad(0x60n) + pad(i) + pad(j) + adata;
      const jr = await jeth.call(aj, data);
      const sr = await sol.call(as, data);
      expect(jr.returnHex, `a[${i}][${j}]`).toBe(sr.returnHex);
    }
    const oob = '0x' + sel('atS(string[][],uint256,uint256)') + pad(0x60n) + pad(0n) + pad(2n) + adata;
    const jr = await jeth.call(aj, oob);
    const sr = await sol.call(as, oob);
    expect(jr.success).toBe(false);
    expect(jr.returnHex).toBe(sr.returnHex);
  });

  it('u256[][][] element access m[i][j][k] at every depth', async () => {
    const r3 = await makeData('make3()');
    const mdata = r3.slice(2 + 64); // drop the leading 0x20 offset word
    const cases: [bigint, bigint, bigint, bigint][] = [
      [0n, 0n, 0n, 1n],
      [0n, 0n, 1n, 2n],
      [0n, 1n, 0n, 3n],
      [1n, 0n, 0n, 4n],
      [1n, 0n, 2n, 6n],
    ];
    for (const [i, j, k, want] of cases) {
      const data =
        '0x' + sel('at3(uint256[][][],uint256,uint256,uint256)') + pad(0x80n) + pad(i) + pad(j) + pad(k) + mdata;
      const jr = await jeth.call(aj, data);
      const sr = await sol.call(as, data);
      expect(jr.returnHex, `m[${i}][${j}][${k}]`).toBe(sr.returnHex);
      expect(decodeUint(jr.returnHex)).toBe(want);
    }
    // OOB at each level -> Panic(0x32) identically
    for (const [i, j, k] of [
      [2n, 0n, 0n],
      [0n, 2n, 0n],
      [0n, 0n, 2n],
    ] as [bigint, bigint, bigint][]) {
      const data =
        '0x' + sel('at3(uint256[][][],uint256,uint256,uint256)') + pad(0x80n) + pad(i) + pad(j) + pad(k) + mdata;
      const jr = await jeth.call(aj, data);
      const sr = await sol.call(as, data);
      expect(jr.success, `OOB [${i}][${j}][${k}]`).toBe(false);
      expect(jr.returnHex).toBe(sr.returnHex);
    }
  });
});
