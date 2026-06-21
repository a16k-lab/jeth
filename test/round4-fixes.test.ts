// Round-4 gaps: mapping-valued nested inner-array push/.length (this.m[k][i].push/.length),
// write through a ternary-selected memory array ((c?xs:ys)[i] = v), and whole inner-array
// return (return this.dd[i]). Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const K = 0xabcn;

const JETH = `@contract class R4 {
  @state m: mapping<u256, u256[][]>;
  @state dd: u256[][];
  @external pushOuter(k: u256): void { this.m[k].push(); }
  @external pushInner(k: u256, i: u256, v: u256): void { this.m[k][i].push(v); }
  @external @view innerLen(k: u256, i: u256): u256 { return this.m[k][i].length; }
  @external @view at(k: u256, i: u256, j: u256): u256 { return this.m[k][i][j]; }
  @external ddPush(): void { this.dd.push(); }
  @external ddPushInner(i: u256, v: u256): void { this.dd[i].push(v); }
  @external @view getInner(i: u256): u256[] { return this.dd[i]; }
  @external @pure ternWrite(c: bool, i: u256, v: u256): u256 {
    let xs: u256[] = [1n, 2n]; let ys: u256[] = [3n, 4n];
    (c ? xs : ys)[i] = v;
    return xs[0n] + xs[1n] + ys[0n] + ys[1n];
  }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract R4 {
  mapping(uint256 => uint256[][]) m;
  uint256[][] dd;
  function pushOuter(uint256 k) external { m[k].push(); }
  function pushInner(uint256 k, uint256 i, uint256 v) external { m[k][i].push(v); }
  function innerLen(uint256 k, uint256 i) external view returns (uint256){ return m[k][i].length; }
  function at(uint256 k, uint256 i, uint256 j) external view returns (uint256){ return m[k][i][j]; }
  function ddPush() external { dd.push(); }
  function ddPushInner(uint256 i, uint256 v) external { dd[i].push(v); }
  function getInner(uint256 i) external view returns (uint256[] memory){ return dd[i]; }
  function ternWrite(bool c, uint256 i, uint256 v) external pure returns (uint256) {
    uint256[] memory xs = new uint256[](2); xs[0]=1; xs[1]=2;
    uint256[] memory ys = new uint256[](2); ys[0]=3; ys[1]=4;
    (c ? xs : ys)[i] = v;
    return xs[0] + xs[1] + ys[0] + ys[1];
  }
}`;

describe('round-4 fixes vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function send(data: string) { const j = await jeth.call(aj, data); const s = await sol.call(as, data); expect(j.success, `${j.exceptionError}`).toBe(s.success); }
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'R4.jeth' });
    const sb = compileSolidity(SOL, 'R4');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  it('mapping-valued nested inner-array push + .length + index', async () => {
    await send(encodeCall(sel('pushOuter(uint256)'), [K]));
    await send(encodeCall(sel('pushInner(uint256,uint256,uint256)'), [K, 0n, 11n]));
    await send(encodeCall(sel('pushInner(uint256,uint256,uint256)'), [K, 0n, 22n]));
    await eq('innerLen', encodeCall(sel('innerLen(uint256,uint256)'), [K, 0n]));
    await eq('at[0][1]', encodeCall(sel('at(uint256,uint256,uint256)'), [K, 0n, 1n]));
  });
  it('whole inner-array return (return this.dd[i])', async () => {
    await send(encodeCall(sel('ddPush()'), []));
    await send(encodeCall(sel('ddPushInner(uint256,uint256)'), [0n, 7n]));
    await send(encodeCall(sel('ddPushInner(uint256,uint256)'), [0n, 8n]));
    await eq('getInner[0]', encodeCall(sel('getInner(uint256)'), [0n]));
  });
  it('write through a ternary-selected memory array', async () => {
    await eq('ternWrite true', encodeCall(sel('ternWrite(bool,uint256,uint256)'), [1n, 0n, 99n]));
    await eq('ternWrite false', encodeCall(sel('ternWrite(bool,uint256,uint256)'), [0n, 1n, 88n]));
  });
});
