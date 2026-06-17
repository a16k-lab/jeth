// Pushing a whole inner array onto a nested storage array: this.dd.push(memArray) /
// push([literal]) / push(storageArray). Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

const JETH = `@contract class PA {
  @state dd: u256[][];
  @state src: u256[];
  @external pushMem(a: u256, b: u256, c: u256): void { let xs: u256[] = [a, b, c]; this.dd.push(xs); }
  @external pushLit(): void { this.dd.push([7n, 8n]); }
  @external pushEmpty(): void { this.dd.push(); }
  @external fillSrc(v: u256): void { this.src.push(v); }
  @external pushSrc(): void { this.dd.push(this.src); }
  @view getAll(): u256[][] { return this.dd; }
  @view at(i: u256, j: u256): u256 { return this.dd[i][j]; }
  @view innerLen(i: u256): u256 { return this.dd[i].length; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract PA {
  uint256[][] dd;
  uint256[] src;
  function pushMem(uint256 a, uint256 b, uint256 c) external { uint256[] memory xs = new uint256[](3); xs[0]=a;xs[1]=b;xs[2]=c; dd.push(xs); }
  function pushLit() external { uint256[] memory xs = new uint256[](2); xs[0]=7;xs[1]=8; dd.push(xs); }
  function pushEmpty() external { dd.push(); }
  function fillSrc(uint256 v) external { src.push(v); }
  function pushSrc() external { dd.push(src); }
  function getAll() external view returns (uint256[][] memory){ return dd; }
  function at(uint256 i, uint256 j) external view returns (uint256){ return dd[i][j]; }
  function innerLen(uint256 i) external view returns (uint256){ return dd[i].length; }
}`;

describe('push whole array element vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function send(data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `send (jeth err=${j.exceptionError})`).toBe(s.success);
  }
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'PA.jeth' });
    const sb = compileSolidity(SOL, 'PA');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  it('push a memory array, a literal, an empty, and a storage array', async () => {
    await send(encodeCall(sel('pushMem(uint256,uint256,uint256)'), [11n, 22n, 33n]));
    await send(encodeCall(sel('pushLit()'), []));
    await send(encodeCall(sel('pushEmpty()'), []));
    await send(encodeCall(sel('fillSrc(uint256)'), [100n]));
    await send(encodeCall(sel('fillSrc(uint256)'), [200n]));
    await send(encodeCall(sel('pushSrc()'), []));
    await eq('innerLen[0]', encodeCall(sel('innerLen(uint256)'), [0n]));
    await eq('innerLen[2] empty', encodeCall(sel('innerLen(uint256)'), [2n]));
    await eq('at[0][2]', encodeCall(sel('at(uint256,uint256)'), [0n, 2n]));
    await eq('at[1][0]', encodeCall(sel('at(uint256,uint256)'), [1n, 0n]));
    await eq('at[3][1] from storage', encodeCall(sel('at(uint256,uint256)'), [3n, 1n]));
    await eq('getAll', encodeCall(sel('getAll()'), []));
  });
});
