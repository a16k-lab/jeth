// Whole inner-array return at depth via a multi-step base: return this.m[k][i] (mapping
// nested), return this.ddd[i][j] / this.ddd[i] (3D), return this.ss[i] (string[][]).
// Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const K = 0xabcn;

const JETH = `@contract class IR {
  @state m: mapping<u256, u256[][]>;
  @state ddd: u256[][][];
  @state ss: string[][];
  @external mPushOuter(k: u256): void { this.m[k].push(); }
  @external mPushInner(k: u256, i: u256, v: u256): void { this.m[k][i].push(v); }
  @view mInner(k: u256, i: u256): u256[] { return this.m[k][i]; }
  @external d3a(): void { this.ddd.push(); }
  @external d3b(i: u256): void { this.ddd[i].push(); }
  @external d3c(i: u256, j: u256, v: u256): void { this.ddd[i][j].push(v); }
  @view d3Inner1(i: u256, j: u256): u256[] { return this.ddd[i][j]; }
  @view d3Inner2(i: u256): u256[][] { return this.ddd[i]; }
  @external sPushOuter(): void { this.ss.push(); }
  @external sPushInner(i: u256, s: string): void { this.ss[i].push(s); }
  @view sInner(i: u256): string[] { return this.ss[i]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract IR {
  mapping(uint256 => uint256[][]) m;
  uint256[][][] ddd;
  string[][] ss;
  function mPushOuter(uint256 k) external { m[k].push(); }
  function mPushInner(uint256 k, uint256 i, uint256 v) external { m[k][i].push(v); }
  function mInner(uint256 k, uint256 i) external view returns (uint256[] memory){ return m[k][i]; }
  function d3a() external { ddd.push(); }
  function d3b(uint256 i) external { ddd[i].push(); }
  function d3c(uint256 i, uint256 j, uint256 v) external { ddd[i][j].push(v); }
  function d3Inner1(uint256 i, uint256 j) external view returns (uint256[] memory){ return ddd[i][j]; }
  function d3Inner2(uint256 i) external view returns (uint256[][] memory){ return ddd[i]; }
  function sPushOuter() external { ss.push(); }
  function sPushInner(uint256 i, string calldata s) external { ss[i].push(s); }
  function sInner(uint256 i) external view returns (string[] memory){ return ss[i]; }
}`;

const LONG = 'a definitely-longer-than-thirty-two-byte string for the nested inner-array return';

describe('whole inner-array return at depth vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  function strCall(sig: string, head: bigint[], s: string): string {
    const b = Buffer.from(s, 'utf8'); const nwords = Math.ceil(b.length / 32);
    let data = ''; for (let i = 0; i < nwords; i++) data += Buffer.concat([b.subarray(i*32, i*32+32), Buffer.alloc(32)]).subarray(0,32).toString('hex');
    let h = '0x' + sel(sig); for (const w of head) h += pad(w);
    h += pad(BigInt((head.length + 1) * 32)) + pad(BigInt(b.length)) + data; return h;
  }
  async function send(data: string) { const j = await jeth.call(aj, data); const s = await sol.call(as, data); expect(j.success, `${j.exceptionError}`).toBe(s.success); }
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'IR.jeth' });
    const sb = compileSolidity(SOL, 'IR');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  it('return this.m[k][i] (mapping<K,u256[][]> inner)', async () => {
    await send(encodeCall(sel('mPushOuter(uint256)'), [K]));
    await send(encodeCall(sel('mPushInner(uint256,uint256,uint256)'), [K, 0n, 11n]));
    await send(encodeCall(sel('mPushInner(uint256,uint256,uint256)'), [K, 0n, 22n]));
    await eq('mInner', encodeCall(sel('mInner(uint256,uint256)'), [K, 0n]));
  });
  it('return this.ddd[i][j] and this.ddd[i] (3D)', async () => {
    await send(encodeCall(sel('d3a()'), []));
    await send(encodeCall(sel('d3b(uint256)'), [0n]));
    await send(encodeCall(sel('d3c(uint256,uint256,uint256)'), [0n, 0n, 7n]));
    await send(encodeCall(sel('d3c(uint256,uint256,uint256)'), [0n, 0n, 8n]));
    await eq('d3Inner1', encodeCall(sel('d3Inner1(uint256,uint256)'), [0n, 0n]));
    await eq('d3Inner2', encodeCall(sel('d3Inner2(uint256)'), [0n]));
  });
  it('return this.ss[i] (string[][] inner, long)', async () => {
    await send(encodeCall(sel('sPushOuter()'), []));
    await send(strCall('sPushInner(uint256,string)', [0n], 'hi'));
    await send(strCall('sPushInner(uint256,string)', [0n], LONG));
    await eq('sInner', encodeCall(sel('sInner(uint256)'), [0n]));
  });
});
