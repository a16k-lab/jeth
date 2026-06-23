// A5: storage nested dynamic arrays u256[][], string[][], D[][] (per-inner data slots:
// inner length at the AccessPath slot, data at keccak(that slot), recursively). push/pop
// /length/index on outer + inner, whole-array return. Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
function strPush(sel: string, head: bigint[], s: string): string {
  const b = Buffer.from(s, 'utf8');
  const nwords = Math.ceil(b.length / 32);
  let data = '';
  for (let i = 0; i < nwords; i++)
    data += Buffer.concat([b.subarray(i * 32, i * 32 + 32), Buffer.alloc(32)])
      .subarray(0, 32)
      .toString('hex');
  let h = '0x' + functionSelector(sel);
  for (const w of head) h += pad(w);
  h += pad(BigInt((head.length + 1) * 32)) + pad(BigInt(b.length)) + data;
  return h;
}

const JETH = `@struct class D { a: u256; s: string; }
@contract class NA {
  @state dd: u256[][];
  @state ss: string[][];
  @state ddd: u256[][][];
  @state da: D[][];
  @external pushOuter(): void { this.dd.push(); }
  @external pushInner(i: u256, v: u256): void { this.dd[i].push(v); }
  @external popInner(i: u256): void { this.dd[i].pop(); }
  @external setAt(i: u256, j: u256, v: u256): void { this.dd[i][j] = v; }
  @external @view outerLen(): u256 { return this.dd.length; }
  @external @view innerLen(i: u256): u256 { return this.dd[i].length; }
  @external @view at(i: u256, j: u256): u256 { return this.dd[i][j]; }
  @external @view getDD(): u256[][] { return this.dd; }
  @external pushSOuter(): void { this.ss.push(); }
  @external pushSInner(i: u256, s: string): void { this.ss[i].push(s); }
  @external @view getSS(): string[][] { return this.ss; }
  @external @view sAt(i: u256, j: u256): string { return this.ss[i][j]; }
  @external push3a(): void { this.ddd.push(); }
  @external push3b(i: u256): void { this.ddd[i].push(); }
  @external push3c(i: u256, j: u256, v: u256): void { this.ddd[i][j].push(v); }
  @external @view at3(i: u256, j: u256, k: u256): u256 { return this.ddd[i][j][k]; }
  @external @view getDDD(): u256[][][] { return this.ddd; }
  @external pushDAOuter(): void { this.da.push(); }
  @external pushDAInner(i: u256, a: u256, s: string): void { this.da[i].push(D(a, s)); }
  @external @view getDA(): D[][] { return this.da; }
  @external @view daAt(i: u256, j: u256): D { return this.da[i][j]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract NA {
  struct D { uint256 a; string s; }
  uint256[][] dd; string[][] ss; uint256[][][] ddd; D[][] da;
  function pushOuter() external { dd.push(); }
  function pushInner(uint256 i, uint256 v) external { dd[i].push(v); }
  function popInner(uint256 i) external { dd[i].pop(); }
  function setAt(uint256 i, uint256 j, uint256 v) external { dd[i][j] = v; }
  function outerLen() external view returns (uint256){ return dd.length; }
  function innerLen(uint256 i) external view returns (uint256){ return dd[i].length; }
  function at(uint256 i, uint256 j) external view returns (uint256){ return dd[i][j]; }
  function getDD() external view returns (uint256[][] memory){ return dd; }
  function pushSOuter() external { ss.push(); }
  function pushSInner(uint256 i, string calldata s) external { ss[i].push(s); }
  function getSS() external view returns (string[][] memory){ return ss; }
  function sAt(uint256 i, uint256 j) external view returns (string memory){ return ss[i][j]; }
  function push3a() external { ddd.push(); }
  function push3b(uint256 i) external { ddd[i].push(); }
  function push3c(uint256 i, uint256 j, uint256 v) external { ddd[i][j].push(v); }
  function at3(uint256 i, uint256 j, uint256 k) external view returns (uint256){ return ddd[i][j][k]; }
  function getDDD() external view returns (uint256[][][] memory){ return ddd; }
  function pushDAOuter() external { da.push(); }
  function pushDAInner(uint256 i, uint256 a, string calldata s) external { da[i].push(D(a, s)); }
  function getDA() external view returns (D[][] memory){ return da; }
  function daAt(uint256 i, uint256 j) external view returns (D memory){ return da[i][j]; }
}`;

const LONG = 'a definitely-longer-than-thirty-two-byte nested string element for the test path';

describe('storage nested dynamic arrays vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function send(data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `send success (jeth err=${j.exceptionError})`).toBe(s.success);
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

  it('u256[][]: push outer/inner, index, length, pop, whole return', async () => {
    await send(encodeCall(sel('pushOuter()'), []));
    await send(encodeCall(sel('pushOuter()'), []));
    await send(encodeCall(sel('pushInner(uint256,uint256)'), [0n, 11n]));
    await send(encodeCall(sel('pushInner(uint256,uint256)'), [0n, 22n]));
    await send(encodeCall(sel('pushInner(uint256,uint256)'), [1n, 33n]));
    await eq('outerLen', encodeCall(sel('outerLen()'), []));
    await eq('innerLen[0]', encodeCall(sel('innerLen(uint256)'), [0n]));
    await eq('at[0][1]', encodeCall(sel('at(uint256,uint256)'), [0n, 1n]));
    await send(encodeCall(sel('setAt(uint256,uint256,uint256)'), [0n, 1n, 99n]));
    await eq('at[0][1] after set', encodeCall(sel('at(uint256,uint256)'), [0n, 1n]));
    await eq('getDD', encodeCall(sel('getDD()'), []));
    await send(encodeCall(sel('popInner(uint256)'), [0n]));
    await eq('getDD after pop', encodeCall(sel('getDD()'), []));
    await eq('at OOB', encodeCall(sel('at(uint256,uint256)'), [5n, 0n]));
  });

  it('string[][]: push, index, whole return (long strings)', async () => {
    await send(encodeCall(sel('pushSOuter()'), []));
    await send(strPush('pushSInner(uint256,string)', [0n], 'hi'));
    await send(strPush('pushSInner(uint256,string)', [0n], LONG));
    await eq('sAt[0][1]', encodeCall(sel('sAt(uint256,uint256)'), [0n, 1n]));
    await eq('getSS', encodeCall(sel('getSS()'), []));
  });

  it('u256[][][]: triple nesting push/index/return', async () => {
    await send(encodeCall(sel('push3a()'), []));
    await send(encodeCall(sel('push3b(uint256)'), [0n]));
    await send(encodeCall(sel('push3c(uint256,uint256,uint256)'), [0n, 0n, 7n]));
    await send(encodeCall(sel('push3c(uint256,uint256,uint256)'), [0n, 0n, 8n]));
    await eq('at3[0][0][1]', encodeCall(sel('at3(uint256,uint256,uint256)'), [0n, 0n, 1n]));
    await eq('getDDD', encodeCall(sel('getDDD()'), []));
  });

  it('D[][]: nested dynamic-struct array push/index/return', async () => {
    await send(encodeCall(sel('pushDAOuter()'), []));
    await send(strPush('pushDAInner(uint256,uint256,string)', [0n, 5n], LONG));
    await eq('daAt[0][0]', encodeCall(sel('daAt(uint256,uint256)'), [0n, 0n]));
    await eq('getDA', encodeCall(sel('getDA()'), []));
  });
});
