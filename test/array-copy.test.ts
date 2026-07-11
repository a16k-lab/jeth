// A3: whole dynamic-array storage-to-storage deep copy (this.a = this.b) and into a
// mapping-valued array (this.m[k] = this.arr). Value / packed / static-struct / string[]
// / dynamic-struct elements, with grow + shrink (tail clearing). Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const K = BigInt('0x' + 'ab'.repeat(20));
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

const JETH = `type P = { x: u128; y: u128; };
type D = { a: u256; s: string; };
class AC {
  a: u256[];
  b: u256[];
  pa: P[];
  pb: P[];
  sa: string[];
  sb: string[];
  da: D[];
  db: D[];
  ma: mapping<address, u256[]>;
  mb: mapping<address, u256[]>;
  pushA(v: u256): External<void> { this.a.push(v); }
  pushB(v: u256): External<void> { this.b.push(v); }
  pushPB(x: u128, y: u128): External<void> { this.pb.push(P(x, y)); }
  pushSB(s: string): External<void> { this.sb.push(s); }
  pushDB(av: u256, s: string): External<void> { this.db.push(D(av, s)); }
  pushMB(k: address, v: u256): External<void> { this.mb[k].push(v); }
  copyAB(): External<void> { this.a = this.b; }
  copyPA(): External<void> { this.pa = this.pb; }
  copySA(): External<void> { this.sa = this.sb; }
  copyDA(): External<void> { this.da = this.db; }
  copyToMap(k: address): External<void> { this.ma[k] = this.b; }
  copyFromMap(k: address): External<void> { this.a = this.mb[k]; }
  get getA(): External<u256[]> { return this.a; }
  get getPA(): External<P[]> { return this.pa; }
  get getSA(): External<string[]> { return this.sa; }
  get getDA(): External<D[]> { return this.da; }
  get getMA(k: address): External<u256[]> { return this.ma[k]; }
  get lenA(): External<u256> { return this.a.length; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract AC {
  struct P { uint128 x; uint128 y; }
  struct D { uint256 a; string s; }
  uint256[] a; uint256[] b; P[] pa; P[] pb; string[] sa; string[] sb; D[] da; D[] db;
  mapping(address => uint256[]) ma; mapping(address => uint256[]) mb;
  function pushA(uint256 v) external { a.push(v); }
  function pushB(uint256 v) external { b.push(v); }
  function pushPB(uint128 x, uint128 y) external { pb.push(P(x, y)); }
  function pushSB(string calldata s) external { sb.push(s); }
  function pushDB(uint256 av, string calldata s) external { db.push(D(av, s)); }
  function pushMB(address k, uint256 v) external { mb[k].push(v); }
  function copyAB() external { a = b; }
  function copyPA() external { pa = pb; }
  function copySA() external { sa = sb; }
  function copyDA() external { da = db; }
  function copyToMap(address k) external { ma[k] = b; }
  function copyFromMap(address k) external { a = mb[k]; }
  function getA() external view returns (uint256[] memory){ return a; }
  function getPA() external view returns (P[] memory){ return pa; }
  function getSA() external view returns (string[] memory){ return sa; }
  function getDA() external view returns (D[] memory){ return da; }
  function getMA(address k) external view returns (uint256[] memory){ return ma[k]; }
  function lenA() external view returns (uint256){ return a.length; }
}`;

const LONG = 'a definitely-longer-than-thirty-two-byte string element for the copy test path';

describe('whole dynamic-array storage-to-storage copy vs Solidity', () => {
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
    const jb = compile(JETH, { fileName: 'AC.jeth' });
    const sb = compileSolidity(SOL, 'AC');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('value array u256[]: grow then shrink copy', async () => {
    for (const v of [10n, 20n, 30n]) await send(encodeCall(sel('pushB(uint256)'), [v]));
    await send(encodeCall(sel('copyAB()'), []));
    await eq('getA after copy (grow 0->3)', encodeCall(sel('getA()'), []));
    // make a longer than b, then copy again -> a must shrink to b.length with tail cleared
    for (const v of [99n, 98n, 97n, 96n, 95n]) await send(encodeCall(sel('pushA(uint256)'), [v]));
    await send(encodeCall(sel('copyAB()'), []));
    await eq('getA after copy (shrink 8->3)', encodeCall(sel('getA()'), []));
    await eq('lenA', encodeCall(sel('lenA()'), []));
  });

  it('static-struct array P[] copy', async () => {
    await send(encodeCall(sel('pushPB(uint128,uint128)'), [1n, 2n]));
    await send(encodeCall(sel('pushPB(uint128,uint128)'), [3n, 4n]));
    await send(encodeCall(sel('copyPA()'), []));
    await eq('getPA after copy', encodeCall(sel('getPA()'), []));
  });

  it('string[] copy (dynamic elements, long data slots)', async () => {
    await send(strPush('pushSB(string)', [], 'hi'));
    await send(strPush('pushSB(string)', [], LONG));
    await send(encodeCall(sel('copySA()'), []));
    await eq('getSA after copy', encodeCall(sel('getSA()'), []));
  });

  it('copy into a mapping-valued array this.ma[k] = this.b', async () => {
    await send(encodeCall(sel('copyToMap(address)'), [K]));
    await eq('getMA after copy', encodeCall(sel('getMA(address)'), [K]));
  });

  it('dynamic-struct array D[] copy (per-element deep copy incl long string)', async () => {
    await send(strPush('pushDB(uint256,string)', [5n], 'hi'));
    await send(strPush('pushDB(uint256,string)', [6n], LONG));
    await send(encodeCall(sel('copyDA()'), []));
    await eq('getDA after copy', encodeCall(sel('getDA()'), []));
  });

  it('copy FROM a mapping-valued array this.a = this.mb[k] (then shrink)', async () => {
    for (const v of [7n, 8n, 9n]) await send(encodeCall(sel('pushMB(address,uint256)'), [K, v]));
    await send(encodeCall(sel('copyFromMap(address)'), [K]));
    await eq('getA from map', encodeCall(sel('getA()'), []));
  });
});
