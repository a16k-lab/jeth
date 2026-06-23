// Phase 4: returning a WHOLE mapping value `return this.m[k]` (struct / dynamic
// struct / value array / string[]) via the storage-source recursive encoder at the
// runtime keccak(key.base) slot. Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const K = BigInt('0x' + 'ab'.repeat(20));
function strArg(sel: string, headStatic: bigint[], s: string): string {
  const b = Buffer.from(s, 'utf8');
  const nwords = Math.ceil(b.length / 32);
  let data = '';
  for (let i = 0; i < nwords; i++)
    data += Buffer.concat([b.subarray(i * 32, i * 32 + 32), Buffer.alloc(32)])
      .subarray(0, 32)
      .toString('hex');
  let h = '0x' + functionSelector(sel);
  for (const w of headStatic) h += pad(w);
  h += pad(BigInt((headStatic.length + 1) * 32)) + pad(BigInt(b.length)) + data;
  return h;
}

const JETH = `@struct class P { x: u128; y: u128; }
@struct class D { a: u256; s: string; }
@contract class MR {
  @state mp: mapping<address, P>;
  @state md: mapping<address, D>;
  @state mu: mapping<address, u256[]>;
  @state ms: mapping<address, string[]>;
  @external setP(k: address, x: u128, y: u128): void { this.mp[k].x = x; this.mp[k].y = y; }
  @external setDA(k: address, a: u256): void { this.md[k].a = a; }
  @external setDS(k: address, s: string): void { this.md[k].s = s; }
  @external pushU(k: address, v: u256): void { this.mu[k].push(v); }
  @external pushS(k: address, s: string): void { this.ms[k].push(s); }
  @external @view getP(k: address): P { return this.mp[k]; }
  @external @view getD(k: address): D { return this.md[k]; }
  @external @view getU(k: address): u256[] { return this.mu[k]; }
  @external @view getS(k: address): string[] { return this.ms[k]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MR {
  struct P { uint128 x; uint128 y; }
  struct D { uint256 a; string s; }
  mapping(address => P) mp;
  mapping(address => D) md;
  mapping(address => uint256[]) mu;
  mapping(address => string[]) ms;
  function setP(address k, uint128 x, uint128 y) external { mp[k].x = x; mp[k].y = y; }
  function setDA(address k, uint256 a) external { md[k].a = a; }
  function setDS(address k, string calldata s) external { md[k].s = s; }
  function pushU(address k, uint256 v) external { mu[k].push(v); }
  function pushS(address k, string calldata s) external { ms[k].push(s); }
  function getP(address k) external view returns (P memory){ return mp[k]; }
  function getD(address k) external view returns (D memory){ return md[k]; }
  function getU(address k) external view returns (uint256[] memory){ return mu[k]; }
  function getS(address k) external view returns (string[] memory){ return ms[k]; }
}`;

const LONG = 'a value string definitely longer than thirty-two bytes for the long path';

describe('returning a whole mapping value vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const sel = (s: string) => functionSelector(s);
  async function send(data: string) {
    await jeth.call(aj, data);
    await sol.call(as, data);
  }
  async function eqGet(label: string, selSig: string) {
    const data = encodeCall(sel(selSig), [K]);
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'MR.jeth' });
    const sb = compileSolidity(SOL, 'MR');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('return this.mp[k] (static struct value) byte-identical', async () => {
    await send(encodeCall(sel('setP(address,uint128,uint128)'), [K, 0xcafen, 0xbeefn]));
    await eqGet('getP', 'getP(address)');
  });
  it('return this.md[k] (dynamic struct value) byte-identical, short + long', async () => {
    await send(encodeCall(sel('setDA(address,uint256)'), [K, 99n]));
    await send(strArg('setDS(address,string)', [K], 'hi'));
    await eqGet('getD short', 'getD(address)');
    await send(strArg('setDS(address,string)', [K], LONG));
    await eqGet('getD long', 'getD(address)');
  });
  it('return this.mu[k] (value array) byte-identical', async () => {
    await eqGet('getU empty', 'getU(address)');
    await send(encodeCall(sel('pushU(address,uint256)'), [K, 11n]));
    await send(encodeCall(sel('pushU(address,uint256)'), [K, 22n]));
    await eqGet('getU n=2', 'getU(address)');
  });
  it('return this.ms[k] (string[]) byte-identical incl long', async () => {
    await send(strArg('pushS(address,string)', [K], 'ab'));
    await send(strArg('pushS(address,string)', [K], LONG));
    await eqGet('getS n=2', 'getS(address)');
  });
});
