// Whole-struct assignment into a mapping value (audit gap): this.m[k] = Struct(...)
// for a static struct and a dynamic struct, plus the storage-to-storage copy form
// this.m[a] = this.m[b] and this.m[k] = this.d. Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const A = BigInt('0x' + '11'.repeat(20));
const B = BigInt('0x' + '22'.repeat(20));
function strSet(sel: string, head: bigint[], s: string): string {
  const b = Buffer.from(s, 'utf8');
  const nwords = Math.ceil(b.length / 32);
  let data = '';
  for (let i = 0; i < nwords; i++) data += Buffer.concat([b.subarray(i * 32, i * 32 + 32), Buffer.alloc(32)]).subarray(0, 32).toString('hex');
  let h = '0x' + functionSelector(sel);
  for (const w of head) h += pad(w);
  h += pad(BigInt((head.length + 1) * 32)) + pad(BigInt(b.length)) + data;
  return h;
}

const JETH = `@struct class P { x: u128; y: u128; }
@struct class D { a: u256; s: string; }
@contract class MS {
  @state mp: mapping<address, P>;
  @state md: mapping<address, D>;
  @state dd: D;
  @external setP(k: address, x: u128, y: u128): void { this.mp[k] = P(x, y); }
  @external setD(k: address, a: u256, s: string): void { this.md[k] = D(a, s); }
  @external copyP(a: address, b: address): void { this.mp[a] = this.mp[b]; }
  @external copyD(a: address, b: address): void { this.md[a] = this.md[b]; }
  @external setDD(a: u256, s: string): void { this.dd = D(a, s); }
  @external fromState(k: address): void { this.md[k] = this.dd; }
  @external @view getP(k: address): P { return this.mp[k]; }
  @external @view getD(k: address): D { return this.md[k]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract MS {
  struct P { uint128 x; uint128 y; }
  struct D { uint256 a; string s; }
  mapping(address => P) mp;
  mapping(address => D) md;
  D dd;
  function setP(address k, uint128 x, uint128 y) external { mp[k] = P(x, y); }
  function setD(address k, uint256 a, string calldata s) external { md[k] = D(a, s); }
  function copyP(address a, address b) external { mp[a] = mp[b]; }
  function copyD(address a, address b) external { md[a] = md[b]; }
  function setDD(uint256 a, string calldata s) external { dd = D(a, s); }
  function fromState(address k) external { md[k] = dd; }
  function getP(address k) external view returns (P memory){ return mp[k]; }
  function getD(address k) external view returns (D memory){ return md[k]; }
}`;

const LONG = 'a definitely-longer-than-thirty-two-byte string for the long storage path copy';

describe('whole-struct assignment into a mapping value vs Solidity', () => {
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
    const jb = compile(JETH, { fileName: 'MS.jeth' });
    const sb = compileSolidity(SOL, 'MS');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('static struct literal: this.mp[k] = P(x,y)', async () => {
    await send(encodeCall(sel('setP(address,uint128,uint128)'), [A, 0xcafen, 0xbeefn]));
    await eq('getP', encodeCall(sel('getP(address)'), [A]));
  });

  it('dynamic struct literal: this.md[k] = D(a,s) short + long', async () => {
    await send(strSet('setD(address,uint256,string)', [A], 'hi'));
    await eq('getD short', encodeCall(sel('getD(address)'), [A]));
    await send(strSet('setD(address,uint256,string)', [A], LONG));
    await eq('getD long', encodeCall(sel('getD(address)'), [A]));
  });

  it('static struct copy: this.mp[a] = this.mp[b]', async () => {
    await send(encodeCall(sel('setP(address,uint128,uint128)'), [B, 7n, 9n]));
    await send(encodeCall(sel('copyP(address,address)'), [A, B]));
    await eq('getP after copy', encodeCall(sel('getP(address)'), [A]));
  });

  it('dynamic struct copy (long): this.md[a] = this.md[b] re-stores long data slots', async () => {
    await send(strSet('setD(address,uint256,string)', [B], LONG));
    await send(encodeCall(sel('copyD(address,address)'), [A, B]));
    await eq('getD after copy', encodeCall(sel('getD(address)'), [A]));
  });

  it('overwrite long mapping struct with short clears tail (copy path)', async () => {
    await send(strSet('setD(address,uint256,string)', [A], LONG));
    await send(strSet('setD(address,uint256,string)', [B], 'x'));
    await send(encodeCall(sel('copyD(address,address)'), [A, B]));
    await eq('getD after shrink-copy', encodeCall(sel('getD(address)'), [A]));
  });

  it('copy from a state struct: this.md[k] = this.dd', async () => {
    await send(strSet('setDD(uint256,string)', [], LONG));
    await send(encodeCall(sel('fromState(address)'), [A]));
    await eq('getD from state', encodeCall(sel('getD(address)'), [A]));
  });
});
