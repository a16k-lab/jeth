// Whole-struct array element: read (return this.recs[i]), write (this.recs[i] = D(...)),
// and element-to-element copy (this.recs[i] = this.recs[j]) for static + dynamic struct
// arrays (dynamic D[], fixed Arr<P,N>, mapping-valued mapping<K,D[]>). Byte-identical to
// Solidity incl. short/long-string transitions and OOB Panic(0x32).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const K = BigInt('0x' + 'ab'.repeat(20));
function strSet(sel: string, head: bigint[], s: string): string {
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
class SA {
  recs: D[];
  fa: Arr<P, 3>;
  md: mapping<address, D[]>;
  pushD(a: u256, s: string): External<void> { this.recs.push(D(a, s)); }
  setD(i: u256, a: u256, s: string): External<void> { this.recs[i] = D(a, s); }
  copyD(i: u256, j: u256): External<void> { this.recs[i] = this.recs[j]; }
  setFA(i: u256, x: u128, y: u128): External<void> { this.fa[i] = P(x, y); }
  pushMD(k: address, a: u256, s: string): External<void> { this.md[k].push(D(a, s)); }
  setMD(k: address, i: u256, a: u256, s: string): External<void> { this.md[k][i] = D(a, s); }
  get getD(i: u256): External<D> { return this.recs[i]; }
  get getFA(i: u256): External<P> { return this.fa[i]; }
  get getMD(k: address, i: u256): External<D> { return this.md[k][i]; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract SA {
  struct P { uint128 x; uint128 y; }
  struct D { uint256 a; string s; }
  D[] recs;
  P[3] fa;
  mapping(address => D[]) md;
  function pushD(uint256 a, string calldata s) external { recs.push(D(a, s)); }
  function setD(uint256 i, uint256 a, string calldata s) external { recs[i] = D(a, s); }
  function copyD(uint256 i, uint256 j) external { recs[i] = recs[j]; }
  function setFA(uint256 i, uint128 x, uint128 y) external { fa[i] = P(x, y); }
  function pushMD(address k, uint256 a, string calldata s) external { md[k].push(D(a, s)); }
  function setMD(address k, uint256 i, uint256 a, string calldata s) external { md[k][i] = D(a, s); }
  function getD(uint256 i) external view returns (D memory){ return recs[i]; }
  function getFA(uint256 i) external view returns (P memory){ return fa[i]; }
  function getMD(address k, uint256 i) external view returns (D memory){ return md[k][i]; }
}`;

const LONG = 'a definitely-longer-than-thirty-two-byte string for the long storage element path';

describe('whole-struct array element read/write/copy vs Solidity', () => {
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
    const jb = compile(JETH, { fileName: 'SA.jeth' });
    const sb = compileSolidity(SOL, 'SA');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('dynamic struct array: push, then read whole element (short + long)', async () => {
    await send(strSet('pushD(uint256,string)', [1n], 'hi'));
    await send(strSet('pushD(uint256,string)', [2n], LONG));
    await eq('getD[0]', encodeCall(sel('getD(uint256)'), [0n]));
    await eq('getD[1]', encodeCall(sel('getD(uint256)'), [1n]));
  });

  it('whole-element write this.recs[i] = D(...) overwrites (long->short clears tail)', async () => {
    await send(strSet('setD(uint256,uint256,string)', [0n, 42n], LONG));
    await eq('getD[0] after set long', encodeCall(sel('getD(uint256)'), [0n]));
    await send(strSet('setD(uint256,uint256,string)', [0n, 7n], 'x'));
    await eq('getD[0] after set short', encodeCall(sel('getD(uint256)'), [0n]));
  });

  it('element-to-element copy this.recs[i] = this.recs[j]', async () => {
    await send(strSet('setD(uint256,uint256,string)', [1n, 99n], LONG));
    await send(encodeCall(sel('copyD(uint256,uint256)'), [0n, 1n]));
    await eq('getD[0] after copy', encodeCall(sel('getD(uint256)'), [0n]));
  });

  it('OOB whole-element write/read revert identically (Panic 0x32)', async () => {
    await eq('getD OOB', encodeCall(sel('getD(uint256)'), [9n]));
    {
      const data = strSet('setD(uint256,uint256,string)', [9n, 1n], 'z');
      const j = await jeth.call(aj, data);
      const s = await sol.call(as, data);
      expect(j.success, 'setD OOB success parity').toBe(s.success);
    }
  });

  it('fixed array of static struct: this.fa[i] = P(x,y), read back', async () => {
    await send(encodeCall(sel('setFA(uint256,uint128,uint128)'), [1n, 0xcafen, 0xbeefn]));
    await eq('getFA[1]', encodeCall(sel('getFA(uint256)'), [1n]));
    await eq('getFA[0] default', encodeCall(sel('getFA(uint256)'), [0n]));
  });

  it('mapping-valued struct array element write/read', async () => {
    await send(strSet('pushMD(address,uint256,string)', [K, 1n], 'p'));
    await send(strSet('setMD(address,uint256,uint256,string)', [K, 0n, 5n], LONG));
    await eq('getMD', encodeCall(sel('getMD(address,uint256)'), [K, 0n]));
  });
});
