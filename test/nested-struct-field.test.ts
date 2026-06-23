// A1: whole nested-struct FIELD read/write/copy: this.o.inner = D(...) / return this.o.inner
// / this.o.inner = this.x, and the multi-level form this.recs[i].inner = D(...) /
// return this.recs[i].inner. Static + dynamic inner struct. Byte-identical to Solidity.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
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

const JETH = `@struct class P { x: u128; y: u128; }
@struct class D { a: u256; s: string; }
@struct class O { p: u256; inner: D; q: u256; }
@struct class S { p: u256; pt: P; q: u256; }
@contract class NF {
  @state o: O;
  @state s2: S;
  @state d2: D;
  @state recs: O[];
  @external setO(p: u256, a: u256, str: string, q: u256): void { this.o.p = p; this.o.inner = D(a, str); this.o.q = q; }
  @external setInner(a: u256, str: string): void { this.o.inner = D(a, str); }
  @external setS(p: u256, x: u128, y: u128, q: u256): void { this.s2.p = p; this.s2.pt = P(x, y); this.s2.q = q; }
  @external setD2(a: u256, str: string): void { this.d2 = D(a, str); }
  @external copyInnerFromD2(): void { this.o.inner = this.d2; }
  @external copyD2FromInner(): void { this.d2 = this.o.inner; }
  @external pushO(p: u256, a: u256, str: string, q: u256): void { this.recs.push(O(p, D(a, str), q)); }
  @external setRecInner(i: u256, a: u256, str: string): void { this.recs[i].inner = D(a, str); }
  @external @view getInner(): D { return this.o.inner; }
  @external @view getPt(): P { return this.s2.pt; }
  @external @view getO(): O { return this.o; }
  @external @view getRecInner(i: u256): D { return this.recs[i].inner; }
  @external @view getOp(): u256 { return this.o.p; }
  @external @view getOq(): u256 { return this.o.q; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract NF {
  struct P { uint128 x; uint128 y; }
  struct D { uint256 a; string s; }
  struct O { uint256 p; D inner; uint256 q; }
  struct S { uint256 p; P pt; uint256 q; }
  O o; S s2; D d2; O[] recs;
  function setO(uint256 p, uint256 a, string calldata str, uint256 q) external { o.p = p; o.inner = D(a, str); o.q = q; }
  function setInner(uint256 a, string calldata str) external { o.inner = D(a, str); }
  function setS(uint256 p, uint128 x, uint128 y, uint256 q) external { s2.p = p; s2.pt = P(x, y); s2.q = q; }
  function setD2(uint256 a, string calldata str) external { d2 = D(a, str); }
  function copyInnerFromD2() external { o.inner = d2; }
  function copyD2FromInner() external { d2 = o.inner; }
  function pushO(uint256 p, uint256 a, string calldata str, uint256 q) external { recs.push(O(p, D(a, str), q)); }
  function setRecInner(uint256 i, uint256 a, string calldata str) external { recs[i].inner = D(a, str); }
  function getInner() external view returns (D memory){ return o.inner; }
  function getPt() external view returns (P memory){ return s2.pt; }
  function getO() external view returns (O memory){ return o; }
  function getRecInner(uint256 i) external view returns (D memory){ return recs[i].inner; }
  function getOp() external view returns (uint256){ return o.p; }
  function getOq() external view returns (uint256){ return o.q; }
}`;

const LONG = 'a definitely-longer-than-thirty-two-byte string for the nested inner field';

describe('whole nested-struct field read/write/copy vs Solidity', () => {
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
    const jb = compile(JETH, { fileName: 'NF.jeth' });
    const sb = compileSolidity(SOL, 'NF');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('this.o.inner = D(...) (short+long), siblings preserved, whole-O return', async () => {
    // setO(p, a, str, q)
    const setO = (p: bigint, a: bigint, str: string, q: bigint) => {
      const b = Buffer.from(str, 'utf8');
      const nwords = Math.ceil(b.length / 32);
      let data = '';
      for (let i = 0; i < nwords; i++)
        data += Buffer.concat([b.subarray(i * 32, i * 32 + 32), Buffer.alloc(32)])
          .subarray(0, 32)
          .toString('hex');
      // head: p, a, offset(str), q  -> 4 words; str offset = 4*32 = 0x80
      let h = '0x' + sel('setO(uint256,uint256,string,uint256)');
      h += pad(p) + pad(a) + pad(0x80n) + pad(q) + pad(BigInt(b.length)) + data;
      return h;
    };
    await send(setO(11n, 22n, 'hi', 33n));
    await eq('getInner short', encodeCall(sel('getInner()'), []));
    await eq('getO short', encodeCall(sel('getO()'), []));
    await eq('getOp', encodeCall(sel('getOp()'), []));
    await eq('getOq', encodeCall(sel('getOq()'), []));
    await send(setO(11n, 22n, LONG, 33n));
    await eq('getInner long', encodeCall(sel('getInner()'), []));
    await eq('getO long', encodeCall(sel('getO()'), []));
    // overwrite long->short via setInner, siblings must remain 11/33
    await send(strSet('setInner(uint256,string)', [99n], 'x'));
    await eq('getInner shrink', encodeCall(sel('getInner()'), []));
    await eq('getOp preserved', encodeCall(sel('getOp()'), []));
    await eq('getOq preserved', encodeCall(sel('getOq()'), []));
  });

  it('static inner field this.s2.pt = P(x,y), read back', async () => {
    await send(encodeCall(sel('setS(uint256,uint128,uint128,uint256)'), [5n, 0xcafen, 0xbeefn, 6n]));
    await eq('getPt', encodeCall(sel('getPt()'), []));
  });

  it('copy nested field both directions: o.inner <-> d2', async () => {
    await send(strSet('setD2(uint256,string)', [77n], LONG));
    await send(encodeCall(sel('copyInnerFromD2()'), []));
    await eq('getInner after copy from d2', encodeCall(sel('getInner()'), []));
    await send(strSet('setInner(uint256,string)', [88n], 'short'));
    await send(encodeCall(sel('copyD2FromInner()'), []));
    await eq('getInner unchanged', encodeCall(sel('getInner()'), []));
  });

  it('multi-level this.recs[i].inner = D(...) / return this.recs[i].inner', async () => {
    const pushO = (p: bigint, a: bigint, str: string, q: bigint) => {
      const b = Buffer.from(str, 'utf8');
      const nwords = Math.ceil(b.length / 32);
      let data = '';
      for (let i = 0; i < nwords; i++)
        data += Buffer.concat([b.subarray(i * 32, i * 32 + 32), Buffer.alloc(32)])
          .subarray(0, 32)
          .toString('hex');
      let h = '0x' + sel('pushO(uint256,uint256,string,uint256)');
      h += pad(p) + pad(a) + pad(0x80n) + pad(q) + pad(BigInt(b.length)) + data;
      return h;
    };
    await send(pushO(1n, 2n, 'aa', 3n));
    await send(strSet('setRecInner(uint256,uint256,string)', [0n, 55n], LONG));
    await eq('getRecInner', encodeCall(sel('getRecInner(uint256)'), [0n]));
  });
});
