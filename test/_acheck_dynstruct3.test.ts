// AUDIT probe 3: nested mapping to dyn struct; struct with TWO dynamic fields (nested
// dyn struct + a string). Raw slots vs solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const sel = (x: string) => functionSelector(x);
const enc = new TextEncoder();
const s = (str: string) => enc.encode(str);
const slotKeccak = (p: bigint) => BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad(p)) as `0x${string}`))));
const mapSlot = (key: bigint, slot: bigint) =>
  BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad(key) + pad(slot)) as `0x${string}`))));

function payload(bytes: Uint8Array): string {
  const words = Math.ceil(bytes.length / 32);
  let data = '';
  for (let i = 0; i < words * 32; i++) data += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  return data;
}
function callDyn(selSig: string, staticHead: bigint[], bytes: Uint8Array): string {
  const headWords = staticHead.length + 1;
  let h = '0x' + sel(selSig);
  for (const w of staticHead) h += pad(w);
  h += pad(BigInt(headWords * 32));
  h += pad(BigInt(bytes.length)) + payload(bytes);
  return h;
}

const JETH = `
@struct class D { a: u256; s: string; }
@struct class W { x: u256; inner: D; t: string; }
@contract
class A {
  @state mm: mapping<u256, mapping<u256, D>>;  // slot 0
  @state w: W;                                  // slot 1..4: x@1, inner.a@2, inner.s@3, t@4
  @external setMA(k1: u256, k2: u256, v: u256): void { this.mm[k1][k2].a = v; }
  @external setMS(k1: u256, k2: u256, v: string): void { this.mm[k1][k2].s = v; }
  @external @view getMA(k1: u256, k2: u256): u256 { return this.mm[k1][k2].a; }
  @external @view getMS(k1: u256, k2: u256): string { return this.mm[k1][k2].s; }
  @external setWx(v: u256): void { this.w.x = v; }
  @external setWInnerA(v: u256): void { this.w.inner.a = v; }
  @external setWInnerS(v: string): void { this.w.inner.s = v; }
  @external setWt(v: string): void { this.w.t = v; }
  @external @view getWx(): u256 { return this.w.x; }
  @external @view getWInnerA(): u256 { return this.w.inner.a; }
  @external @view getWInnerS(): string { return this.w.inner.s; }
  @external @view getWt(): string { return this.w.t; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract A {
  struct D { uint256 a; string s; }
  struct W { uint256 x; D inner; string t; }
  mapping(uint256 => mapping(uint256 => D)) mm;
  W w;
  function setMA(uint256 k1, uint256 k2, uint256 v) external { mm[k1][k2].a = v; }
  function setMS(uint256 k1, uint256 k2, string calldata v) external { mm[k1][k2].s = v; }
  function getMA(uint256 k1, uint256 k2) external view returns (uint256){ return mm[k1][k2].a; }
  function getMS(uint256 k1, uint256 k2) external view returns (string memory){ return mm[k1][k2].s; }
  function setWx(uint256 v) external { w.x = v; }
  function setWInnerA(uint256 v) external { w.inner.a = v; }
  function setWInnerS(string calldata v) external { w.inner.s = v; }
  function setWt(string calldata v) external { w.t = v; }
  function getWx() external view returns (uint256){ return w.x; }
  function getWInnerA() external view returns (uint256){ return w.inner.a; }
  function getWInnerS() external view returns (string memory){ return w.inner.s; }
  function getWt() external view returns (string memory){ return w.t; }
}`;

let jeth: Harness, sol: Harness, aj: Address, as: Address;
beforeAll(async () => {
  const jb = compile(JETH, { fileName: 'A.jeth' });
  const sb = compileSolidity(SOL, 'A');
  jeth = await Harness.create();
  sol = await Harness.create();
  aj = await jeth.deploy(jb.creationBytecode);
  as = await sol.deploy(sb.creation);
});

async function eq(label: string, data: string) {
  const j = await jeth.call(aj, data);
  const sr = await sol.call(as, data);
  expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(sr.success);
  expect(j.returnHex, `${label} returndata`).toBe(sr.returnHex);
  return { j, s: sr };
}
async function eqSlot(slot: bigint, label: string) {
  expect(await readSlot(jeth, aj, slot), label).toBe(await readSlot(sol, as, slot));
}

const SHORT = 'ab';
const LONG40 = 'X'.repeat(40);
const LONG70 = 'Q'.repeat(70);

describe('AUDIT probe3: nested mapping + two-dynamic-field struct', () => {
  it('mapping<u256,mapping<u256,D>>: deep key, raw slots, isolation', async () => {
    await eq('setMA 1,2', encodeCall(sel('setMA(uint256,uint256,uint256)'), [1n, 2n, 0xaan]));
    await eq('setMS 1,2 long', callDyn('setMS(uint256,uint256,string)', [1n, 2n], s(LONG40)));
    await eq('setMA 3,4', encodeCall(sel('setMA(uint256,uint256,uint256)'), [3n, 4n, 0xbbn]));
    await eq('setMS 3,4 short', callDyn('setMS(uint256,uint256,string)', [3n, 4n], s(SHORT)));
    // slot for mm[k1][k2]: keccak(k2 . keccak(k1 . 0))
    const inner12 = mapSlot(2n, mapSlot(1n, 0n));
    const inner34 = mapSlot(4n, mapSlot(3n, 0n));
    await eqSlot(inner12 + 0n, 'mm[1][2].a');
    await eqSlot(inner12 + 1n, 'mm[1][2].s header (long)');
    await eqSlot(slotKeccak(inner12 + 1n), 'mm[1][2].s long data');
    await eqSlot(inner34 + 0n, 'mm[3][4].a');
    await eqSlot(inner34 + 1n, 'mm[3][4].s header (short)');
    let r = await eq('getMA 1,2', encodeCall(sel('getMA(uint256,uint256)'), [1n, 2n]));
    expect(decodeUint(r.j.returnHex)).toBe(0xaan);
    await eq('getMS 1,2', encodeCall(sel('getMS(uint256,uint256)'), [1n, 2n]));
    await eq('getMS 3,4', encodeCall(sel('getMS(uint256,uint256)'), [3n, 4n]));
    // overwrite mm[1][2].s long->short: clear old data
    await eq('setMS 1,2 short', callDyn('setMS(uint256,uint256,string)', [1n, 2n], s(SHORT)));
    await eqSlot(inner12 + 1n, 'mm[1][2].s header after short');
    await eqSlot(slotKeccak(inner12 + 1n), 'mm[1][2].s old data cleared');
  });

  it('W{x; D inner; t}: layout x@1 inner.a@2 inner.s@3 t@4, two dyn fields independent', async () => {
    await eq('setWx', encodeCall(sel('setWx(uint256)'), [0x1111n]));
    await eq('setWInnerA', encodeCall(sel('setWInnerA(uint256)'), [0x2222n]));
    await eq('setWInnerS long', callDyn('setWInnerS(string)', [], s(LONG40)));
    await eq('setWt long', callDyn('setWt(string)', [], s(LONG70)));
    await eqSlot(1n, 'W.x slot1');
    await eqSlot(2n, 'W.inner.a slot2');
    await eqSlot(3n, 'W.inner.s header slot3');
    await eqSlot(4n, 'W.t header slot4');
    await eqSlot(slotKeccak(3n), 'W.inner.s data');
    for (let i = 0n; i < 3n; i++) await eqSlot(slotKeccak(4n) + i, `W.t data w${i}`);
    let r = await eq('getWx', encodeCall(sel('getWx()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0x1111n);
    r = await eq('getWInnerA', encodeCall(sel('getWInnerA()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0x2222n);
    await eq('getWInnerS', encodeCall(sel('getWInnerS()'), []));
    await eq('getWt', encodeCall(sel('getWt()'), []));
    // overwrite inner.s short, then t short: each must clear ONLY its own data slots
    await eq('setWInnerS short', callDyn('setWInnerS(string)', [], s(SHORT)));
    await eqSlot(3n, 'W.inner.s header short');
    await eqSlot(slotKeccak(3n), 'W.inner.s old data cleared');
    await eqSlot(4n, 'W.t header UNCHANGED (still long)');
    for (let i = 0n; i < 3n; i++) await eqSlot(slotKeccak(4n) + i, `W.t data w${i} unchanged`);
    await eq('getWt still long', encodeCall(sel('getWt()'), []));
    // sibling statics intact
    await eqSlot(1n, 'W.x intact');
    await eqSlot(2n, 'W.inner.a intact');
  });
});
