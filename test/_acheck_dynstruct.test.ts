// AUDIT probe: storage dynamic structs - packing, field-RMW, overwrite-clear, adversarial.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, decodeUint } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const sel = (s: string) => functionSelector(s);
const enc = new TextEncoder();
const s = (str: string) => enc.encode(str);
const slotKeccak = (p: bigint) => BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad(p)) as `0x${string}`))));

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

// JETH source. Struct F packs two u64 BEFORE the bytes; struct G has a u128 packed
// adjacent to a bool, then a string, then another u128 - to stress packing siblings.
const JETH = `
@struct class D { a: u256; s: string; }
@struct class F { p: u64; q: u64; c: bytes; }       // p,q pack slot0; c slot1
@struct class G { a: u128; flag: bool; s: string; b: u128; } // a,flag pack slot0; s slot1; b slot2
@struct class H { s: string; n: u256; }             // s slot0; n slot1 (dyn field FIRST)
@contract
class A {
  @state d: D;            // 0..1
  @state sent: u256;      // 2
  @state f: F;            // 3..4
  @state g: G;            // 5..7
  @state h: H;            // 8..9
  @state m: mapping<u256, D>;  // 10

  @external setDa(v: u256): void { this.d.a = v; }
  @external setDs(v: string): void { this.d.s = v; }
  @external @view getDs(): string { return this.d.s; }
  @external @view getDa(): u256 { return this.d.a; }

  @external setFp(v: u64): void { this.f.p = v; }
  @external setFq(v: u64): void { this.f.q = v; }
  @external setFc(v: bytes): void { this.f.c = v; }
  @external @view getFp(): u64 { return this.f.p; }
  @external @view getFq(): u64 { return this.f.q; }
  @external @view getFc(): bytes { return this.f.c; }

  @external setGa(v: u128): void { this.g.a = v; }
  @external setGflag(v: bool): void { this.g.flag = v; }
  @external setGs(v: string): void { this.g.s = v; }
  @external setGb(v: u128): void { this.g.b = v; }
  @external @view getGa(): u128 { return this.g.a; }
  @external @view getGflag(): bool { return this.g.flag; }
  @external @view getGs(): string { return this.g.s; }
  @external @view getGb(): u128 { return this.g.b; }

  @external setHs(v: string): void { this.h.s = v; }
  @external setHn(v: u256): void { this.h.n = v; }
  @external @view getHs(): string { return this.h.s; }
  @external @view getHn(): u256 { return this.h.n; }

  @external setMa(k: u256, v: u256): void { this.m[k].a = v; }
  @external setMs(k: u256, v: string): void { this.m[k].s = v; }
  @external @view getMs(k: u256): string { return this.m[k].s; }
  @external @view getMa(k: u256): u256 { return this.m[k].a; }

  @external setSent(v: u256): void { this.sent = v; }
  @external @view getSent(): u256 { return this.sent; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract A {
  struct D { uint256 a; string s; }
  struct F { uint64 p; uint64 q; bytes c; }
  struct G { uint128 a; bool flag; string s; uint128 b; }
  struct H { string s; uint256 n; }
  D d;
  uint256 sent;
  F f;
  G g;
  H h;
  mapping(uint256 => D) m;
  function setDa(uint256 v) external { d.a = v; }
  function setDs(string calldata v) external { d.s = v; }
  function getDs() external view returns (string memory){ return d.s; }
  function getDa() external view returns (uint256){ return d.a; }
  function setFp(uint64 v) external { f.p = v; }
  function setFq(uint64 v) external { f.q = v; }
  function setFc(bytes calldata v) external { f.c = v; }
  function getFp() external view returns (uint64){ return f.p; }
  function getFq() external view returns (uint64){ return f.q; }
  function getFc() external view returns (bytes memory){ return f.c; }
  function setGa(uint128 v) external { g.a = v; }
  function setGflag(bool v) external { g.flag = v; }
  function setGs(string calldata v) external { g.s = v; }
  function setGb(uint128 v) external { g.b = v; }
  function getGa() external view returns (uint128){ return g.a; }
  function getGflag() external view returns (bool){ return g.flag; }
  function getGs() external view returns (string memory){ return g.s; }
  function getGb() external view returns (uint128){ return g.b; }
  function setHs(string calldata v) external { h.s = v; }
  function setHn(uint256 v) external { h.n = v; }
  function getHs() external view returns (string memory){ return h.s; }
  function getHn() external view returns (uint256){ return h.n; }
  function setMa(uint256 k, uint256 v) external { m[k].a = v; }
  function setMs(uint256 k, string calldata v) external { m[k].s = v; }
  function getMs(uint256 k) external view returns (string memory){ return m[k].s; }
  function getMa(uint256 k) external view returns (uint256){ return m[k].a; }
  function setSent(uint256 v) external { sent = v; }
  function getSent() external view returns (uint256){ return sent; }
}`;

let jeth: Harness, sol: Harness, aj: Address, as: Address;
beforeAll(async () => {
  const jb = compile(JETH, { fileName: 'A.jeth' });
  const sb = compileSolidity(SOL, 'A');
  jeth = await Harness.create(); sol = await Harness.create();
  aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
});

async function eq(label: string, data: string) {
  const j = await jeth.call(aj, data); const sr = await sol.call(as, data);
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
const EXACT32 = 'Z'.repeat(32);

describe('AUDIT storage dynamic structs', () => {
  it('F{u64 p; u64 q; bytes c}: p,q pack in slot3, c in slot4; RMW preserves sibling', async () => {
    await eq('setFp', encodeCall(sel('setFp(uint64)'), [0xdeadn]));
    await eq('setFq', encodeCall(sel('setFq(uint64)'), [0xbeefn]));
    await eq('setFc long40', callDyn('setFc(bytes)', [], s(LONG40)));
    await eqSlot(3n, 'F slot3 (p|q packed)');
    await eqSlot(4n, 'F.c header slot4');
    await eqSlot(slotKeccak(4n), 'F.c long data w0');
    let r = await eq('getFp', encodeCall(sel('getFp()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0xdeadn);
    r = await eq('getFq', encodeCall(sel('getFq()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0xbeefn);
    await eq('getFc', encodeCall(sel('getFc()'), []));
    // overwrite c long->short: clear old data slot
    await eq('setFc short', callDyn('setFc(bytes)', [], s(SHORT)));
    await eqSlot(4n, 'F.c header after short');
    await eqSlot(slotKeccak(4n), 'F.c old data cleared');
    // p,q must be untouched after all c writes
    await eqSlot(3n, 'F slot3 still packed after c writes');
  });

  it('G{u128 a; bool flag; string s; u128 b}: a,flag pack slot5; s slot6; b slot7', async () => {
    await eq('setGa', encodeCall(sel('setGa(uint128)'), [(1n << 127n) | 0x1234n]));
    await eq('setGflag', encodeCall(sel('setGflag(bool)'), [1n]));
    await eq('setGb', encodeCall(sel('setGb(uint128)'), [(1n << 120n) | 0x99n]));
    await eq('setGs long70', callDyn('setGs(string)', [], s(LONG70)));
    await eqSlot(5n, 'G slot5 (a|flag packed)');
    await eqSlot(6n, 'G.s header slot6');
    await eqSlot(7n, 'G slot7 (b)');
    await eqSlot(slotKeccak(6n), 'G.s long data w0');
    let r = await eq('getGa', encodeCall(sel('getGa()'), []));
    expect(decodeUint(r.j.returnHex)).toBe((1n << 127n) | 0x1234n);
    r = await eq('getGflag', encodeCall(sel('getGflag()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(1n);
    r = await eq('getGb', encodeCall(sel('getGb()'), []));
    expect(decodeUint(r.j.returnHex)).toBe((1n << 120n) | 0x99n);
    await eq('getGs', encodeCall(sel('getGs()'), []));
    // overwrite s long->short, then verify a/flag/b siblings intact
    await eq('setGs short', callDyn('setGs(string)', [], s(SHORT)));
    await eqSlot(5n, 'G slot5 after s overwrite');
    await eqSlot(7n, 'G slot7 after s overwrite');
    await eqSlot(slotKeccak(6n), 'G.s old data cleared');
  });

  it('H{string s; u256 n}: dynamic field FIRST (slot8), n slot9', async () => {
    await eq('setHn', encodeCall(sel('setHn(uint256)'), [0xcafen]));
    await eq('setHs long40', callDyn('setHs(string)', [], s(LONG40)));
    await eqSlot(8n, 'H.s header slot8');
    await eqSlot(9n, 'H.n slot9');
    await eqSlot(slotKeccak(8n), 'H.s long data');
    let r = await eq('getHn', encodeCall(sel('getHn()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0xcafen);
    await eq('getHs', encodeCall(sel('getHs()'), []));
  });

  it('exact-32 string (boundary short/long): must be LONG form', async () => {
    await eq('setDs exact32', callDyn('setDs(string)', [], s(EXACT32)));
    await eqSlot(1n, 'd.s header exact32 (long: 2*32+1=0x41)');
    await eqSlot(slotKeccak(1n), 'd.s exact32 data w0');
    await eq('getDs exact32', encodeCall(sel('getDs()'), []));
    // exact-31 is SHORT (inline)
    await eq('setDs 31', callDyn('setDs(string)', [], s('Y'.repeat(31))));
    await eqSlot(1n, 'd.s header 31 (short inline)');
    await eqSlot(slotKeccak(1n), 'd.s old exact32 data cleared');
    await eq('getDs 31', encodeCall(sel('getDs()'), []));
  });

  it('mapping<u256,D> field writes, raw slots, sentinel intact', async () => {
    const mapSlot = (key: bigint, slot: bigint) =>
      BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad(key) + pad(slot)) as `0x${string}`))));
    await eq('setMa k=5', encodeCall(sel('setMa(uint256,uint256)'), [5n, 0x777n]));
    await eq('setMs k=5 long40', callDyn('setMs(uint256,string)', [5n], s(LONG40)));
    const b = mapSlot(5n, 10n);
    await eqSlot(b + 0n, 'm[5].a');
    await eqSlot(b + 1n, 'm[5].s header');
    await eqSlot(slotKeccak(b + 1n), 'm[5].s long data');
    let r = await eq('getMa', encodeCall(sel('getMa(uint256)'), [5n]));
    expect(decodeUint(r.j.returnHex)).toBe(0x777n);
    await eq('getMs', encodeCall(sel('getMs(uint256)'), [5n]));
    await eq('setSent', encodeCall(sel('setSent(uint256)'), [0xdeadn]));
    await eqSlot(2n, 'sentinel intact');
  });
});
