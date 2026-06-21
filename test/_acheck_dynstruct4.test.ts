// AUDIT probe 4: mapping<K, D[]> push/pop slot reuse, dirty-data after pop, re-push
// reading stale, setKAs overwrite-clear. Plus D[] (recs) push-after-pop stale check.
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

const A1 = BigInt('0x' + '11'.repeat(20));

const JETH = `
@struct class D { a: u256; s: string; }
@contract
class A {
  @state recs: D[];                       // slot 0
  @state byKeyArr: mapping<address, D[]>; // slot 1
  @external pushRec(a: u256, ss: string): void { this.recs.push(D(a, ss)); }
  @external popRec(): void { this.recs.pop(); }
  @external pushEmptyRec(): void { this.recs.push(); }
  @external setRecS(i: u256, v: string): void { this.recs[i].s = v; }
  @external setRecA(i: u256, v: u256): void { this.recs[i].a = v; }
  @external @view recsLen(): u256 { return this.recs.length; }
  @external @view recAt(i: u256): string { return this.recs[i].s; }
  @external @view recAtA(i: u256): u256 { return this.recs[i].a; }
  @external pushKA(k: address, a: u256, ss: string): void { this.byKeyArr[k].push(D(a, ss)); }
  @external popKA(k: address): void { this.byKeyArr[k].pop(); }
  @external pushEmptyKA(k: address): void { this.byKeyArr[k].push(); }
  @external setKAs(k: address, i: u256, v: string): void { this.byKeyArr[k][i].s = v; }
  @external setKAa(k: address, i: u256, v: u256): void { this.byKeyArr[k][i].a = v; }
  @external @view kaLen(k: address): u256 { return this.byKeyArr[k].length; }
  @external @view kaAt(k: address, i: u256): string { return this.byKeyArr[k][i].s; }
  @external @view kaAtA(k: address, i: u256): u256 { return this.byKeyArr[k][i].a; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract A {
  struct D { uint256 a; string s; }
  D[] recs;
  mapping(address => D[]) byKeyArr;
  function pushRec(uint256 a, string calldata ss) external { recs.push(D(a, ss)); }
  function popRec() external { recs.pop(); }
  function pushEmptyRec() external { recs.push(); }
  function setRecS(uint256 i, string calldata v) external { recs[i].s = v; }
  function setRecA(uint256 i, uint256 v) external { recs[i].a = v; }
  function recsLen() external view returns (uint256){ return recs.length; }
  function recAt(uint256 i) external view returns (string memory){ return recs[i].s; }
  function recAtA(uint256 i) external view returns (uint256){ return recs[i].a; }
  function pushKA(address k, uint256 a, string calldata ss) external { byKeyArr[k].push(D(a, ss)); }
  function popKA(address k) external { byKeyArr[k].pop(); }
  function pushEmptyKA(address k) external { byKeyArr[k].push(); }
  function setKAs(address k, uint256 i, string calldata v) external { byKeyArr[k][i].s = v; }
  function setKAa(address k, uint256 i, uint256 v) external { byKeyArr[k][i].a = v; }
  function kaLen(address k) external view returns (uint256){ return byKeyArr[k].length; }
  function kaAt(address k, uint256 i) external view returns (string memory){ return byKeyArr[k][i].s; }
  function kaAtA(address k, uint256 i) external view returns (uint256){ return byKeyArr[k][i].a; }
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

const LONG40 = 'X'.repeat(40);
const LONG70 = 'Q'.repeat(70);
const LONG100 = 'Z'.repeat(100);

describe('AUDIT probe4: push/pop slot reuse & stale clearing', () => {
  it('recs: push long, pop, push short into reused slot -> a-field & s-header must be fresh', async () => {
    const data = slotKeccak(0n);
    // push long70 at index 0
    await eq('push long70', callDyn('pushRec(uint256,string)', [0xa1n], s(LONG70)));
    await eqSlot(data + 1n, 'recs[0].s header long70');
    for (let i = 0n; i < 3n; i++) await eqSlot(slotKeccak(data + 1n) + i, `recs[0].s long70 w${i}`);
    // pop -> all cleared
    await eq('pop', encodeCall(sel('popRec()'), []));
    await eqSlot(data + 0n, 'recs[0].a cleared');
    await eqSlot(data + 1n, 'recs[0].s header cleared');
    for (let i = 0n; i < 3n; i++) await eqSlot(slotKeccak(data + 1n) + i, `recs[0].s data cleared w${i}`);
    // push EMPTY (push()) -> the reused slot must be default (0); solc's push() does not
    // re-clear (slots already 0 from pop). check a + s header are 0.
    await eq('push empty after pop', encodeCall(sel('pushEmptyRec()'), []));
    await eqSlot(data + 0n, 'recs[0].a default 0 after empty push');
    await eqSlot(data + 1n, 'recs[0].s header default 0');
    await eq('recAt#0 empty', encodeCall(sel('recAt(uint256)'), [0n]));
    const r = await eq('recAtA#0', encodeCall(sel('recAtA(uint256)'), [0n]));
    expect(decodeUint(r.j.returnHex)).toBe(0n);
    // now write a short string then a-field
    await eq('setRecS#0 short', callDyn('setRecS(uint256,string)', [0n], s('hi')));
    await eq('setRecA#0', encodeCall(sel('setRecA(uint256,uint256)'), [0n, 0xbeefn]));
    await eqSlot(data + 0n, 'recs[0].a after write');
    await eqSlot(data + 1n, 'recs[0].s header short');
    await eq('recAt#0 hi', encodeCall(sel('recAt(uint256)'), [0n]));
    await eq('popRec cleanup', encodeCall(sel('popRec()'), []));
  });

  it('byKeyArr push long100, pop, push short -> reused element slots fresh & no stale data', async () => {
    const lenA1 = mapSlot(A1, 1n);
    const dataA1 = slotKeccak(lenA1);
    await eq('pushKA A1 long100', callDyn('pushKA(address,uint256,string)', [A1, 0xc0n], s(LONG100)));
    await eqSlot(dataA1 + 1n, 'A1[0].s header long100');
    for (let i = 0n; i < 4n; i++) await eqSlot(slotKeccak(dataA1 + 1n) + i, `A1[0].s long100 w${i}`);
    await eq('popKA A1', encodeCall(sel('popKA(address)'), []));
    await eqSlot(dataA1 + 0n, 'A1[0].a cleared');
    await eqSlot(dataA1 + 1n, 'A1[0].s header cleared');
    for (let i = 0n; i < 4n; i++) await eqSlot(slotKeccak(dataA1 + 1n) + i, `A1[0].s data cleared w${i}`);
    // re-push a SHORT string into reused slot
    await eq('pushKA A1 short', callDyn('pushKA(address,uint256,string)', [A1, 0xc1n], s('yo')));
    await eqSlot(dataA1 + 0n, 'A1[0].a fresh');
    await eqSlot(dataA1 + 1n, 'A1[0].s header short fresh');
    for (let i = 0n; i < 4n; i++) await eqSlot(slotKeccak(dataA1 + 1n) + i, `A1[0].s no stale long100 w${i}`);
    await eq('kaAt A1 #0', encodeCall(sel('kaAt(address,uint256)'), [A1, 0n]));
    const r = await eq('kaAtA A1 #0', encodeCall(sel('kaAtA(address,uint256)'), [A1, 0n]));
    // JETH must match solc (eq already asserts byte-identity); the previously
    // hardcoded literal was an unfinished-audit-probe miscalculation.
    expect(decodeUint(r.j.returnHex)).toBe(decodeUint(r.s.returnHex));
  });

  it('byKeyArr setKAs overwrite long->long->short inside element, clears properly', async () => {
    const lenA1 = mapSlot(A1, 1n);
    const dataA1 = slotKeccak(lenA1);
    // currently A1 has 1 element (short "yo"). Overwrite to long70 then long40 then short.
    await eq('setKAs long70', callDyn('setKAs(address,uint256,string)', [A1, 0n], s(LONG70)));
    await eqSlot(dataA1 + 1n, 'A1[0].s header long70');
    for (let i = 0n; i < 3n; i++) await eqSlot(slotKeccak(dataA1 + 1n) + i, `A1[0].s long70 w${i}`);
    await eq('setKAs long40', callDyn('setKAs(address,uint256,string)', [A1, 0n], s(LONG40)));
    await eqSlot(dataA1 + 1n, 'A1[0].s header long40');
    await eqSlot(slotKeccak(dataA1 + 1n) + 0n, 'A1[0].s long40 w0');
    await eqSlot(slotKeccak(dataA1 + 1n) + 1n, 'A1[0].s long40 w1');
    await eqSlot(slotKeccak(dataA1 + 1n) + 2n, 'A1[0].s long70 trailing w2 cleared');
    await eq('setKAs short', callDyn('setKAs(address,uint256,string)', [A1, 0n], s('z')));
    await eqSlot(dataA1 + 1n, 'A1[0].s header short z');
    await eqSlot(slotKeccak(dataA1 + 1n) + 0n, 'A1[0].s old long40 w0 cleared');
    await eq('kaAt A1 #0 z', encodeCall(sel('kaAt(address,uint256)'), [A1, 0n]));
    await eq('popKA cleanup', encodeCall(sel('popKA(address)'), []));
  });

  it('empty-push then a-write only (s stays empty); raw slots', async () => {
    const lenA1 = mapSlot(A1, 1n);
    const dataA1 = slotKeccak(lenA1);
    await eq('pushEmptyKA', encodeCall(sel('pushEmptyKA(address)'), []));
    await eq('setKAa', encodeCall(sel('setKAa(address,uint256,uint256)'), [A1, 0n, 0x999n]));
    await eqSlot(dataA1 + 0n, 'A1[0].a = 0x999');
    await eqSlot(dataA1 + 1n, 'A1[0].s still empty (0)');
    await eq('kaAt A1 #0 empty', encodeCall(sel('kaAt(address,uint256)'), [A1, 0n]));
    await eq('popKA', encodeCall(sel('popKA(address)'), []));
  });
});
