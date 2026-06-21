// AUDIT probe 2: long->long shrink clearing, whole-struct-assign clears, raw inline word.
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

const JETH = `
@struct class D { a: u256; s: string; }
@contract
class A {
  @state d: D;            // 0..1
  @external setDa(v: u256): void { this.d.a = v; }
  @external setDs(v: string): void { this.d.s = v; }
  @external setD(a: u256, ss: string): void { this.d = D(a, ss); }
  @external @view getDs(): string { return this.d.s; }
  @external @view getDa(): u256 { return this.d.a; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract A {
  struct D { uint256 a; string s; }
  D d;
  function setDa(uint256 v) external { d.a = v; }
  function setDs(string calldata v) external { d.s = v; }
  function setD(uint256 a, string calldata ss) external { d = D(a, ss); }
  function getDs() external view returns (string memory){ return d.s; }
  function getDa() external view returns (uint256){ return d.a; }
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

describe('AUDIT probe2: shrink clearing & whole-assign', () => {
  it('long->long shrink: trailing data words cleared (100 bytes -> 40 bytes)', async () => {
    const LONG100 = 'A'.repeat(100); // 4 words
    const LONG40 = 'B'.repeat(40);   // 2 words
    await eq('setDs 100', callDyn('setDs(string)', [], s(LONG100)));
    await eqSlot(1n, 'd.s header 100');
    for (let i = 0n; i < 4n; i++) await eqSlot(slotKeccak(1n) + i, `d.s 100 data w${i}`);
    await eq('setDs 40', callDyn('setDs(string)', [], s(LONG40)));
    await eqSlot(1n, 'd.s header 40 after shrink');
    await eqSlot(slotKeccak(1n) + 0n, 'd.s 40 data w0');
    await eqSlot(slotKeccak(1n) + 1n, 'd.s 40 data w1');
    await eqSlot(slotKeccak(1n) + 2n, 'd.s trailing w2 cleared');
    await eqSlot(slotKeccak(1n) + 3n, 'd.s trailing w3 cleared');
    await eq('getDs after shrink', encodeCall(sel('getDs()'), []));
  });

  it('whole struct assign D(a, long) then D(a, "") clears tail', async () => {
    const LONG70 = 'C'.repeat(70); // 3 words
    await eq('setD long70', callDyn('setD(uint256,string)', [0x11n], s(LONG70)));
    await eqSlot(1n, 'd.s header long70');
    for (let i = 0n; i < 3n; i++) await eqSlot(slotKeccak(1n) + i, `d.s long70 w${i}`);
    // whole-assign empty string
    await eq('setD empty', callDyn('setD(uint256,string)', [0x22n], new Uint8Array(0)));
    await eqSlot(0n, 'd.a after empty assign');
    await eqSlot(1n, 'd.s header empty (0)');
    for (let i = 0n; i < 3n; i++) await eqSlot(slotKeccak(1n) + i, `d.s old long70 w${i} cleared`);
    await eq('getDs empty', encodeCall(sel('getDs()'), []));
    const r = await eq('getDa', encodeCall(sel('getDa()'), []));
    expect(decodeUint(r.j.returnHex)).toBe(0x22n);
  });

  it('field setDs with a string whose bytes have a trailing partial word (37 bytes)', async () => {
    const L37 = 'D'.repeat(37); // 2 words, 2nd word has 5 used bytes
    await eq('setDs 37', callDyn('setDs(string)', [], s(L37)));
    await eqSlot(1n, 'd.s header 37 (len*2+1 = 75 = 0x4b)');
    await eqSlot(slotKeccak(1n), 'd.s 37 data w0 (full)');
    await eqSlot(slotKeccak(1n) + 1n, 'd.s 37 data w1 (partial, trailing zeros)');
    await eq('getDs 37', encodeCall(sel('getDs()'), []));
  });

  it('field setDs zero-length string after a short: header zeroed', async () => {
    await eq('setDs short ab', callDyn('setDs(string)', [], s('ab')));
    await eqSlot(1n, 'd.s short header');
    await eq('setDs empty', callDyn('setDs(string)', [], new Uint8Array(0)));
    await eqSlot(1n, 'd.s header zeroed (empty)');
    await eq('getDs empty', encodeCall(sel('getDs()'), []));
  });

  it('whole struct assign with exactly-32 string (long boundary)', async () => {
    const L32 = 'E'.repeat(32);
    await eq('setD 32', callDyn('setD(uint256,string)', [0x33n], s(L32)));
    await eqSlot(0n, 'd.a 32');
    await eqSlot(1n, 'd.s header 32 (long, 65=0x41)');
    await eqSlot(slotKeccak(1n), 'd.s 32 data w0');
    await eq('getDs 32', encodeCall(sel('getDs()'), []));
  });
});
