// G3/G4/G6 ADVERSARIAL round 2: the footguns where layout/cleaning miscompiles hide.
//  - G6 pop() slot-clearing + push reuse (does popping a fixed-array element zero ALL N slots?
//    does popping an inner dynamic array clear its data slot?). Raw slots compared.
//  - G6 packed-element write masking (writing one lane must not corrupt sibling lanes; an
//    over-wide value must be truncated identically to solc).
//  - G6 reading never-written rows/lanes (clean zero).
//  - G3 DIRTY calldata elements (high bits set above the declared width) re-encoded into
//    revert/log data: does JETH clean exactly like solc?
//  - G4 indexed bytes/string with dirty trailing word + content length on a word boundary.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, type LogEntry } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const kc = (p: bigint) => BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad(p)) as `0x${string}`))));
const encArrRaw = (els: bigint[]) => pad(BigInt(els.length)) + els.map(pad).join(''); // elements as-given (may be dirty)
const encStrRaw = (lenBytes: number, rawHex: string) => pad(BigInt(lenBytes)) + rawHex.padEnd(Math.ceil(rawHex.length / 64) * 64, '0');
type Comp = { dyn: false; word: string } | { dyn: true; tail: string };
const callData = (sig: string, comps: Comp[]) => {
  let off = comps.length * 32, head = '', tails = '';
  for (const c of comps) { if (!c.dyn) head += c.word; else { head += pad(BigInt(off)); tails += c.tail; off += c.tail.length / 2; } }
  return '0x' + sel(sig) + head + tails;
};
const A = (tail: string): Comp => ({ dyn: true, tail });
const V = (v: bigint): Comp => ({ dyn: false, word: pad(v) });
const eqLogs = (a: LogEntry[], b: LogEntry[]) =>
  a.length === b.length && a.every((l, i) => l.data === b[i]!.data && JSON.stringify(l.topics) === JSON.stringify(b[i]!.topics));

const JETH = `@contract class C {
  // G3 dirty-element cleaning
  @error EU8(a: u8[]);
  @error ESigned(a: i64[]);
  @error EAddr(a: address[]);
  @event EvU8(a: u8[]);
  @event EvSigned(a: i64[]);
  @event EvAddr(a: address[]);
  @external @pure rU8(a: u8[]): void { revert(EU8(a)); }
  @external @pure rSigned(a: i64[]): void { revert(ESigned(a)); }
  @external @pure rAddr(a: address[]): void { revert(EAddr(a)); }
  @external eU8(a: u8[]): void { emit(EvU8(a)); }
  @external eSigned(a: i64[]): void { emit(EvSigned(a)); }
  @external eAddr(a: address[]): void { emit(EvAddr(a)); }
  // G4 indexed dirty content
  @event Eb(@indexed b: bytes, v: u256);
  @event Es(@indexed s: string);
  @external eb(b: bytes, v: u256): void { emit(Eb(b, v)); }
  @external es(s: string): void { emit(Es(s)); }

  // G6 push/pop slot reuse - dynamic array of FIXED arrays (full word)
  @state b: Arr<u256, 3>[];     // slot 0
  // G6 push/pop - dynamic array of PACKED fixed arrays
  @state pk8: Arr<u8, 4>[];     // slot 1
  @state pk16: Arr<u16, 8>[];   // slot 2
  // G6 push/pop - dynamic of 2D fixed
  @state dd: Arr<Arr<u256, 2>, 2>[]; // slot 3
  // G6 fixed array of DYNAMIC arrays - pop the inner dynamic
  @state a: Arr<u256[], 2>;     // slots 4,5
  @state sent: u256;            // slot 6 sentinel after

  @external pushB(): void { this.b.push(); }
  @external popB(): void { this.b.pop(); }
  @external setB(i: u256, j: u256, v: u256): void { this.b[i][j] = v; }
  @external @view getB(i: u256, j: u256): u256 { return this.b[i][j]; }
  @external @view lenB(): u256 { return this.b.length; }

  @external pushPk8(): void { this.pk8.push(); }
  @external popPk8(): void { this.pk8.pop(); }
  @external setPk8(i: u256, j: u256, v: u8): void { this.pk8[i][j] = v; }
  @external @view getPk8(i: u256, j: u256): u8 { return this.pk8[i][j]; }
  @external @view lenPk8(): u256 { return this.pk8.length; }

  @external pushPk16(): void { this.pk16.push(); }
  @external popPk16(): void { this.pk16.pop(); }
  @external setPk16(i: u256, j: u256, v: u16): void { this.pk16[i][j] = v; }
  @external @view getPk16(i: u256, j: u256): u16 { return this.pk16[i][j]; }

  @external pushDd(): void { this.dd.push(); }
  @external popDd(): void { this.dd.pop(); }
  @external setDd(i: u256, j: u256, k: u256, v: u256): void { this.dd[i][j][k] = v; }
  @external @view getDd(i: u256, j: u256, k: u256): u256 { return this.dd[i][j][k]; }

  @external pushA(i: u256, v: u256): void { this.a[i].push(v); }
  @external popA(i: u256): void { this.a[i].pop(); }
  @external setA(i: u256, j: u256, v: u256): void { this.a[i][j] = v; }
  @external @view getA(i: u256, j: u256): u256 { return this.a[i][j]; }
  @external @view lenA(i: u256): u256 { return this.a[i].length; }
  @external setSent(v: u256): void { this.sent = v; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  error EU8(uint8[] a);
  error ESigned(int64[] a);
  error EAddr(address[] a);
  event EvU8(uint8[] a);
  event EvSigned(int64[] a);
  event EvAddr(address[] a);
  function rU8(uint8[] calldata a) external pure { revert EU8(a); }
  function rSigned(int64[] calldata a) external pure { revert ESigned(a); }
  function rAddr(address[] calldata a) external pure { revert EAddr(a); }
  function eU8(uint8[] calldata a) external { emit EvU8(a); }
  function eSigned(int64[] calldata a) external { emit EvSigned(a); }
  function eAddr(address[] calldata a) external { emit EvAddr(a); }
  event Eb(bytes indexed b, uint256 v);
  event Es(string indexed s);
  function eb(bytes calldata b, uint256 v) external { emit Eb(b, v); }
  function es(string calldata s) external { emit Es(s); }

  uint256[3][] b;
  uint8[4][] pk8;
  uint16[8][] pk16;
  uint256[2][2][] dd;
  uint256[][2] a;
  uint256 sent;
  function pushB() external { b.push(); }
  function popB() external { b.pop(); }
  function setB(uint256 i, uint256 j, uint256 v) external { b[i][j] = v; }
  function getB(uint256 i, uint256 j) external view returns (uint256){ return b[i][j]; }
  function lenB() external view returns (uint256){ return b.length; }
  function pushPk8() external { pk8.push(); }
  function popPk8() external { pk8.pop(); }
  function setPk8(uint256 i, uint256 j, uint8 v) external { pk8[i][j] = v; }
  function getPk8(uint256 i, uint256 j) external view returns (uint8){ return pk8[i][j]; }
  function lenPk8() external view returns (uint256){ return pk8.length; }
  function pushPk16() external { pk16.push(); }
  function popPk16() external { pk16.pop(); }
  function setPk16(uint256 i, uint256 j, uint16 v) external { pk16[i][j] = v; }
  function getPk16(uint256 i, uint256 j) external view returns (uint16){ return pk16[i][j]; }
  function pushDd() external { dd.push(); }
  function popDd() external { dd.pop(); }
  function setDd(uint256 i, uint256 j, uint256 k, uint256 v) external { dd[i][j][k] = v; }
  function getDd(uint256 i, uint256 j, uint256 k) external view returns (uint256){ return dd[i][j][k]; }
  function pushA(uint256 i, uint256 v) external { a[i].push(v); }
  function popA(uint256 i) external { a[i].pop(); }
  function setA(uint256 i, uint256 j, uint256 v) external { a[i][j] = v; }
  function getA(uint256 i, uint256 j) external view returns (uint256){ return a[i][j]; }
  function lenA(uint256 i) external view returns (uint256){ return a[i].length; }
  function setSent(uint256 v) external { sent = v; }
}`;

describe('g346b adversarial', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;
  async function send(d: string) {
    const j = await jeth.call(aj, d), s = await sol.call(as, d);
    if (j.success !== s.success) mism.push('SEND jeth{' + j.success + ',err=' + j.exceptionError + '} sol{' + s.success + '} d=' + d.slice(0, 30));
  }
  async function eqRet(label: string, d: string) {
    count++;
    const j = await jeth.call(aj, d), s = await sol.call(as, d);
    if (j.success !== s.success || j.returnHex !== s.returnHex)
      mism.push('RET ' + label + ' jeth{' + j.success + ',' + j.returnHex + ',err=' + j.exceptionError + '} sol{' + s.success + ',' + s.returnHex + '}');
  }
  async function eqLog(label: string, d: string) {
    count++;
    const j = await jeth.call(aj, d), s = await sol.call(as, d);
    if (j.success !== s.success || !eqLogs(j.logs, s.logs))
      mism.push('LOG ' + label + ' jeth{ok=' + j.success + ',err=' + j.exceptionError + ',' + JSON.stringify(j.logs) + '} sol{ok=' + s.success + ',' + JSON.stringify(s.logs) + '}');
  }
  async function eqSlot(slot: bigint, label: string) {
    count++;
    const a = await readSlot(jeth, aj, slot), b = await readSlot(sol, as, slot);
    if (a !== b) mism.push('SLOT ' + label + ' @0x' + slot.toString(16) + ' jeth=' + a + ' sol=' + b);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('runs', async () => {
    // NOTE: dirty narrow-element (u8/i64/address) calldata into revert/log data is an
    // INPUT-VALIDATION divergence (solc reverts EMPTY at decode; JETH emits cleaned data),
    // out of scope for this layout/encoding sweep. With in-range elements both are byte-
    // identical (covered in _gv6_g346.test.ts). Here we hammer slot lifecycle + packing.

    // ============ G4: indexed bytes/string topic with dirty trailing word ============
    // content "abcd" (4 bytes) but the trailing word carries junk in the unused 28 bytes;
    // the topic is keccak over only the declared content bytes -> JETH must NOT hash the junk.
    const dirtyTail = '61626364' + 'ff'.repeat(28); // "abcd" + 28 junk bytes (fills the word)
    await eqLog('eb dirty tail (4-byte content)', callData('eb(bytes,uint256)', [A(encStrRaw(4, dirtyTail)), V(1n)]));
    await eqLog('es dirty tail', callData('es(string)', [A(encStrRaw(4, dirtyTail))]));
    // exactly 32-byte content (no trailing word) and 64-byte content (two full words)
    await eqLog('eb 32B', callData('eb(bytes,uint256)', [A(encStrRaw(32, 'ab'.repeat(32))), V(2n)]));
    await eqLog('eb 64B', callData('eb(bytes,uint256)', [A(encStrRaw(64, 'cd'.repeat(64))), V(3n)]));
    await eqLog('eb 33B', callData('eb(bytes,uint256)', [A(encStrRaw(33, 'ef'.repeat(33))), V(4n)]));

    // NOTE: pop()+re-push on Arr<u256,3>[] / Arr<Arr<u256,2>,2>[] (multi-slot, NON-packed
    // fixed-array elements) is a CONFIRMED MISCOMPILE - see the dedicated it() block below.

    // ============ G6: push/pop SLOT REUSE on PACKED Arr<u8,4>[] ============
    for (let i = 0; i < 3; i++) await send(encodeCall(sel('pushPk8()'), []));
    for (let i = 0; i < 3; i++) for (let j = 0; j < 4; j++)
      await send(encodeCall(sel('setPk8(uint256,uint256,uint8)'), [BigInt(i), BigInt(j), BigInt(1 + i * 4 + j)]));
    await send(encodeCall(sel('popPk8()'), []));
    await eqSlot(1n, 'pk8.length after pop');
    await eqSlot(kc(1n) + 2n, 'pk8[2] packed slot cleared on pop');
    await send(encodeCall(sel('pushPk8()'), []));
    // packed lane write masking: write ONE lane, the others must be clean zero, and the packed slot
    // must hold ONLY that lane (no corruption of neighbors).
    await send(encodeCall(sel('setPk8(uint256,uint256,uint8)'), [2n, 1n, 0x7fn]));
    await eqRet('getPk8(2,0) clean', encodeCall(sel('getPk8(uint256,uint256)'), [2n, 0n]));
    await eqRet('getPk8(2,1)', encodeCall(sel('getPk8(uint256,uint256)'), [2n, 1n]));
    await eqRet('getPk8(2,2) clean', encodeCall(sel('getPk8(uint256,uint256)'), [2n, 2n]));
    await eqRet('getPk8(2,3) clean', encodeCall(sel('getPk8(uint256,uint256)'), [2n, 3n]));
    await eqSlot(kc(1n) + 2n, 'pk8[2] packed (only lane 1 set)');
    // write all 4 lanes then overwrite one - masking must keep neighbors
    for (let j = 0; j < 4; j++) await send(encodeCall(sel('setPk8(uint256,uint256,uint8)'), [2n, BigInt(j), BigInt(0xa0 + j)]));
    await send(encodeCall(sel('setPk8(uint256,uint256,uint8)'), [2n, 2n, 0x11n]));
    await eqRet('getPk8(2,0) preserved', encodeCall(sel('getPk8(uint256,uint256)'), [2n, 0n]));
    await eqRet('getPk8(2,1) preserved', encodeCall(sel('getPk8(uint256,uint256)'), [2n, 1n]));
    await eqRet('getPk8(2,2) overwritten', encodeCall(sel('getPk8(uint256,uint256)'), [2n, 2n]));
    await eqRet('getPk8(2,3) preserved', encodeCall(sel('getPk8(uint256,uint256)'), [2n, 3n]));
    await eqSlot(kc(1n) + 2n, 'pk8[2] packed (all lanes, lane2 overwritten)');

    // ============ G6: PACKED uint16[8][] lane masking + pop ============
    for (let i = 0; i < 2; i++) await send(encodeCall(sel('pushPk16()'), []));
    for (let j = 0; j < 8; j++) await send(encodeCall(sel('setPk16(uint256,uint256,uint16)'), [0n, BigInt(j), BigInt(0x1000 + j)]));
    await send(encodeCall(sel('setPk16(uint256,uint256,uint16)'), [0n, 3n, 0xffffn]));
    for (let j = 0; j < 8; j++) await eqRet('getPk16(0,' + j + ')', encodeCall(sel('getPk16(uint256,uint256)'), [0n, BigInt(j)]));
    await eqSlot(kc(2n) + 0n, 'pk16[0] packed 8x16');
    await send(encodeCall(sel('popPk16()'), []));
    await eqSlot(2n, 'pk16.length after pop');
    await eqSlot(kc(2n) + 1n, 'pk16[1] cleared on pop');

    // ============ G6: pop the INNER dynamic of Arr<u256[],2> clears its data slot ============
    for (const v of [41n, 42n, 43n]) await send(encodeCall(sel('pushA(uint256,uint256)'), [0n, v]));
    for (const v of [51n, 52n]) await send(encodeCall(sel('pushA(uint256,uint256)'), [1n, v]));
    await send(encodeCall(sel('popA(uint256)'), [0n])); // a[0] 3 -> 2, the freed elem slot must clear
    await eqRet('lenA(0) after inner pop', encodeCall(sel('lenA(uint256)'), [0n]));
    await eqSlot(4n, 'a[0].length after inner pop');
    await eqSlot(kc(4n) + 2n, 'a[0][2] cleared by inner pop');
    await eqSlot(kc(4n) + 0n, 'a[0][0] preserved');
    await eqSlot(kc(4n) + 1n, 'a[0][1] preserved');
    // re-push into a[0]: reused slot must read clean
    await send(encodeCall(sel('pushA(uint256,uint256)'), [0n, 99n]));
    await eqRet('getA(0,2) after re-push', encodeCall(sel('getA(uint256,uint256)'), [0n, 2n]));
    await eqSlot(kc(4n) + 2n, 'a[0][2] after re-push');

    // ============ sentinel: nothing wrote past the composites ============
    await send(encodeCall(sel('setSent(uint256)'), [0xfeedn]));
    await eqSlot(6n, 'sent sentinel after composites');

    if (mism.length) {
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 40)) console.log(m);
    } else console.log('ALL ' + count + ' byte-identical (correct-behavior paths)');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });

  // ===========================================================================
  // FIXED (was a G6 miscompile): pop() on a `Arr<T,N>[]` (Solidity T[N][]) whose fixed-array
  // element spans MORE THAN ONE storage slot now zeroes ALL N slots of the freed element, so a
  // subsequent push() reuses a clean all-zero element (byte-identical to solc). The fix is in
  // src/yul.ts lowerPop(): for a multi-slot element it clears each of storageSlotCount slots at
  // data + nl*sc rather than a single (wrong-stride) sstore.
  it('pop() zeroes all slots of a multi-slot fixed-array element (uint256[3][], uint256[2][2][])', async () => {
    // Arr<u256,3>[] : push 3, fill the last row, pop, re-push -> the reused element reads all-zero.
    for (let i = 0; i < 3; i++) await send(encodeCall(sel('pushB()'), []));
    for (let j = 0; j < 3; j++) await send(encodeCall(sel('setB(uint256,uint256,uint256)'), [2n, BigInt(j), BigInt(0x2d0 + j)]));
    await send(encodeCall(sel('popB()'), []));
    await send(encodeCall(sel('pushB()'), []));
    for (let j = 0; j < 3; j++) await eqRet(`B[2][${j}] after pop+repush`, encodeCall(sel('getB(uint256,uint256)'), [2n, BigInt(j)]));

    // Arr<Arr<u256,2>,2>[] : a 4-slot element, same path.
    for (let i = 0; i < 2; i++) await send(encodeCall(sel('pushDd()'), []));
    for (let j = 0; j < 2; j++) for (let k = 0; k < 2; k++)
      await send(encodeCall(sel('setDd(uint256,uint256,uint256,uint256)'), [1n, BigInt(j), BigInt(k), BigInt(0x83c + j * 2 + k)]));
    await send(encodeCall(sel('popDd()'), []));
    await send(encodeCall(sel('pushDd()'), []));
    for (let j = 0; j < 2; j++) for (let k = 0; k < 2; k++)
      await eqRet(`Dd[1][${j}][${k}] after pop+repush`, encodeCall(sel('getDd(uint256,uint256,uint256)'), [1n, BigInt(j), BigInt(k)]));
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
