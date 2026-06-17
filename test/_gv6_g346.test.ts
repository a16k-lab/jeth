// G3/G4/G6 hard differential sweep vs solc (0.8.x, cancun, optimizer on).
// G3: @error / @event with a NON-INDEXED dynamic-array argument -> compare revert
//     returndata and event LOG data byte-for-byte. Element types u256/address/i64/u8/
//     bytes32, nested u256[][] / u256[][][], empty, mixed args; calldata + memory sources.
// G4: an INDEXED bytes/string event param -> topic = keccak256(content). Compare topics+data.
// G6: storage Arr<T[],N> (= uint256[][N]) and Arr<T,N>[] (= uint256[N][], incl. PACKED
//     fixed elements). Compare getter return values AND RAW STORAGE SLOTS (layout interop).
//     Sentinels before/after the composites catch slot over/underflow.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address, hexToBytes } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, type LogEntry } from '../src/evm.js';
import { functionSelector, keccak, toHex } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
// keccak256(pad32(p)) as bigint - the base slot of a dynamic array whose length lives at p.
const kc = (p: bigint) => BigInt('0x' + toHex(keccak(hexToBytes(('0x' + pad(p)) as `0x${string}`))));

// --- head/tail calldata encoders (encodeCall is flat-words-only) ---
const encArr = (els: bigint[]) => pad(BigInt(els.length)) + els.map(pad).join('');
const encNest = (rows: bigint[][]) => {
  let off = rows.length * 32, table = '', tails = '';
  for (const row of rows) { table += pad(BigInt(off)); const t = encArr(row); tails += t; off += t.length / 2; }
  return pad(BigInt(rows.length)) + table + tails;
};
const encNest3 = (cube: bigint[][][]) => {
  // uint256[][][]: outer length, table of offsets to each 2D block, then each 2D block.
  let off = cube.length * 32, table = '', tails = '';
  for (const plane of cube) { table += pad(BigInt(off)); const t = encNest(plane); tails += t; off += t.length / 2; }
  return pad(BigInt(cube.length)) + table + tails;
};
const encStr = (s: string) => {
  const h = Buffer.from(s, 'utf8').toString('hex');
  return pad(BigInt(h.length / 2)) + h.padEnd(Math.ceil(h.length / 64) * 64, '0');
};

type Comp = { dyn: false; word: string } | { dyn: true; tail: string };
const callData = (sig: string, comps: Comp[]) => {
  let off = comps.length * 32, head = '', tails = '';
  for (const c of comps) {
    if (!c.dyn) head += c.word;
    else { head += pad(BigInt(off)); tails += c.tail; off += c.tail.length / 2; }
  }
  return '0x' + sel(sig) + head + tails;
};
const A = (tail: string): Comp => ({ dyn: true, tail });
const V = (v: bigint): Comp => ({ dyn: false, word: pad(v) });

const eqLogs = (a: LogEntry[], b: LogEntry[]) =>
  a.length === b.length && a.every((l, i) => l.data === b[i]!.data && JSON.stringify(l.topics) === JSON.stringify(b[i]!.topics));

// ---------------------------------------------------------------------------
const JETH = `@contract class C {
  // ---- G3: errors/events with non-indexed dynamic-array args ----
  @error E1(a: u256[]);
  @error E2(tag: u256, a: u256[]);
  @error E3(a: u256[], s: string);
  @error E3b(a: u256[], b: bytes);
  @error E4(a: u256[], b: u256[]);
  @error EAddr(a: address[]);
  @error ESigned(a: i64[]);
  @error EU8(a: u8[]);
  @error EB32(a: bytes32[]);
  @error ENest(a: u256[][]);
  @error ENest3(a: u256[][][]);
  @error EMixNest(tag: u256, a: u256[][], s: string);
  @event Ev1(a: u256[]);
  @event Ev2(@indexed tag: u256, a: u256[]);
  @event Ev3(a: u256[], s: string);
  @event Ev3b(a: u256[], b: bytes);
  @event Ev4(a: u256[], b: u256[]);
  @event EvAddr(a: address[]);
  @event EvSigned(a: i64[]);
  @event EvU8(a: u8[]);
  @event EvB32(a: bytes32[]);
  @event EvNest(a: u256[][]);
  @event EvNest3(a: u256[][][]);
  // errors - calldata array sources
  @external @pure r1(a: u256[]): void { revert(E1(a)); }
  @external @pure r2(t: u256, a: u256[]): void { revert(E2(t, a)); }
  @external @pure r3(a: u256[], s: string): void { revert(E3(a, s)); }
  @external @pure r3b(a: u256[], b: bytes): void { revert(E3b(a, b)); }
  @external @pure r4(a: u256[], b: u256[]): void { revert(E4(a, b)); }
  @external @pure rAddr(a: address[]): void { revert(EAddr(a)); }
  @external @pure rSigned(a: i64[]): void { revert(ESigned(a)); }
  @external @pure rU8(a: u8[]): void { revert(EU8(a)); }
  @external @pure rB32(a: bytes32[]): void { revert(EB32(a)); }
  @external @pure rNest(a: u256[][]): void { revert(ENest(a)); }
  @external @pure rNest3(a: u256[][][]): void { revert(ENest3(a)); }
  @external @pure rMixNest(t: u256, a: u256[][], s: string): void { revert(EMixNest(t, a, s)); }
  // errors - memory array sources (flat value arrays only)
  @external @pure rMemU(x: u256, y: u256, z: u256): void { let xs: u256[] = [x, y, z]; revert(E1(xs)); }
  @external @pure rMemI(x: i64, y: i64): void { let xs: i64[] = [x, y]; revert(ESigned(xs)); }
  @external @pure rMemA(x: address, y: address): void { let xs: address[] = [x, y]; revert(EAddr(xs)); }
  @external @pure rMemU8(x: u8, y: u8): void { let xs: u8[] = [x, y]; revert(EU8(xs)); }
  @external @pure rMemB32(x: bytes32, y: bytes32): void { let xs: bytes32[] = [x, y]; revert(EB32(xs)); }
  // events - calldata array sources
  @external e1(a: u256[]): void { emit(Ev1(a)); }
  @external e2(t: u256, a: u256[]): void { emit(Ev2(t, a)); }
  @external e3(a: u256[], s: string): void { emit(Ev3(a, s)); }
  @external e3b(a: u256[], b: bytes): void { emit(Ev3b(a, b)); }
  @external e4(a: u256[], b: u256[]): void { emit(Ev4(a, b)); }
  @external eAddr(a: address[]): void { emit(EvAddr(a)); }
  @external eSigned(a: i64[]): void { emit(EvSigned(a)); }
  @external eU8(a: u8[]): void { emit(EvU8(a)); }
  @external eB32(a: bytes32[]): void { emit(EvB32(a)); }
  @external eNest(a: u256[][]): void { emit(EvNest(a)); }
  @external eNest3(a: u256[][][]): void { emit(EvNest3(a)); }
  // events - memory array sources
  @external eMemU(x: u256, y: u256): void { let xs: u256[] = [x, y]; emit(Ev1(xs)); }
  @external eMemA(x: address, y: address, z: address): void { let xs: address[] = [x, y, z]; emit(EvAddr(xs)); }

  // ---- G4: indexed bytes/string event params ----
  @event Es(@indexed s: string, v: u256);
  @event Eb(@indexed b: bytes, v: u256);
  @event Emix(@indexed k: u256, @indexed s: string, v: u256);
  @event Etwo(@indexed s1: string, @indexed s2: string);
  @event Eonly(@indexed s: string);
  @event EidxArr(@indexed b: bytes, a: u256[]);
  @external es(s: string, v: u256): void { emit(Es(s, v)); }
  @external eb(b: bytes, v: u256): void { emit(Eb(b, v)); }
  @external emix(k: u256, s: string, v: u256): void { emit(Emix(k, s, v)); }
  @external etwo(s1: string, s2: string): void { emit(Etwo(s1, s2)); }
  @external eonly(s: string): void { emit(Eonly(s)); }
  @external eidxArr(b: bytes, a: u256[]): void { emit(EidxArr(b, a)); }

  // ---- G6: storage Arr<T[],N> (fixed array of dynamic arrays) ----
  @state s0: u256;                  // sentinel before
  @state a: Arr<u256[], 3>;         // uint256[][3]: slots 1,2,3
  @state ab: Arr<bytes32[], 2>;     // bytes32[][2]: slots 4,5
  @state s1: u256;                  // sentinel between

  // ---- G6: storage Arr<T,N>[] (dynamic array of fixed arrays) ----
  @state b: Arr<u256, 2>[];         // uint256[2][]: slot 7
  @state c: Arr<u256, 3>[];         // uint256[3][]: slot 8
  @state d: Arr<u256, 5>[];         // uint256[5][]: slot 9
  @state pk8: Arr<u8, 4>[];         // uint8[4][] packed: slot 10
  @state pk16: Arr<u16, 8>[];       // uint16[8][] packed: slot 11
  @state pkI64: Arr<i64, 2>[];      // int64[2][] packed: slot 12
  @state ba: Arr<bytes32, 2>[];     // bytes32[2][]: slot 13
  @state ad: Arr<address, 2>[];     // address[2][]: slot 14
  @state dd: Arr<Arr<u256, 2>, 2>[]; // uint256[2][2][]: slot 15
  @state s2: u256;                  // sentinel after

  @external setS0(v: u256): void { this.s0 = v; }
  @external setS1(v: u256): void { this.s1 = v; }
  @external setS2(v: u256): void { this.s2 = v; }

  @external pushA(i: u256, v: u256): void { this.a[i].push(v); }
  @external setA(i: u256, j: u256, v: u256): void { this.a[i][j] = v; }
  @view getA(i: u256, j: u256): u256 { return this.a[i][j]; }
  @view lenA(i: u256): u256 { return this.a[i].length; }
  @external pushAb(i: u256, v: bytes32): void { this.ab[i].push(v); }
  @view getAb(i: u256, j: u256): bytes32 { return this.ab[i][j]; }
  @view lenAb(i: u256): u256 { return this.ab[i].length; }

  @external pushB(): void { this.b.push(); }
  @external setB(i: u256, j: u256, v: u256): void { this.b[i][j] = v; }
  @view getB(i: u256, j: u256): u256 { return this.b[i][j]; }
  @view lenB(): u256 { return this.b.length; }
  @external pushC(): void { this.c.push(); }
  @external setC(i: u256, j: u256, v: u256): void { this.c[i][j] = v; }
  @view getC(i: u256, j: u256): u256 { return this.c[i][j]; }
  @view lenC(): u256 { return this.c.length; }
  @external pushD(): void { this.d.push(); }
  @external setD(i: u256, j: u256, v: u256): void { this.d[i][j] = v; }
  @view getD(i: u256, j: u256): u256 { return this.d[i][j]; }
  @view lenD(): u256 { return this.d.length; }

  @external pushPk8(): void { this.pk8.push(); }
  @external setPk8(i: u256, j: u256, v: u8): void { this.pk8[i][j] = v; }
  @view getPk8(i: u256, j: u256): u8 { return this.pk8[i][j]; }
  @external pushPk16(): void { this.pk16.push(); }
  @external setPk16(i: u256, j: u256, v: u16): void { this.pk16[i][j] = v; }
  @view getPk16(i: u256, j: u256): u16 { return this.pk16[i][j]; }
  @external pushPkI64(): void { this.pkI64.push(); }
  @external setPkI64(i: u256, j: u256, v: i64): void { this.pkI64[i][j] = v; }
  @view getPkI64(i: u256, j: u256): i64 { return this.pkI64[i][j]; }

  @external pushBa(): void { this.ba.push(); }
  @external setBa(i: u256, j: u256, v: bytes32): void { this.ba[i][j] = v; }
  @view getBa(i: u256, j: u256): bytes32 { return this.ba[i][j]; }
  @external pushAd(): void { this.ad.push(); }
  @external setAd(i: u256, j: u256, v: address): void { this.ad[i][j] = v; }
  @view getAd(i: u256, j: u256): address { return this.ad[i][j]; }

  @external pushDd(): void { this.dd.push(); }
  @external setDd(i: u256, j: u256, k: u256, v: u256): void { this.dd[i][j][k] = v; }
  @view getDd(i: u256, j: u256, k: u256): u256 { return this.dd[i][j][k]; }
  @view lenDd(): u256 { return this.dd.length; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  error E1(uint256[] a);
  error E2(uint256 tag, uint256[] a);
  error E3(uint256[] a, string s);
  error E3b(uint256[] a, bytes b);
  error E4(uint256[] a, uint256[] b);
  error EAddr(address[] a);
  error ESigned(int64[] a);
  error EU8(uint8[] a);
  error EB32(bytes32[] a);
  error ENest(uint256[][] a);
  error ENest3(uint256[][][] a);
  error EMixNest(uint256 tag, uint256[][] a, string s);
  event Ev1(uint256[] a);
  event Ev2(uint256 indexed tag, uint256[] a);
  event Ev3(uint256[] a, string s);
  event Ev3b(uint256[] a, bytes b);
  event Ev4(uint256[] a, uint256[] b);
  event EvAddr(address[] a);
  event EvSigned(int64[] a);
  event EvU8(uint8[] a);
  event EvB32(bytes32[] a);
  event EvNest(uint256[][] a);
  event EvNest3(uint256[][][] a);
  function r1(uint256[] calldata a) external pure { revert E1(a); }
  function r2(uint256 t, uint256[] calldata a) external pure { revert E2(t, a); }
  function r3(uint256[] calldata a, string calldata s) external pure { revert E3(a, s); }
  function r3b(uint256[] calldata a, bytes calldata b) external pure { revert E3b(a, b); }
  function r4(uint256[] calldata a, uint256[] calldata b) external pure { revert E4(a, b); }
  function rAddr(address[] calldata a) external pure { revert EAddr(a); }
  function rSigned(int64[] calldata a) external pure { revert ESigned(a); }
  function rU8(uint8[] calldata a) external pure { revert EU8(a); }
  function rB32(bytes32[] calldata a) external pure { revert EB32(a); }
  function rNest(uint256[][] calldata a) external pure { revert ENest(a); }
  function rNest3(uint256[][][] calldata a) external pure { revert ENest3(a); }
  function rMixNest(uint256 t, uint256[][] calldata a, string calldata s) external pure { revert EMixNest(t, a, s); }
  function rMemU(uint256 x, uint256 y, uint256 z) external pure { uint256[] memory xs = new uint256[](3); xs[0]=x;xs[1]=y;xs[2]=z; revert E1(xs); }
  function rMemI(int64 x, int64 y) external pure { int64[] memory xs = new int64[](2); xs[0]=x;xs[1]=y; revert ESigned(xs); }
  function rMemA(address x, address y) external pure { address[] memory xs = new address[](2); xs[0]=x;xs[1]=y; revert EAddr(xs); }
  function rMemU8(uint8 x, uint8 y) external pure { uint8[] memory xs = new uint8[](2); xs[0]=x;xs[1]=y; revert EU8(xs); }
  function rMemB32(bytes32 x, bytes32 y) external pure { bytes32[] memory xs = new bytes32[](2); xs[0]=x;xs[1]=y; revert EB32(xs); }
  function e1(uint256[] calldata a) external { emit Ev1(a); }
  function e2(uint256 t, uint256[] calldata a) external { emit Ev2(t, a); }
  function e3(uint256[] calldata a, string calldata s) external { emit Ev3(a, s); }
  function e3b(uint256[] calldata a, bytes calldata b) external { emit Ev3b(a, b); }
  function e4(uint256[] calldata a, uint256[] calldata b) external { emit Ev4(a, b); }
  function eAddr(address[] calldata a) external { emit EvAddr(a); }
  function eSigned(int64[] calldata a) external { emit EvSigned(a); }
  function eU8(uint8[] calldata a) external { emit EvU8(a); }
  function eB32(bytes32[] calldata a) external { emit EvB32(a); }
  function eNest(uint256[][] calldata a) external { emit EvNest(a); }
  function eNest3(uint256[][][] calldata a) external { emit EvNest3(a); }
  function eMemU(uint256 x, uint256 y) external { uint256[] memory xs = new uint256[](2); xs[0]=x;xs[1]=y; emit Ev1(xs); }
  function eMemA(address x, address y, address z) external { address[] memory xs = new address[](3); xs[0]=x;xs[1]=y;xs[2]=z; emit EvAddr(xs); }

  event Es(string indexed s, uint256 v);
  event Eb(bytes indexed b, uint256 v);
  event Emix(uint256 indexed k, string indexed s, uint256 v);
  event Etwo(string indexed s1, string indexed s2);
  event Eonly(string indexed s);
  event EidxArr(bytes indexed b, uint256[] a);
  function es(string calldata s, uint256 v) external { emit Es(s, v); }
  function eb(bytes calldata b, uint256 v) external { emit Eb(b, v); }
  function emix(uint256 k, string calldata s, uint256 v) external { emit Emix(k, s, v); }
  function etwo(string calldata s1, string calldata s2) external { emit Etwo(s1, s2); }
  function eonly(string calldata s) external { emit Eonly(s); }
  function eidxArr(bytes calldata b, uint256[] calldata a) external { emit EidxArr(b, a); }

  uint256 s0;
  uint256[][3] a;
  bytes32[][2] ab;
  uint256 s1;
  uint256[2][] b;
  uint256[3][] c;
  uint256[5][] d;
  uint8[4][] pk8;
  uint16[8][] pk16;
  int64[2][] pkI64;
  bytes32[2][] ba;
  address[2][] ad;
  uint256[2][2][] dd;
  uint256 s2;
  function setS0(uint256 v) external { s0 = v; }
  function setS1(uint256 v) external { s1 = v; }
  function setS2(uint256 v) external { s2 = v; }
  function pushA(uint256 i, uint256 v) external { a[i].push(v); }
  function setA(uint256 i, uint256 j, uint256 v) external { a[i][j] = v; }
  function getA(uint256 i, uint256 j) external view returns (uint256){ return a[i][j]; }
  function lenA(uint256 i) external view returns (uint256){ return a[i].length; }
  function pushAb(uint256 i, bytes32 v) external { ab[i].push(v); }
  function getAb(uint256 i, uint256 j) external view returns (bytes32){ return ab[i][j]; }
  function lenAb(uint256 i) external view returns (uint256){ return ab[i].length; }
  function pushB() external { b.push(); }
  function setB(uint256 i, uint256 j, uint256 v) external { b[i][j] = v; }
  function getB(uint256 i, uint256 j) external view returns (uint256){ return b[i][j]; }
  function lenB() external view returns (uint256){ return b.length; }
  function pushC() external { c.push(); }
  function setC(uint256 i, uint256 j, uint256 v) external { c[i][j] = v; }
  function getC(uint256 i, uint256 j) external view returns (uint256){ return c[i][j]; }
  function lenC() external view returns (uint256){ return c.length; }
  function pushD() external { d.push(); }
  function setD(uint256 i, uint256 j, uint256 v) external { d[i][j] = v; }
  function getD(uint256 i, uint256 j) external view returns (uint256){ return d[i][j]; }
  function lenD() external view returns (uint256){ return d.length; }
  function pushPk8() external { pk8.push(); }
  function setPk8(uint256 i, uint256 j, uint8 v) external { pk8[i][j] = v; }
  function getPk8(uint256 i, uint256 j) external view returns (uint8){ return pk8[i][j]; }
  function pushPk16() external { pk16.push(); }
  function setPk16(uint256 i, uint256 j, uint16 v) external { pk16[i][j] = v; }
  function getPk16(uint256 i, uint256 j) external view returns (uint16){ return pk16[i][j]; }
  function pushPkI64() external { pkI64.push(); }
  function setPkI64(uint256 i, uint256 j, int64 v) external { pkI64[i][j] = v; }
  function getPkI64(uint256 i, uint256 j) external view returns (int64){ return pkI64[i][j]; }
  function pushBa() external { ba.push(); }
  function setBa(uint256 i, uint256 j, bytes32 v) external { ba[i][j] = v; }
  function getBa(uint256 i, uint256 j) external view returns (bytes32){ return ba[i][j]; }
  function pushAd() external { ad.push(); }
  function setAd(uint256 i, uint256 j, address v) external { ad[i][j] = v; }
  function getAd(uint256 i, uint256 j) external view returns (address){ return ad[i][j]; }
  function pushDd() external { dd.push(); }
  function setDd(uint256 i, uint256 j, uint256 k, uint256 v) external { dd[i][j][k] = v; }
  function getDd(uint256 i, uint256 j, uint256 k) external view returns (uint256){ return dd[i][j][k]; }
  function lenDd() external view returns (uint256){ return dd.length; }
}`;

describe('g346', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;
  async function send(d: string) {
    const j = await jeth.call(aj, d), s = await sol.call(as, d);
    if (j.success !== s.success) mism.push('SEND mismatch jeth{' + j.success + ',err=' + j.exceptionError + '} sol{' + s.success + '} d=' + d.slice(0, 30));
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

  const arr = [1n, 2n, 3n, 0n, M - 1n];
  const bigArr = [0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 11n, 12n];
  const SHORT = 'abc';
  const EXACT = 'abcdefghijklmnopqrstuvwxyz012345'; // 32 bytes
  const LONG = 'this string is definitely longer than thirty-two bytes for the keccak topic test';
  const HUGE = 'x'.repeat(200);

  it('runs', async () => {
    // ===================== G3: errors with array data =====================
    await eqRet('r1', callData('r1(uint256[])', [A(encArr(arr))]));
    await eqRet('r1 empty', callData('r1(uint256[])', [A(encArr([]))]));
    await eqRet('r1 big', callData('r1(uint256[])', [A(encArr(bigArr))]));
    await eqRet('r2 (val+arr)', callData('r2(uint256,uint256[])', [V(99n), A(encArr(arr))]));
    await eqRet('r3 (arr+str short)', callData('r3(uint256[],string)', [A(encArr(arr)), A(encStr(SHORT))]));
    await eqRet('r3 (arr+str long)', callData('r3(uint256[],string)', [A(encArr(arr)), A(encStr(LONG))]));
    await eqRet('r3 (arr+str empty)', callData('r3(uint256[],string)', [A(encArr([])), A(encStr(''))]));
    await eqRet('r3b (arr+bytes)', callData('r3b(uint256[],bytes)', [A(encArr(arr)), A(encStr(LONG))]));
    await eqRet('r4 (arr+arr)', callData('r4(uint256[],uint256[])', [A(encArr(arr)), A(encArr([7n, 8n]))]));
    await eqRet('r4 (empty+arr)', callData('r4(uint256[],uint256[])', [A(encArr([])), A(encArr([7n, 8n]))]));
    await eqRet('rAddr', callData('rAddr(address[])', [A(encArr([0x1111n, 0xbeefn, 0n, (1n << 160n) - 1n]))]));
    await eqRet('rAddr empty', callData('rAddr(address[])', [A(encArr([]))]));
    await eqRet('rSigned', callData('rSigned(int64[])', [A(encArr([1n, M - 1n, (1n << 63n) - 1n, M - (1n << 63n), 0n]))]));
    await eqRet('rU8', callData('rU8(uint8[])', [A(encArr([0n, 1n, 127n, 128n, 255n]))]));
    await eqRet('rB32', callData('rB32(bytes32[])', [A(encArr([0n, M - 1n, 0xdeadbeefn << 224n]))]));
    await eqRet('rNest', callData('rNest(uint256[][])', [A(encNest([[1n, 2n], [3n], []]))]));
    await eqRet('rNest empty', callData('rNest(uint256[][])', [A(encNest([]))]));
    await eqRet('rNest varied', callData('rNest(uint256[][])', [A(encNest([[], [1n], [2n, 3n, 4n, 5n]]))]));
    await eqRet('rNest3', callData('rNest3(uint256[][][])', [A(encNest3([[[1n, 2n], [3n]], [[4n]], []]))]));
    await eqRet('rNest3 deep', callData('rNest3(uint256[][][])', [A(encNest3([[[]], [[1n, 2n, 3n], [], [4n]]]))]));
    await eqRet('rMixNest', callData('rMixNest(uint256,uint256[][],string)', [V(7n), A(encNest([[1n], [2n, 3n]])), A(encStr(LONG))]));
    // memory array sources
    await eqRet('rMemU', encodeCall(sel('rMemU(uint256,uint256,uint256)'), [7n, 8n, 9n]));
    await eqRet('rMemI', encodeCall(sel('rMemI(int64,int64)'), [(1n << 63n) - 1n, M - (1n << 63n)]));
    await eqRet('rMemA', encodeCall(sel('rMemA(address,address)'), [0xabcdn, (1n << 160n) - 1n]));
    await eqRet('rMemU8', encodeCall(sel('rMemU8(uint8,uint8)'), [200n, 5n]));
    await eqRet('rMemB32', encodeCall(sel('rMemB32(bytes32,bytes32)'), [M - 1n, 0x42n]));

    // ===================== G3: events with array data =====================
    await eqLog('e1', callData('e1(uint256[])', [A(encArr(arr))]));
    await eqLog('e1 empty', callData('e1(uint256[])', [A(encArr([]))]));
    await eqLog('e1 big', callData('e1(uint256[])', [A(encArr(bigArr))]));
    await eqLog('e2 (idx tag + arr)', callData('e2(uint256,uint256[])', [V(42n), A(encArr(arr))]));
    await eqLog('e3 (arr+str)', callData('e3(uint256[],string)', [A(encArr(arr)), A(encStr(LONG))]));
    await eqLog('e3 (arr+str empty)', callData('e3(uint256[],string)', [A(encArr([])), A(encStr(''))]));
    await eqLog('e3b (arr+bytes)', callData('e3b(uint256[],bytes)', [A(encArr(arr)), A(encStr(SHORT))]));
    await eqLog('e4 (arr+arr)', callData('e4(uint256[],uint256[])', [A(encArr(arr)), A(encArr([9n, 8n, 7n]))]));
    await eqLog('eAddr', callData('eAddr(address[])', [A(encArr([0x1234n, 0n, (1n << 160n) - 1n]))]));
    await eqLog('eSigned', callData('eSigned(int64[])', [A(encArr([1n, M - 1n, (1n << 63n) - 1n, M - (1n << 63n)]))]));
    await eqLog('eU8', callData('eU8(uint8[])', [A(encArr([0n, 255n, 128n]))]));
    await eqLog('eB32', callData('eB32(bytes32[])', [A(encArr([0n, M - 1n, 0xcafen << 240n]))]));
    await eqLog('eNest', callData('eNest(uint256[][])', [A(encNest([[1n, 2n], [3n], []]))]));
    await eqLog('eNest empty', callData('eNest(uint256[][])', [A(encNest([]))]));
    await eqLog('eNest3', callData('eNest3(uint256[][][])', [A(encNest3([[[1n], [2n, 3n]], [[4n, 5n, 6n]]]))]));
    await eqLog('eMemU', encodeCall(sel('eMemU(uint256,uint256)'), [11n, 22n]));
    await eqLog('eMemA', encodeCall(sel('eMemA(address,address,address)'), [0xa1n, 0xa2n, 0xa3n]));

    // ===================== G4: indexed bytes/string topic =====================
    for (const s of [SHORT, EXACT, LONG, '', HUGE]) {
      await eqLog(`es("${s.slice(0, 6)}")`, callData('es(string,uint256)', [A(encStr(s)), V(7n)]));
      await eqLog(`eb("${s.slice(0, 6)}")`, callData('eb(bytes,uint256)', [A(encStr(s)), V(9n)]));
      await eqLog(`eonly("${s.slice(0, 6)}")`, callData('eonly(string)', [A(encStr(s))]));
    }
    await eqLog('emix', callData('emix(uint256,string,uint256)', [V(42n), A(encStr(LONG)), V(100n)]));
    await eqLog('emix empty', callData('emix(uint256,string,uint256)', [V(0n), A(encStr('')), V(1n)]));
    await eqLog('etwo', callData('etwo(string,string)', [A(encStr(SHORT)), A(encStr(LONG))]));
    await eqLog('etwo empty/exact', callData('etwo(string,string)', [A(encStr('')), A(encStr(EXACT))]));
    await eqLog('etwo exact/exact', callData('etwo(string,string)', [A(encStr(EXACT)), A(encStr(EXACT))]));
    await eqLog('eidxArr', callData('eidxArr(bytes,uint256[])', [A(encStr(LONG)), A(encArr(arr))]));
    await eqLog('eidxArr empty bytes', callData('eidxArr(bytes,uint256[])', [A(encStr('')), A(encArr([]))]));

    // ===================== G6: Arr<u256[],3> (uint256[][3]) =====================
    for (const v of [11n, 12n, 13n]) await send(encodeCall(sel('pushA(uint256,uint256)'), [0n, v]));
    for (const v of [21n, 22n]) await send(encodeCall(sel('pushA(uint256,uint256)'), [1n, v]));
    // a[2] stays empty (varied row lengths)
    await send(encodeCall(sel('setA(uint256,uint256,uint256)'), [0n, 1n, 99n]));
    await eqRet('lenA(0)', encodeCall(sel('lenA(uint256)'), [0n]));
    await eqRet('lenA(1)', encodeCall(sel('lenA(uint256)'), [1n]));
    await eqRet('lenA(2) empty', encodeCall(sel('lenA(uint256)'), [2n]));
    await eqRet('getA(0,1)', encodeCall(sel('getA(uint256,uint256)'), [0n, 1n]));
    await eqRet('getA(0,2)', encodeCall(sel('getA(uint256,uint256)'), [0n, 2n]));
    await eqRet('getA(1,1)', encodeCall(sel('getA(uint256,uint256)'), [1n, 1n]));
    // raw slots: a is uint256[][3] at base slot 1: a[i].length @ slot 1+i; a[i][j] @ keccak(1+i)+j
    await eqSlot(1n, 'a[0].length');
    await eqSlot(2n, 'a[1].length');
    await eqSlot(3n, 'a[2].length (empty)');
    await eqSlot(kc(1n) + 0n, 'a[0][0]');
    await eqSlot(kc(1n) + 1n, 'a[0][1]');
    await eqSlot(kc(1n) + 2n, 'a[0][2]');
    await eqSlot(kc(2n) + 0n, 'a[1][0]');
    await eqSlot(kc(2n) + 1n, 'a[1][1]');

    // G6: Arr<bytes32[],2> (bytes32[][2]) at base slot 4
    for (const v of [0x11n << 248n, 0x22n << 248n]) await send(encodeCall(sel('pushAb(uint256,bytes32)'), [0n, v]));
    await send(encodeCall(sel('pushAb(uint256,bytes32)'), [1n, M - 1n]));
    await eqRet('lenAb(0)', encodeCall(sel('lenAb(uint256)'), [0n]));
    await eqRet('getAb(0,0)', encodeCall(sel('getAb(uint256,uint256)'), [0n, 0n]));
    await eqRet('getAb(1,0)', encodeCall(sel('getAb(uint256,uint256)'), [1n, 0n]));
    await eqSlot(4n, 'ab[0].length');
    await eqSlot(5n, 'ab[1].length');
    await eqSlot(kc(4n) + 0n, 'ab[0][0]');
    await eqSlot(kc(4n) + 1n, 'ab[0][1]');
    await eqSlot(kc(5n) + 0n, 'ab[1][0]');

    // ===================== G6: Arr<u256,2>[] (uint256[2][]) at slot 7 =====================
    await send(encodeCall(sel('pushB()'), []));
    await send(encodeCall(sel('pushB()'), []));
    await send(encodeCall(sel('pushB()'), []));
    for (const [i, j, v] of [[0n, 0n, 100n], [0n, 1n, 101n], [1n, 0n, 110n], [2n, 1n, 121n]] as [bigint, bigint, bigint][])
      await send(encodeCall(sel('setB(uint256,uint256,uint256)'), [i, j, v]));
    await eqRet('lenB', encodeCall(sel('lenB()'), []));
    await eqRet('getB(0,1)', encodeCall(sel('getB(uint256,uint256)'), [0n, 1n]));
    await eqRet('getB(2,1)', encodeCall(sel('getB(uint256,uint256)'), [2n, 1n]));
    await eqSlot(7n, 'b.length');
    await eqSlot(kc(7n) + 0n, 'b[0][0]');
    await eqSlot(kc(7n) + 1n, 'b[0][1]');
    await eqSlot(kc(7n) + 2n, 'b[1][0]');
    await eqSlot(kc(7n) + 5n, 'b[2][1]');

    // G6: Arr<u256,3>[] (uint256[3][]) at slot 8
    await send(encodeCall(sel('pushC()'), []));
    await send(encodeCall(sel('pushC()'), []));
    for (const [i, j, v] of [[0n, 0n, 300n], [0n, 2n, 302n], [1n, 1n, 311n]] as [bigint, bigint, bigint][])
      await send(encodeCall(sel('setC(uint256,uint256,uint256)'), [i, j, v]));
    await eqRet('lenC', encodeCall(sel('lenC()'), []));
    await eqRet('getC(0,2)', encodeCall(sel('getC(uint256,uint256)'), [0n, 2n]));
    await eqRet('getC(1,1)', encodeCall(sel('getC(uint256,uint256)'), [1n, 1n]));
    await eqSlot(8n, 'c.length');
    await eqSlot(kc(8n) + 0n, 'c[0][0]');
    await eqSlot(kc(8n) + 2n, 'c[0][2]');
    await eqSlot(kc(8n) + 4n, 'c[1][1]');

    // G6: Arr<u256,5>[] (uint256[5][]) at slot 9
    await send(encodeCall(sel('pushD()'), []));
    await send(encodeCall(sel('pushD()'), []));
    for (const [i, j, v] of [[0n, 0n, 500n], [0n, 4n, 504n], [1n, 2n, 512n]] as [bigint, bigint, bigint][])
      await send(encodeCall(sel('setD(uint256,uint256,uint256)'), [i, j, v]));
    await eqRet('lenD', encodeCall(sel('lenD()'), []));
    await eqRet('getD(0,4)', encodeCall(sel('getD(uint256,uint256)'), [0n, 4n]));
    await eqRet('getD(1,2)', encodeCall(sel('getD(uint256,uint256)'), [1n, 2n]));
    await eqSlot(9n, 'd.length');
    await eqSlot(kc(9n) + 0n, 'd[0][0]');
    await eqSlot(kc(9n) + 4n, 'd[0][4]');
    await eqSlot(kc(9n) + 7n, 'd[1][2]');

    // ===================== G6: PACKED fixed elements =====================
    // pk8 uint8[4][] at slot 10: each element = uint8[4] packed in ONE slot at keccak(10)+i
    await send(encodeCall(sel('pushPk8()'), []));
    await send(encodeCall(sel('pushPk8()'), []));
    for (const [i, j, v] of [[0n, 0n, 1n], [0n, 3n, 4n], [1n, 1n, 9n], [1n, 2n, 200n]] as [bigint, bigint, bigint][])
      await send(encodeCall(sel('setPk8(uint256,uint256,uint8)'), [i, j, v]));
    await eqRet('getPk8(0,0)', encodeCall(sel('getPk8(uint256,uint256)'), [0n, 0n]));
    await eqRet('getPk8(0,3)', encodeCall(sel('getPk8(uint256,uint256)'), [0n, 3n]));
    await eqRet('getPk8(1,2)', encodeCall(sel('getPk8(uint256,uint256)'), [1n, 2n]));
    await eqSlot(10n, 'pk8.length');
    await eqSlot(kc(10n) + 0n, 'pk8[0] packed (1 slot)');
    await eqSlot(kc(10n) + 1n, 'pk8[1] packed (1 slot)');

    // pk16 uint16[8][] at slot 11: each element = uint16[8] packed in ONE slot at keccak(11)+i
    await send(encodeCall(sel('pushPk16()'), []));
    await send(encodeCall(sel('pushPk16()'), []));
    for (const [i, j, v] of [[0n, 0n, 0x1111n], [0n, 7n, 0x7777n], [1n, 3n, 0xffffn], [1n, 4n, 0x1234n]] as [bigint, bigint, bigint][])
      await send(encodeCall(sel('setPk16(uint256,uint256,uint16)'), [i, j, v]));
    await eqRet('getPk16(0,0)', encodeCall(sel('getPk16(uint256,uint256)'), [0n, 0n]));
    await eqRet('getPk16(0,7)', encodeCall(sel('getPk16(uint256,uint256)'), [0n, 7n]));
    await eqRet('getPk16(1,3)', encodeCall(sel('getPk16(uint256,uint256)'), [1n, 3n]));
    await eqRet('getPk16(1,4)', encodeCall(sel('getPk16(uint256,uint256)'), [1n, 4n]));
    await eqSlot(11n, 'pk16.length');
    await eqSlot(kc(11n) + 0n, 'pk16[0] packed (1 slot, 8x16=128bit)');
    await eqSlot(kc(11n) + 1n, 'pk16[1] packed');

    // pkI64 int64[2][] at slot 12: each element = int64[2] packed in ONE slot at keccak(12)+i
    await send(encodeCall(sel('pushPkI64()'), []));
    await send(encodeCall(sel('pushPkI64()'), []));
    for (const [i, j, v] of [[0n, 0n, (1n << 63n) - 1n], [0n, 1n, M - (1n << 63n)], [1n, 0n, M - 1n], [1n, 1n, 42n]] as [bigint, bigint, bigint][])
      await send(encodeCall(sel('setPkI64(uint256,uint256,int64)'), [i, j, v]));
    await eqRet('getPkI64(0,0) max', encodeCall(sel('getPkI64(uint256,uint256)'), [0n, 0n]));
    await eqRet('getPkI64(0,1) min', encodeCall(sel('getPkI64(uint256,uint256)'), [0n, 1n]));
    await eqRet('getPkI64(1,0) -1', encodeCall(sel('getPkI64(uint256,uint256)'), [1n, 0n]));
    await eqRet('getPkI64(1,1) 42', encodeCall(sel('getPkI64(uint256,uint256)'), [1n, 1n]));
    await eqSlot(12n, 'pkI64.length');
    await eqSlot(kc(12n) + 0n, 'pkI64[0] packed (2x64=128bit, sign in slot)');
    await eqSlot(kc(12n) + 1n, 'pkI64[1] packed');

    // ba bytes32[2][] at slot 13: full-word fixed element, stride 2
    await send(encodeCall(sel('pushBa()'), []));
    await send(encodeCall(sel('pushBa()'), []));
    for (const [i, j, v] of [[0n, 0n, 0xaan << 248n], [0n, 1n, 0xbbn << 248n], [1n, 1n, M - 1n]] as [bigint, bigint, bigint][])
      await send(encodeCall(sel('setBa(uint256,uint256,bytes32)'), [i, j, v]));
    await eqRet('getBa(0,1)', encodeCall(sel('getBa(uint256,uint256)'), [0n, 1n]));
    await eqRet('getBa(1,1)', encodeCall(sel('getBa(uint256,uint256)'), [1n, 1n]));
    await eqSlot(13n, 'ba.length');
    await eqSlot(kc(13n) + 0n, 'ba[0][0]');
    await eqSlot(kc(13n) + 1n, 'ba[0][1]');
    await eqSlot(kc(13n) + 3n, 'ba[1][1]');

    // ad address[2][] at slot 14: address fixed element, stride 2 (one word each)
    await send(encodeCall(sel('pushAd()'), []));
    await send(encodeCall(sel('pushAd()'), []));
    for (const [i, j, v] of [[0n, 0n, 0xdeadn], [0n, 1n, (1n << 160n) - 1n], [1n, 0n, 0xbeefn]] as [bigint, bigint, bigint][])
      await send(encodeCall(sel('setAd(uint256,uint256,address)'), [i, j, v]));
    await eqRet('getAd(0,1)', encodeCall(sel('getAd(uint256,uint256)'), [0n, 1n]));
    await eqRet('getAd(1,0)', encodeCall(sel('getAd(uint256,uint256)'), [1n, 0n]));
    await eqSlot(14n, 'ad.length');
    await eqSlot(kc(14n) + 0n, 'ad[0][0]');
    await eqSlot(kc(14n) + 1n, 'ad[0][1]');
    await eqSlot(kc(14n) + 2n, 'ad[1][0]');

    // dd uint256[2][2][] at slot 15: element = uint256[2][2] (4 words), stride 4
    await send(encodeCall(sel('pushDd()'), []));
    await send(encodeCall(sel('pushDd()'), []));
    for (const [i, j, k, v] of [[0n, 0n, 0n, 1000n], [0n, 0n, 1n, 1001n], [0n, 1n, 0n, 1010n], [0n, 1n, 1n, 1011n], [1n, 1n, 1n, 1111n]] as [bigint, bigint, bigint, bigint][])
      await send(encodeCall(sel('setDd(uint256,uint256,uint256,uint256)'), [i, j, k, v]));
    await eqRet('lenDd', encodeCall(sel('lenDd()'), []));
    await eqRet('getDd(0,1,1)', encodeCall(sel('getDd(uint256,uint256,uint256)'), [0n, 1n, 1n]));
    await eqRet('getDd(1,1,1)', encodeCall(sel('getDd(uint256,uint256,uint256)'), [1n, 1n, 1n]));
    await eqSlot(15n, 'dd.length');
    await eqSlot(kc(15n) + 0n, 'dd[0][0][0]');
    await eqSlot(kc(15n) + 1n, 'dd[0][0][1]');
    await eqSlot(kc(15n) + 2n, 'dd[0][1][0]');
    await eqSlot(kc(15n) + 3n, 'dd[0][1][1]');
    await eqSlot(kc(15n) + 7n, 'dd[1][1][1]');

    // ===================== sentinels (slot over/underflow detection) =====================
    await send(encodeCall(sel('setS0(uint256)'), [0xdead0000n]));
    await send(encodeCall(sel('setS1(uint256)'), [0xdead1111n]));
    await send(encodeCall(sel('setS2(uint256)'), [0xdead2222n]));
    await eqSlot(0n, 's0 sentinel (before composites)');
    await eqSlot(6n, 's1 sentinel (between regions)');
    await eqSlot(16n, 's2 sentinel (after composites)');

    if (mism.length) {
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 40)) console.log(m);
    } else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
