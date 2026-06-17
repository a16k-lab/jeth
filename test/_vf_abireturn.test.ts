// VF probe: ABI RETURN encoding of complex types. Focus areas:
//  - struct with BOTH fixed and dynamic fields (head inline + dyn head-offset/tail)
//  - array of structs each carrying a dynamic field (D[] where D has string/bytes)
//  - nested dynamic returns: string[], bytes[], u256[][]
//  - multi-value returns (tuples) mixing value / bytes / struct / dynamic-array
//  - empty dynamic returns (empty arrays, empty strings/bytes, empty struct arrays)
// Compares returnHex byte-for-byte (head/tail offsets included) against solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const sel = (s: string) => functionSelector(s);
const enc = new TextEncoder();
const A1 = BigInt('0x' + '11'.repeat(20));
const A2 = BigInt('0x' + '22'.repeat(20));
const AMAX = (1n << 160n) - 1n;

// Right-pad raw bytes to 32-byte multiple, hex (no 0x). 0-length -> no payload word.
function padData(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';
  const words = Math.ceil(bytes.length / 32);
  let h = '';
  for (let i = 0; i < words * 32; i++) h += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  return h;
}
const sb = (str: string) => enc.encode(str);
// Encode one dynamic bytes/string element: [len][padded data].
function dynElem(bytes: Uint8Array): string {
  return pad(BigInt(bytes.length)) + padData(bytes);
}

// Encode a string[]/bytes[] DATA REGION (no outer offset): [len][offset table][payloads].
function encodeArrayRegion(strs: Uint8Array[]): string {
  const L = strs.length;
  const payloads = strs.map(dynElem);
  let offBytes = L * 32;
  let table = '';
  for (const p of payloads) {
    table += pad(BigInt(offBytes));
    offBytes += p.length / 2;
  }
  return pad(BigInt(L)) + table + payloads.join('');
}

const JETH = `
@struct class FD { a: u256; s: string; }                 // fixed then dynamic
@struct class DF { s: string; a: u256; }                 // dynamic then fixed
@struct class Mix { p: u64; q: u64; s: string; b: bytes; z: u256; } // packed p,q + 2 dyn + tail value
@struct class TwoDyn { s: string; t: string; }           // two dynamic fields
@struct class Nest { x: u256; inner: FD; y: u256; }       // dynamic struct field
@struct class StatPack { a: u128; b: u128; c: bool; }     // fully static (packs)
@contract class C {
  @state recs: FD[];
  @state mixes: Mix[];
  @state stats: StatPack[];
  @state names: string[];
  @state blobs: bytes[];
  @state grid: u256[][];
  @state vals: u256[];
  @state empties: string[];
  @state fd1: FD;
  @state fd2: FD;

  @external pushVal(v: u256): void { this.vals.push(v); }
  @external setFd1(a: u256, s: string): void { this.fd1 = FD(a, s); }
  @external setFd2(a: u256, s: string): void { this.fd2 = FD(a, s); }

  // --- struct with fixed + dynamic, built from args ---
  @external @pure mkFD(a: u256, s: string): FD { return FD(a, s); }
  @external @pure mkDF(s: string, a: u256): DF { return DF(s, a); }
  @external @pure mkMix(p: u64, q: u64, s: string, b: bytes, z: u256): Mix { return Mix(p, q, s, b, z); }
  @external @pure mkTwoDyn(s: string, t: string): TwoDyn { return TwoDyn(s, t); }
  @external @pure mkNest(x: u256, a: u256, s: string, y: u256): Nest { return Nest(x, FD(a, s), y); }
  @external @pure echoFD(d: FD): FD { return d; }
  @external @pure echoMix(m: Mix): Mix { return m; }
  @external @pure echoVals(a: u256, b: address, c: bool, d: u8, e: i8, f: bytes4): [u256, address, bool, u8, i8, bytes4] { return [a, b, c, d, e, f]; }

  // --- struct array (each element carries dynamic field), from storage ---
  @external pushFD(a: u256, s: string): void { this.recs.push(FD(a, s)); }
  @view allFD(): FD[] { return this.recs; }
  @external pushMix(p: u64, q: u64, s: string, b: bytes, z: u256): void { this.mixes.push(Mix(p, q, s, b, z)); }
  @view allMix(): Mix[] { return this.mixes; }
  @external pushStat(a: u128, b: u128, c: bool): void { this.stats.push(StatPack(a, b, c)); }
  @view allStat(): StatPack[] { return this.stats; }

  // --- nested dynamic returns from storage ---
  @external pushName(s: string): void { this.names.push(s); }
  @view allNames(): string[] { return this.names; }
  @external pushBlob(b: bytes): void { this.blobs.push(b); }
  @view allBlobs(): bytes[] { return this.blobs; }
  @external gridPush(): void { this.grid.push(); }
  @external gridPushInner(i: u256, v: u256): void { this.grid[i].push(v); }
  @view allGrid(): u256[][] { return this.grid; }

  // --- nested dynamic returns echoed (pure, from calldata) ---
  @external @pure echoNames(a: string[]): string[] { return a; }
  @external @pure echoBlobs(a: bytes[]): bytes[] { return a; }
  @external @pure echoGrid(a: u256[][]): u256[][] { return a; }

  // --- multi-value returns mixing components ---
  @external @pure mvValStr(n: u256, s: string): [u256, string] { return [n, s]; }
  @external @pure mvStrVal(s: string, n: u256): [string, u256] { return [s, n]; }
  @external @pure mvTwoStr(a: string, b: string): [string, string] { return [a, b]; }
  @external @pure mvValBytesVal(n: u256, b: bytes, m: u256): [u256, bytes, u256] { return [n, b, m]; }
  @view mvStructVal(n: u256): [FD, u256] { return [this.fd1, n]; }
  @view mvValStruct(n: u256): [u256, FD] { return [n, this.fd1]; }
  @view mvStructStruct(): [FD, FD] { return [this.fd1, this.fd2]; }
  @external @pure mvAllStatic(a: u256, b: address, c: bool): [u256, address, bool] { return [a, b, c]; }
  @view mvArrVal(n: u256): [u256[], u256] { return [this.vals, n]; }
  @view mvStrArr(n: u256): [string[], u256] { return [this.names, n]; }

  // --- empty dynamic returns (storage-backed empties + literals) ---
  @external @pure emptyStr(): string { return ""; }
  @view emptyArr(): u256[] { return this.vals; }
  @view emptyStrArr(): string[] { return this.empties; }
  @external @pure emptyStructWithEmptyStr(): FD { return FD(0n, ""); }
  @external @pure passBytes(b: bytes): bytes { return b; }
}`;

const JETH2 = JETH;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct FD { uint256 a; string s; }
  struct DF { string s; uint256 a; }
  struct Mix { uint64 p; uint64 q; string s; bytes b; uint256 z; }
  struct TwoDyn { string s; string t; }
  struct Nest { uint256 x; FD inner; uint256 y; }
  struct StatPack { uint128 a; uint128 b; bool c; }
  FD[] recs;
  Mix[] mixes;
  StatPack[] stats;
  string[] names;
  bytes[] blobs;
  uint256[][] grid;
  uint256[] vals;
  string[] empties;
  FD fd1;
  FD fd2;
  function pushVal(uint256 v) external { vals.push(v); }
  function setFd1(uint256 a, string calldata s) external { fd1 = FD(a, s); }
  function setFd2(uint256 a, string calldata s) external { fd2 = FD(a, s); }

  function mkFD(uint256 a, string calldata s) external pure returns (FD memory){ return FD(a, s); }
  function mkDF(string calldata s, uint256 a) external pure returns (DF memory){ return DF(s, a); }
  function mkMix(uint64 p, uint64 q, string calldata s, bytes calldata b, uint256 z) external pure returns (Mix memory){ return Mix(p, q, s, b, z); }
  function mkTwoDyn(string calldata s, string calldata t) external pure returns (TwoDyn memory){ return TwoDyn(s, t); }
  function mkNest(uint256 x, uint256 a, string calldata s, uint256 y) external pure returns (Nest memory){ return Nest(x, FD(a, s), y); }
  function echoFD(FD calldata d) external pure returns (FD memory){ return d; }
  function echoMix(Mix calldata m) external pure returns (Mix memory){ return m; }
  function echoVals(uint256 a, address b, bool c, uint8 d, int8 e, bytes4 f) external pure returns (uint256, address, bool, uint8, int8, bytes4){ return (a, b, c, d, e, f); }

  function pushFD(uint256 a, string calldata s) external { recs.push(FD(a, s)); }
  function allFD() external view returns (FD[] memory){ return recs; }
  function pushMix(uint64 p, uint64 q, string calldata s, bytes calldata b, uint256 z) external { mixes.push(Mix(p, q, s, b, z)); }
  function allMix() external view returns (Mix[] memory){ return mixes; }
  function pushStat(uint128 a, uint128 b, bool c) external { stats.push(StatPack(a, b, c)); }
  function allStat() external view returns (StatPack[] memory){ return stats; }

  function pushName(string calldata s) external { names.push(s); }
  function allNames() external view returns (string[] memory){ return names; }
  function pushBlob(bytes calldata b) external { blobs.push(b); }
  function allBlobs() external view returns (bytes[] memory){ return blobs; }
  function gridPush() external { grid.push(); }
  function gridPushInner(uint256 i, uint256 v) external { grid[i].push(v); }
  function allGrid() external view returns (uint256[][] memory){ return grid; }

  function echoNames(string[] calldata a) external pure returns (string[] memory){ return a; }
  function echoBlobs(bytes[] calldata a) external pure returns (bytes[] memory){ return a; }
  function echoGrid(uint256[][] calldata a) external pure returns (uint256[][] memory){ return a; }

  function mvValStr(uint256 n, string calldata s) external pure returns (uint256, string memory){ return (n, s); }
  function mvStrVal(string calldata s, uint256 n) external pure returns (string memory, uint256){ return (s, n); }
  function mvTwoStr(string calldata a, string calldata b) external pure returns (string memory, string memory){ return (a, b); }
  function mvValBytesVal(uint256 n, bytes calldata b, uint256 m) external pure returns (uint256, bytes memory, uint256){ return (n, b, m); }
  function mvStructVal(uint256 n) external view returns (FD memory, uint256){ return (fd1, n); }
  function mvValStruct(uint256 n) external view returns (uint256, FD memory){ return (n, fd1); }
  function mvStructStruct() external view returns (FD memory, FD memory){ return (fd1, fd2); }
  function mvAllStatic(uint256 a, address b, bool c) external pure returns (uint256, address, bool){ return (a, b, c); }
  function mvArrVal(uint256 n) external view returns (uint256[] memory, uint256){ return (vals, n); }
  function mvStrArr(uint256 n) external view returns (string[] memory, uint256){ return (names, n); }

  function emptyStr() external pure returns (string memory){ return ""; }
  function emptyArr() external view returns (uint256[] memory){ return vals; }
  function emptyStrArr() external view returns (string[] memory){ return empties; }
  function emptyStructWithEmptyStr() external pure returns (FD memory){ return FD(0, ""); }
  function passBytes(bytes calldata b) external pure returns (bytes memory){ return b; }
}`;

// ---- calldata builders ----------------------------------------------------

// Single dynamic head/tail (one bytes/string param at head position 0).
function call1Dyn(sig: string, head: bigint[], bytes: Uint8Array): string {
  // head holds placeholders; dyn arg sits at offset = head.length*32 (assumes 1 dyn last).
  let h = '0x' + sel(sig);
  for (const w of head) h += pad(w);
  h += dynElem(bytes);
  return h;
}

// (uint256 n, string s) -> head [n][off=0x40], tail string.
function callValStr(sig: string, n: bigint, s: Uint8Array): string {
  return '0x' + sel(sig) + pad(n) + pad(0x40n) + dynElem(s);
}
// (string s, uint256 n) -> head [off=0x40][n], tail string.
function callStrVal(sig: string, s: Uint8Array, n: bigint): string {
  return '0x' + sel(sig) + pad(0x40n) + pad(n) + dynElem(s);
}
// (uint256 n, bytes b, uint256 m) -> head [n][off=0x60][m], tail bytes.
function callValBytesVal(sig: string, n: bigint, b: Uint8Array, m: bigint): string {
  return '0x' + sel(sig) + pad(n) + pad(0x60n) + pad(m) + dynElem(b);
}
// (string a, string b) -> two tails.
function callTwoStr(sig: string, a: Uint8Array, b: Uint8Array): string {
  const ea = dynElem(a), eb = dynElem(b);
  const offA = 0x40n;
  const offB = 0x40n + BigInt(ea.length / 2);
  return '0x' + sel(sig) + pad(offA) + pad(offB) + ea + eb;
}
// (FD d) where FD={uint256 a; string s}: a dynamic tuple. head=[off=0x20], then tuple: [a][off=0x40][s].
function callFD(sig: string, a: bigint, s: Uint8Array): string {
  const tuple = pad(a) + pad(0x40n) + dynElem(s);
  return '0x' + sel(sig) + pad(0x20n) + tuple;
}
// (Mix m) where Mix={u64 p;u64 q;string s;bytes b;u256 z}. dynamic tuple.
// tuple head: [p][q][off_s][off_b][z]; off relative to tuple start.
function callMix(sig: string, p: bigint, q: bigint, s: Uint8Array, b: Uint8Array, z: bigint): string {
  const es = dynElem(s), eb = dynElem(b);
  const headWords = 5;
  const offS = BigInt(headWords * 32);
  const offB = offS + BigInt(es.length / 2);
  const tuple = pad(p) + pad(q) + pad(offS) + pad(offB) + pad(z) + es + eb;
  return '0x' + sel(sig) + pad(0x20n) + tuple;
}
// string[] / bytes[] sole param.
function callArr1(sig: string, strs: Uint8Array[]): string {
  return '0x' + sel(sig) + pad(0x20n) + encodeArrayRegion(strs);
}
// (string s, uint256[] x) -> head [off_s][off_x], tail string then array.
function callStrArr(sig: string, s: Uint8Array, x: bigint[]): string {
  const es = dynElem(s);
  const offS = 0x40n;
  const offX = 0x40n + BigInt(es.length / 2);
  let arrTail = pad(BigInt(x.length));
  for (const v of x) arrTail += pad(v);
  return '0x' + sel(sig) + pad(offS) + pad(offX) + es + arrTail;
}
// (uint256[] x, uint256 n) -> head [off_x=0x40][n], tail array.
function callArrVal(sig: string, x: bigint[], n: bigint): string {
  let arr = pad(BigInt(x.length));
  for (const v of x) arr += pad(v);
  return '0x' + sel(sig) + pad(0x40n) + pad(n) + arr;
}
// u256[][] sole param: outer off=0x20, then [len][inner off table][inner arrays].
function encode2D(rows: bigint[][]): string {
  const L = rows.length;
  const innerEncs = rows.map((r) => {
    let h = pad(BigInt(r.length));
    for (const v of r) h += pad(v);
    return h;
  });
  let off = L * 32;
  let table = '';
  for (const e of innerEncs) {
    table += pad(BigInt(off));
    off += e.length / 2;
  }
  return pad(BigInt(L)) + table + innerEncs.join('');
}
function callGrid(sig: string, rows: bigint[][]): string {
  return '0x' + sel(sig) + pad(0x20n) + encode2D(rows);
}

describe('VF abireturn', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;
  async function eq(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success || j.returnHex !== s.returnHex)
      mism.push(
        label +
          ': jeth{ok=' + j.success + ',ret=' + j.returnHex + ',err=' + j.exceptionError + '} sol{ok=' + s.success + ',ret=' + s.returnHex + '}',
      );
  }
  async function send(data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    // sanity: both sides should agree on send success too
    if (j.success !== s.success) mism.push('SEND ' + data.slice(0, 12) + ': jeth ok=' + j.success + ' err=' + j.exceptionError + ' sol ok=' + s.success);
  }

  beforeAll(async () => {
    const jb = compile(JETH2, { fileName: 'C.jeth' });
    const sbld = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sbld.creation);
  });

  it('runs', async () => {
    // string-length boundary corpus
    const strs: [string, Uint8Array][] = [
      ['empty', sb('')],
      ['1', sb('a')],
      ['31', sb('Y'.repeat(31))],
      ['32', sb('Z'.repeat(32))],
      ['33', sb('W'.repeat(33))],
      ['63', sb('q'.repeat(63))],
      ['64', sb('r'.repeat(64))],
      ['65', sb('s'.repeat(65))],
      ['100', sb('X'.repeat(100))],
    ];
    // ---- empty dynamic returns (checked FIRST, before any storage is seeded) ----
    await eq('emptyArr (vals empty)', encodeCall(sel('emptyArr()'), []));
    await eq('emptyStrArr (empties empty)', encodeCall(sel('emptyStrArr()'), []));

    // ---- struct FD{a; s}: fixed+dynamic, built from args ----
    for (const [ln, s] of strs)
      for (const v of [0n, M - 1n, 1n << 128n]) await eq(`mkFD a=${v} s=${ln}`, callValStr('mkFD(uint256,string)', v, s));
    // ---- struct DF{s; a}: dynamic-then-fixed ----
    for (const [ln, s] of strs)
      for (const v of [0n, M - 1n]) await eq(`mkDF s=${ln} a=${v}`, callStrVal('mkDF(string,uint256)', s, v));
    // ---- echo FD (decode + re-encode) ----
    for (const [ln, s] of strs)
      for (const v of [7n, M - 1n]) await eq(`echoFD a=${v} s=${ln}`, callFD('echoFD((uint256,string))', v, s));

    // ---- Mix{p;q;s;b;z}: packed statics + 2 dyn + tail value ----
    const blobs: [string, Uint8Array][] = [
      ['e', new Uint8Array(0)],
      ['1', new Uint8Array([0xff])],
      ['32', new Uint8Array(32).fill(0xab)],
      ['40', new Uint8Array(40).map((_, k) => (k * 13) & 0xff)],
    ];
    for (const [sn, s] of [strs[0], strs[2], strs[4], strs[6]] as [string, Uint8Array][])
      for (const [bn, b] of blobs)
        await eq(`mkMix s=${sn} b=${bn}`, callMix('mkMix(uint64,uint64,string,bytes,uint256)', 0xdeadn, 0xbeefn, s, b, (1n << 200n) | 9n));
    for (const [sn, s] of [strs[1], strs[3], strs[5]] as [string, Uint8Array][])
      for (const [bn, b] of blobs)
        await eq(`echoMix s=${sn} b=${bn}`, callMix('echoMix((uint64,uint64,string,bytes,uint256))', 1n, 2n, s, b, 0n));

    // ---- TwoDyn{s; t} construct ----
    for (const [an, a] of [strs[0], strs[2], strs[4]] as [string, Uint8Array][])
      for (const [bn, b] of [strs[1], strs[3], strs[6]] as [string, Uint8Array][])
        await eq(`mkTwoDyn ${an}/${bn}`, callTwoStr('mkTwoDyn(string,string)', a, b));

    // ---- Nest{x; FD inner; y}: nested dynamic struct field ----
    // mkNest has 4 args (x,a,s,y); build proper calldata: head [x][a][off_s=0x80][y], tail string.
    for (const [ln, s] of strs)
      for (const [x, a, y] of [[1n, 2n, 3n], [M - 1n, 0n, 1n << 128n]] as [bigint, bigint, bigint][]) {
        const data = '0x' + sel('mkNest(uint256,uint256,string,uint256)') + pad(x) + pad(a) + pad(0x80n) + pad(y) + dynElem(s);
        await eq(`mkNest x=${x} s=${ln} y=${y}`, data);
      }

    // ---- struct array FD[] each with dynamic field (from storage) ----
    await eq('allFD empty', encodeCall(sel('allFD()'), []));
    const fdSeed: [bigint, string][] = [[10n, ''], [20n, 'hi'], [30n, 'Z'.repeat(32)], [40n, 'Q'.repeat(70)], [50n, 'm'.repeat(33)]];
    for (let i = 0; i < fdSeed.length; i++) {
      const [a, s] = fdSeed[i]!;
      await send(callValStr('pushFD(uint256,string)', a, sb(s)));
      await eq(`allFD n=${i + 1}`, encodeCall(sel('allFD()'), []));
    }
    // ---- struct array Mix[] each with TWO dynamic fields + packed statics + tail value.
    //      This is the gnarliest return shape: element offset table -> per-element tuple
    //      with its own two dynamic head-offsets. Mix string/bytes lengths across boundary.
    function callPushMix(p: bigint, q: bigint, str: Uint8Array, byt: Uint8Array, z: bigint): string {
      const es = dynElem(str), eb = dynElem(byt);
      const offS = BigInt(5 * 32);
      const offB = offS + BigInt(es.length / 2);
      return '0x' + sel('pushMix(uint64,uint64,string,bytes,uint256)') + pad(p) + pad(q) + pad(offS) + pad(offB) + pad(z) + es + eb;
    }
    await eq('allMix empty', encodeCall(sel('allMix()'), []));
    const mixSeed: [bigint, bigint, string, Uint8Array, bigint][] = [
      [1n, 2n, '', new Uint8Array(0), 0n],
      [0xffffn, 0xeeeen, 'hi', new Uint8Array([0xaa, 0xbb]), M - 1n],
      [3n, 4n, 'Z'.repeat(32), new Uint8Array(33).fill(0xcd), 1n << 200n],
      [5n, 6n, 'W'.repeat(65), new Uint8Array(0), 7n],
      [7n, 8n, '', new Uint8Array(64).map((_, k) => k & 0xff), 9n],
    ];
    for (let i = 0; i < mixSeed.length; i++) {
      const [p, q, str, byt, z] = mixSeed[i]!;
      await send(callPushMix(p, q, sb(str), byt, z));
      await eq(`allMix n=${i + 1}`, encodeCall(sel('allMix()'), []));
    }

    // ---- struct array StatPack[] (fully static, packed) ----
    await eq('allStat empty', encodeCall(sel('allStat()'), []));
    for (const [a, b, c] of [[1n, 2n, 1n], [(1n << 127n) | 5n, 0n, 0n], [AMAX & ((1n << 128n) - 1n), 7n, 1n]] as [bigint, bigint, bigint][]) {
      await send(encodeCall(sel('pushStat(uint128,uint128,bool)'), [a, b, c]));
      await eq('allStat grow', encodeCall(sel('allStat()'), []));
    }

    // ---- nested dynamic from storage: string[], bytes[], u256[][] ----
    await eq('allNames empty', encodeCall(sel('allNames()'), []));
    // pushName(string) has 1 dyn param: outer off=0x20.
    for (const [ln, s] of strs) await send(callArr1Single('pushName(string)', s));
    await eq('allNames full', encodeCall(sel('allNames()'), []));

    await eq('allBlobs empty', encodeCall(sel('allBlobs()'), []));
    for (const [bn, b] of blobs) await send(callArr1Single('pushBlob(bytes)', b));
    await eq('allBlobs full', encodeCall(sel('allBlobs()'), []));

    // grid u256[][]
    await eq('allGrid empty', encodeCall(sel('allGrid()'), []));
    await send(encodeCall(sel('gridPush()'), []));
    await send(encodeCall(sel('gridPush()'), []));
    await send(encodeCall(sel('gridPush()'), []));
    await eq('allGrid 3 empty rows', encodeCall(sel('allGrid()'), []));
    for (const [i, v] of [[0n, 11n], [0n, 12n], [1n, 99n], [2n, 1n], [2n, 2n], [2n, 3n]] as [bigint, bigint][])
      await send(encodeCall(sel('gridPushInner(uint256,uint256)'), [i, v]));
    await eq('allGrid filled', encodeCall(sel('allGrid()'), []));

    // ---- nested dynamic echoed (pure, from calldata) ----
    const nameSets: Uint8Array[][] = [
      [],
      [sb('hello')],
      [sb('ab'), sb(''), sb('X'.repeat(40))],
      [sb('Y'.repeat(31)), sb('Z'.repeat(32)), sb('W'.repeat(33))],
      [sb(''), sb(''), sb('')],
      [sb('a'.repeat(100)), sb('b')],
    ];
    for (let i = 0; i < nameSets.length; i++) await eq(`echoNames #${i}`, callArr1('echoNames(string[])', nameSets[i]!));
    const blobSets: Uint8Array[][] = [
      [],
      [new Uint8Array([0, 1, 2, 255])],
      [new Uint8Array(0), new Uint8Array(50).map((_, k) => (k * 7) & 0xff), new Uint8Array([9])],
      [new Uint8Array(32).fill(1), new Uint8Array(33).fill(2)],
    ];
    for (let i = 0; i < blobSets.length; i++) await eq(`echoBlobs #${i}`, callArr1('echoBlobs(bytes[])', blobSets[i]!));
    const gridSets: bigint[][][] = [
      [],
      [[]],
      [[1n]],
      [[1n, 2n], [3n], []],
      [[], [], []],
      [[M - 1n, 0n, 1n << 255n], [7n]],
    ];
    for (let i = 0; i < gridSets.length; i++) await eq(`echoGrid #${i}`, callGrid('echoGrid(uint256[][])', gridSets[i]!));

    // ---- multi-value returns mixing components ----
    for (const [ln, s] of strs) {
      await eq(`mvValStr s=${ln}`, callValStr('mvValStr(uint256,string)', 42n, s));
      await eq(`mvStrVal s=${ln}`, callStrVal('mvStrVal(string,uint256)', s, 42n));
    }
    // mvStructVal / mvValStruct (storage struct fd1 + value), across the string corpus.
    for (const [ln, s] of strs) {
      await send(callValStr('setFd1(uint256,string)', 0xc0den, s));
      await eq(`mvStructVal s=${ln}`, encodeCall(sel('mvStructVal(uint256)'), [9n]));
      await eq(`mvValStruct s=${ln}`, encodeCall(sel('mvValStruct(uint256)'), [7n]));
    }
    for (const [an, a] of [strs[0], strs[2], strs[4]] as [string, Uint8Array][])
      for (const [bn, b] of [strs[1], strs[5], strs[7]] as [string, Uint8Array][])
        await eq(`mvTwoStr ${an}/${bn}`, callTwoStr('mvTwoStr(string,string)', a, b));
    for (const [bn, b] of blobs)
      await eq(`mvValBytesVal b=${bn}`, callValBytesVal('mvValBytesVal(uint256,bytes,uint256)', 1n, b, 2n));
    // mvStructStruct: two storage structs fd1, fd2 across mixed string lengths.
    for (const [an, a] of [strs[0], strs[3]] as [string, Uint8Array][])
      for (const [bn, b] of [strs[4], strs[6]] as [string, Uint8Array][]) {
        await send(callValStr('setFd1(uint256,string)', 1n, a));
        await send(callValStr('setFd2(uint256,string)', 2n, b));
        await eq(`mvStructStruct ${an}/${bn}`, encodeCall(sel('mvStructStruct()'), []));
      }
    // mvArrVal (storage vals + value) / mvStrArr (storage names string[] + value).
    // names already seeded earlier (full corpus). Seed vals now, checking growth.
    await eq('mvArrVal vals empty', encodeCall(sel('mvArrVal(uint256)'), [0xfen]));
    for (const v of [1n, M - 1n, 1n << 200n, 0n]) {
      await send(encodeCall(sel('pushVal(uint256)'), [v]));
      await eq(`mvArrVal grow`, encodeCall(sel('mvArrVal(uint256)'), [0xfen]));
    }
    await eq('mvStrArr names', encodeCall(sel('mvStrArr(uint256)'), [0x1234n]));
    // mvAllStatic
    for (const [a, b, c] of [[0n, A1, 0n], [M - 1n, AMAX, 1n], [1n << 128n, A2, 1n]] as [bigint, bigint, bigint][])
      await eq(`mvAllStatic`, encodeCall(sel('mvAllStatic(uint256,address,bool)'), [a, b, c]));

    // ---- ADVERSARIAL: non-canonical INPUT offset tables (reordered tails, gaps,
    //      overlapping element offsets). solc accepts any in-range offsets and emits a
    //      CANONICAL return; JETH must reproduce solc byte-for-byte (incl. revert cases). ----
    // echoNames(string[]): outer off=0x20, then region [len][offTable...][payloads].
    // Case A: 2 elements with tails laid out in REVERSE order (offsets still in range).
    {
      const e0 = dynElem(sb('AAAA')); // 1 word len + 1 word data
      const e1 = dynElem(sb('B'.repeat(40))); // 1 word len + 2 words data
      const L = 2;
      const tableBytes = L * 32;
      // put e1 first physically, e0 second; offsets point accordingly.
      const offE1 = tableBytes; // e1 sits right after table
      const offE0 = tableBytes + e1.length / 2;
      const region = pad(BigInt(L)) + pad(BigInt(offE0)) + pad(BigInt(offE1)) + e1 + e0;
      await eq('echoNames reversed tails', '0x' + sel('echoNames(string[])') + pad(0x20n) + region);
    }
    // Case B: a GAP (extra padding word) between table and first payload.
    {
      const e0 = dynElem(sb('hi'));
      const e1 = dynElem(sb('Z'.repeat(33)));
      const L = 2;
      const tableBytes = L * 32;
      const gap = pad(0n); // one filler word
      const offE0 = tableBytes + 32; // skip the gap
      const offE1 = offE0 + e0.length / 2;
      const region = pad(BigInt(L)) + pad(BigInt(offE0)) + pad(BigInt(offE1)) + gap + e0 + e1;
      await eq('echoNames gap-before-payload', '0x' + sel('echoNames(string[])') + pad(0x20n) + region);
    }
    // Case C: OVERLAPPING offsets - both table words point to the SAME element.
    {
      const e0 = dynElem(sb('shared'));
      const e1 = dynElem(sb('other'));
      const L = 2;
      const tableBytes = L * 32;
      const offFirst = tableBytes;
      const region = pad(BigInt(L)) + pad(BigInt(offFirst)) + pad(BigInt(offFirst)) + e0 + e1;
      await eq('echoNames overlapping->first', '0x' + sel('echoNames(string[])') + pad(0x20n) + region);
    }
    // Case D: outer offset != 0x20 (extra leading filler word before the region).
    {
      const region = encodeArrayRegion([sb('p'), sb('qq')]);
      const data = '0x' + sel('echoNames(string[])') + pad(0x40n) + pad(0xdeadn) + region;
      await eq('echoNames outer-off=0x40', data);
    }
    // Case E: echoGrid with a non-canonical inner-array offset table (reversed rows).
    {
      const r0 = pad(2n) + pad(7n) + pad(8n); // len2
      const r1 = pad(1n) + pad(99n); // len1
      const L = 2;
      const tableBytes = L * 32;
      const offR1 = tableBytes;
      const offR0 = tableBytes + r1.length / 2;
      const region = pad(BigInt(L)) + pad(BigInt(offR0)) + pad(BigInt(offR1)) + r1 + r0;
      await eq('echoGrid reversed rows', '0x' + sel('echoGrid(uint256[][])') + pad(0x20n) + region);
    }
    // Case F: echoBlobs overlapping offsets (both -> first), element has dirty trailing
    // pad bytes that solc DROPS on re-encode (length<32 but full word present).
    {
      const e0 = pad(3n) + 'aabbcc' + 'ff'.repeat(29); // declares len 3, but full word has trailing garbage
      const e1 = dynElem(new Uint8Array([1, 2]));
      const L = 2;
      const tableBytes = L * 32;
      const offFirst = tableBytes;
      const offSecond = tableBytes + e0.length / 2;
      const region = pad(BigInt(L)) + pad(BigInt(offFirst)) + pad(BigInt(offSecond)) + e0 + e1;
      await eq('echoBlobs trailing-garbage drop', '0x' + sel('echoBlobs(bytes[])') + pad(0x20n) + region);
    }
    // Case G: string echo (sole) with trailing garbage past declared length - re-encode
    // must zero the pad bytes. passBytes does the same for bytes.
    {
      const data = '0x' + sel('passBytes(bytes)') + pad(0x20n) + pad(5n) + 'deadbeef99' + 'ff'.repeat(27);
      await eq('passBytes trailing-garbage drop', data);
    }

    // ---- ADVERSARIAL: dirty high bits on packed/narrow fields must be masked in the
    //      ABI return exactly as solc does (decode cleans, re-encode is canonical) ----
    // echoMix with dirty p/q (u64) high bits + dirty z is full width.
    for (const dp of [M - 1n, (1n << 100n) | 5n, (1n << 64n) | 0xabn]) {
      await eq(`echoMix dirty p=${dp.toString(16)}`, callMix('echoMix((uint64,uint64,string,bytes,uint256))', dp, M - 1n, sb('hi'), new Uint8Array([1, 2, 3]), M - 1n));
    }
    // echoVals: dirty bool/u8/i8/bytes4 must each be cleaned per solc rules.
    // bytes4 is left-aligned: pass full 32-byte word; low 28 bytes are garbage to be dropped.
    function callEchoVals(a: bigint, b: bigint, c: bigint, d: bigint, e: bigint, f: bigint): string {
      return '0x' + sel('echoVals(uint256,address,bool,uint8,int8,bytes4)') + pad(a) + pad(b) + pad(c) + pad(d) + pad(e) + pad(f);
    }
    const dirtyAddr = [(1n << 200n) | A1, M - 1n, AMAX];
    const dirtyU8 = [0n, 0xffn, 0x100n, (1n << 200n) | 0x42n, M - 1n];
    const dirtyI8 = [0n, 0x7fn, 0x80n, 0xffn, (1n << 200n) | 0x80n, M - 1n];
    const dirtyB4 = [0x11223344n << 224n, M - 1n, (0xdeadbeefn << 224n) | 0x123n, 0n];
    for (const b of dirtyAddr) for (const c of [0n, 1n, 0xffn]) for (const d of dirtyU8) {
      await eq(`echoVals b=${b.toString(16)} c=${c} d=${d.toString(16)}`, callEchoVals(0x99n, b, c, d, 0x7fn, 0x11223344n << 224n));
    }
    for (const e of dirtyI8) for (const f of dirtyB4)
      await eq(`echoVals e=${e.toString(16)} f=${f.toString(16)}`, callEchoVals(1n, A1, 1n, 0x55n, e, f));

    // ---- empty dynamic returns ----
    await eq('emptyStr', encodeCall(sel('emptyStr()'), []));
    await eq('emptyStrArr', encodeCall(sel('emptyStrArr()'), [])); // empties never pushed
    await eq('emptyStructWithEmptyStr', encodeCall(sel('emptyStructWithEmptyStr()'), []));
    await eq('passBytes empty', callArr1Single('passBytes(bytes)', new Uint8Array(0)));
    await eq('passBytes 1', callArr1Single('passBytes(bytes)', new Uint8Array([0xaa])));

    if (mism.length) {
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 40)) console.log(m);
    } else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});

// single dynamic param: outer off=0x20 then [len][data]
function callArr1Single(sig: string, b: Uint8Array): string {
  return '0x' + sel(sig) + pad(0x20n) + dynElem(b);
}
