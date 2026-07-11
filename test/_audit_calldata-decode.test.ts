// _audit_calldata-decode: adversarial differential audit of CALLDATA ABI DECODE
// for function params. Targets the least-covered, most miscompile-prone shapes:
//   - Arr<bytes,2> / Arr<string,2>  (fixed array of DYNAMIC byte sequences)
//   - bytes[] / string[]            (array of dynamic byte sequences)
//   - u256[][] / u256[][][]         (2- and 3-level nested dynamic arrays)
//   - Arr<string[],2>               (fixed array of dynamic array of string)
//   - D[]                           (dynamic array of DYNAMIC struct, string field)
//   - narrow/signed dynamic value arrays (u8[], i8[], i256[], bool[], bytes1[], bytes4[])
//   - struct with fixed-array field / struct with dynamic-array field (echo)
//
// INVARIANT: byte-identical to solc on (success, returnHex) for EVERY case. We
// hand-encode malformed offsets/lengths/bounds and dirty narrow elements and
// assert jeth == solc. A divergence is a P0 miscompile.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const enc = new TextEncoder();

// Right-pad raw bytes to a 32-byte multiple (no 0x). 0-length => no payload word.
function padData(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';
  const words = Math.ceil(bytes.length / 32);
  let h = '';
  for (let i = 0; i < words * 32; i++) h += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  return h;
}
const sb = (s: string) => enc.encode(s);
// bytes/string element body: [len][padded data].
const elemBody = (b: Uint8Array) => pad(BigInt(b.length)) + padData(b);

// ---- DATA-REGION encoders (no outer offset word) -----------------------------
// bytes[] / string[] : [len][offset table][payloads]; offsets relative to table start.
function dynBytesArrayRegion(items: Uint8Array[]): string {
  const L = items.length;
  const payloads = items.map(elemBody);
  let off = L * 32;
  let table = '';
  for (const p of payloads) {
    table += pad(BigInt(off));
    off += p.length / 2;
  }
  return pad(BigInt(L)) + table + payloads.join('');
}
// Arr<bytes,N> / Arr<string,N> (FIXED array of dynamic): [offset table of N][payloads];
// NO outer length word. Offsets relative to the table start.
function fixedBytesRegion(items: Uint8Array[]): string {
  const N = items.length;
  const payloads = items.map(elemBody);
  let off = N * 32;
  let table = '';
  for (const p of payloads) {
    table += pad(BigInt(off));
    off += p.length / 2;
  }
  return table + payloads.join('');
}
// u256[] data region [len][elems].
const dynValRegion = (xs: bigint[]) => pad(BigInt(xs.length)) + xs.map(pad).join('');
// u256[][] region: [outerLen][inner offset table][inner regions]; inner offs rel. table start.
function nested2Region(rows: bigint[][]): string {
  const L = rows.length;
  const inner = rows.map(dynValRegion);
  let off = L * 32;
  let table = '';
  for (const ir of inner) {
    table += pad(BigInt(off));
    off += ir.length / 2;
  }
  return pad(BigInt(L)) + table + inner.join('');
}
// u256[][][] region: [outerLen][offset table][nested2 regions]; offs rel. table start.
function nested3Region(cube: bigint[][][]): string {
  const L = cube.length;
  const inner = cube.map(nested2Region);
  let off = L * 32;
  let table = '';
  for (const ir of inner) {
    table += pad(BigInt(off));
    off += ir.length / 2;
  }
  return pad(BigInt(L)) + table + inner.join('');
}
// Arr<string[],N> (fixed of dynamic array of string): [N-word offset table][string[] regions].
function fixedStringArrRegion(rows: Uint8Array[][]): string {
  const N = rows.length;
  const inner = rows.map(dynBytesArrayRegion);
  let off = N * 32;
  let table = '';
  for (const ir of inner) {
    table += pad(BigInt(off));
    off += ir.length / 2;
  }
  return table + inner.join('');
}
// D[] where D = {uint64 a; string s;} dynamic struct array:
// [len][offset table][D tuples]; each D tuple = [a][offset to s][s body].
function dynStructArrayRegion(items: { a: bigint; s: Uint8Array }[]): string {
  const L = items.length;
  const tuples = items.map(({ a, s }) => {
    // tuple head = 2 words: [a][offset-to-s = 0x40]; then s body.
    return pad(a) + pad(0x40n) + elemBody(s);
  });
  let off = L * 32;
  let table = '';
  for (const t of tuples) {
    table += pad(BigInt(off));
    off += t.length / 2;
  }
  return pad(BigInt(L)) + table + tuples.join('');
}

// ============================ CONTRACT UNDER TEST =============================
const JETH = `
type WithArr = { id: u64; data: Arr<u256,3>; tag: u64; };
type WithDyn = { a: u64; xs: u256[]; b: u64; };
type D = { a: u64; s: string; };

class C {
  // fixed array of dynamic byte sequences
  get fbAt(a: Arr<bytes,2>, i: u256): External<bytes> { return a[i]; }
  get fbLen(a: Arr<bytes,2>, i: u256): External<u256> { return a[i].length; }
  get fbEcho(a: Arr<bytes,2>): External<Arr<bytes,2>> { return a; }
  get fsAt(a: Arr<string,2>, i: u256): External<string> { return a[i]; }
  get fsEcho(a: Arr<string,2>): External<Arr<string,2>> { return a; }
  get fb3At(a: Arr<bytes,3>, i: u256): External<bytes> { return a[i]; }

  // array of dynamic byte sequences
  get baAt(a: bytes[], i: u256): External<bytes> { return a[i]; }
  get baLen(a: bytes[]): External<u256> { return a.length; }
  get baElemLen(a: bytes[], i: u256): External<u256> { return a[i].length; }
  get baEcho(a: bytes[]): External<bytes[]> { return a; }
  get saAt(a: string[], i: u256): External<string> { return a[i]; }
  get saEcho(a: string[]): External<string[]> { return a; }

  // nested dynamic value arrays
  get m2At(m: u256[][], i: u256, j: u256): External<u256> { return m[i][j]; }
  get m2Len(m: u256[][]): External<u256> { return m.length; }
  get m2InnerLen(m: u256[][], i: u256): External<u256> { return m[i].length; }
  get m2Echo(m: u256[][]): External<u256[][]> { return m; }
  get m3At(m: u256[][][], i: u256, j: u256, k: u256): External<u256> { return m[i][j][k]; }
  get m3Echo(m: u256[][][]): External<u256[][][]> { return m; }

  // bytes[][] : nested array of dynamic byte sequences
  get bbAt(m: bytes[][], i: u256, j: u256): External<bytes> { return m[i][j]; }

  // fixed array of dynamic array of string
  get fsaAt(a: Arr<string[],2>, i: u256, j: u256): External<string> { return a[i][j]; }
  get fsaLen(a: Arr<string[],2>, i: u256): External<u256> { return a[i].length; }

  // dynamic array of DYNAMIC struct (string field)
  get dsS(a: D[], i: u256): External<string> { return a[i].s; }
  get dsA(a: D[], i: u256): External<u64> { return a[i].a; }
  get dsLen(a: D[]): External<u256> { return a.length; }

  // narrow / signed dynamic value arrays (lazy dirty validation on a[i])
  get u8At(a: u8[], i: u256): External<u8> { return a[i]; }
  get i8At(a: i8[], i: u256): External<i8> { return a[i]; }
  get i256At(a: i256[], i: u256): External<i256> { return a[i]; }
  get boolAt(a: bool[], i: u256): External<bool> { return a[i]; }
  get b1At(a: bytes1[], i: u256): External<bytes1> { return a[i]; }
  get b4At(a: bytes4[], i: u256): External<bytes4> { return a[i]; }
  get addrAt(a: address[], i: u256): External<address> { return a[i]; }
  get u8Echo(a: u8[]): External<u8[]> { return a; }

  // struct with fixed-array field / dynamic-array field (echo + leaf)
  get waData(t: WithArr, j: u256): External<u256> { return t.data[j]; }
  get waEcho(t: WithArr): External<WithArr> { return t; }
  get wdEcho(t: WithDyn): External<WithDyn> { return t; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct WithArr { uint64 id; uint256[3] data; uint64 tag; }
  struct WithDyn { uint64 a; uint256[] xs; uint64 b; }
  struct D { uint64 a; string s; }

  function fbAt(bytes[2] calldata a, uint256 i) external pure returns (bytes memory){ return a[i]; }
  function fbLen(bytes[2] calldata a, uint256 i) external pure returns (uint256){ return a[i].length; }
  function fbEcho(bytes[2] calldata a) external pure returns (bytes[2] memory){ return a; }
  function fsAt(string[2] calldata a, uint256 i) external pure returns (string memory){ return a[i]; }
  function fsEcho(string[2] calldata a) external pure returns (string[2] memory){ return a; }
  function fb3At(bytes[3] calldata a, uint256 i) external pure returns (bytes memory){ return a[i]; }

  function baAt(bytes[] calldata a, uint256 i) external pure returns (bytes memory){ return a[i]; }
  function baLen(bytes[] calldata a) external pure returns (uint256){ return a.length; }
  function baElemLen(bytes[] calldata a, uint256 i) external pure returns (uint256){ return a[i].length; }
  function baEcho(bytes[] calldata a) external pure returns (bytes[] memory){ return a; }
  function saAt(string[] calldata a, uint256 i) external pure returns (string memory){ return a[i]; }
  function saEcho(string[] calldata a) external pure returns (string[] memory){ return a; }

  function m2At(uint256[][] calldata m, uint256 i, uint256 j) external pure returns (uint256){ return m[i][j]; }
  function m2Len(uint256[][] calldata m) external pure returns (uint256){ return m.length; }
  function m2InnerLen(uint256[][] calldata m, uint256 i) external pure returns (uint256){ return m[i].length; }
  function m2Echo(uint256[][] calldata m) external pure returns (uint256[][] memory){ return m; }
  function m3At(uint256[][][] calldata m, uint256 i, uint256 j, uint256 k) external pure returns (uint256){ return m[i][j][k]; }
  function m3Echo(uint256[][][] calldata m) external pure returns (uint256[][][] memory){ return m; }

  function bbAt(bytes[][] calldata m, uint256 i, uint256 j) external pure returns (bytes memory){ return m[i][j]; }

  function fsaAt(string[][2] calldata a, uint256 i, uint256 j) external pure returns (string memory){ return a[i][j]; }
  function fsaLen(string[][2] calldata a, uint256 i) external pure returns (uint256){ return a[i].length; }

  function dsS(D[] calldata a, uint256 i) external pure returns (string memory){ return a[i].s; }
  function dsA(D[] calldata a, uint256 i) external pure returns (uint64){ return a[i].a; }
  function dsLen(D[] calldata a) external pure returns (uint256){ return a.length; }

  function u8At(uint8[] calldata a, uint256 i) external pure returns (uint8){ return a[i]; }
  function i8At(int8[] calldata a, uint256 i) external pure returns (int8){ return a[i]; }
  function i256At(int256[] calldata a, uint256 i) external pure returns (int256){ return a[i]; }
  function boolAt(bool[] calldata a, uint256 i) external pure returns (bool){ return a[i]; }
  function b1At(bytes1[] calldata a, uint256 i) external pure returns (bytes1){ return a[i]; }
  function b4At(bytes4[] calldata a, uint256 i) external pure returns (bytes4){ return a[i]; }
  function addrAt(address[] calldata a, uint256 i) external pure returns (address){ return a[i]; }
  function u8Echo(uint8[] calldata a) external pure returns (uint8[] memory){ return a; }

  function waData(WithArr calldata t, uint256 j) external pure returns (uint256){ return t.data[j]; }
  function waEcho(WithArr calldata t) external pure returns (WithArr memory){ return t; }
  function wdEcho(WithDyn calldata t) external pure returns (WithDyn memory){ return t; }
}`;

describe('_audit_calldata-decode: adversarial calldata decode parity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const divergences: string[] = [];
  let nCases = 0;

  async function eq(label: string, data: string) {
    nCases++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    const ok = j.success === s.success && j.returnHex === s.returnHex;
    if (!ok) {
      divergences.push(
        `DIVERGENCE [${label}]\n  data=${data}\n` +
          `  jeth: success=${j.success} err=${j.exceptionError} ret=${j.returnHex}\n` +
          `  sol : success=${s.success} ret=${s.returnHex}`,
      );
    }
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const cb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(cb.creation);
  });

  // ======================= Arr<bytes,2> fixed-of-dynamic-bytes =================
  it('fbAt valid + OOB i + dirty/boundary element offsets', async () => {
    const slf = sel('fbAt(bytes[2],uint256)');
    const sll = sel('fbLen(bytes[2],uint256)');
    const region = fixedBytesRegion([sb('hello'), sb('world!!')]);
    const at = (i: bigint) => '0x' + slf + pad(0x40n) + pad(i) + region;
    const len = (i: bigint) => '0x' + sll + pad(0x40n) + pad(i) + region;
    await eq('fbAt[0]', at(0n));
    await eq('fbAt[1]', at(1n));
    await eq('fbLen[0]', len(0n));
    await eq('fbLen[1]', len(1n));
    // i OOB (N=2): solc reverts (no length to bound). Panic 0x32 or empty?
    for (const [nm, v] of [
      ['2', 2n],
      ['2^64', 1n << 64n],
      ['2^255', 1n << 255n],
      ['max', M - 1n],
    ] as const) {
      await eq(`fbAt i OOB ${nm}`, at(v));
      await eq(`fbLen i OOB ${nm}`, len(v));
    }
  });

  it('fbAt empty / single-empty elements', async () => {
    const slf = sel('fbAt(bytes[2],uint256)');
    const region = fixedBytesRegion([new Uint8Array(0), sb('x')]);
    const at = (i: bigint) => '0x' + slf + pad(0x40n) + pad(i) + region;
    await eq('fbAt empty[0]', at(0n));
    await eq('fbAt empty[1]', at(1n));
    const region2 = fixedBytesRegion([sb('A'.repeat(40)), new Uint8Array(0)]);
    const at2 = (i: bigint) => '0x' + slf + pad(0x40n) + pad(i) + region2;
    await eq('fbAt long[0]', at2(0n));
    await eq('fbAt long[1]empty', at2(1n));
  });

  it('fbEcho whole-param echo', async () => {
    const sle = sel('fbEcho(bytes[2])');
    for (const items of [
      [new Uint8Array(0), new Uint8Array(0)],
      [sb('a'), sb('bb')],
      [sb('A'.repeat(33)), sb('B'.repeat(1))],
      [sb('x'.repeat(64)), sb('y'.repeat(31))],
    ]) {
      await eq(`fbEcho ${items.map((x) => x.length)}`, '0x' + sle + pad(0x20n) + fixedBytesRegion(items));
    }
  });

  it('fbAt outer-param offset attack (dirty/high-bit/0/midword/pastEnd)', async () => {
    const slf = sel('fbAt(bytes[2],uint256)');
    const region = fixedBytesRegion([sb('aa'), sb('bb')]);
    // outer offset is the FIRST head word; second head word is i.
    const mk = (off: bigint, i: bigint) => '0x' + slf + pad(off) + pad(i) + region;
    await eq('fbAt off 0x40 ok', mk(0x40n, 0n));
    for (const [nm, off] of [
      ['2^64', 1n << 64n],
      ['2^64-1', (1n << 64n) - 1n],
      ['2^255', 1n << 255n],
      ['2^256-1', M - 1n],
      ['2^256-4', M - 4n],
      ['0', 0n],
      ['0x41 mid', 0x41n],
      ['0x3f', 0x3fn],
      ['pastEnd', 0xfffn],
    ] as const)
      await eq(`fbAt outer off ${nm}`, mk(off, 0n));
  });

  it('fbAt TRUNCATED offset table (only first of 2 table words present)', async () => {
    // KEY ATTACK: the Arr<bytes,N> param binding validates only that the FIRST table
    // word is readable, not all N. Feed calldata where the 2nd table word is missing.
    const slf = sel('fbAt(bytes[2],uint256)');
    const sll = sel('fbLen(bytes[2],uint256)');
    // body = [off0=0x40][<<truncated>>]: only one table word after the offset.
    const headOnly = (s: string) => '0x' + s + pad(0x40n) + pad(0n);
    // 0 table words
    await eq('fbAt no table at all (i=0)', headOnly(slf));
    await eq('fbLen no table at all (i=0)', headOnly(sll));
    // 1 table word, valid-looking off0, but no payload; read i=0 then i=1
    const oneWord = pad(0x40n); // off0 points to byte 0x40 (the 2nd table slot, which is absent)
    await eq('fbAt 1 table word i=0', headOnly(slf) + oneWord);
    await eq('fbAt 1 table word i=1', '0x' + slf + pad(0x40n) + pad(1n) + oneWord);
    await eq('fbLen 1 table word i=1', '0x' + sll + pad(0x40n) + pad(1n) + oneWord);
    // 2 table words but no payload region
    await eq('fbAt 2 table words no payload i=0', headOnly(slf) + pad(0x40n) + pad(0x60n));
    await eq('fbAt 2 table words no payload i=1', '0x' + slf + pad(0x40n) + pad(1n) + pad(0x40n) + pad(0x60n));
  });

  it('fbAt element offset malformed (high-bit/past-end/aliased)', async () => {
    const slf = sel('fbAt(bytes[2],uint256)');
    const sll = sel('fbLen(bytes[2],uint256)');
    // base table at byte 0x40; off0 valid -> payload of "abc". corrupt off1.
    const payload0 = elemBody(sb('abc')); // 0x40-byte-len? elemBody: [len][data]
    const off1Base = BigInt(64 + payload0.length / 2);
    const build = (off0: bigint, off1: bigint) => pad(off0) + pad(off1) + payload0 + elemBody(sb('z'));
    const at = (off0: bigint, off1: bigint, i: bigint) => '0x' + slf + pad(0x40n) + pad(i) + build(off0, off1);
    const len = (off0: bigint, off1: bigint, i: bigint) => '0x' + sll + pad(0x40n) + pad(i) + build(off0, off1);
    await eq('fbAt valid both', at(64n, off1Base, 0n));
    await eq('fbAt valid [1]', at(64n, off1Base, 1n));
    for (const [nm, off1] of [
      ['2^64', 1n << 64n],
      ['2^64-1', (1n << 64n) - 1n],
      ['2^255', 1n << 255n],
      ['2^256-1', M - 1n],
      ['0', 0n],
      ['alias=off0', 64n],
      ['pastEnd', 0xfffn],
    ] as const) {
      await eq(`fbAt off1=${nm} read[1]`, at(64n, off1, 1n));
      await eq(`fbLen off1=${nm} read[1]`, len(64n, off1, 1n));
      await eq(`fbAt off1=${nm} read[0] (untouched)`, at(64n, off1, 0n));
    }
  });

  it('fbAt element LENGTH malformed (2^64/2^64-1/past-end/exact)', async () => {
    const slf = sel('fbAt(bytes[2],uint256)');
    // off0 valid; element0 length declared = LEN with payload short/exact.
    const build = (len0: bigint, payloadWords: number) => {
      const elem0 = pad(len0) + 'ff'.repeat(payloadWords * 32);
      const off1 = BigInt(64 + elem0.length / 2);
      return pad(64n) + pad(off1) + elem0 + elemBody(sb('z'));
    };
    const at = (len0: bigint, pw: number, i: bigint) => '0x' + slf + pad(0x40n) + pad(i) + build(len0, pw);
    await eq('fbAt len0=2^64-1', at((1n << 64n) - 1n, 0, 0n));
    await eq('fbAt len0=2^64', at(1n << 64n, 0, 0n));
    await eq('fbAt len0=2^256-1', at(M - 1n, 0, 0n));
    await eq('fbAt len0=64 payload=1word (past end)', at(64n, 1, 0n));
    await eq('fbAt len0=32 payload=1word ok', at(32n, 1, 0n));
    await eq('fbAt len0=33 payload=2word ok', at(33n, 2, 0n));
    // element1 still readable when element0 corrupt
    await eq('fbAt len0=2^256-1 read[1]', at(M - 1n, 0, 1n));
  });

  // ======================= Arr<string,2> fixed-of-dynamic-string ===============
  it('fsAt + fsEcho parity', async () => {
    const slf = sel('fsAt(string[2],uint256)');
    const sle = sel('fsEcho(string[2])');
    for (const items of [
      [sb('foo'), sb('bar')],
      [sb(''), sb('utf8 éè')],
      [sb('A'.repeat(40)), sb('')],
    ]) {
      const region = fixedBytesRegion(items);
      await eq(`fsAt[0] ${items.map((x) => x.length)}`, '0x' + slf + pad(0x40n) + pad(0n) + region);
      await eq(`fsAt[1] ${items.map((x) => x.length)}`, '0x' + slf + pad(0x40n) + pad(1n) + region);
      await eq(`fsEcho ${items.map((x) => x.length)}`, '0x' + sle + pad(0x20n) + region);
    }
  });

  // ======================= Arr<bytes,3> ========================================
  it('fb3At N=3 fixed bytes: valid + truncated table', async () => {
    const slf = sel('fb3At(bytes[3],uint256)');
    const region = fixedBytesRegion([sb('one'), sb('two'), sb('three')]);
    const at = (i: bigint) => '0x' + slf + pad(0x40n) + pad(i) + region;
    for (let i = 0n; i < 3n; i++) await eq(`fb3At[${i}]`, at(i));
    await eq('fb3At[3] OOB', at(3n));
    // truncated: only 2 of 3 table words present, read [2]
    const trunc = '0x' + slf + pad(0x40n) + pad(2n) + pad(0x60n) + pad(0x80n);
    await eq('fb3At truncated table read[2]', trunc);
    await eq('fb3At truncated table read[0]', '0x' + slf + pad(0x40n) + pad(0n) + pad(0x60n) + pad(0x80n));
  });

  // ======================= bytes[] / string[] ==================================
  it('baAt + baLen + baElemLen + baEcho parity', async () => {
    const slf = sel('baAt(bytes[],uint256)');
    const sll = sel('baLen(bytes[])');
    const slel = sel('baElemLen(bytes[],uint256)');
    const sle = sel('baEcho(bytes[])');
    const items = [sb('alpha'), sb(''), sb('z'.repeat(50))];
    const region = dynBytesArrayRegion(items);
    await eq('baLen', '0x' + sll + pad(0x20n) + region);
    for (let i = 0n; i < 3n; i++) {
      await eq(`baAt[${i}]`, '0x' + slf + pad(0x40n) + pad(i) + region);
      await eq(`baElemLen[${i}]`, '0x' + slel + pad(0x40n) + pad(i) + region);
    }
    await eq('baAt[3] OOB', '0x' + slf + pad(0x40n) + pad(3n) + region);
    await eq('baEcho', '0x' + sle + pad(0x20n) + region);
    // empty array
    await eq('baLen empty', '0x' + sll + pad(0x20n) + dynBytesArrayRegion([]));
    await eq('baEcho empty', '0x' + sle + pad(0x20n) + dynBytesArrayRegion([]));
    await eq('baAt[0] empty OOB', '0x' + slf + pad(0x40n) + pad(0n) + dynBytesArrayRegion([]));
  });

  it('baAt malformed outer length (2^64/2^64-1/2^256-1/truncated)', async () => {
    const slf = sel('baAt(bytes[],uint256)');
    const sll = sel('baLen(bytes[])');
    const body = (len: bigint, tableAndPayload: string) => pad(len) + tableAndPayload;
    // 1 valid element body region (table for it would be [off0][payload])
    const tail = pad(0x20n) + elemBody(sb('hi'));
    const mkAt = (len: bigint, i: bigint) => '0x' + slf + pad(0x40n) + pad(i) + body(len, tail);
    const mkLen = (len: bigint) => '0x' + sll + pad(0x20n) + body(len, tail);
    await eq('baLen len=2^64', mkLen(1n << 64n));
    await eq('baLen len=2^64-1', mkLen((1n << 64n) - 1n));
    await eq('baLen len=2^256-1', mkLen(M - 1n));
    await eq('baAt len=2^64-1 read[0]', mkAt((1n << 64n) - 1n, 0n));
    await eq('baAt len=3 (table truncated) read[0]', mkAt(3n, 0n));
    await eq('baAt len=3 read[2] OOB-ish', mkAt(3n, 2n));
  });

  it('baAt malformed element offset/length (high-bit/past-end/aliased)', async () => {
    const slf = sel('baAt(bytes[],uint256)');
    const slel = sel('baElemLen(bytes[],uint256)');
    // outer len=2; table [off0][off1]; payloads. Corrupt off1.
    const p0 = elemBody(sb('aaa'));
    const off1Base = BigInt(64 + p0.length / 2);
    const build = (off0: bigint, off1: bigint) => pad(2n) + pad(off0) + pad(off1) + p0 + elemBody(sb('bb'));
    const at = (off0: bigint, off1: bigint, i: bigint) => '0x' + slf + pad(0x40n) + pad(i) + build(off0, off1);
    await eq('baAt valid[0]', at(64n, off1Base, 0n));
    await eq('baAt valid[1]', at(64n, off1Base, 1n));
    for (const [nm, off1] of [
      ['2^64', 1n << 64n],
      ['2^255', 1n << 255n],
      ['2^256-1', M - 1n],
      ['0', 0n],
      ['alias', 64n],
      ['pastEnd', 0x800n],
    ] as const) {
      await eq(`baAt off1=${nm} read[1]`, at(64n, off1, 1n));
      await eq(`baAt off1=${nm} read[0]`, at(64n, off1, 0n));
    }
    // element length malformed
    const buildLen = (len1: bigint) => {
      const e1 = pad(len1);
      const off1 = BigInt(64 + p0.length / 2);
      return pad(2n) + pad(64n) + pad(off1) + p0 + e1;
    };
    await eq('baElemLen len1=2^64-1', '0x' + slel + pad(0x40n) + pad(1n) + buildLen((1n << 64n) - 1n));
    await eq('baElemLen len1=2^256-1', '0x' + slel + pad(0x40n) + pad(1n) + buildLen(M - 1n));
  });

  it('saAt + saEcho string[] parity', async () => {
    const slf = sel('saAt(string[],uint256)');
    const sle = sel('saEcho(string[])');
    const items = [sb('one'), sb('two two'), sb('')];
    const region = dynBytesArrayRegion(items);
    for (let i = 0n; i < 3n; i++) await eq(`saAt[${i}]`, '0x' + slf + pad(0x40n) + pad(i) + region);
    await eq('saAt[3] OOB', '0x' + slf + pad(0x40n) + pad(3n) + region);
    await eq('saEcho', '0x' + sle + pad(0x20n) + region);
  });

  // ======================= u256[][] nested =====================================
  it('m2 element/len/echo + OOB across the grid', async () => {
    const slf = sel('m2At(uint256[][],uint256,uint256)');
    const sll = sel('m2Len(uint256[][])');
    const sil = sel('m2InnerLen(uint256[][],uint256)');
    const sle = sel('m2Echo(uint256[][])');
    const rows = [[1n, 2n, 3n], [], [M - 1n, 0n]];
    const region = nested2Region(rows);
    await eq('m2Len', '0x' + sll + pad(0x20n) + region);
    await eq('m2Echo', '0x' + sle + pad(0x20n) + region);
    for (let ri = 0; ri < rows.length; ri++) {
      const i = BigInt(ri);
      const row = rows[ri]!;
      await eq(`m2InnerLen[${ri}]`, '0x' + sil + pad(0x40n) + pad(i) + region);
      for (let j = 0; j < row.length; j++)
        await eq(`m2At[${ri}][${j}]`, '0x' + slf + pad(0x60n) + pad(i) + pad(BigInt(j)) + region);
      await eq(`m2At[${ri}][len] OOB`, '0x' + slf + pad(0x60n) + pad(i) + pad(BigInt(row.length)) + region);
    }
    // outer OOB
    for (const v of [3n, 1n << 64n, 1n << 255n, M - 1n]) {
      await eq(`m2InnerLen i OOB ${v}`, '0x' + sil + pad(0x40n) + pad(v) + region);
      await eq(`m2At i OOB ${v}`, '0x' + slf + pad(0x60n) + pad(v) + pad(0n) + region);
    }
  });

  it('m2 inner offset/length malformed', async () => {
    const slf = sel('m2At(uint256[][],uint256,uint256)');
    const sil = sel('m2InnerLen(uint256[][],uint256)');
    // outer len=2, table [off0][off1], inner0=[10,11], inner1=[20].
    const inner0 = dynValRegion([10n, 11n]);
    const off1Base = BigInt(64 + inner0.length / 2);
    const build = (off0: bigint, off1: bigint) => pad(2n) + pad(off0) + pad(off1) + inner0 + dynValRegion([20n]);
    const at = (off0: bigint, off1: bigint, i: bigint, j: bigint) =>
      '0x' + slf + pad(0x60n) + pad(i) + pad(j) + build(off0, off1);
    await eq('m2 valid[0][1]', at(64n, off1Base, 0n, 1n));
    for (const [nm, off1] of [
      ['2^64', 1n << 64n],
      ['2^255', 1n << 255n],
      ['2^256-1', M - 1n],
      ['0', 0n],
      ['pastEnd', 0x800n],
    ] as const) {
      await eq(`m2 off1=${nm} read[1][0]`, at(64n, off1, 1n, 0n));
      await eq(`m2InnerLen off1=${nm} [1]`, '0x' + sil + pad(0x40n) + pad(1n) + build(64n, off1));
      await eq(`m2 off1=${nm} read[0][0] untouched`, at(64n, off1, 0n, 0n));
    }
    // inner length malformed
    const buildLen = (len1: bigint) => {
      const e1 = pad(len1) + pad(99n);
      const off1 = BigInt(64 + inner0.length / 2);
      return pad(2n) + pad(64n) + pad(off1) + inner0 + e1;
    };
    await eq(
      'm2 inner1 len=2^64-1 read[1][0]',
      '0x' + slf + pad(0x60n) + pad(1n) + pad(0n) + buildLen((1n << 64n) - 1n),
    );
    await eq('m2 inner1 len=2^256-1 read[1][0]', '0x' + slf + pad(0x60n) + pad(1n) + pad(0n) + buildLen(M - 1n));
  });

  // ======================= u256[][][] 3-level ==================================
  it('m3 element + echo (3-level nested)', async () => {
    const slf = sel('m3At(uint256[][][],uint256,uint256,uint256)');
    const sle = sel('m3Echo(uint256[][][])');
    const cube = [[[1n, 2n], [3n]], [[]], [[7n], [8n, 9n, 10n]]];
    const region = nested3Region(cube);
    await eq('m3Echo', '0x' + sle + pad(0x20n) + region);
    for (let i = 0; i < cube.length; i++) {
      const plane = cube[i]!;
      for (let j = 0; j < plane.length; j++) {
        const row = plane[j]!;
        for (let k = 0; k < row.length; k++)
          await eq(
            `m3At[${i}][${j}][${k}]`,
            '0x' + slf + pad(0x80n) + pad(BigInt(i)) + pad(BigInt(j)) + pad(BigInt(k)) + region,
          );
      }
    }
    // OOB at each level
    await eq('m3At i OOB', '0x' + slf + pad(0x80n) + pad(3n) + pad(0n) + pad(0n) + region);
    await eq('m3At j OOB', '0x' + slf + pad(0x80n) + pad(0n) + pad(5n) + pad(0n) + region);
    await eq('m3At k OOB', '0x' + slf + pad(0x80n) + pad(0n) + pad(0n) + pad(5n) + region);
    await eq('m3At i 2^255', '0x' + slf + pad(0x80n) + pad(1n << 255n) + pad(0n) + pad(0n) + region);
    await eq('m3At k 2^64', '0x' + slf + pad(0x80n) + pad(0n) + pad(0n) + pad(1n << 64n) + region);
  });

  // ======================= bytes[][] nested-bytes ==============================
  it('bbAt nested array of bytes', async () => {
    const slf = sel('bbAt(bytes[][],uint256,uint256)');
    // outer len=2; outer table [o0][o1]; each inner = bytes[] region.
    const inner0 = dynBytesArrayRegion([sb('aa'), sb('bbb')]);
    const inner1 = dynBytesArrayRegion([sb('')]);
    const o1 = BigInt(64 + inner0.length / 2);
    const region = pad(2n) + pad(64n) + pad(o1) + inner0 + inner1;
    const at = (i: bigint, j: bigint) => '0x' + slf + pad(0x60n) + pad(i) + pad(j) + region;
    await eq('bbAt[0][0]', at(0n, 0n));
    await eq('bbAt[0][1]', at(0n, 1n));
    await eq('bbAt[1][0]', at(1n, 0n));
    await eq('bbAt[0][2] OOB', at(0n, 2n));
    await eq('bbAt[1][1] OOB', at(1n, 1n));
    await eq('bbAt[2][0] outer OOB', at(2n, 0n));
    await eq('bbAt[2^255][0]', at(1n << 255n, 0n));
  });

  // ======================= Arr<string[],2> fixed-of-dynarray-string ============
  it('fsaAt fixed array of string[]', async () => {
    const slf = sel('fsaAt(string[][2],uint256,uint256)');
    const sll = sel('fsaLen(string[][2],uint256)');
    const region = fixedStringArrRegion([[sb('a'), sb('bb')], [sb('ccc')]]);
    const at = (i: bigint, j: bigint) => '0x' + slf + pad(0x40n) + pad(i) + pad(j) + region;
    const len = (i: bigint) => '0x' + sll + pad(0x40n) + pad(i) + region;
    await eq('fsaLen[0]', len(0n));
    await eq('fsaLen[1]', len(1n));
    await eq('fsaAt[0][0]', at(0n, 0n));
    await eq('fsaAt[0][1]', at(0n, 1n));
    await eq('fsaAt[1][0]', at(1n, 0n));
    await eq('fsaAt[0][2] inner OOB', at(0n, 2n));
    await eq('fsaAt[1][1] inner OOB', at(1n, 1n));
    await eq('fsaAt[2][0] outer OOB', at(2n, 0n));
    await eq('fsaLen[2] outer OOB', len(2n));
    await eq('fsaAt[2^64][0]', at(1n << 64n, 0n));
  });

  // ======================= D[] dynamic struct array ============================
  it('dsS / dsA / dsLen dynamic struct array (string field)', async () => {
    const slS = sel('dsS(D[],uint256)');
    const slA = sel('dsA(D[],uint256)');
    const slL = sel('dsLen(D[])');
    const items = [
      { a: 7n, s: sb('first') },
      { a: 0xffffffffffffffffn, s: sb('') },
      { a: 42n, s: sb('z'.repeat(40)) },
    ];
    const region = dynStructArrayRegion(items);
    await eq('dsLen', '0x' + slL + pad(0x20n) + region);
    for (let i = 0n; i < 3n; i++) {
      await eq(`dsA[${i}]`, '0x' + slA + pad(0x40n) + pad(i) + region);
      await eq(`dsS[${i}]`, '0x' + slS + pad(0x40n) + pad(i) + region);
    }
    await eq('dsA[3] OOB', '0x' + slA + pad(0x40n) + pad(3n) + region);
    await eq('dsS[3] OOB', '0x' + slS + pad(0x40n) + pad(3n) + region);
    await eq('dsS[2^255] OOB', '0x' + slS + pad(0x40n) + pad(1n << 255n) + region);
    // dirty a-field (high bits in uint64) -> validate revert
    const dirtyA =
      pad(2n) +
      pad(0x40n) +
      pad(0x80n) +
      (pad(M - 1n) + pad(0x40n) + elemBody(sb('q'))) +
      (pad(5n) + pad(0x40n) + elemBody(sb('w')));
    await eq('dsA[0] dirty high bits', '0x' + slA + pad(0x40n) + pad(0n) + dirtyA);
    await eq('dsS[0] dirty a not read', '0x' + slS + pad(0x40n) + pad(0n) + dirtyA);
  });

  // ======================= narrow / signed dynamic value arrays =================
  it('u8[] / i8[] dirty-element validation', async () => {
    const slu = sel('u8At(uint8[],uint256)');
    const sli = sel('i8At(int8[],uint256)');
    const arr = (xs: bigint[]) => dynValRegion(xs);
    const u = (xs: bigint[], i: bigint) => '0x' + slu + pad(0x40n) + pad(i) + arr(xs);
    const s = (xs: bigint[], i: bigint) => '0x' + sli + pad(0x40n) + pad(i) + arr(xs);
    await eq('u8[0]=0xff clean', u([0xffn], 0n));
    await eq('u8[0]=0x100 dirty', u([0x100n], 0n));
    await eq('u8[0]=max dirty', u([M - 1n], 0n));
    await eq('u8 dirty[0] read[1] clean', u([M - 1n, 5n], 1n));
    await eq('u8 dirty[0] read[0]', u([M - 1n, 5n], 0n));
    await eq('u8 OOB', u([1n], 1n));
    // int8: valid sign-extensions vs dirty
    await eq('i8 -1 valid', s([M - 1n], 0n)); // sign-extended -1
    await eq('i8 -128 valid', s([M - 128n], 0n));
    await eq('i8 127', s([127n], 0n));
    await eq('i8 128 dirty (not sign-ext)', s([128n], 0n));
    await eq('i8 0x1ff dirty', s([0x1ffn], 0n));
    await eq('i8 highbits dirty', s([(1n << 200n) | 5n], 0n));
  });

  it('bool[] / bytes1[] / bytes4[] / address[] dirty validation', async () => {
    const slbool = sel('boolAt(bool[],uint256)');
    const slb1 = sel('b1At(bytes1[],uint256)');
    const slb4 = sel('b4At(bytes4[],uint256)');
    const sla = sel('addrAt(address[],uint256)');
    const arr = (xs: bigint[]) => dynValRegion(xs);
    await eq('bool 0', '0x' + slbool + pad(0x40n) + pad(0n) + arr([0n]));
    await eq('bool 1', '0x' + slbool + pad(0x40n) + pad(0n) + arr([1n]));
    await eq('bool 2 dirty', '0x' + slbool + pad(0x40n) + pad(0n) + arr([2n]));
    await eq('bool max dirty', '0x' + slbool + pad(0x40n) + pad(0n) + arr([M - 1n]));
    await eq('bool dirty[0] read[1]', '0x' + slbool + pad(0x40n) + pad(1n) + arr([5n, 1n]));
    // bytes1 left-aligned: low 31 bytes must be zero
    const b1 = 0xabn << (31n * 8n);
    await eq('bytes1 clean', '0x' + slb1 + pad(0x40n) + pad(0n) + arr([b1]));
    await eq('bytes1 dirty low', '0x' + slb1 + pad(0x40n) + pad(0n) + arr([b1 | 1n]));
    await eq('bytes1 all set', '0x' + slb1 + pad(0x40n) + pad(0n) + arr([M - 1n]));
    const b4 = 0xdeadbeefn << (28n * 8n);
    await eq('bytes4 clean', '0x' + slb4 + pad(0x40n) + pad(0n) + arr([b4]));
    await eq('bytes4 dirty low', '0x' + slb4 + pad(0x40n) + pad(0n) + arr([b4 | 1n]));
    const A = 0x1234567890abcdef1234567890abcdef12345678n;
    await eq('address clean', '0x' + sla + pad(0x40n) + pad(0n) + arr([A]));
    await eq('address dirty high96', '0x' + sla + pad(0x40n) + pad(0n) + arr([(1n << 200n) | A]));
    await eq('address all set', '0x' + sla + pad(0x40n) + pad(0n) + arr([M - 1n]));
  });

  it('i256[] full-width (no validation) + u8Echo whole-array', async () => {
    const sli = sel('i256At(int256[],uint256)');
    const sle = sel('u8Echo(uint8[])');
    const arr = (xs: bigint[]) => dynValRegion(xs);
    await eq('i256 -1', '0x' + sli + pad(0x40n) + pad(0n) + arr([M - 1n]));
    await eq('i256 highbits ok', '0x' + sli + pad(0x40n) + pad(0n) + arr([1n << 200n]));
    await eq('i256 min', '0x' + sli + pad(0x40n) + pad(0n) + arr([1n << 255n]));
    await eq('i256 OOB', '0x' + sli + pad(0x40n) + pad(1n) + arr([1n]));
    // whole u8[] echo: solc validates EVERY element on decode-to-memory
    await eq('u8Echo clean', '0x' + sle + pad(0x20n) + arr([1n, 2n, 3n]));
    await eq('u8Echo dirty mid', '0x' + sle + pad(0x20n) + arr([1n, 0x100n, 3n]));
    await eq('u8Echo dirty last', '0x' + sle + pad(0x20n) + arr([1n, 2n, M - 1n]));
    await eq('u8Echo empty', '0x' + sle + pad(0x20n) + arr([]));
  });

  // ======================= struct with fixed-array / dynamic-array field ========
  it('WithArr (fixed-array field) leaf + echo', async () => {
    const sld = sel('waData(WithArr,uint256)');
    const sle = sel('waEcho(WithArr)');
    // WithArr static: head = [id][data0][data1][data2][tag] (5 words inline).
    const head = pad(7n) + pad(100n) + pad(200n) + pad(300n) + pad(9n);
    for (let j = 0n; j < 3n; j++) await eq(`waData[${j}]`, '0x' + sld + head + pad(j));
    await eq('waData[3] OOB', '0x' + sld + head + pad(3n));
    await eq('waData[2^64] OOB', '0x' + sld + head + pad(1n << 64n));
    await eq('waEcho', '0x' + sle + head);
    // dirty id (uint64 high bits) -> validate revert on read of id during echo
    const dirtyHead = pad(M - 1n) + pad(100n) + pad(200n) + pad(300n) + pad(9n);
    await eq('waEcho dirty id', '0x' + sle + dirtyHead);
    await eq('waData[0] dirty id not read', '0x' + sld + dirtyHead + pad(0n));
  });

  it('WithDyn (dynamic-array field) echo', async () => {
    const sle = sel('wdEcho(WithDyn)');
    // WithDyn dynamic: outer offset 0x20; tuple = [a][offset-to-xs=0x60][b][xs body].
    const tuple = (a: bigint, xs: bigint[], b: bigint) => pad(a) + pad(0x60n) + pad(b) + dynValRegion(xs);
    await eq('wdEcho 3 elems', '0x' + sle + pad(0x20n) + tuple(1n, [10n, 20n, 30n], 2n));
    await eq('wdEcho empty xs', '0x' + sle + pad(0x20n) + tuple(5n, [], 6n));
    await eq('wdEcho big xs', '0x' + sle + pad(0x20n) + tuple(7n, [M - 1n, 0n, 1n, 2n], 8n));
    // dirty a (uint64) on echo -> validate revert
    await eq('wdEcho dirty a', '0x' + sle + pad(0x20n) + (pad(M - 1n) + pad(0x60n) + pad(2n) + dynValRegion([1n])));
    // malformed inner xs offset
    await eq('wdEcho xs off=2^64', '0x' + sle + pad(0x20n) + (pad(1n) + pad(1n << 64n) + pad(2n) + dynValRegion([1n])));
    await eq('wdEcho xs off=2^256-1', '0x' + sle + pad(0x20n) + (pad(1n) + pad(M - 1n) + pad(2n) + dynValRegion([1n])));
    // malformed outer offset
    await eq('wdEcho outer off=2^64', '0x' + sle + pad(1n << 64n) + tuple(1n, [1n], 2n));
    await eq('wdEcho outer off=2^256-1', '0x' + sle + pad(M - 1n) + tuple(1n, [1n], 2n));
    await eq('wdEcho outer off=0', '0x' + sle + pad(0n) + tuple(1n, [1n], 2n));
  });

  // ======================= ROUND 2: deep offset/aliasing attacks ===============

  it('Arr<bytes,2> element offset pointing into head/table/selector region', async () => {
    const slf = sel('fbAt(bytes[2],uint256)');
    // base table at byte 0x40 (after offset word + i word). off relative to table start.
    // off=0 -> lenPtr = tableStart (the off0 word itself = some value used as length!).
    const payload = elemBody(sb('data'));
    const build = (off0: bigint, off1: bigint) => pad(off0) + pad(off1) + payload + elemBody(sb('z'));
    const at = (off0: bigint, off1: bigint, i: bigint) => '0x' + slf + pad(0x40n) + pad(i) + build(off0, off1);
    // off0=0: element length = the table word at tableStart (= off0 itself = 0) -> empty bytes
    await eq('fbAt off0=0 read[0]', at(0n, 0x40n, 0n));
    // off0=0x20: lenPtr points at off1 word (= 0x40 = 64), length=64, payload follows
    await eq('fbAt off0=0x20 read[0]', at(0x20n, 0x40n, 0n));
    // off small odd (not word-aligned)
    await eq('fbAt off0=0x21 read[0]', at(0x21n, 0x40n, 0n));
    await eq('fbAt off0=0x1f read[0]', at(0x1fn, 0x40n, 0n));
    // off0 negative-ish (high bit) -> wraps; solc lazy slt should accept and read wrapped
    await eq('fbAt off0=2^255 read[0]', at(1n << 255n, 0x40n, 0n));
    await eq('fbAt off0=2^256-0x20 read[0]', at(M - 0x20n, 0x40n, 0n));
    await eq('fbAt off0=2^256-1 read[0]', at(M - 1n, 0x40n, 0n));
  });

  it('Arr<bytes,2> outer offset that aliases / overlaps i word', async () => {
    const slf = sel('fbAt(bytes[2],uint256)');
    const region = fixedBytesRegion([sb('aa'), sb('bb')]);
    // outer off=0x20 -> table starts AT the i word (overlap). solc reads table from there.
    await eq('fbAt outer off 0x20 (overlap i)', '0x' + slf + pad(0x20n) + pad(0n) + region);
    // outer off=0x00 -> table at the offset word itself.
    await eq('fbAt outer off 0x00', '0x' + slf + pad(0x00n) + pad(0n) + region);
  });

  it('D[] element tuple-head straddles calldatasize boundary', async () => {
    const slA = sel('dsA(D[],uint256)');
    const slS = sel('dsS(D[],uint256)');
    // len=1, table [off0]. Place off0 so the 2-word tuple head runs exactly to / past end.
    // tuple head = 2 words (a + s-offset). data start (tableStart) = byte 0x40+? :
    // body after the two head words [outerOff][i]; outer off word is at head, i is 2nd.
    // For dsA: head = [outerOff=0x40][i]; body = [len][off0][tuple...]
    const tuple = pad(7n) + pad(0x40n) + elemBody(sb('hi')); // a, s-off, s body
    const build = (off0: bigint) => pad(1n) + pad(off0) + tuple;
    const aA = (off0: bigint, i: bigint) => '0x' + slA + pad(0x40n) + pad(i) + build(off0);
    const aS = (off0: bigint, i: bigint) => '0x' + slS + pad(0x40n) + pad(i) + build(off0);
    // valid: off0 = 0x20 (table start has 1 word for [off0], tuple right after)
    await eq('dsA off0=0x20 valid', aA(0x20n, 0n));
    await eq('dsS off0=0x20 valid', aS(0x20n, 0n));
    // off0 pushing the tuple head past end
    for (const [nm, off0] of [
      ['2^64', 1n << 64n],
      ['2^64-1', (1n << 64n) - 1n],
      ['2^255', 1n << 255n],
      ['2^256-1', M - 1n],
      ['2^256-0x40', M - 0x40n],
      ['pastEnd', 0x800n],
      ['0', 0n],
    ] as const) {
      await eq(`dsA off0=${nm}`, aA(off0, 0n));
      await eq(`dsS off0=${nm}`, aS(off0, 0n));
    }
  });

  it('D[] inner string-field offset corruption', async () => {
    const slS = sel('dsS(D[],uint256)');
    // len=1; tuple = [a][s-off][s body]. corrupt s-off (relative to tuple start).
    const build = (sOff: bigint) => pad(1n) + pad(0x20n) + pad(7n) + pad(sOff) + elemBody(sb('payload'));
    const aS = (sOff: bigint) => '0x' + slS + pad(0x40n) + pad(0n) + build(sOff);
    await eq('dsS s-off=0x40 valid', aS(0x40n));
    for (const [nm, off] of [
      ['2^64', 1n << 64n],
      ['2^255', 1n << 255n],
      ['2^256-1', M - 1n],
      ['2^256-0x20', M - 0x20n],
      ['0', 0n],
      ['pastEnd', 0x800n],
      ['midword', 0x41n],
    ] as const)
      await eq(`dsS s-off=${nm}`, aS(off));
  });

  it('D[] dirty length / outer offset', async () => {
    const slL = sel('dsLen(D[])');
    const slS = sel('dsS(D[],uint256)');
    const tuple = pad(7n) + pad(0x40n) + elemBody(sb('x'));
    const body = (len: bigint) => pad(len) + pad(0x20n) + tuple;
    await eq('dsLen len=2^64', '0x' + slL + pad(0x20n) + body(1n << 64n));
    await eq('dsLen len=2^64-1', '0x' + slL + pad(0x20n) + body((1n << 64n) - 1n));
    await eq('dsLen len=2^256-1', '0x' + slL + pad(0x20n) + body(M - 1n));
    await eq('dsS len=2 (table truncated) read[1]', '0x' + slS + pad(0x40n) + pad(1n) + body(2n));
    // outer offset corruption
    for (const [nm, off] of [
      ['2^64', 1n << 64n],
      ['2^256-1', M - 1n],
      ['0', 0n],
      ['midword', 0x21n],
    ] as const)
      await eq(`dsLen outer off ${nm}`, '0x' + slL + pad(off) + body(1n));
  });

  it('u256[][][] mid-level (j) inner offset corruption', async () => {
    const slf = sel('m3At(uint256[][][],uint256,uint256,uint256)');
    // outer len=1, off to one m2 region. corrupt the inner-2 offset table inside it.
    // Build a m2 region with 2 inner arrays; corrupt the 2nd inner offset.
    const inner0 = dynValRegion([1n, 2n]);
    const innerOff1Base = BigInt(64 + inner0.length / 2);
    const m2 = (off1: bigint) => pad(2n) + pad(64n) + pad(off1) + inner0 + dynValRegion([3n]);
    // wrap m2 in a len-1 outer
    const region = (off1: bigint) => pad(1n) + pad(0x20n) + m2(off1);
    const at = (off1: bigint, i: bigint, j: bigint, k: bigint) =>
      '0x' + slf + pad(0x80n) + pad(i) + pad(j) + pad(k) + region(off1);
    await eq('m3 valid [0][1][0]', at(innerOff1Base, 0n, 1n, 0n));
    for (const [nm, off1] of [
      ['2^64', 1n << 64n],
      ['2^255', 1n << 255n],
      ['2^256-1', M - 1n],
      ['0', 0n],
      ['pastEnd', 0x800n],
    ] as const) {
      await eq(`m3 j-off1=${nm} read[0][1][0]`, at(off1, 0n, 1n, 0n));
      await eq(`m3 j-off1=${nm} read[0][0][0] untouched`, at(off1, 0n, 0n, 0n));
    }
  });

  it('bytes[][] inner bytes-array offset/length corruption', async () => {
    const slf = sel('bbAt(bytes[][],uint256,uint256)');
    // outer len=1; inner = bytes[] region; corrupt inner bytes element offset.
    const p0 = elemBody(sb('hello'));
    const innerOff1 = BigInt(64 + p0.length / 2);
    const innerRegion = (eOff1: bigint) => pad(2n) + pad(64n) + pad(eOff1) + p0 + elemBody(sb('q'));
    const region = (eOff1: bigint) => pad(1n) + pad(0x20n) + innerRegion(eOff1);
    const at = (eOff1: bigint, i: bigint, j: bigint) => '0x' + slf + pad(0x60n) + pad(i) + pad(j) + region(eOff1);
    await eq('bb valid [0][1]', at(innerOff1, 0n, 1n));
    for (const [nm, off] of [
      ['2^64', 1n << 64n],
      ['2^255', 1n << 255n],
      ['2^256-1', M - 1n],
      ['0', 0n],
      ['pastEnd', 0x800n],
    ] as const) {
      await eq(`bb inner eOff1=${nm} read[0][1]`, at(off, 0n, 1n));
      await eq(`bb inner eOff1=${nm} read[0][0]`, at(off, 0n, 0n));
    }
  });

  it('Arr<string[],2> inner string offset corruption + outer table truncation', async () => {
    const slf = sel('fsaAt(string[][2],uint256,uint256)');
    // fixed N=2 table [t0][t1]; each ti -> a string[] region. corrupt t1.
    const inner0 = dynBytesArrayRegion([sb('a'), sb('bb')]);
    const t1Base = BigInt(64 + inner0.length / 2);
    const build = (t0: bigint, t1: bigint) => pad(t0) + pad(t1) + inner0 + dynBytesArrayRegion([sb('c')]);
    const at = (t0: bigint, t1: bigint, i: bigint, j: bigint) =>
      '0x' + slf + pad(0x40n) + pad(i) + pad(j) + build(t0, t1);
    await eq('fsa valid [1][0]', at(64n, t1Base, 1n, 0n));
    for (const [nm, t1] of [
      ['2^64', 1n << 64n],
      ['2^255', 1n << 255n],
      ['2^256-1', M - 1n],
      ['0', 0n],
      ['pastEnd', 0x800n],
    ] as const) {
      await eq(`fsa t1=${nm} read[1][0]`, at(64n, t1, 1n, 0n));
      await eq(`fsa t1=${nm} read[0][0] untouched`, at(64n, t1, 0n, 0n));
    }
    // truncated outer fixed table (only t0 present)
    await eq('fsa only t0 word read[0][0]', '0x' + slf + pad(0x40n) + pad(0n) + pad(0n) + pad(0x40n));
    await eq('fsa only t0 word read[1][0]', '0x' + slf + pad(0x40n) + pad(1n) + pad(0n) + pad(0x40n));
  });

  it('m2Echo / m3Echo / baEcho with malformed inner offsets (decode-to-memory path)', async () => {
    // ECHO decodes the WHOLE param to memory: solc uses the UNSIGNED offset cap and
    // Panic(0x41) on oversized alloc. Exercise high-bit/huge inner offsets/lengths.
    const e2 = sel('m2Echo(uint256[][])');
    const e3 = sel('m3Echo(uint256[][][])');
    const eb = sel('baEcho(bytes[])');
    // m2 with inner off1 high-bit
    const inner0 = dynValRegion([1n, 2n]);
    const off1Base = BigInt(64 + inner0.length / 2);
    const m2body = (off1: bigint) => pad(2n) + pad(64n) + pad(off1) + inner0 + dynValRegion([3n]);
    for (const [nm, off1] of [
      ['valid', off1Base],
      ['2^64', 1n << 64n],
      ['2^255', 1n << 255n],
      ['2^256-1', M - 1n],
      ['0', 0n],
    ] as const)
      await eq(`m2Echo off1=${nm}`, '0x' + e2 + pad(0x20n) + m2body(off1));
    // m2 with huge inner length (Panic 0x41 alloc region)
    const m2len = (len: bigint) => pad(1n) + pad(0x20n) + pad(len);
    await eq('m2Echo inner len=2^64', '0x' + e2 + pad(0x20n) + m2len(1n << 64n));
    await eq('m2Echo inner len=2^64-1', '0x' + e2 + pad(0x20n) + m2len((1n << 64n) - 1n));
    await eq('m2Echo inner len=2^256-1', '0x' + e2 + pad(0x20n) + m2len(M - 1n));
    await eq('m2Echo inner len=2^250', '0x' + e2 + pad(0x20n) + m2len(1n << 250n));
    // baEcho with huge element length
    const baLen = (len: bigint) => pad(1n) + pad(0x20n) + pad(len);
    await eq('baEcho elem len=2^64', '0x' + eb + pad(0x20n) + baLen(1n << 64n));
    await eq('baEcho elem len=2^256-1', '0x' + eb + pad(0x20n) + baLen(M - 1n));
    await eq('baEcho elem len=2^250', '0x' + eb + pad(0x20n) + baLen(1n << 250n));
    await eq('baEcho elem off=2^256-1', '0x' + eb + pad(0x20n) + (pad(1n) + pad(M - 1n)));
    await eq('baEcho elem off=2^64', '0x' + eb + pad(0x20n) + (pad(1n) + pad(1n << 64n)));
    // m3Echo malformed
    await eq('m3Echo outer off 2^64', '0x' + e3 + pad(1n << 64n));
    await eq(
      'm3Echo inner len 2^256-1',
      '0x' + e3 + pad(0x20n) + (pad(1n) + pad(0x20n) + pad(1n) + pad(0x20n) + pad(M - 1n)),
    );
  });

  it('fbEcho / fsEcho whole-fixed-bytes echo with malformed element offsets/lengths', async () => {
    const eb = sel('fbEcho(bytes[2])');
    // N=2 fixed; table [t0][t1]; corrupt t1 then echo whole.
    const p0 = elemBody(sb('alpha'));
    const t1Base = BigInt(64 + p0.length / 2);
    const build = (t1: bigint) => pad(64n) + pad(t1) + p0 + elemBody(sb('beta'));
    await eq('fbEcho valid', '0x' + eb + pad(0x20n) + build(t1Base));
    await eq('fbEcho t1=2^64', '0x' + eb + pad(0x20n) + build(1n << 64n));
    await eq('fbEcho t1=2^256-1', '0x' + eb + pad(0x20n) + build(M - 1n));
    await eq('fbEcho t1=2^255', '0x' + eb + pad(0x20n) + build(1n << 255n));
    await eq('fbEcho t1=0', '0x' + eb + pad(0x20n) + build(0n));
    // element length huge (alloc Panic region) during echo
    const buildLen = (len1: bigint) => {
      const e1 = pad(len1);
      const t1 = BigInt(64 + p0.length / 2);
      return pad(64n) + pad(t1) + p0 + e1;
    };
    await eq('fbEcho elem1 len=2^64', '0x' + eb + pad(0x20n) + buildLen(1n << 64n));
    await eq('fbEcho elem1 len=2^256-1', '0x' + eb + pad(0x20n) + buildLen(M - 1n));
    await eq('fbEcho elem1 len=2^250', '0x' + eb + pad(0x20n) + buildLen(1n << 250n));
  });

  it('cross-check: m2 element reads match m2Echo for the same payload', async () => {
    const slf = sel('m2At(uint256[][],uint256,uint256)');
    const sle = sel('m2Echo(uint256[][])');
    const rows = [[5n, 6n, 7n], [8n], [], [9n, 10n]];
    const region = nested2Region(rows);
    await eq('m2 xcheck echo', '0x' + sle + pad(0x20n) + region);
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i]!;
      for (let j = 0; j < row.length; j++)
        await eq(`m2 xcheck[${i}][${j}]`, '0x' + slf + pad(0x60n) + pad(BigInt(i)) + pad(BigInt(j)) + region);
    }
  });

  it('cross-check: baAt element reads match baEcho', async () => {
    const slf = sel('baAt(bytes[],uint256)');
    const sle = sel('baEcho(bytes[])');
    const items = [sb('xx'), sb(''), sb('y'.repeat(35)), sb('zzzz')];
    const region = dynBytesArrayRegion(items);
    await eq('ba xcheck echo', '0x' + sle + pad(0x20n) + region);
    for (let i = 0n; i < BigInt(items.length); i++)
      await eq(`ba xcheck[${i}]`, '0x' + slf + pad(0x40n) + pad(i) + region);
  });

  // ======================= ROUND 3: boundary-exact + trailing junk =============

  it('baAt element length EXACTLY at payload-fits boundary (off-by-one)', async () => {
    const slf = sel('baAt(bytes[],uint256)');
    // len=1; element body = [len][exactly len bytes padded]. Test len at word boundaries.
    const mk = (declaredLen: bigint, payloadBytes: number) => {
      const elem = pad(declaredLen) + 'aa'.repeat(payloadBytes) + '00'.repeat((32 - (payloadBytes % 32)) % 32);
      return '0x' + slf + pad(0x40n) + pad(0n) + pad(1n) + pad(0x20n) + elem;
    };
    // declaredLen 32, payload exactly 32 -> ok
    await eq('baAt len=32 payload=32', mk(32n, 32));
    // declaredLen 33, payload 33 (2 words) -> ok
    await eq('baAt len=33 payload=33', mk(33n, 33));
    // declaredLen 33, payload only 32 bytes present (1 word) -> past end revert
    await eq(
      'baAt len=33 payload=32 (short)',
      '0x' + slf + pad(0x40n) + pad(0n) + pad(1n) + pad(0x20n) + pad(33n) + 'aa'.repeat(32),
    );
    // declaredLen 0 payload 0 -> empty ok
    await eq('baAt len=0', '0x' + slf + pad(0x40n) + pad(0n) + pad(1n) + pad(0x20n) + pad(0n));
    // declaredLen 1 with 1 word payload -> ok
    await eq('baAt len=1 payload=1word', mk(1n, 1));
  });

  it('m2 inner length EXACTLY at payload-fits (stride=32) boundary', async () => {
    const slf = sel('m2At(uint256[][],uint256,uint256)');
    // len outer=1; inner declared len = L, with exactly L words present.
    const mk = (innerLen: bigint, wordsPresent: number, j: bigint) => {
      const inner = pad(innerLen) + Array.from({ length: wordsPresent }, (_, k) => pad(BigInt(k + 1))).join('');
      return '0x' + slf + pad(0x60n) + pad(0n) + pad(j) + pad(1n) + pad(0x20n) + inner;
    };
    await eq('m2 inner len=2 words=2 read[0][1]', mk(2n, 2, 1n));
    await eq('m2 inner len=2 words=2 read[0][2] OOB', mk(2n, 2, 2n));
    await eq('m2 inner len=3 words=2 (short) read[0][0]', mk(3n, 2, 0n));
    await eq('m2 inner len=3 words=2 (short) read[0][2]', mk(3n, 2, 2n));
    await eq('m2 inner len=0 read[0][0] OOB', mk(0n, 0, 0n));
  });

  it('trailing junk after valid payload is ignored (parity)', async () => {
    const junk = 'deadbeef'.repeat(8); // 32 extra bytes
    const slf = sel('m2At(uint256[][],uint256,uint256)');
    const region = nested2Region([[1n, 2n], [3n]]);
    await eq('m2 valid + 32B junk', '0x' + slf + pad(0x60n) + pad(0n) + pad(1n) + region + junk);
    await eq('m2 valid + 32B junk read[1][0]', '0x' + slf + pad(0x60n) + pad(1n) + pad(0n) + region + junk);
    const baf = sel('baAt(bytes[],uint256)');
    const bar = dynBytesArrayRegion([sb('aa'), sb('bb')]);
    await eq('ba valid + junk', '0x' + baf + pad(0x40n) + pad(1n) + bar + junk);
    const eb = sel('fbEcho(bytes[2])');
    await eq('fbEcho valid + junk', '0x' + eb + pad(0x20n) + fixedBytesRegion([sb('x'), sb('y')]) + junk);
  });

  it('outer-array offset at exact calldatasize-0x1f signed boundary', async () => {
    // calldataDynArray uses slt(p+0x1f, calldatasize). Probe offsets that place the
    // length word's last byte exactly at / just past calldatasize.
    const slf = sel('m2Len(uint256[][])');
    // Build minimal: just a single length word for the outer array.
    // body must contain the length word at byte (4 + off). We feed off so the length
    // word ends exactly at calldatasize.
    const lenWord = pad(0n); // outer length 0
    // total calldata = 4 (sel) + 32 (offset word) + 32 (len word) = 68 bytes
    // offset word value 0x20 -> length word at byte 4+0x20=36, ends at 68 = calldatasize. ok.
    await eq('m2Len off=0x20 exact', '0x' + slf + pad(0x20n) + lenWord);
    // off=0x21 -> length word at byte 37, ends at 69 > 68 -> revert
    await eq('m2Len off=0x21 past', '0x' + slf + pad(0x21n) + lenWord);
    // off=0x1f -> length word at byte 35, ends at 67 < 68 -> ok (reads 1 byte of junk-free)
    await eq('m2Len off=0x1f', '0x' + slf + pad(0x1fn) + lenWord);
    // add a trailing word to push calldatasize out, then off=0x40
    await eq('m2Len off=0x40 with tail', '0x' + slf + pad(0x40n) + pad(0xdeadn) + lenWord);
  });

  // ===================== FIXED: Arr<dyn,N> full-head readability =====================
  // The Arr<dyn,N> (bytes[2]/string[2]/...) outer-param binding now validates that the WHOLE
  // N-word static offset table is readable (dataPtr + N*32 <= calldatasize, src/yul.ts), not
  // just the first word. A head whose first word fits but whose words 1..N-1 run past
  // calldatasize now EMPTY-reverts byte-identically to solc (was a P0 miscompile).
  it('Arr<bytes,N> outer offset: full N-word head readability -> EMPTY revert parity', async () => {
    const slf = sel('fbAt(bytes[2],uint256)');
    const oneTableWord = pad(0x40n); // single body word -> calldatasize = 100
    await eq('fbAt off 0x20 head-fits-exact', '0x' + slf + pad(0x20n) + pad(0n) + oneTableWord); // both accept
    await eq('fbAt off 0x40 first-word-past', '0x' + slf + pad(0x40n) + pad(0n) + oneTableWord); // both revert
    await eq('fbAt off 0x21 (2nd head word past end)', '0x' + slf + pad(0x21n) + pad(0n) + oneTableWord); // both EMPTY-revert
    await eq('fbAt off 0x3f (2nd head word past end)', '0x' + slf + pad(0x3fn) + pad(0n) + oneTableWord); // both EMPTY-revert
  });

  it('i256[] / addr[] whole-array out-of-bounds with declared-vs-actual length mismatch', async () => {
    const sli = sel('i256At(int256[],uint256)');
    const sla = sel('addrAt(address[],uint256)');
    // declared len bigger than payload -> read in declared range but past payload
    const mkI = (len: bigint, xs: bigint[], i: bigint) =>
      '0x' + sli + pad(0x40n) + pad(i) + pad(len) + xs.map(pad).join('');
    await eq('i256 len=3 payload=1 read[0]', mkI(3n, [42n], 0n));
    await eq('i256 len=3 payload=1 read[2] (past)', mkI(3n, [42n], 2n));
    await eq('i256 len=2^64-1 read[0]', mkI((1n << 64n) - 1n, [42n], 0n));
    await eq('i256 len=2^64 read[0]', mkI(1n << 64n, [42n], 0n));
    const A = 0x00000000000000000000000000000000000000ffn;
    await eq('addr len=2 payload=2 read[1]', '0x' + sla + pad(0x40n) + pad(1n) + pad(2n) + pad(A) + pad(A + 1n));
    await eq('addr len=2 payload=1 read[1] past', '0x' + sla + pad(0x40n) + pad(1n) + pad(2n) + pad(A));
  });

  // ======================= calldatasize / no-args edge =========================
  it('short calldata: missing head words across shapes', async () => {
    // each external fn requires its full static head; feed selector-only / partial.
    for (const s of [
      'fbAt(bytes[2],uint256)',
      'baAt(bytes[],uint256)',
      'm2At(uint256[][],uint256,uint256)',
      'm3At(uint256[][][],uint256,uint256,uint256)',
      'dsS(D[],uint256)',
      'waEcho(WithArr)',
      'wdEcho(WithDyn)',
    ]) {
      await eq(`selector-only ${s}`, '0x' + sel(s));
      await eq(`one-word ${s}`, '0x' + sel(s) + pad(0n));
    }
  });

  it('REPORT: case count + any divergences', () => {
    if (divergences.length) {
      throw new Error(`\n${divergences.length} DIVERGENCE(S):\n` + divergences.join('\n\n'));
    }
    // eslint-disable-next-line no-console
    console.log(`_audit_calldata-decode: ${nCases} differential cases, all jeth==solc`);
  });
});
