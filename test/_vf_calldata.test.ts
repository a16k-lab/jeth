// _vf_calldata: adversarial differential probe of CALLDATA DECODING parity vs solc.
// One contract C with many decode shapes: nested dyn arrays (u256[][], u8[][]),
// string[]/bytes[], dynamic structs (with string/bytes fields, nested), fixed arrays
// as params, tuples, bytes/string scalar params, mixed static+dynamic, multi-arg.
// We hand-build calldata word-by-word so we can feed adversarial payloads: dirty
// high bits in narrow-type args, boundary offsets, huge lengths, truncated tails,
// overlapping/non-canonical offsets, trailing junk. Every probe must be BYTE-IDENTICAL
// to solc (success flag AND returndata, including the exact revert form).
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

// Right-pad raw bytes to a 32-byte multiple, hex (no 0x). 0-length => no payload word.
function padData(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';
  const words = Math.ceil(bytes.length / 32);
  let h = '';
  for (let i = 0; i < words * 32; i++) h += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  return h;
}
const sb = (str: string) => enc.encode(str);

// Encode a string/bytes element body: [len][padded data].
const elemBody = (b: Uint8Array) => pad(BigInt(b.length)) + padData(b);

// Encode a string[]/bytes[] DATA REGION (no outer offset): [len][offset table][payloads].
// Offsets are relative to the table start (word after len).
function arrayRegion(items: Uint8Array[]): string {
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

// Encode a u256[][] (or u8[][]) DATA REGION (no outer offset):
// [outerLen][inner offset table][inner regions]. Inner offsets relative to table start.
function nestedRegion(rows: bigint[][]): string {
  const L = rows.length;
  const inner = rows.map((r) => pad(BigInt(r.length)) + r.map(pad).join(''));
  let off = L * 32;
  let table = '';
  for (const ir of inner) {
    table += pad(BigInt(off));
    off += ir.length / 2;
  }
  return pad(BigInt(L)) + table + inner.join('');
}

// Encode a dynamic value array region [len][elems].
const dynValRegion = (xs: bigint[]) => pad(BigInt(xs.length)) + xs.map(pad).join('');

const JETH = `
@struct class Pt { x: u128; y: u128; }
@struct class Acct { bal: u128; nonce: u64; active: bool; }
@struct class Inner { a: u128; b: u128; }
@struct class Outer { p: u64; inner: Inner; q: u64; }
@struct class WithArr { id: u64; data: Arr<u256, 2>; }
@struct class Dyn { a: u64; s: string; b: bytes; z: u64; }
@struct class NestDyn { x: u64; d: Dyn; y: u64; }

@contract
class C {
  // --- scalar value params with narrow types (dirty-bit territory) ---
  @external @pure echoU8(x: u8): u8 { return x; }
  @external @pure echoI8(x: i8): i8 { return x; }
  @external @pure echoBool(x: bool): bool { return x; }
  @external @pure echoAddr(x: address): address { return x; }
  @external @pure echoB4(x: bytes4): bytes4 { return x; }
  @external @pure addU8(a: u8, b: u8): u8 { unchecked: { return u8(a + b); } }

  // --- bytes / string scalar params ---
  @external @pure echoBytes(b: bytes): bytes { return b; }
  @external @pure echoStr(s: string): string { return s; }
  @external @pure bytesLen(b: bytes): u256 { return b.length; }
  @external @pure byteAt(b: bytes, i: u256): bytes1 { return b[i]; }

  // --- fixed-array params ---
  @external @pure sumTriple(a: Arr<u256, 3>): u256 { return a[0n] + a[1n] + a[2n]; }
  @external @pure pickU8(a: Arr<u8, 4>, i: u256): u8 { return a[i]; }

  // --- dynamic value-array param ---
  @external @pure dynLen(a: u256[]): u256 { return a.length; }
  @external @pure dynAt(a: u256[], i: u256): u256 { return a[i]; }
  @external @pure dynAtU8(a: u8[], i: u256): u8 { return a[i]; }

  // --- nested dynamic arrays ---
  @external @pure mLen(m: u256[][]): u256 { return m.length; }
  @external @pure mInnerLen(m: u256[][], i: u256): u256 { return m[i].length; }
  @external @pure mAt(m: u256[][], i: u256, j: u256): u256 { return m[i][j]; }
  @external @pure echoM(m: u256[][]): u256[][] { return m; }
  @external @pure mAtU8(m: u8[][], i: u256, j: u256): u8 { return m[i][j]; }

  // --- string[] / bytes[] ---
  @external @pure saLen(a: string[]): u256 { return a.length; }
  @external @pure saAt(a: string[], i: u256): string { return a[i]; }
  @external @pure echoSA(a: string[]): string[] { return a; }
  @external @pure baAt(a: bytes[], i: u256): bytes { return a[i]; }

  // --- static struct params ---
  @external @pure ptX(p: Pt): u128 { return p.x; }
  @external @pure ptY(p: Pt): u128 { return p.y; }
  @external @pure acctNonce(a: Acct): u64 { return a.nonce; }
  @external @pure acctActive(a: Acct): bool { return a.active; }
  @external @pure outerB(o: Outer): u128 { return o.inner.b; }
  @external @pure outerQ(o: Outer): u64 { return o.q; }
  @external @pure waId(t: WithArr): u64 { return t.id; }
  @external @pure waData(t: WithArr, j: u256): u256 { return t.data[j]; }

  // --- dynamic array of static struct ---
  @external @pure ptsLen(ps: Pt[]): u256 { return ps.length; }
  @external @pure ptsX(ps: Pt[], i: u256): u128 { return ps[i].x; }
  @external @pure echoPts(ps: Pt[]): Pt[] { return ps; }

  // --- dynamic struct param (string + bytes fields) ---
  @external @pure dynA(d: Dyn): u64 { return d.a; }
  @external @pure dynZ(d: Dyn): u64 { return d.z; }
  @external @pure dynS(d: Dyn): string { return d.s; }
  @external @pure dynB(d: Dyn): bytes { return d.b; }
  @external @pure echoDyn(d: Dyn): Dyn { return d; }
  @external @pure ndY(n: NestDyn): u64 { return n.y; }
  @external @pure ndInnerA(n: NestDyn): u64 { return n.d.a; }

  // --- mixed static + dynamic args (head-cursor advance) ---
  @external @pure mix1(x: u256, a: u256[], y: u256): u256 { return x + y + a.length; }
  @external @pure mix2(a: u256[], s: string, b: u256[]): u256 { unchecked: { return a.length + b.length; } }
  @external @pure mix3(p: Pt, a: u256[], q: u64): u256 { unchecked: { return p.x + a.length + q; } }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct Pt { uint128 x; uint128 y; }
  struct Acct { uint128 bal; uint64 nonce; bool active; }
  struct Inner { uint128 a; uint128 b; }
  struct Outer { uint64 p; Inner inner; uint64 q; }
  struct WithArr { uint64 id; uint256[2] data; }
  struct Dyn { uint64 a; string s; bytes b; uint64 z; }
  struct NestDyn { uint64 x; Dyn d; uint64 y; }

  function echoU8(uint8 x) external pure returns (uint8){ return x; }
  function echoI8(int8 x) external pure returns (int8){ return x; }
  function echoBool(bool x) external pure returns (bool){ return x; }
  function echoAddr(address x) external pure returns (address){ return x; }
  function echoB4(bytes4 x) external pure returns (bytes4){ return x; }
  function addU8(uint8 a, uint8 b) external pure returns (uint8){ unchecked { return a + b; } }

  function echoBytes(bytes calldata b) external pure returns (bytes memory){ return b; }
  function echoStr(string calldata s) external pure returns (string memory){ return s; }
  function bytesLen(bytes calldata b) external pure returns (uint256){ return b.length; }
  function byteAt(bytes calldata b, uint256 i) external pure returns (bytes1){ return b[i]; }

  function sumTriple(uint256[3] calldata a) external pure returns (uint256){ return a[0]+a[1]+a[2]; }
  function pickU8(uint8[4] calldata a, uint256 i) external pure returns (uint8){ return a[i]; }

  function dynLen(uint256[] calldata a) external pure returns (uint256){ return a.length; }
  function dynAt(uint256[] calldata a, uint256 i) external pure returns (uint256){ return a[i]; }
  function dynAtU8(uint8[] calldata a, uint256 i) external pure returns (uint8){ return a[i]; }

  function mLen(uint256[][] calldata m) external pure returns (uint256){ return m.length; }
  function mInnerLen(uint256[][] calldata m, uint256 i) external pure returns (uint256){ return m[i].length; }
  function mAt(uint256[][] calldata m, uint256 i, uint256 j) external pure returns (uint256){ return m[i][j]; }
  function echoM(uint256[][] calldata m) external pure returns (uint256[][] memory){ return m; }
  function mAtU8(uint8[][] calldata m, uint256 i, uint256 j) external pure returns (uint8){ return m[i][j]; }

  function saLen(string[] calldata a) external pure returns (uint256){ return a.length; }
  function saAt(string[] calldata a, uint256 i) external pure returns (string memory){ return a[i]; }
  function echoSA(string[] calldata a) external pure returns (string[] memory){ return a; }
  function baAt(bytes[] calldata a, uint256 i) external pure returns (bytes memory){ return a[i]; }

  function ptX(Pt calldata p) external pure returns (uint128){ return p.x; }
  function ptY(Pt calldata p) external pure returns (uint128){ return p.y; }
  function acctNonce(Acct calldata a) external pure returns (uint64){ return a.nonce; }
  function acctActive(Acct calldata a) external pure returns (bool){ return a.active; }
  function outerB(Outer calldata o) external pure returns (uint128){ return o.inner.b; }
  function outerQ(Outer calldata o) external pure returns (uint64){ return o.q; }
  function waId(WithArr calldata t) external pure returns (uint64){ return t.id; }
  function waData(WithArr calldata t, uint256 j) external pure returns (uint256){ return t.data[j]; }

  function ptsLen(Pt[] calldata ps) external pure returns (uint256){ return ps.length; }
  function ptsX(Pt[] calldata ps, uint256 i) external pure returns (uint128){ return ps[i].x; }
  function echoPts(Pt[] calldata ps) external pure returns (Pt[] memory){ return ps; }

  function dynA(Dyn calldata d) external pure returns (uint64){ return d.a; }
  function dynZ(Dyn calldata d) external pure returns (uint64){ return d.z; }
  function dynS(Dyn calldata d) external pure returns (string memory){ return d.s; }
  function dynB(Dyn calldata d) external pure returns (bytes memory){ return d.b; }
  function echoDyn(Dyn calldata d) external pure returns (Dyn memory){ return d; }
  function ndY(NestDyn calldata n) external pure returns (uint64){ return n.y; }
  function ndInnerA(NestDyn calldata n) external pure returns (uint64){ return n.d.a; }

  function mix1(uint256 x, uint256[] calldata a, uint256 y) external pure returns (uint256){ return x + y + a.length; }
  function mix2(uint256[] calldata a, string calldata s, uint256[] calldata b) external pure returns (uint256){ unchecked { return a.length + b.length; } }
  function mix3(Pt calldata p, uint256[] calldata a, uint64 q) external pure returns (uint256){ unchecked { return p.x + a.length + q; } }
}`;

describe('_vf_calldata: adversarial calldata decode parity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;

  // raw calldata from selector + 32-byte words.
  const raw = (selSig: string, words: bigint[], tail = '') =>
    '0x' + sel(selSig) + words.map(pad).join('') + tail;
  // raw calldata from selector + an already-built hex body (no 0x).
  const rawHex = (selSig: string, bodyHex: string) => '0x' + sel(selSig) + bodyHex;

  async function eq(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success || j.returnHex !== s.returnHex)
      mism.push(
        label +
          ': jeth{ok=' + j.success + ',ret=' + j.returnHex + ',err=' + j.exceptionError +
          '} sol{ok=' + s.success + ',ret=' + s.returnHex + '}',
      );
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const cb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(cb.creation);
  });

  it('runs', async () => {
    // ===== (A) narrow scalar params with dirty high bits =====
    const dirties = [
      0n, 1n, 0xffn, 0x100n, 0x1ffn, (1n << 64n) | 7n, (1n << 200n) | 0xabn,
      M - 1n, 1n << 255n, (1n << 255n) | 0x7fn,
    ];
    for (const v of dirties) {
      await eq('echoU8 ' + v.toString(16), raw('echoU8(uint8)', [v]));
      await eq('echoI8 ' + v.toString(16), raw('echoI8(int8)', [v]));
      await eq('echoBool ' + v.toString(16), raw('echoBool(bool)', [v]));
      await eq('echoAddr ' + v.toString(16), raw('echoAddr(address)', [v]));
      await eq('echoB4 ' + v.toString(16), raw('echoB4(bytes4)', [v]));
    }
    // addU8 with dirty inputs (both must clean before adding, or both keep dirty)
    for (const a of [0n, 0xffn, 0x100n, (1n << 64n) | 5n, M - 1n])
      for (const b of [1n, 0xffn, 0x1ffn, M - 1n])
        await eq('addU8 ' + a.toString(16) + ',' + b.toString(16), raw('addU8(uint8,uint8)', [a, b]));

    // ===== (B) bytes/string scalar params =====
    for (const body of [sb(''), sb('a'), sb('hello'), sb('Z'.repeat(31)), sb('Z'.repeat(32)), sb('W'.repeat(33)), sb('Q'.repeat(96))]) {
      await eq('echoBytes len' + body.length, rawHex('echoBytes(bytes)', pad(0x20n) + elemBody(body)));
      await eq('echoStr len' + body.length, rawHex('echoStr(string)', pad(0x20n) + elemBody(body)));
      await eq('bytesLen len' + body.length, rawHex('bytesLen(bytes)', pad(0x20n) + elemBody(body)));
    }
    // byteAt: in-range and OOB
    const bb = sb('abcdef');
    for (const i of [0n, 3n, 5n, 6n, 7n, 100n, M - 1n])
      await eq('byteAt i=' + i, rawHex('byteAt(bytes,uint256)', pad(0x40n) + pad(i) + elemBody(bb)));

    // bytes malformed: trailing-bit non-zero padding in last word; trailing junk; bad offset.
    // last-word non-canonical padding (3-byte string with junk in remaining 29 bytes).
    {
      const junkPad = pad(3n) + ('616263' + 'ff'.repeat(29)); // "abc" + 29 junk bytes
      await eq('echoBytes dirty-pad', rawHex('echoBytes(bytes)', pad(0x20n) + junkPad));
      await eq('echoStr dirty-pad', rawHex('echoStr(string)', pad(0x20n) + junkPad));
    }
    await eq('echoBytes bad-offset', raw('echoBytes(bytes)', [0x1000n]));
    await eq('echoBytes off=2^255', raw('echoBytes(bytes)', [1n << 255n]));
    await eq('echoBytes len-huge', raw('echoBytes(bytes)', [0x20n, M - 1n]));
    await eq('echoBytes len-2^64', raw('echoBytes(bytes)', [0x20n, 1n << 64n]));
    // len declared but no payload words
    await eq('echoBytes len=33 no-payload', raw('echoBytes(bytes)', [0x20n, 33n]));
    // trailing junk after a valid bytes
    await eq('echoBytes trailing-junk', rawHex('echoBytes(bytes)', pad(0x20n) + elemBody(sb('hi')) + 'de'.repeat(32)));
    // non-32-aligned but in-range offset
    await eq('echoBytes off=0x28', rawHex('echoBytes(bytes)', pad(0x28n) + '00'.repeat(8) + elemBody(sb('xy'))));

    // ===== (C) fixed-array params =====
    await eq('sumTriple', raw('sumTriple(uint256[3])', [10n, 20n, 30n]));
    await eq('sumTriple max', raw('sumTriple(uint256[3])', [M - 1n, 1n, 0n])); // overflow -> Panic 0x11
    for (const i of [0n, 1n, 2n, 3n, 4n, M - 1n])
      await eq('pickU8 i=' + i, raw('pickU8(uint8[4],uint256)', [10n, 20n, 30n, 40n, i]));
    // dirty element read vs unread (lazy)
    await eq('pickU8 dirty-read', raw('pickU8(uint8[4],uint256)', [1n, 2n, 0x1ffn, 4n, 2n]));
    await eq('pickU8 dirty-unread', raw('pickU8(uint8[4],uint256)', [1n, 2n, 0x1ffn, 4n, 0n]));
    await eq('pickU8 dirty-elem0-read0', raw('pickU8(uint8[4],uint256)', [1n << 250n, 2n, 3n, 4n, 0n]));
    // short calldata for fixed array
    await eq('sumTriple short', '0x' + sel('sumTriple(uint256[3])') + pad(1n) + pad(2n));

    // ===== (D) dynamic value-array param =====
    for (const arr of [[], [0n], [1n, 2n, 3n], [M - 1n, 0n, 7n, 42n, 99n]]) {
      await eq('dynLen n=' + arr.length, rawHex('dynLen(uint256[])', pad(0x20n) + dynValRegion(arr)));
      for (let i = 0; i < arr.length; i++)
        await eq('dynAt n=' + arr.length + ' i=' + i, rawHex('dynAt(uint256[],uint256)', pad(0x40n) + pad(BigInt(i)) + dynValRegion(arr)));
      // OOB index
      await eq('dynAt OOB n=' + arr.length, rawHex('dynAt(uint256[],uint256)', pad(0x40n) + pad(BigInt(arr.length)) + dynValRegion(arr)));
    }
    // dynAtU8: element value cleaning / dirty-bit
    await eq('dynAtU8 clean', rawHex('dynAtU8(uint8[],uint256)', pad(0x40n) + pad(0n) + dynValRegion([0x7fn, 2n])));
    await eq('dynAtU8 dirty-read', rawHex('dynAtU8(uint8[],uint256)', pad(0x40n) + pad(0n) + dynValRegion([0x1ffn, 2n])));
    await eq('dynAtU8 dirty-unread', rawHex('dynAtU8(uint8[],uint256)', pad(0x40n) + pad(1n) + dynValRegion([0x1ffn, 2n])));
    // dynamic array malformed
    await eq('dynLen bad-offset', raw('dynLen(uint256[])', [0x1000n]));
    await eq('dynLen off=2^255', raw('dynLen(uint256[])', [1n << 255n]));
    await eq('dynLen huge-len', raw('dynLen(uint256[])', [0x20n, 1n << 64n]));
    await eq('dynLen len2-payload1', raw('dynLen(uint256[])', [0x20n, 2n, 5n])); // declare 2, supply 1
    await eq('dynLen off=0x28 nonalign', rawHex('dynLen(uint256[])', pad(0x28n) + '00'.repeat(8) + dynValRegion([1n, 2n])));
    await eq('dynLen trailing-junk', rawHex('dynLen(uint256[])', pad(0x20n) + dynValRegion([1n, 2n]) + 'ab'.repeat(32)));

    // ===== (E) nested dynamic arrays u256[][] =====
    const grids: bigint[][][] = [
      [],
      [[]],
      [[1n, 2n], [3n]],
      [[], [7n], [8n, 9n, 10n]],
      [[M - 1n], [0n, 0n], []],
    ];
    for (const g of grids) {
      await eq('mLen ' + JSON.stringify(g.map((r) => r.length)), rawHex('mLen(uint256[][])', pad(0x20n) + nestedRegion(g)));
      await eq('echoM ' + JSON.stringify(g.map((r) => r.length)), rawHex('echoM(uint256[][])', pad(0x20n) + nestedRegion(g)));
      for (let i = 0; i < g.length; i++) {
        await eq('mInnerLen i=' + i, rawHex('mInnerLen(uint256[][],uint256)', pad(0x40n) + pad(BigInt(i)) + nestedRegion(g)));
        for (let j = 0; j < g[i]!.length; j++)
          await eq('mAt i=' + i + ' j=' + j, rawHex('mAt(uint256[][],uint256,uint256)', pad(0x60n) + pad(BigInt(i)) + pad(BigInt(j)) + nestedRegion(g)));
        // inner OOB
        await eq('mAt inner-OOB i=' + i, rawHex('mAt(uint256[][],uint256,uint256)', pad(0x60n) + pad(BigInt(i)) + pad(BigInt(g[i]!.length)) + nestedRegion(g)));
      }
      // outer OOB
      await eq('mAt outer-OOB', rawHex('mAt(uint256[][],uint256,uint256)', pad(0x60n) + pad(BigInt(g.length)) + pad(0n) + nestedRegion(g)));
    }
    // nested malformed: bad inner offset, truncated inner table, huge inner len.
    await eq('mLen bad-outer', raw('mLen(uint256[][])', [0x1000n]));
    await eq('mLen trunc-table', raw('mLen(uint256[][])', [0x20n, 3n, 0x60n])); // declare 3 inner, 1 table word
    await eq('mAt inner-bad-off', rawHex('mAt(uint256[][],uint256,uint256)', pad(0x60n) + pad(0n) + pad(0n) + pad(1n) + pad(0x1000n)));
    await eq('mAt inner-huge-len', rawHex('mAt(uint256[][],uint256,uint256)', pad(0x60n) + pad(0n) + pad(0n) + pad(1n) + pad(0x20n) + pad(1n << 64n)));
    // u8[][] element cleaning / dirty
    await eq('mAtU8 clean', rawHex('mAtU8(uint8[][],uint256,uint256)', pad(0x60n) + pad(0n) + pad(0n) + nestedRegion([[0x7fn]])));
    await eq('mAtU8 dirty-read', rawHex('mAtU8(uint8[][],uint256,uint256)', pad(0x60n) + pad(0n) + pad(0n) + nestedRegion([[0x1ffn]])));

    // ===== (F) string[] / bytes[] =====
    const big = 'X'.repeat(40);
    const lists: Uint8Array[][] = [
      [],
      [sb('hello')],
      [sb('ab'), sb(''), sb(big)],
      [sb('Y'.repeat(31)), sb('Z'.repeat(32)), sb('W'.repeat(33))],
    ];
    for (const l of lists) {
      await eq('saLen ' + l.length, rawHex('saLen(string[])', pad(0x20n) + arrayRegion(l)));
      await eq('echoSA ' + l.length, rawHex('echoSA(string[])', pad(0x20n) + arrayRegion(l)));
      for (let i = 0; i < l.length; i++)
        await eq('saAt ' + l.length + ' i=' + i, rawHex('saAt(string[],uint256)', pad(0x40n) + pad(BigInt(i)) + arrayRegion(l)));
      await eq('saAt OOB ' + l.length, rawHex('saAt(string[],uint256)', pad(0x40n) + pad(BigInt(l.length)) + arrayRegion(l)));
    }
    await eq('baAt', rawHex('baAt(bytes[],uint256)', pad(0x40n) + pad(0n) + arrayRegion([new Uint8Array([1, 2, 3])])));
    // string[] malformed
    await eq('saLen bad-outer', raw('saLen(string[])', [0x1000n]));
    await eq('saLen trunc-table', raw('saLen(string[])', [0x20n, 3n, 0x60n]));
    await eq('saAt bad-elem-off', raw('saAt(string[],uint256)', [0x40n, 0n, 1n, 0x1000n]));
    await eq('saAt payload-past-end', raw('saAt(string[],uint256)', [0x40n, 0n, 1n, 0x20n, 0x40n]));
    await eq('saAt wrong-base-off', raw('saAt(string[],uint256)', [0x40n, 0n, 1n, 0x100n]));

    // ===== (G) static struct params (dirty leaves) =====
    await eq('ptX', raw('ptX((uint128,uint128))', [0xcafen, 0xbeefn]));
    await eq('ptY', raw('ptY((uint128,uint128))', [0xcafen, 0xbeefn]));
    await eq('ptX dirty-x-read', raw('ptX((uint128,uint128))', [(1n << 200n) | 0xcafen, 0xbeefn]));
    await eq('ptX dirty-y-unread', raw('ptX((uint128,uint128))', [0xcafen, (1n << 200n) | 0xbeefn]));
    await eq('acctNonce', raw('acctNonce((uint128,uint64,bool))', [1000n, 7n, 1n]));
    await eq('acctActive', raw('acctActive((uint128,uint64,bool))', [1000n, 7n, 1n]));
    await eq('acctNonce dirty', raw('acctNonce((uint128,uint64,bool))', [1000n, 1n << 64n, 1n]));
    await eq('acctActive dirty', raw('acctActive((uint128,uint64,bool))', [1000n, 7n, 2n]));
    await eq('acctActive dirty-255', raw('acctActive((uint128,uint64,bool))', [1000n, 7n, 0xffn]));
    await eq('acctNonce dirty-unread-bal', raw('acctNonce((uint128,uint64,bool))', [1n << 200n, 7n, 1n]));
    await eq('outerB', raw('outerB((uint64,(uint128,uint128),uint64))', [0x11n, 0xaaaan, 0xbbbbn, 0x22n]));
    await eq('outerQ', raw('outerQ((uint64,(uint128,uint128),uint64))', [0x11n, 0xaaaan, 0xbbbbn, 0x22n]));
    await eq('outerQ dirty-q', raw('outerQ((uint64,(uint128,uint128),uint64))', [0x11n, 0xaaaan, 0xbbbbn, 1n << 64n]));
    await eq('waId', raw('waId((uint64,uint256[2]))', [9n, 0x111n, 0x222n]));
    await eq('waData j=0', raw('waData((uint64,uint256[2]),uint256)', [9n, 0x111n, 0x222n, 0n]));
    await eq('waData j=1', raw('waData((uint64,uint256[2]),uint256)', [9n, 0x111n, 0x222n, 1n]));
    await eq('waData OOB', raw('waData((uint64,uint256[2]),uint256)', [9n, 0x111n, 0x222n, 2n]));
    // short struct calldata
    await eq('outerB short', '0x' + sel('outerB((uint64,(uint128,uint128),uint64))') + pad(1n) + pad(2n) + pad(3n));

    // ===== (H) dynamic array of static struct Pt[] =====
    const ptsCases: bigint[][] = [[], [1n, 2n], [1n, 2n, 3n, 4n], [5n, 6n, 7n, 8n, 9n, 10n]];
    for (const flat of ptsCases) {
      const n = flat.length / 2;
      const region = pad(BigInt(n)) + flat.map(pad).join('');
      await eq('ptsLen n=' + n, rawHex('ptsLen((uint128,uint128)[])', pad(0x20n) + region));
      await eq('echoPts n=' + n, rawHex('echoPts((uint128,uint128)[])', pad(0x20n) + region));
      for (let i = 0; i < n; i++)
        await eq('ptsX n=' + n + ' i=' + i, rawHex('ptsX((uint128,uint128)[],uint256)', pad(0x40n) + pad(BigInt(i)) + region));
      await eq('ptsX OOB n=' + n, rawHex('ptsX((uint128,uint128)[],uint256)', pad(0x40n) + pad(BigInt(n)) + region));
    }
    // Pt[] dirty field read vs unread; echo validates all fields.
    await eq('ptsX dirty-x-read', rawHex('ptsX((uint128,uint128)[],uint256)', pad(0x40n) + pad(0n) + pad(1n) + pad((1n << 200n) | 1n) + pad(2n)));
    await eq('echoPts dirty-y', rawHex('echoPts((uint128,uint128)[])', pad(0x20n) + pad(1n) + pad(1n) + pad((1n << 200n) | 2n)));
    // Pt[] one-word short / huge len
    await eq('ptsLen short', raw('ptsLen((uint128,uint128)[])', [0x20n, 2n, 1n, 2n, 3n]));
    await eq('ptsLen huge', raw('ptsLen((uint128,uint128)[])', [0x20n, 1n << 64n]));

    // ===== (I) dynamic struct param Dyn{a, string s, bytes b, z} =====
    // tuple head: [a][off_s][off_b][z]; offsets relative to tuple start.
    function dynStruct(a: bigint, s: Uint8Array, b: Uint8Array, z: bigint): string {
      // 4 head words; tail: s-body then b-body. off relative to tuple start.
      const sBody = elemBody(s);
      const bBody = elemBody(b);
      const offS = 4n * 32n;
      const offB = offS + BigInt(sBody.length / 2);
      return (pad(a) + pad(offS) + pad(offB) + pad(z) + sBody + bBody);
    }
    const dynCases: [bigint, Uint8Array, Uint8Array, bigint][] = [
      [1n, sb(''), new Uint8Array(0), 2n],
      [0xaan, sb('hi'), new Uint8Array([1, 2, 3]), 0xbbn],
      [7n, sb('Z'.repeat(40)), new Uint8Array(50).map((_, k) => (k * 7) & 0xff), 9n],
      [0n, sb('Z'.repeat(32)), new Uint8Array(0), M & 0n],
    ];
    for (const [a, s, b, z] of dynCases) {
      const tuple = dynStruct(a, s, b, z);
      const body = pad(0x20n) + tuple; // single param: head offset to tuple = 0x20
      await eq('dynA a=' + a, rawHex('dynA((uint64,string,bytes,uint64))', body));
      await eq('dynZ z=' + z, rawHex('dynZ((uint64,string,bytes,uint64))', body));
      await eq('dynS', rawHex('dynS((uint64,string,bytes,uint64))', body));
      await eq('dynB', rawHex('dynB((uint64,string,bytes,uint64))', body));
      await eq('echoDyn', rawHex('echoDyn((uint64,string,bytes,uint64))', body));
    }
    // dynamic struct dirty static-field validation
    {
      const sBody = elemBody(sb('x'));
      const bBody = elemBody(new Uint8Array([9]));
      const offS = 4n * 32n;
      const offB = offS + BigInt(sBody.length / 2);
      // dirty 'a' (bit64 set), read a -> revert empty (both)
      const dirtyA = pad(1n << 64n) + pad(offS) + pad(offB) + pad(2n) + sBody + bBody;
      await eq('dynA dirty-a-read', rawHex('dynA((uint64,string,bytes,uint64))', pad(0x20n) + dirtyA));
      await eq('dynZ dirty-a-unread', rawHex('dynZ((uint64,string,bytes,uint64))', pad(0x20n) + dirtyA));
      // echo validates static fields -> dirty 'a' reverts even via echo
      await eq('echoDyn dirty-a', rawHex('echoDyn((uint64,string,bytes,uint64))', pad(0x20n) + dirtyA));
    }
    // dynamic struct malformed: bad inner offset for s
    await eq('dynS bad-off-s', rawHex('dynS((uint64,string,bytes,uint64))', pad(0x20n) + pad(1n) + pad(0x1000n) + pad(0x80n) + pad(2n)));

    // ===== (J) nested dynamic struct NestDyn{x, Dyn d, y} =====
    {
      // outer tuple head: [x][off_d][y]; d is a dynamic tuple itself.
      const a = 5n, z = 6n, x = 0x10n, y = 0x20n;
      const s = sb('inner'), b = new Uint8Array([7, 8]);
      const sBody = elemBody(s), bBody = elemBody(b);
      const dOffS = 4n * 32n, dOffB = dOffS + BigInt(sBody.length / 2);
      const dTuple = pad(a) + pad(dOffS) + pad(dOffB) + pad(z) + sBody + bBody;
      const outOffD = 3n * 32n; // after [x][off_d][y]
      const outerTuple = pad(x) + pad(outOffD) + pad(y) + dTuple;
      const body = pad(0x20n) + outerTuple;
      await eq('ndY', rawHex('ndY((uint64,(uint64,string,bytes,uint64),uint64))', body));
      await eq('ndInnerA', rawHex('ndInnerA((uint64,(uint64,string,bytes,uint64),uint64))', body));
    }

    // ===== (K) mixed static + dynamic args =====
    await eq('mix1', rawHex('mix1(uint256,uint256[],uint256)', pad(100n) + pad(0x60n) + pad(7n) + dynValRegion([1n, 2n, 3n])));
    await eq('mix1 overflow', rawHex('mix1(uint256,uint256[],uint256)', pad(M - 1n) + pad(0x60n) + pad(5n) + dynValRegion([1n])));
    // mix2(a, s, b): three offsets, then regions in order a,s,b. base = byte 4.
    {
      const aReg = dynValRegion([1n, 2n]);
      const sReg = elemBody(sb('abc'));
      const bReg = dynValRegion([9n]);
      const offA = 0x60n; // 3 head words
      const offS = offA + BigInt(aReg.length / 2);
      const offB = offS + BigInt(sReg.length / 2);
      await eq('mix2', rawHex('mix2(uint256[],string,uint256[])', pad(offA) + pad(offS) + pad(offB) + aReg + sReg + bReg));
    }
    // mix3(Pt p, a, q): p inline (2 words), then offset to a, then q.
    {
      const aReg = dynValRegion([1n, 2n, 3n, 4n]);
      // head: [p.x][p.y][off_a][q] -> off_a base byte4 = 0x80
      await eq('mix3', rawHex('mix3((uint128,uint128),uint256[],uint64)', pad(0x05n) + pad(0n) + pad(0x80n) + pad(0x07n) + aReg));
      // dirty p.y (unread) -> still ok
      await eq('mix3 dirty-py', rawHex('mix3((uint128,uint128),uint256[],uint64)', pad(0x05n) + pad((1n << 200n)) + pad(0x80n) + pad(0x07n) + aReg));
      // dirty q (bit64) -> read q in length sum? q is used; dirty must revert
      await eq('mix3 dirty-q', rawHex('mix3((uint128,uint128),uint256[],uint64)', pad(0x05n) + pad(0n) + pad(0x80n) + pad(1n << 64n) + aReg));
    }

    // ===== (M) deep adversarial decode-validation edges =====
    // (M1) mix2: malformed UNREAD param 's'. Body never reads s, but solc validates
    // ALL dynamic params on entry. If JETH lazily skips validating s, it diverges.
    {
      const aReg = dynValRegion([1n, 2n]);
      const bReg = dynValRegion([9n]);
      // s offset points past calldatasize -> solc reverts EMPTY on entry decode.
      const aOff = 0x60n;
      // place a after head, b after a; give s a bogus huge offset.
      const sBogus = 0x100000n;
      const bOff = aOff + BigInt(aReg.length / 2);
      await eq('mix2 unread-s bad-offset', rawHex('mix2(uint256[],string,uint256[])', pad(aOff) + pad(sBogus) + pad(bOff) + aReg + bReg));
      // s length declares payload past end (unread) -> entry decode revert EMPTY.
      const sBad = pad(0x40n); // declares 64-byte string, no payload
      const aOff2 = 0x60n;
      const sOff2 = aOff2 + BigInt(aReg.length / 2);
      const bOff2 = sOff2 + 32n; // s body is 1 word (just the bad length)
      await eq('mix2 unread-s payload-past', rawHex('mix2(uint256[],string,uint256[])', pad(aOff2) + pad(sOff2) + pad(bOff2) + aReg + sBad + bReg));
      // s offset = 2^256-32 (wraps near top) unread.
      await eq('mix2 unread-s off-wrap', rawHex('mix2(uint256[],string,uint256[])', pad(aOff) + pad(M - 32n) + pad(bOff) + aReg + bReg));
    }

    // (M2) bytes payload exact-fit vs one byte over the last word.
    {
      // len=32 needs exactly one payload word. Provide exactly that -> OK.
      await eq('echoBytes len32 exact', rawHex('echoBytes(bytes)', pad(0x20n) + pad(32n) + 'aa'.repeat(32)));
      // len=33 needs two payload words (64 bytes). Provide only 63 bytes -> EMPTY.
      await eq('echoBytes len33 short1', rawHex('echoBytes(bytes)', pad(0x20n) + pad(33n) + 'bb'.repeat(63)));
      // len=32 but only 31 payload bytes -> EMPTY.
      await eq('echoBytes len32 short1', rawHex('echoBytes(bytes)', pad(0x20n) + pad(32n) + 'cc'.repeat(31)));
    }

    // (M3) dynamic array length at the Panic(0x41) allocation boundary on ECHO.
    // echoM/echoSA must allocate; a length so large it cannot fit -> solc reverts.
    await eq('dynLen len=2^32', raw('dynLen(uint256[])', [0x20n, 1n << 32n]));
    await eq('dynLen len=2^65', raw('dynLen(uint256[])', [0x20n, 1n << 65n]));
    await eq('echoSA huge-len', raw('echoSA(string[])', [0x20n, 1n << 64n]));
    await eq('echoM huge-outer', raw('echoM(uint256[][])', [0x20n, 1n << 64n]));

    // (M4) offset = exactly calldatasize (points at the very end => zero-length
    // array reads succeed iff a length word is readable; here it is one-past => EMPTY).
    {
      // body is just the single head word (the offset). offset = 0x20 means length
      // word would start at byte 4+0x20 = 0x24, which is past end (no body) -> EMPTY.
      await eq('dynLen off=end', raw('dynLen(uint256[])', [0x20n]));
      // offset = 0 -> length word at byte 4 = the offset word itself (=0x20=32) -> array of 32 elems but no payload -> EMPTY.
      await eq('dynLen off=0', raw('dynLen(uint256[])', [0n]));
    }

    // (M5) fixed-array-of-struct: dirty leaf in UNREAD element (lazy) vs READ element.
    {
      // ptsX with n=2; element 1 has dirty x; read i=0 (clean) -> OK; read i=1 -> revert.
      const region = pad(2n) + pad(1n) + pad(2n) + pad((1n << 130n) | 3n) + pad(4n);
      await eq('ptsX dirty-elem1 read0', rawHex('ptsX((uint128,uint128)[],uint256)', pad(0x40n) + pad(0n) + region));
      await eq('ptsX dirty-elem1 read1', rawHex('ptsX((uint128,uint128)[],uint256)', pad(0x40n) + pad(1n) + region));
      // echoPts validates EVERY field -> dirty x in any element reverts even on echo.
      await eq('echoPts dirty-elem1', rawHex('echoPts((uint128,uint128)[])', pad(0x20n) + region));
    }

    // (M6) nested u256[][] echo with overlapping / backward inner offsets (solc accepts).
    {
      // outer len=2; both inner offsets point at the SAME inner array [len=1][42].
      const innerBody = pad(1n) + pad(42n);
      const tableStart = 2n * 32n; // first inner sits right after 2-word table
      const region = pad(2n) + pad(tableStart) + pad(tableStart) + innerBody;
      await eq('echoM overlap-inner', rawHex('echoM(uint256[][])', pad(0x20n) + region));
      await eq('mAt overlap i=1 j=0', rawHex('mAt(uint256[][],uint256,uint256)', pad(0x60n) + pad(1n) + pad(0n) + region));
    }

    // (M7) dynamic struct: bytes/string field offset that wraps / points backward.
    {
      const sBody = elemBody(sb('ok'));
      const bBody = elemBody(new Uint8Array([1]));
      // valid baseline already covered; now b offset points into s's region (overlap).
      const offS = 4n * 32n;
      // b offset = offS too (overlap onto the string body) -> solc reads s body as b.
      const tuple = pad(7n) + pad(offS) + pad(offS) + pad(9n) + sBody + bBody;
      await eq('dynB overlap-s', rawHex('dynB((uint64,string,bytes,uint64))', pad(0x20n) + tuple));
      // s offset wraps to 2^256-32 -> EMPTY on read.
      const tupleBad = pad(7n) + pad(M - 32n) + pad(offS + BigInt(sBody.length / 2)) + pad(9n) + sBody + bBody;
      await eq('dynS off-wrap', rawHex('dynS((uint64,string,bytes,uint64))', pad(0x20n) + tupleBad));
    }

    // (M8) bytes byte-index OOB family and length-0 indexing.
    await eq('byteAt empty i=0', rawHex('byteAt(bytes,uint256)', pad(0x40n) + pad(0n) + elemBody(sb(''))));
    await eq('byteAt len1 i=1', rawHex('byteAt(bytes,uint256)', pad(0x40n) + pad(1n) + elemBody(sb('Q'))));

    // (M9) two same-shape dynamic params sharing one offset (both point at one array).
    // mix2(a,s,b): a and b both point at the SAME u256[] region; s in between.
    {
      const aReg = dynValRegion([7n, 8n, 9n]); // len 3
      const sReg = elemBody(sb('mid'));
      const offA = 0x60n;
      const offS = offA + BigInt(aReg.length / 2);
      // b offset = a offset (alias). length sum = 3 + 3 = 6.
      await eq('mix2 alias-ab', rawHex('mix2(uint256[],string,uint256[])', pad(offA) + pad(offS) + pad(offA) + aReg + sReg));
    }

    // (M10) string param with multi-word length whose top bits are set (huge) and a
    // valid-looking but oversized length.
    await eq('echoStr len top-bit', rawHex('echoStr(string)', pad(0x20n) + pad(1n << 255n)));
    await eq('echoStr len 0xffff', rawHex('echoStr(string)', pad(0x20n) + pad(0xffffn) + 'ab'.repeat(2)));

    // ===== (N) final corner wave =====
    // (N1) sub-word (single-byte) truncation of a dynamic array payload.
    await eq('dynLen len1 short-1byte', rawHex('dynLen(uint256[])', pad(0x20n) + pad(1n) + 'ff'.repeat(31)));
    await eq('echoBytes len1 short-1byte', rawHex('echoBytes(bytes)', pad(0x20n) + pad(1n) + 'ff'.repeat(0))); // declares 1 byte, no payload word

    // (N2) length word that straddles calldata end (offset points so the length
    // word is only partially present). offset=0x20 with body only 0x20-1 bytes long.
    await eq('dynLen len-word-straddle', '0x' + sel('dynLen(uint256[])') + pad(0x20n) + 'ff'.repeat(31));

    // (N3) signed narrow types: sign bit + dirty upper bits sign-extension parity.
    for (const v of [0n, 1n, 0x7fn, 0x80n, 0xffn, 0x100n, (1n << 200n) | 0x80n, M - 1n, (M - 1n) ^ 0xffn]) {
      await eq('echoI8 sx ' + v.toString(16), raw('echoI8(int8)', [v]));
    }

    // (N4) echo of a string[] whose element forces multi-word allocation + a 0-len
    // element sandwiched between long elements (re-encode offset table parity).
    await eq('echoSA mixed-long', rawHex('echoSA(string[])', pad(0x20n) + arrayRegion([sb('A'.repeat(65)), sb(''), sb('B'.repeat(64)), sb('c')])));
    await eq('echoM jagged-large', rawHex('echoM(uint256[][])', pad(0x20n) + nestedRegion([[1n, 2n, 3n, 4n, 5n], [], [9n], [0n, 0n]])));

    // (N5) waData: dirty id (unread) ok; dirty data element (read) cleaned (uint256 = no clean).
    await eq('waData dirty-id-unread', raw('waData((uint64,uint256[2]),uint256)', [1n << 100n, 0x111n, 0x222n, 0n]));

    // (N6) Pt[] with stride boundary: declared length whose payload ends exactly at
    // calldatasize vs one word short (stride = 2 words).
    await eq('ptsLen exact n=3', raw('ptsLen((uint128,uint128)[])', [0x20n, 3n, 1n, 2n, 3n, 4n, 5n, 6n]));
    await eq('ptsLen short n=3', raw('ptsLen((uint128,uint128)[])', [0x20n, 3n, 1n, 2n, 3n, 4n, 5n]));

    // (N7) dynamic struct where a static leaf after a dynamic field is dirty (read z).
    {
      const sBody = elemBody(sb('q'));
      const bBody = elemBody(new Uint8Array([2]));
      const offS = 4n * 32n;
      const offB = offS + BigInt(sBody.length / 2);
      const tuple = pad(1n) + pad(offS) + pad(offB) + pad(1n << 64n) + sBody + bBody; // z dirty
      await eq('dynZ dirty-z-read', rawHex('dynZ((uint64,string,bytes,uint64))', pad(0x20n) + tuple));
      await eq('dynA dirty-z-unread', rawHex('dynA((uint64,string,bytes,uint64))', pad(0x20n) + tuple));
    }

    // ===== (L) empty calldata / unknown selector / partial selector =====
    await eq('empty', '0x');
    await eq('unknown-sel', '0xdeadbeef');
    await eq('partial-sel', '0xdead');
    await eq('sel-only echoU8', '0x' + sel('echoU8(uint8)'));
    await eq('sel+partial-word', '0x' + sel('echoU8(uint8)') + 'ff'.repeat(10));

    if (mism.length) {
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 40)) console.log(m);
    } else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
