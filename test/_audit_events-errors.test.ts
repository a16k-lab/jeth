// ADVERSARIAL DIFFERENTIAL AUDIT: events + errors (family: events-errors).
//
// Invariant: byte-identical to solc on (success/revert parity, revert returndata,
// AND emitted logs: topics + data byte-for-byte). This suite hunts for ANY divergence
// across emit/revert with value/bytes/string/array/struct args, indexed and non-indexed
// and mixed.
//
// KEY recently-fixed behavior under test: a calldata value-element array argument to an
// @event/@error VALIDATES every dirty element and reverts (unlike a return echo which
// cleans). We confirm BOTH the indexed-topic path (keccak of element words) and the
// non-indexed-data path revert on dirty narrow / bool / address / short-bytesN elements,
// identically to solc, comparing topics + data byte-for-byte. We also confirm the
// >3-indexed gate and indexed-shape gates are pure rejects (parity, not miscompile).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, type LogEntry } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const U256_MAX = M - 1n;
const A = BigInt('0x' + 'aa'.repeat(20));
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');

// ABI dynamic value-array tail [len][e0][e1]...; raw words so callers can inject DIRTY bits.
const arr = (xs: bigint[]) => pad(BigInt(xs.length)) + xs.map(pad).join('');
// raw bytes/string tail [len][padded data]
const rawBytesTail = (hex: string) => {
  const nb = hex.length / 2;
  const words = Math.ceil(nb / 32);
  return pad(BigInt(nb)) + hex.padEnd(words * 64, '0');
};
const strTail = (s: string) => rawBytesTail(Buffer.from(s, 'utf8').toString('hex'));

const eqLogs = (a: LogEntry[], b: LogEntry[]) =>
  a.length === b.length &&
  a.every((l, i) => l.data === b[i]!.data && JSON.stringify(l.topics) === JSON.stringify(b[i]!.topics));

// ----------------------------------------------------------------------------
// One JETH contract and the parallel Solidity contract exercising every shape.
// ----------------------------------------------------------------------------
const JETH = `@contract class C {
  // ---- errors with value-array args (calldata source) ----
  @error EU(a: u256[]);
  @error E8(a: u8[]);
  @error E16(a: u16[]);
  @error EBool(a: bool[]);
  @error EAddr(a: address[]);
  @error EB4(a: bytes4[]);
  @error EI8(a: i8[]);
  @error EI128(a: i128[]);
  @error ETag(tag: u256, a: u256[]);
  @error EArrStr(a: u256[], s: string);
  @error EStr(s: string);
  @error EBytes(b: bytes);
  @error ETwoArr(a: u8[], b: address[]);
  // ---- events: value-array args ----
  @event VEU(a: u256[]);
  @event VE8(a: u8[]);
  @event VEBool(a: bool[]);
  @event VEAddr(a: address[]);
  @event VEB4(a: bytes4[]);
  @event VEI8(a: i8[]);
  @event VETag(@indexed tag: u256, a: u256[]);
  @event VEArrStr(a: u256[], s: string);
  // ---- events: indexed value-array topics (keccak of element words) ----
  @event IU(@indexed a: u256[]);
  @event I8(@indexed a: u8[]);
  @event IBool(@indexed a: bool[]);
  @event IAddr(@indexed a: address[]);
  @event IB4(@indexed a: bytes4[]);
  @event II8(@indexed a: i8[]);
  @event IFirst(@indexed a: u256[], v: u256);
  @event ILast(k: u256, @indexed a: u256[]);
  @event IThree(@indexed k: u256, @indexed a: u256[], @indexed b: address[]);
  @event IMixData(@indexed a: u256[], s: string, v: u256);
  @event IMulti(@indexed a: u256[], @indexed b: u8[]);
  // ---- events: indexed bytes/string topics (keccak of content) ----
  @event IS(@indexed s: string, v: u256);
  @event IBy(@indexed b: bytes, v: u256);
  @event ITwoStr(@indexed s1: string, @indexed s2: string);
  // ---- events: scalar indexed/non-indexed (dirty-bit decode parity) ----
  @event Mixed(@indexed flag: u8, @indexed s: i16, @indexed ok: bool, who: address, sig: bytes4);
  @event Scalars(@indexed a: u8, b: i16, @indexed c: bool, d: bytes4, e: address);

  // ===== error functions =====
  @external @pure rEU(a: u256[]): void { revert(EU(a)); }
  @external @pure rE8(a: u8[]): void { revert(E8(a)); }
  @external @pure rE16(a: u16[]): void { revert(E16(a)); }
  @external @pure rEBool(a: bool[]): void { revert(EBool(a)); }
  @external @pure rEAddr(a: address[]): void { revert(EAddr(a)); }
  @external @pure rEB4(a: bytes4[]): void { revert(EB4(a)); }
  @external @pure rEI8(a: i8[]): void { revert(EI8(a)); }
  @external @pure rEI128(a: i128[]): void { revert(EI128(a)); }
  @external @pure rETag(t: u256, a: u256[]): void { revert(ETag(t, a)); }
  @external @pure rEArrStr(a: u256[], s: string): void { revert(EArrStr(a, s)); }
  @external @pure rEStr(s: string): void { revert(EStr(s)); }
  @external @pure rEBytes(b: bytes): void { revert(EBytes(b)); }
  @external @pure rETwoArr(a: u8[], b: address[]): void { revert(ETwoArr(a, b)); }

  // ===== event functions =====
  @external veu(a: u256[]): void { emit(VEU(a)); }
  @external ve8(a: u8[]): void { emit(VE8(a)); }
  @external veBool(a: bool[]): void { emit(VEBool(a)); }
  @external veAddr(a: address[]): void { emit(VEAddr(a)); }
  @external veB4(a: bytes4[]): void { emit(VEB4(a)); }
  @external veI8(a: i8[]): void { emit(VEI8(a)); }
  @external veTag(t: u256, a: u256[]): void { emit(VETag(t, a)); }
  @external veArrStr(a: u256[], s: string): void { emit(VEArrStr(a, s)); }

  @external iu(a: u256[]): void { emit(IU(a)); }
  @external i8(a: u8[]): void { emit(I8(a)); }
  @external iBool(a: bool[]): void { emit(IBool(a)); }
  @external iAddr(a: address[]): void { emit(IAddr(a)); }
  @external iB4(a: bytes4[]): void { emit(IB4(a)); }
  @external iI8(a: i8[]): void { emit(II8(a)); }
  @external iFirst(a: u256[], v: u256): void { emit(IFirst(a, v)); }
  @external iLast(k: u256, a: u256[]): void { emit(ILast(k, a)); }
  @external iThree(k: u256, a: u256[], b: address[]): void { emit(IThree(k, a, b)); }
  @external iMixData(a: u256[], s: string, v: u256): void { emit(IMixData(a, s, v)); }
  @external iMulti(a: u256[], b: u8[]): void { emit(IMulti(a, b)); }

  @external is_(s: string, v: u256): void { emit(IS(s, v)); }
  @external iby(b: bytes, v: u256): void { emit(IBy(b, v)); }
  @external itwoStr(s1: string, s2: string): void { emit(ITwoStr(s1, s2)); }

  @external eMixed(fl: u8, s: i16, ok: bool, w: address, sig: bytes4): void { emit(Mixed(fl, s, ok, w, sig)); }
  @external eScalars(a: u8, b: i16, c: bool, d: bytes4, e: address): void { emit(Scalars(a, b, c, d, e)); }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  error EU(uint256[] a);
  error E8(uint8[] a);
  error E16(uint16[] a);
  error EBool(bool[] a);
  error EAddr(address[] a);
  error EB4(bytes4[] a);
  error EI8(int8[] a);
  error EI128(int128[] a);
  error ETag(uint256 tag, uint256[] a);
  error EArrStr(uint256[] a, string s);
  error EStr(string s);
  error EBytes(bytes b);
  error ETwoArr(uint8[] a, address[] b);
  event VEU(uint256[] a);
  event VE8(uint8[] a);
  event VEBool(bool[] a);
  event VEAddr(address[] a);
  event VEB4(bytes4[] a);
  event VEI8(int8[] a);
  event VETag(uint256 indexed tag, uint256[] a);
  event VEArrStr(uint256[] a, string s);
  event IU(uint256[] indexed a);
  event I8(uint8[] indexed a);
  event IBool(bool[] indexed a);
  event IAddr(address[] indexed a);
  event IB4(bytes4[] indexed a);
  event II8(int8[] indexed a);
  event IFirst(uint256[] indexed a, uint256 v);
  event ILast(uint256 k, uint256[] indexed a);
  event IThree(uint256 indexed k, uint256[] indexed a, address[] indexed b);
  event IMixData(uint256[] indexed a, string s, uint256 v);
  event IMulti(uint256[] indexed a, uint8[] indexed b);
  event IS(string indexed s, uint256 v);
  event IBy(bytes indexed b, uint256 v);
  event ITwoStr(string indexed s1, string indexed s2);
  event Mixed(uint8 indexed flag, int16 indexed s, bool indexed ok, address who, bytes4 sig);
  event Scalars(uint8 indexed a, int16 b, bool indexed c, bytes4 d, address e);

  function rEU(uint256[] calldata a) external pure { revert EU(a); }
  function rE8(uint8[] calldata a) external pure { revert E8(a); }
  function rE16(uint16[] calldata a) external pure { revert E16(a); }
  function rEBool(bool[] calldata a) external pure { revert EBool(a); }
  function rEAddr(address[] calldata a) external pure { revert EAddr(a); }
  function rEB4(bytes4[] calldata a) external pure { revert EB4(a); }
  function rEI8(int8[] calldata a) external pure { revert EI8(a); }
  function rEI128(int128[] calldata a) external pure { revert EI128(a); }
  function rETag(uint256 t, uint256[] calldata a) external pure { revert ETag(t, a); }
  function rEArrStr(uint256[] calldata a, string calldata s) external pure { revert EArrStr(a, s); }
  function rEStr(string calldata s) external pure { revert EStr(s); }
  function rEBytes(bytes calldata b) external pure { revert EBytes(b); }
  function rETwoArr(uint8[] calldata a, address[] calldata b) external pure { revert ETwoArr(a, b); }

  function veu(uint256[] calldata a) external { emit VEU(a); }
  function ve8(uint8[] calldata a) external { emit VE8(a); }
  function veBool(bool[] calldata a) external { emit VEBool(a); }
  function veAddr(address[] calldata a) external { emit VEAddr(a); }
  function veB4(bytes4[] calldata a) external { emit VEB4(a); }
  function veI8(int8[] calldata a) external { emit VEI8(a); }
  function veTag(uint256 t, uint256[] calldata a) external { emit VETag(t, a); }
  function veArrStr(uint256[] calldata a, string calldata s) external { emit VEArrStr(a, s); }

  function iu(uint256[] calldata a) external { emit IU(a); }
  function i8(uint8[] calldata a) external { emit I8(a); }
  function iBool(bool[] calldata a) external { emit IBool(a); }
  function iAddr(address[] calldata a) external { emit IAddr(a); }
  function iB4(bytes4[] calldata a) external { emit IB4(a); }
  function iI8(int8[] calldata a) external { emit II8(a); }
  function iFirst(uint256[] calldata a, uint256 v) external { emit IFirst(a, v); }
  function iLast(uint256 k, uint256[] calldata a) external { emit ILast(k, a); }
  function iThree(uint256 k, uint256[] calldata a, address[] calldata b) external { emit IThree(k, a, b); }
  function iMixData(uint256[] calldata a, string calldata s, uint256 v) external { emit IMixData(a, s, v); }
  function iMulti(uint256[] calldata a, uint8[] calldata b) external { emit IMulti(a, b); }

  function is_(string calldata s, uint256 v) external { emit IS(s, v); }
  function iby(bytes calldata b, uint256 v) external { emit IBy(b, v); }
  function itwoStr(string calldata s1, string calldata s2) external { emit ITwoStr(s1, s2); }

  function eMixed(uint8 fl, int16 s, bool ok, address w, bytes4 sig) external { emit Mixed(fl, s, ok, w, sig); }
  function eScalars(uint8 a, int16 b, bool c, bytes4 d, address e) external { emit Scalars(a, b, c, d, e); }
}`;

describe('ADVERSARIAL events+errors vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;

  // Compare success, revert returndata, AND emitted logs (topics + data) byte-for-byte.
  async function eq(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    const probs: string[] = [];
    if (j.success !== s.success) probs.push('ok j=' + j.success + ' s=' + s.success);
    if (j.returnHex !== s.returnHex) probs.push('ret j=' + j.returnHex + ' s=' + s.returnHex);
    if (!eqLogs(j.logs, s.logs)) probs.push('logs\n  j=' + JSON.stringify(j.logs) + '\n  s=' + JSON.stringify(s.logs));
    if (probs.length) mism.push(label + ' {jethErr=' + j.exceptionError + '} :: ' + probs.join(' | '));
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('runs all adversarial cases', async () => {
    const DIRTY = U256_MAX; // all 256 bits set
    // bytesN are left-aligned; raw word = value << (32-size)*8
    const b4 = (v: bigint) => (v << (28n * 8n)) % M;

    // ============================================================
    // 1. CLEAN value-array args: error + event (data) + indexed topic
    // ============================================================
    const cleanU256: bigint[][] = [
      [],
      [0n],
      [U256_MAX],
      [1n, 2n, 3n],
      Array.from({ length: 40 }, (_, i) => BigInt(i) * 13n + 1n),
    ];
    for (const xs of cleanU256) {
      await eq(`rEU clean[${xs.length}]`, '0x' + sel('rEU(uint256[])') + pad(0x20n) + arr(xs));
      await eq(`veu clean[${xs.length}]`, '0x' + sel('veu(uint256[])') + pad(0x20n) + arr(xs));
      await eq(`iu clean[${xs.length}]`, '0x' + sel('iu(uint256[])') + pad(0x20n) + arr(xs));
    }
    for (const xs of [[], [0n], [255n], [1n, 255n, 128n, 0n]] as bigint[][]) {
      await eq(`rE8 clean[${xs.length}]`, '0x' + sel('rE8(uint8[])') + pad(0x20n) + arr(xs));
      await eq(`ve8 clean[${xs.length}]`, '0x' + sel('ve8(uint8[])') + pad(0x20n) + arr(xs));
      await eq(`i8 clean[${xs.length}]`, '0x' + sel('i8(uint8[])') + pad(0x20n) + arr(xs));
    }
    for (const xs of [[], [0n], [1n], [1n, 0n, 1n]] as bigint[][]) {
      await eq(`rEBool clean`, '0x' + sel('rEBool(bool[])') + pad(0x20n) + arr(xs));
      await eq(`veBool clean`, '0x' + sel('veBool(bool[])') + pad(0x20n) + arr(xs));
      await eq(`iBool clean`, '0x' + sel('iBool(bool[])') + pad(0x20n) + arr(xs));
    }
    for (const xs of [[], [0xa1n], [0n, (1n << 160n) - 1n]] as bigint[][]) {
      await eq(`rEAddr clean`, '0x' + sel('rEAddr(address[])') + pad(0x20n) + arr(xs));
      await eq(`veAddr clean`, '0x' + sel('veAddr(address[])') + pad(0x20n) + arr(xs));
      await eq(`iAddr clean`, '0x' + sel('iAddr(address[])') + pad(0x20n) + arr(xs));
    }
    for (const xs of [[], [b4(0xdeadbeefn)], [b4(0n), b4(0x11223344n)]] as bigint[][]) {
      await eq(`rEB4 clean`, '0x' + sel('rEB4(bytes4[])') + pad(0x20n) + arr(xs));
      await eq(`veB4 clean`, '0x' + sel('veB4(bytes4[])') + pad(0x20n) + arr(xs));
      await eq(`iB4 clean`, '0x' + sel('iB4(bytes4[])') + pad(0x20n) + arr(xs));
    }
    for (const xs of [[], [0n], [127n], [-1n % M], [-128n % M], [127n, -128n % M, -1n % M, 5n]] as bigint[][]) {
      await eq(`rEI8 clean`, '0x' + sel('rEI8(int8[])') + pad(0x20n) + arr(xs));
      await eq(`veI8 clean`, '0x' + sel('veI8(int8[])') + pad(0x20n) + arr(xs));
      await eq(`iI8 clean`, '0x' + sel('iI8(int8[])') + pad(0x20n) + arr(xs));
    }
    for (const xs of [[], [-1n % M], [(1n << 127n) - 1n], [-(1n << 127n) % M]] as bigint[][]) {
      await eq(`rEI128 clean`, '0x' + sel('rEI128(int128[])') + pad(0x20n) + arr(xs));
    }

    // ============================================================
    // 2. DIRTY value-array elements: solc VALIDATES & reverts; JETH must match.
    //    Both error path AND event (data + indexed) path. We compare full
    //    (success, returndata, logs) so a divergence in EITHER direction is caught.
    // ============================================================
    // dirty u8: high bits beyond 8
    for (const xs of [[DIRTY], [0x100n], [0x1ffn], [255n, 0x100n], [DIRTY, 0n, 0x3ffn]] as bigint[][]) {
      await eq(`rE8 dirty`, '0x' + sel('rE8(uint8[])') + pad(0x20n) + arr(xs));
      await eq(`ve8 dirty (data)`, '0x' + sel('ve8(uint8[])') + pad(0x20n) + arr(xs));
      await eq(`i8 dirty (topic)`, '0x' + sel('i8(uint8[])') + pad(0x20n) + arr(xs));
    }
    // dirty u16
    for (const xs of [[DIRTY], [0x10000n], [65535n, 0x10000n]] as bigint[][]) {
      await eq(`rE16 dirty`, '0x' + sel('rE16(uint16[])') + pad(0x20n) + arr(xs));
    }
    // dirty bool: anything > 1
    for (const xs of [[2n], [DIRTY], [1n, 2n], [0n, 0xffn]] as bigint[][]) {
      await eq(`rEBool dirty`, '0x' + sel('rEBool(bool[])') + pad(0x20n) + arr(xs));
      await eq(`veBool dirty (data)`, '0x' + sel('veBool(bool[])') + pad(0x20n) + arr(xs));
      await eq(`iBool dirty (topic)`, '0x' + sel('iBool(bool[])') + pad(0x20n) + arr(xs));
    }
    // dirty address: high 96 bits set
    for (const xs of [[DIRTY], [1n << 160n], [0xa1n, (1n << 200n) | 0xb2n]] as bigint[][]) {
      await eq(`rEAddr dirty`, '0x' + sel('rEAddr(address[])') + pad(0x20n) + arr(xs));
      await eq(`veAddr dirty (data)`, '0x' + sel('veAddr(address[])') + pad(0x20n) + arr(xs));
      await eq(`iAddr dirty (topic)`, '0x' + sel('iAddr(address[])') + pad(0x20n) + arr(xs));
    }
    // dirty bytes4: low (32-4) bytes nonzero
    for (const xs of [[DIRTY], [(0xdeadbeefn << 224n) | 1n], [b4(0x11223344n) | 0xffn]] as bigint[][]) {
      await eq(`rEB4 dirty`, '0x' + sel('rEB4(bytes4[])') + pad(0x20n) + arr(xs));
      await eq(`veB4 dirty (data)`, '0x' + sel('veB4(bytes4[])') + pad(0x20n) + arr(xs));
      await eq(`iB4 dirty (topic)`, '0x' + sel('iB4(bytes4[])') + pad(0x20n) + arr(xs));
    }
    // dirty int8: bad sign extension. 0x80 is +128 (not valid int8), 0xff..00 dirty.
    for (const xs of [[0x80n], [0x17fn], [0xff00n], [-1n % M, 0x80n]] as bigint[][]) {
      await eq(`rEI8 dirty`, '0x' + sel('rEI8(int8[])') + pad(0x20n) + arr(xs));
      await eq(`veI8 dirty (data)`, '0x' + sel('veI8(int8[])') + pad(0x20n) + arr(xs));
      await eq(`iI8 dirty (topic)`, '0x' + sel('iI8(int8[])') + pad(0x20n) + arr(xs));
    }
    // dirty int128
    for (const xs of [[1n << 127n], [1n << 128n], [(1n << 127n) - 1n, 1n << 200n]] as bigint[][]) {
      await eq(`rEI128 dirty`, '0x' + sel('rEI128(int128[])') + pad(0x20n) + arr(xs));
    }
    // dirty in a NON-first position (validation must scan all elements)
    await eq('rE8 dirty last', '0x' + sel('rE8(uint8[])') + pad(0x20n) + arr([1n, 2n, 3n, 0x100n]));
    await eq('ve8 dirty last', '0x' + sel('ve8(uint8[])') + pad(0x20n) + arr([1n, 2n, 0x100n]));
    await eq('i8 dirty mid', '0x' + sel('i8(uint8[])') + pad(0x20n) + arr([0n, 0x200n, 5n]));

    // ============================================================
    // 3. multi-arg with array: tag (indexed/value) + array; two arrays; array+string
    // ============================================================
    for (const xs of [[], [1n, 2n, 3n], [DIRTY]] as bigint[][]) {
      await eq(`rETag[${xs.length}]`, '0x' + sel('rETag(uint256,uint256[])') + pad(99n) + pad(0x40n) + arr(xs));
      await eq(`veTag[${xs.length}]`, '0x' + sel('veTag(uint256,uint256[])') + pad(42n) + pad(0x40n) + arr(xs));
    }
    // two value-array args: u8[] (dirty?) + address[] (dirty?)
    {
      const mk = (au8: bigint[], baddr: bigint[]) => {
        const aTail = arr(au8);
        const offA = 2 * 32;
        const offB = offA + aTail.length / 2;
        return pad(BigInt(offA)) + pad(BigInt(offB)) + aTail + arr(baddr);
      };
      await eq('rETwoArr clean', '0x' + sel('rETwoArr(uint8[],address[])') + mk([1n, 2n], [0xa1n, 0xb2n]));
      await eq('rETwoArr dirtyA', '0x' + sel('rETwoArr(uint8[],address[])') + mk([0x100n], [0xa1n]));
      await eq('rETwoArr dirtyB', '0x' + sel('rETwoArr(uint8[],address[])') + mk([1n], [DIRTY]));
      await eq('iMulti clean', '0x' + sel('iMulti(uint256[],uint8[])') + mk([1n, 2n], [1n, 0n, 9n]));
      await eq('iMulti dirtyB (topic)', '0x' + sel('iMulti(uint256[],uint8[])') + mk([1n, 2n], [0x100n]));
    }
    // array + string (mixed dynamic), clean + dirty array
    {
      const mk = (xs: bigint[], s: string) => {
        const aTail = arr(xs);
        const offA = 2 * 32;
        const offS = offA + aTail.length / 2;
        return pad(BigInt(offA)) + pad(BigInt(offS)) + aTail + strTail(s);
      };
      for (const [xs, s] of [
        [[], ''],
        [[1n, 2n], 'hi'],
        [[1n, 2n, 3n], 'over thirty-two bytes string goes here for the tail test ok yes!!'],
      ] as [bigint[], string][]) {
        await eq(`rEArrStr`, '0x' + sel('rEArrStr(uint256[],string)') + mk(xs, s));
        await eq(`veArrStr`, '0x' + sel('veArrStr(uint256[],string)') + mk(xs, s));
      }
    }
    // indexed array topic alongside non-indexed string + value in data, clean + dirty
    {
      const mk = (xs: bigint[], s: string) => {
        const aTail = arr(xs);
        const offA = 3 * 32;
        const offS = offA + aTail.length / 2;
        return pad(BigInt(offA)) + pad(BigInt(offS)) + pad(123n) + aTail + strTail(s);
      };
      for (const [xs, s] of [
        [[], ''],
        [[1n, 2n, 3n], 'data section string longer than thirty-two bytes for spread!!'],
      ] as [bigint[], string][]) {
        await eq(`iMixData`, '0x' + sel('iMixData(uint256[],string,uint256)') + mk(xs, s));
      }
      await eq(
        'iMixData dirty topic',
        '0x' + sel('iMixData(uint256[],string,uint256)') + mk([0n, 0n], 'x'), // u256 never dirty
      );
    }

    // ============================================================
    // 4. indexed value-array topic position: first / last / three-indexed
    // ============================================================
    for (const xs of [[], [9n], [1n, 2n, 3n], [DIRTY]] as bigint[][]) {
      await eq(`iFirst[${xs.length}]`, '0x' + sel('iFirst(uint256[],uint256)') + pad(0x40n) + pad(7n) + arr(xs));
      await eq(`iLast[${xs.length}]`, '0x' + sel('iLast(uint256,uint256[])') + pad(42n) + pad(0x40n) + arr(xs));
    }
    // three indexed: uint, uint256[], address[] (clean + dirty address element)
    {
      const mk = (a: bigint[], b: bigint[]) => {
        const offA = 3 * 32;
        const aTail = arr(a);
        const offB = offA + aTail.length / 2;
        return pad(5n) + pad(BigInt(offA)) + pad(BigInt(offB)) + aTail + arr(b);
      };
      await eq('iThree clean', '0x' + sel('iThree(uint256,uint256[],address[])') + mk([1n, 2n, 3n], [0xa1n, 0xb2n]));
      await eq('iThree empty', '0x' + sel('iThree(uint256,uint256[],address[])') + mk([], []));
      await eq('iThree dirtyB', '0x' + sel('iThree(uint256,uint256[],address[])') + mk([1n], [DIRTY]));
    }

    // ============================================================
    // 5. indexed bytes/string topic (keccak of content): short/exact32/long/empty
    // ============================================================
    const strCases = [
      '',
      'abc',
      'abcdefghijklmnopqrstuvwxyz012345',
      'this string is definitely longer than thirty-two bytes for the keccak topic test',
    ];
    for (const s of strCases) {
      const t = strTail(s);
      await eq(`is_ "${s.slice(0, 6)}"`, '0x' + sel('is_(string,uint256)') + pad(0x40n) + pad(7n) + t);
      await eq(`iby "${s.slice(0, 6)}"`, '0x' + sel('iby(bytes,uint256)') + pad(0x40n) + pad(9n) + t);
    }
    // two indexed strings
    {
      const mk = (a: string, bb: string) => {
        const t1 = strTail(a);
        const off2 = 0x40n + BigInt(t1.length / 2);
        return pad(0x40n) + pad(off2) + t1 + strTail(bb);
      };
      await eq('itwoStr short/long', '0x' + sel('itwoStr(string,string)') + mk('abc', strCases[3]!));
      await eq('itwoStr empty/exact32', '0x' + sel('itwoStr(string,string)') + mk('', strCases[2]!));
    }
    // raw non-ascii / NUL / 0xff content (no UTF-8 normalization in topic hash)
    for (const hex of ['00', 'ff', '00ff00ff', 'ff'.repeat(40)]) {
      await eq(
        `iby rawHex ${hex.slice(0, 6)}`,
        '0x' + sel('iby(bytes,uint256)') + pad(0x40n) + pad(1n) + rawBytesTail(hex),
      );
    }

    // (struct args to error/event are a clean JETH reject; see gate-parity tests below.)

    // ============================================================
    // 7. scalar indexed/non-indexed dirty-bit decode parity (Mixed / Scalars)
    //    These dirty bits hit the FUNCTION PROLOGUE decode (validateInput), which
    //    solc also does; both should revert before the emit.
    // ============================================================
    await eq(
      'eMixed clean',
      encodeCall(sel('eMixed(uint8,int16,bool,address,bytes4)'), [255n, -3n % M, 1n, A, b4(0xdeadbeefn)]),
    );
    await eq(
      'eMixed minmax',
      encodeCall(sel('eMixed(uint8,int16,bool,address,bytes4)'), [0n, -32768n % M, 0n, 0n, 0n]),
    );
    await eq(
      'eMixed dirtyU8',
      '0x' + sel('eMixed(uint8,int16,bool,address,bytes4)') + pad(0x100n) + pad(5n) + pad(1n) + pad(A) + pad(b4(0x1n)),
    );
    await eq(
      'eMixed dirtyI16',
      '0x' + sel('eMixed(uint8,int16,bool,address,bytes4)') + pad(5n) + pad(0x8000n) + pad(1n) + pad(A) + pad(b4(0x1n)),
    );
    await eq(
      'eMixed dirtyBool',
      '0x' + sel('eMixed(uint8,int16,bool,address,bytes4)') + pad(5n) + pad(5n) + pad(2n) + pad(A) + pad(b4(0x1n)),
    );
    await eq(
      'eMixed dirtyAddr',
      '0x' + sel('eMixed(uint8,int16,bool,address,bytes4)') + pad(5n) + pad(5n) + pad(1n) + pad(DIRTY) + pad(b4(0x1n)),
    );
    await eq(
      'eMixed dirtyBytes4',
      '0x' + sel('eMixed(uint8,int16,bool,address,bytes4)') + pad(5n) + pad(5n) + pad(1n) + pad(A) + pad(0x1n),
    ); // bytes4 right-aligned -> dirty
    await eq(
      'eScalars clean',
      encodeCall(sel('eScalars(uint8,int16,bool,bytes4,address)'), [200n, -5n % M, 1n, b4(0xaabbccddn), A]),
    );
    await eq(
      'eScalars dirtyAll',
      '0x' +
        sel('eScalars(uint8,int16,bool,bytes4,address)') +
        pad(DIRTY) +
        pad(DIRTY) +
        pad(DIRTY) +
        pad(DIRTY) +
        pad(DIRTY),
    );

    // ============================================================
    // 8. MALFORMED calldata for value-array event/error args (decoder parity).
    //    Bad offsets, bad lengths, truncated tails. Both must revert identically.
    // ============================================================
    const arrSels: [string, string][] = [
      ['rEU(uint256[])', 'err'],
      ['veu(uint256[])', 'ev-data'],
      ['iu(uint256[])', 'ev-topic'],
    ];
    const badOffsets: bigint[] = [
      0x0n,
      0x21n,
      0x40n,
      0xffffffffn,
      U256_MAX,
      1n << 64n,
      1n << 255n,
      (1n << 255n) + 0x20n,
    ];
    for (const [s, tag] of arrSels) {
      for (const off of badOffsets) {
        await eq(`${tag} badOff ${off.toString(16)}`, '0x' + sel(s) + pad(off) + arr([1n, 2n]));
      }
      // valid offset 0x20 but length huge (Panic 0x41 region) / past end
      for (const len of [0x21n, 0x100n, U256_MAX, 1n << 64n, (1n << 64n) + 1n]) {
        await eq(`${tag} badLen ${len.toString(16)}`, '0x' + sel(s) + pad(0x20n) + pad(len) + pad(1n));
      }
      // truncated tail: claims len=3 but only one element word present
      await eq(`${tag} truncTail`, '0x' + sel(s) + pad(0x20n) + pad(3n) + pad(1n));
      // length word present, len=0 (empty) but with trailing garbage (extra calldata ignored)
      await eq(`${tag} emptyTrailGarbage`, '0x' + sel(s) + pad(0x20n) + pad(0n) + pad(0xdeadn));
    }
    // aliased / overlapping offsets pointing into the head
    await eq('iu offset->selectorArea', '0x' + sel('iu(uint256[])') + pad(0x4n) + arr([1n]));
    // offset exactly calldatasize-ish boundary: head says off=0x20 but no length word at all
    await eq('iu noLenWord', '0x' + sel('iu(uint256[])') + pad(0x20n));

    // malformed string/bytes for indexed-topic keccak path
    const bsel = sel('iby(bytes,uint256)');
    for (const off of [0x0n, 0x20n, 0xffffffffn, U256_MAX, 1n << 64n]) {
      await eq(`iby badOff ${off.toString(16)}`, '0x' + bsel + pad(off) + pad(1n) + pad(0x40n) + rawBytesTail('ab'));
    }
    for (const len of [0x21n, U256_MAX, 1n << 64n]) {
      await eq(`iby badLen ${len.toString(16)}`, '0x' + bsel + pad(0x40n) + pad(1n) + pad(len) + pad(0xeeeen));
    }
    await eq('iby truncTail', '0x' + bsel + pad(0x40n) + pad(1n) + pad(0x40n)); // claims 64 bytes, none present

    // malformed string for non-indexed error string arg
    const ssel = sel('rEStr(string)');
    for (const off of [0x0n, 0x40n, U256_MAX, 1n << 64n]) {
      await eq(`rEStr badOff ${off.toString(16)}`, '0x' + ssel + pad(off) + rawBytesTail('ab'));
    }
    for (const len of [0x21n, U256_MAX]) {
      await eq(`rEStr badLen ${len.toString(16)}`, '0x' + ssel + pad(0x20n) + pad(len) + pad(0xeen));
    }

    // ============================================================
    // 9. boundary-length sweep for dynamic content (off-by-one padding bugs).
    //    Indexed string topic keccak + non-indexed bytes data, at word boundaries.
    // ============================================================
    for (const n of [0, 1, 31, 32, 33, 63, 64, 65, 95, 96, 127, 128]) {
      const s = 'q'.repeat(n);
      await eq(`is_ boundLen ${n}`, '0x' + sel('is_(string,uint256)') + pad(0x40n) + pad(3n) + strTail(s));
      await eq(`rEBytes boundLen ${n}`, '0x' + sel('rEBytes(bytes)') + pad(0x20n) + strTail(s));
    }

    // ============================================================
    // 10. unknown selector / empty / short calldata parity
    // ============================================================
    await eq('unknownSelector', '0xdeadbeef');
    await eq('emptyCalldata', '0x');
    await eq('shortSelector', '0xaabbcc');

    if (mism.length) {
      // eslint-disable-next-line no-console
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 40)) console.log(m);
    } else {
      // eslint-disable-next-line no-console
      console.log('ALL ' + count + ' byte-identical');
    }
    expect(mism, mism.slice(0, 12).join('\n')).toEqual([]);
    expect(count).toBeGreaterThan(60);
  });

  // ============================================================
  // 11. GATE PARITY: shapes JETH legitimately refuses are clean rejects, not miscompiles.
  // ============================================================
  it('gate: >3 indexed event params rejected (JETH143)', () => {
    let threw = false;
    try {
      compile(
        `@contract class C { @event E(@indexed a: u256, @indexed b: u256, @indexed c: u256, @indexed d: u256); @external f(): void {} }`,
        { fileName: 'C.jeth' },
      );
    } catch (e: any) {
      threw = true;
      expect(JSON.stringify(e.diagnostics ?? e.message)).toContain('JETH143');
    }
    expect(threw).toBe(true);
  });
  it('indexed fixed-array event param now compiles (keccak topic, JETH207 lifted)', () => {
    expect(() =>
      compile(`@contract class C { @event E(@indexed a: Arr<u256, 3>); @external f(): void {} }`, {
        fileName: 'C.jeth',
      }),
    ).not.toThrow();
  });
  it('indexed static-struct, dynamic struct, AND nested-dynamic-struct-field event params all compile (keccak topic)', () => {
    expect(() =>
      compile(
        `@struct class S { x: u256; }
@contract class C { @event E(@indexed s: S); @external f(): void {} }`,
        { fileName: 'C.jeth' },
      ),
    ).not.toThrow();
    // a supported dynamic struct (string field) indexed param now compiles too (keccak of the
    // flattened payload; verified byte-identical in fix-all-divergences.test.ts).
    expect(() =>
      compile(
        `@struct class D { s: string; }
@contract class C { @event E(@indexed d: D); @external f(): void {} }`,
        { fileName: 'C.jeth' },
      ),
    ).not.toThrow();
    // a dynamic struct with a NESTED dynamic struct field is now supported too (the topic is keccak of
    // the recursively flattened payload; byte-identical to solc, verified in fix-all-divergences.test.ts).
    expect(() =>
      compile(
        `@struct class Inner { p: u256; s: string; }
@struct class D2 { x: u256; inner: Inner; }
@contract class C { @event E(@indexed d: D2); @external f(): void {} }`,
        { fileName: 'C.jeth' },
      ),
    ).not.toThrow();
  });
  it('gate: indexed nested dynamic array (u256[][]) event param rejected', () => {
    let threw = false;
    try {
      compile(`@contract class C { @event E(@indexed a: u256[][]); @external f(): void {} }`, { fileName: 'C.jeth' });
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
  });
  it('non-indexed static fixed-array event param now compiles (encoded inline in the data tuple)', () => {
    // previously over-rejected with JETH142; now supported (byte-identical to solc, see event-struct.test.ts).
    expect(() =>
      compile(
        `@contract class C { @event E(a: Arr<u256, 3>); @external f(a: u256, b: u256, c: u256): void { emit(E([a, b, c])); } }`,
        { fileName: 'C.jeth' },
      ),
    ).not.toThrow();
  });
  it('@error with a STATIC struct param AND a DYNAMIC struct param both compile (revert data byte-identical)', () => {
    // a static struct error param is now supported (revert data byte-identical to solc, verified in
    // fix-all-divergences.test.ts).
    expect(() =>
      compile(
        `@struct class S { a: u256; b: bool; }
@contract class C { @error E(s: S); @external @pure f(s: S): void { revert(E(s)); } }`,
        { fileName: 'C.jeth' },
      ),
    ).not.toThrow();
    // a DYNAMIC struct (bytes/string field) error param is now supported too (revert returndata
    // byte-identical to solc, verified in fix-all-divergences.test.ts).
    expect(() =>
      compile(
        `@struct class D { a: u256; s: string; }
@contract class C { @error E(d: D); @external f(): void { revert(E(D(1n, "x"))); } }`,
        { fileName: 'C.jeth' },
      ),
    ).not.toThrow();
  });
  it('non-indexed static struct event param now compiles (encoded inline in the data tuple)', () => {
    // previously over-rejected with JETH142; now supported (byte-identical to solc, see event-struct.test.ts).
    expect(() =>
      compile(
        `@struct class S { a: u256; b: bool; }
@contract class C { @event E(s: S); @external f(s: S): void { emit(E(s)); } }`,
        { fileName: 'C.jeth' },
      ),
    ).not.toThrow();
  });
});
