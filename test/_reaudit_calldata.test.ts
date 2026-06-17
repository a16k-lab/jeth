// _reaudit_calldata: TARGETED RE-AUDIT of the Arr<dyn,N> (fixed array of a DYNAMIC
// element) calldata-param binding in src/yul.ts (~247-264), after two miscompiles
// were fixed there:
//   (1) signed offset cap  -> unsigned  gt(off, 0xffffffffffffffff)
//   (2) first-word-only head readable -> FULL head  gt(add(dataPtr, N*32), calldatasize())
// This file hunts for a THIRD divergence. INVARIANT: for EVERY case, jeth and solc
// must agree byte-for-byte on (success, returnHex). A divergence is a P0 miscompile.
//
// Coverage map (mirrors the audit FOCUS list):
//   1. Arr<dyn,N> head extent: bytes[2], string[2], bytes[3], string[3], uint256[][2].
//      Sweep the OUTER param offset across dataPtr+N*32 == calldatasize (-1/0/+1) for
//      several calldata sizes and N. High-bit offsets 2^64, 2^255, 2^256-1. Echo `a`
//      AND element access a[i] / a[i].length / a[i][j] at each boundary.
//   2. Per-element inner offsets/lengths within the N-word table (high-bit/2^64/
//      past-end/aliased/mid-word/empty).
//   3. Dirty narrow-leaf validation through Arr<dyn,N>-shaped inputs.
//   4. Cross-check element access vs whole echo for the same input.
//   5. Regression on adjacent shapes (u256[], u256[][], u256[][][], Arr<u256,2>[],
//      static/dynamic struct params) -> still byte-identical.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const U64 = 0xffffffffffffffffn;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const enc = new TextEncoder();
const sb = (s: string) => enc.encode(s);

// raw bytes -> 32-byte-multiple hex (no 0x); 0 length => empty.
function padData(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';
  const words = Math.ceil(bytes.length / 32);
  let h = '';
  for (let i = 0; i < words * 32; i++) h += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  return h;
}
// bytes/string element body: [len][padded data].
const elemBody = (b: Uint8Array) => pad(BigInt(b.length)) + padData(b);

// Arr<bytes,N>/Arr<string,N> DATA REGION (no outer length word): [N-word off table][payloads];
// offsets relative to the table start.
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
const dynValRegion = (xs: bigint[]) => pad(BigInt(xs.length)) + xs.map(pad).join('');
// Arr<u256[],N> = uint256[][N] DATA REGION (no outer length): [N-word off table][inner regions].
function fixedU256ArrRegion(rows: bigint[][]): string {
  const N = rows.length;
  const inner = rows.map(dynValRegion);
  let off = N * 32;
  let table = '';
  for (const ir of inner) {
    table += pad(BigInt(off));
    off += ir.length / 2;
  }
  return table + inner.join('');
}
// hex byte length (chars/2) of a region.
const blen = (hex: string) => hex.length / 2;

const JETH = `
@struct class WithArr { id: u64; data: Arr<u256,3>; tag: u64; }
@struct class WithDyn { a: u64; xs: u256[]; b: u64; }
@contract
class C {
  // Arr<dyn,N>: fixed array of DYNAMIC element (the area under audit)
  @external @pure fb2At(a: Arr<bytes,2>, i: u256): bytes { return a[i]; }
  @external @pure fb2Len(a: Arr<bytes,2>, i: u256): u256 { return a[i].length; }
  @external @pure fb2Echo(a: Arr<bytes,2>): Arr<bytes,2> { return a; }
  @external @pure fs2At(a: Arr<string,2>, i: u256): string { return a[i]; }
  @external @pure fs2Echo(a: Arr<string,2>): Arr<string,2> { return a; }
  @external @pure fb3At(a: Arr<bytes,3>, i: u256): bytes { return a[i]; }
  @external @pure fb3Echo(a: Arr<bytes,3>): Arr<bytes,3> { return a; }
  @external @pure fs3At(a: Arr<string,3>, i: u256): string { return a[i]; }
  @external @pure fodAt(a: Arr<u256[],2>, i: u256, j: u256): u256 { return a[i][j]; }
  @external @pure fodLen(a: Arr<u256[],2>, i: u256): u256 { return a[i].length; }
  @external @pure fodEcho(a: Arr<u256[],2>): Arr<u256[],2> { return a; }
  @external @pure fod3Len(a: Arr<u256[],3>, i: u256): u256 { return a[i].length; }

  // a SECOND param after the Arr<dyn,N> exercises the head cursor past the offset word
  @external @pure fb2Tail(a: Arr<bytes,2>, k: u256): u256 { return k; }

  // narrow-leaf inner arrays reached via Arr<dyn,N>: a[i][j] dirty validation
  @external @pure fu8At(a: Arr<u8[],2>, i: u256, j: u256): u8 { return a[i][j]; }
  @external @pure fi8At(a: Arr<i8[],2>, i: u256, j: u256): i8 { return a[i][j]; }
  @external @pure faddrAt(a: Arr<address[],2>, i: u256, j: u256): address { return a[i][j]; }
  @external @pure fb4At(a: Arr<bytes4[],2>, i: u256, j: u256): bytes4 { return a[i][j]; }

  // adjacent regression shapes
  @external @pure vAt(a: u256[], i: u256): u256 { return a[i]; }
  @external @pure m2At(m: u256[][], i: u256, j: u256): u256 { return m[i][j]; }
  @external @pure m3At(m: u256[][][], i: u256, j: u256, k: u256): u256 { return m[i][j][k]; }
  @external @pure dofAt(a: Arr<u256,2>[], i: u256, j: u256): u256 { return a[i][j]; }
  @external @pure waData(t: WithArr, j: u256): u256 { return t.data[j]; }
  @external @pure wdEcho(t: WithDyn): WithDyn { return t; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct WithArr { uint64 id; uint256[3] data; uint64 tag; }
  struct WithDyn { uint64 a; uint256[] xs; uint64 b; }

  function fb2At(bytes[2] calldata a, uint256 i) external pure returns (bytes memory){ return a[i]; }
  function fb2Len(bytes[2] calldata a, uint256 i) external pure returns (uint256){ return a[i].length; }
  function fb2Echo(bytes[2] calldata a) external pure returns (bytes[2] memory){ return a; }
  function fs2At(string[2] calldata a, uint256 i) external pure returns (string memory){ return a[i]; }
  function fs2Echo(string[2] calldata a) external pure returns (string[2] memory){ return a; }
  function fb3At(bytes[3] calldata a, uint256 i) external pure returns (bytes memory){ return a[i]; }
  function fb3Echo(bytes[3] calldata a) external pure returns (bytes[3] memory){ return a; }
  function fs3At(string[3] calldata a, uint256 i) external pure returns (string memory){ return a[i]; }
  function fodAt(uint256[][2] calldata a, uint256 i, uint256 j) external pure returns (uint256){ return a[i][j]; }
  function fodLen(uint256[][2] calldata a, uint256 i) external pure returns (uint256){ return a[i].length; }
  function fodEcho(uint256[][2] calldata a) external pure returns (uint256[][2] memory){ return a; }
  function fod3Len(uint256[][3] calldata a, uint256 i) external pure returns (uint256){ return a[i].length; }

  function fb2Tail(bytes[2] calldata a, uint256 k) external pure returns (uint256){ return k; }

  function fu8At(uint8[][2] calldata a, uint256 i, uint256 j) external pure returns (uint8){ return a[i][j]; }
  function fi8At(int8[][2] calldata a, uint256 i, uint256 j) external pure returns (int8){ return a[i][j]; }
  function faddrAt(address[][2] calldata a, uint256 i, uint256 j) external pure returns (address){ return a[i][j]; }
  function fb4At(bytes4[][2] calldata a, uint256 i, uint256 j) external pure returns (bytes4){ return a[i][j]; }

  function vAt(uint256[] calldata a, uint256 i) external pure returns (uint256){ return a[i]; }
  function m2At(uint256[][] calldata m, uint256 i, uint256 j) external pure returns (uint256){ return m[i][j]; }
  function m3At(uint256[][][] calldata m, uint256 i, uint256 j, uint256 k) external pure returns (uint256){ return m[i][j][k]; }
  function dofAt(uint256[2][] calldata a, uint256 i, uint256 j) external pure returns (uint256){ return a[i][j]; }
  function waData(WithArr calldata t, uint256 j) external pure returns (uint256){ return t.data[j]; }
  function wdEcho(WithDyn calldata t) external pure returns (WithDyn memory){ return t; }
}`;

describe('_reaudit_calldata: Arr<dyn,N> head-extent + adjacent decode parity', () => {
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

  // ============================================================================
  // FOCUS 1: OUTER param-offset sweep across the N-word head/calldatasize boundary.
  // The fixed offset table occupies N words starting at dataPtr = 4 + off. solc (and
  // now jeth) EMPTY-revert iff dataPtr + N*32 > calldatasize. We sweep `off` so the
  // table END lands exactly at, one before, and one past calldatasize, for several
  // total calldata sizes, several N, and both echo + element access.
  // ============================================================================
  it('fb2 outer-offset head-extent sweep (N=2 bytes[2])', async () => {
    // Build a body of `bodyWords` filler words after the head; vary `off` so the
    // 2-word table [dataPtr, dataPtr+0x40) straddles calldatasize.
    // Layout for fb2At: selector | head[off][i] | body. dataPtr = 4 + off.
    // body bytes live at calldata 0x24.. ; calldatasize = 4 + 0x40 + bodyBytes.
    for (const bodyWords of [2, 3, 4, 6]) {
      const filler = pad(0n).repeat(bodyWords); // bodyWords words of zero
      const cdsize = 4 + 0x40 + blen(filler); // total calldata size in bytes
      // We want dataPtr + 0x40 == cdsize  =>  off == cdsize - 4 - 0x40.
      const offExact = BigInt(cdsize - 4 - 0x40);
      for (const [nm, off] of [
        ['exact (end==cds)', offExact],
        ['end-1 (under)', offExact - 1n],
        ['end+1 (over)', offExact + 1n],
        ['end+0x20 (over word)', offExact + 0x20n],
        ['off=0x40 normal', 0x40n],
      ] as const) {
        const data = '0x' + sel('fb2At(bytes[2],uint256)') + pad(off) + pad(0n) + filler;
        await eq(`fb2At bw=${bodyWords} off ${nm}`, data);
        const le = '0x' + sel('fb2Len(bytes[2],uint256)') + pad(off) + pad(0n) + filler;
        await eq(`fb2Len bw=${bodyWords} off ${nm}`, le);
        // echo path through the same offset
        const ec = '0x' + sel('fb2Echo(bytes[2])') + pad(off) + filler;
        await eq(`fb2Echo bw=${bodyWords} off ${nm}`, ec);
      }
    }
  });

  it('fb3 outer-offset head-extent sweep (N=3 bytes[3])', async () => {
    for (const bodyWords of [3, 4, 5, 8]) {
      const filler = pad(0n).repeat(bodyWords);
      const cdsize = 4 + 0x40 + blen(filler);
      // N=3: table end = dataPtr + 0x60.  off such that dataPtr+0x60 == cdsize.
      const offExact = BigInt(cdsize - 4 - 0x60);
      for (const [nm, off] of [
        ['exact', offExact],
        ['end-1', offExact - 1n],
        ['end+1', offExact + 1n],
        ['end+0x20', offExact + 0x20n],
        ['normal 0x40', 0x40n],
      ] as const) {
        const data = '0x' + sel('fb3At(bytes[3],uint256)') + pad(off) + pad(0n) + filler;
        await eq(`fb3At bw=${bodyWords} off ${nm}`, data);
        const ec = '0x' + sel('fb3Echo(bytes[3])') + pad(off) + filler;
        await eq(`fb3Echo bw=${bodyWords} off ${nm}`, ec);
      }
    }
  });

  it('fod outer-offset head-extent sweep (N=2 uint256[][2]) + a[i][j]/len', async () => {
    for (const bodyWords of [2, 3, 5]) {
      const filler = pad(1n).repeat(bodyWords); // nonzero filler so a stray read is visible
      const cdsize = 4 + 0x60 + blen(filler); // 3 head words (off, i, j) for fodAt
      const offExact = BigInt(cdsize - 4 - 0x40); // N=2 table end
      for (const [nm, off] of [
        ['exact', offExact],
        ['end-1', offExact - 1n],
        ['end+1', offExact + 1n],
        ['normal', 0x60n],
      ] as const) {
        await eq(`fodAt bw=${bodyWords} off ${nm}`, '0x' + sel('fodAt(uint256[][2],uint256,uint256)') + pad(off) + pad(0n) + pad(0n) + filler);
      }
      // fodLen has a 2-word head (off, i); recompute boundary for that head size.
      const filler2 = pad(1n).repeat(bodyWords);
      const cds2 = 4 + 0x40 + blen(filler2);
      const offEx2 = BigInt(cds2 - 4 - 0x40);
      for (const [nm, off] of [
        ['exact', offEx2],
        ['end-1', offEx2 - 1n],
        ['end+1', offEx2 + 1n],
      ] as const) {
        await eq(`fodLen bw=${bodyWords} off ${nm}`, '0x' + sel('fodLen(uint256[][2],uint256)') + pad(off) + pad(0n) + filler2);
      }
    }
  });

  // ============================================================================
  // FOCUS 1b: high-bit / huge outer offsets (must EMPTY-revert via the unsigned cap).
  // ============================================================================
  it('fb2/fs2/fod/fb3 outer offset high-bit & huge', async () => {
    const region2 = fixedBytesRegion([sb('aa'), sb('bb')]);
    const sregion2 = fixedBytesRegion([sb('hello'), sb('world')]);
    const fodRegion = fixedU256ArrRegion([[1n, 2n], [3n]]);
    const fb3Region = fixedBytesRegion([sb('a'), sb('bb'), sb('ccc')]);
    for (const [nm, off] of [
      ['2^64', 1n << 64n],
      ['2^64-1', U64],
      ['2^64+1', (1n << 64n) + 1n],
      ['2^128', 1n << 128n],
      ['2^255', 1n << 255n],
      ['2^256-1', M - 1n],
      ['2^256-4', M - 4n],
      ['2^256-0x40', M - 0x40n],
      ['0', 0n],
      ['0x41 midword', 0x41n],
      ['0x3f', 0x3fn],
      ['pastEnd 0xfff', 0xfffn],
    ] as const) {
      await eq(`fb2At outer off ${nm}`, '0x' + sel('fb2At(bytes[2],uint256)') + pad(off) + pad(0n) + region2);
      await eq(`fb2Echo outer off ${nm}`, '0x' + sel('fb2Echo(bytes[2])') + pad(off) + region2);
      await eq(`fs2At outer off ${nm}`, '0x' + sel('fs2At(string[2],uint256)') + pad(off) + pad(0n) + sregion2);
      await eq(`fs2Echo outer off ${nm}`, '0x' + sel('fs2Echo(string[2])') + pad(off) + sregion2);
      await eq(`fodAt outer off ${nm}`, '0x' + sel('fodAt(uint256[][2],uint256,uint256)') + pad(off) + pad(0n) + pad(0n) + fodRegion);
      await eq(`fodEcho outer off ${nm}`, '0x' + sel('fodEcho(uint256[][2])') + pad(off) + fodRegion);
      await eq(`fb3At outer off ${nm}`, '0x' + sel('fb3At(bytes[3],uint256)') + pad(off) + pad(0n) + fb3Region);
    }
  });

  // a SECOND value param after the Arr<dyn,N> param: the head cursor must advance past
  // exactly one offset word, so the tail param decodes from the right head slot.
  it('fb2Tail: param after Arr<dyn,N> decodes from correct head slot', async () => {
    const region = fixedBytesRegion([sb('aa'), sb('bb')]);
    for (const k of [0n, 7n, U64, M - 1n]) {
      await eq(`fb2Tail k=${k}`, '0x' + sel('fb2Tail(bytes[2],uint256)') + pad(0x40n) + pad(k) + region);
    }
    // too-short static head (only the offset word, missing k) -> both empty-revert
    await eq('fb2Tail short head', '0x' + sel('fb2Tail(bytes[2],uint256)') + pad(0x40n));
    // exactly the static head, no body -> table unreadable -> empty-revert
    await eq('fb2Tail head only no body', '0x' + sel('fb2Tail(bytes[2],uint256)') + pad(0x40n) + pad(0n));
  });

  // ============================================================================
  // FOCUS 2: per-element inner offset/length faults within the N-word table.
  // ============================================================================
  it('fb2 element-0 offset faults (high-bit/2^64/past-end/aliased/midword)', async () => {
    // table at byte 0x40 (after off word + i word). off0 corrupt, off1 valid.
    const p0 = elemBody(sb('abc'));
    const off1Base = BigInt(64 + blen(p0));
    const build = (off0: bigint, off1: bigint) => pad(off0) + pad(off1) + p0 + elemBody(sb('z'));
    const at = (off0: bigint, off1: bigint, i: bigint) => '0x' + sel('fb2At(bytes[2],uint256)') + pad(0x40n) + pad(i) + build(off0, off1);
    const le = (off0: bigint, off1: bigint, i: bigint) => '0x' + sel('fb2Len(bytes[2],uint256)') + pad(0x40n) + pad(i) + build(off0, off1);
    await eq('fb2 valid read[0]', at(64n, off1Base, 0n));
    await eq('fb2 valid read[1]', at(64n, off1Base, 1n));
    for (const [nm, off0] of [
      ['2^64', 1n << 64n],
      ['2^64-1', U64],
      ['2^255', 1n << 255n],
      ['2^256-1', M - 1n],
      ['2^256-0x20', M - 0x20n],
      ['0', 0n],
      ['alias off1', off1Base],
      ['pastEnd', 0x800n],
      ['midword 0x21', 0x21n],
      ['0x1f', 0x1fn],
    ] as const) {
      await eq(`fb2 off0=${nm} read[0]`, at(off0, off1Base, 0n));
      await eq(`fb2Len off0=${nm} read[0]`, le(off0, off1Base, 0n));
      await eq(`fb2 off0=${nm} read[1] untouched`, at(off0, off1Base, 1n));
    }
  });

  it('fb2 element-1 length faults (2^64/2^64-1/past-end/exact/truncated)', async () => {
    const build = (len1: bigint, payloadWords: number) => {
      const elem1 = pad(len1) + 'ff'.repeat(payloadWords * 32);
      const off1 = BigInt(64 + blen(elemBody(sb('aa'))));
      return pad(64n) + pad(off1) + elemBody(sb('aa')) + elem1;
    };
    const at = (len1: bigint, pw: number, i: bigint) => '0x' + sel('fb2At(bytes[2],uint256)') + pad(0x40n) + pad(i) + build(len1, pw);
    await eq('fb2 len1=2^64-1', at(U64, 0, 1n));
    await eq('fb2 len1=2^64', at(1n << 64n, 0, 1n));
    await eq('fb2 len1=2^256-1', at(M - 1n, 0, 1n));
    await eq('fb2 len1=64 payload=1word pastEnd', at(64n, 1, 1n));
    await eq('fb2 len1=32 payload=1word ok', at(32n, 1, 1n));
    await eq('fb2 len1=33 payload=2word ok', at(33n, 2, 1n));
    await eq('fb2 len1 corrupt read[0] untouched', at(M - 1n, 0, 0n));
  });

  it('fod inner-array offset/length faults within the 2-word table', async () => {
    // table at byte 0x60 (off + i + j). inner0=[10,11], inner1=[20]. corrupt off1/len1.
    const inner0 = dynValRegion([10n, 11n]);
    const off1Base = BigInt(64 + blen(inner0));
    const build = (off0: bigint, off1: bigint) => pad(off0) + pad(off1) + inner0 + dynValRegion([20n]);
    const at = (off0: bigint, off1: bigint, i: bigint, j: bigint) =>
      '0x' + sel('fodAt(uint256[][2],uint256,uint256)') + pad(0x60n) + pad(i) + pad(j) + build(off0, off1);
    const le = (off0: bigint, off1: bigint, i: bigint) =>
      '0x' + sel('fodLen(uint256[][2],uint256)') + pad(0x40n) + pad(i) + build(off0, off1);
    await eq('fod valid [0][1]', at(64n, off1Base, 0n, 1n));
    await eq('fod valid [1][0]', at(64n, off1Base, 1n, 0n));
    for (const [nm, off1] of [
      ['2^64', 1n << 64n],
      ['2^64-1', U64],
      ['2^255', 1n << 255n],
      ['2^256-1', M - 1n],
      ['0', 0n],
      ['alias', 64n],
      ['pastEnd', 0x800n],
    ] as const) {
      await eq(`fod off1=${nm} [1][0]`, at(64n, off1, 1n, 0n));
      await eq(`fodLen off1=${nm} [1]`, le(64n, off1, 1n));
      await eq(`fod off1=${nm} [0][0] untouched`, at(64n, off1, 0n, 0n));
    }
    // inner length faults: inner1 length huge / past-end
    const buildLen = (len1: bigint, payloadWords: number) => {
      const e1 = pad(len1) + pad(0n).repeat(payloadWords);
      const off1 = BigInt(64 + blen(inner0));
      return pad(64n) + pad(off1) + inner0 + e1;
    };
    const atL = (len1: bigint, pw: number, i: bigint, j: bigint) =>
      '0x' + sel('fodAt(uint256[][2],uint256,uint256)') + pad(0x60n) + pad(i) + pad(j) + buildLen(len1, pw);
    const leL = (len1: bigint, pw: number, i: bigint) =>
      '0x' + sel('fodLen(uint256[][2],uint256)') + pad(0x40n) + pad(i) + buildLen(len1, pw);
    await eq('fod inner1 len=2^64-1 read[1][0]', atL(U64, 0, 1n, 0n));
    await eq('fod inner1 len=2^64 read[1][0]', atL(1n << 64n, 0, 1n, 0n));
    await eq('fod inner1 len=2^256-1 read[1][0]', atL(M - 1n, 0, 1n, 0n));
    await eq('fod inner1 len=2 payload=1 pastEnd len[1]', leL(2n, 1, 1n));
    await eq('fod inner1 len=1 payload=1 ok len[1]', leL(1n, 1, 1n));
  });

  // ============================================================================
  // FOCUS 1c: index OOB on the FIXED length N (Panic 0x32 vs solc) at boundaries.
  // ============================================================================
  it('fb2/fb3/fod index OOB (i>=N) parity incl high-bit i', async () => {
    const r2 = fixedBytesRegion([sb('aa'), sb('bb')]);
    const r3 = fixedBytesRegion([sb('a'), sb('bb'), sb('ccc')]);
    const rfod = fixedU256ArrRegion([[1n, 2n], [3n, 4n]]);
    for (const [nm, i] of [['2', 2n], ['3', 3n], ['2^64', 1n << 64n], ['2^255', 1n << 255n], ['max', M - 1n]] as const) {
      await eq(`fb2At i=${nm}`, '0x' + sel('fb2At(bytes[2],uint256)') + pad(0x40n) + pad(i) + r2);
      await eq(`fb2Len i=${nm}`, '0x' + sel('fb2Len(bytes[2],uint256)') + pad(0x40n) + pad(i) + r2);
      await eq(`fb3At i=${nm}`, '0x' + sel('fb3At(bytes[3],uint256)') + pad(0x40n) + pad(i) + r3);
      await eq(`fodLen i=${nm}`, '0x' + sel('fodLen(uint256[][2],uint256)') + pad(0x40n) + pad(i) + rfod);
      await eq(`fodAt i=${nm}`, '0x' + sel('fodAt(uint256[][2],uint256,uint256)') + pad(0x60n) + pad(i) + pad(0n) + rfod);
    }
    // valid i, j OOB on the inner dynamic array
    await eq('fodAt [0][2] j OOB', '0x' + sel('fodAt(uint256[][2],uint256,uint256)') + pad(0x60n) + pad(0n) + pad(2n) + rfod);
    await eq('fodAt [1][2] j OOB', '0x' + sel('fodAt(uint256[][2],uint256,uint256)') + pad(0x60n) + pad(1n) + pad(2n) + rfod);
  });

  // ============================================================================
  // FOCUS 3: dirty narrow-leaf validation through Arr<dyn,N> -> inner narrow array.
  // a[i][j] lazily validates the leaf; solc reverts on a dirty narrow element.
  // ============================================================================
  it('fu8/fi8/faddr/fb4 dirty narrow leaf through Arr<narrow[],2>', async () => {
    // region: [off0][off1][inner0][inner1]; inner = [len][elems]. dirty an element.
    const region = (i0: bigint[], i1: bigint[]) => fixedU256ArrRegion([i0, i1]);
    const u8 = (i: bigint, j: bigint, i0: bigint[], i1: bigint[]) =>
      '0x' + sel('fu8At(uint8[][2],uint256,uint256)') + pad(0x60n) + pad(i) + pad(j) + region(i0, i1);
    await eq('fu8 [0][0]=0xff clean', u8(0n, 0n, [0xffn], [1n]));
    await eq('fu8 [0][0]=0x100 dirty', u8(0n, 0n, [0x100n], [1n]));
    await eq('fu8 [0][0]=max dirty', u8(0n, 0n, [M - 1n], [1n]));
    await eq('fu8 [1][0] dirty', u8(1n, 0n, [1n], [M - 1n]));
    await eq('fu8 dirty[0] read[1] clean', u8(1n, 0n, [M - 1n], [5n]));
    const i8 = (i: bigint, j: bigint, i0: bigint[], i1: bigint[]) =>
      '0x' + sel('fi8At(int8[][2],uint256,uint256)') + pad(0x60n) + pad(i) + pad(j) + region(i0, i1);
    await eq('fi8 [0][0]=-1 valid', i8(0n, 0n, [M - 1n], [1n]));
    await eq('fi8 [0][0]=-128 valid', i8(0n, 0n, [M - 128n], [1n]));
    await eq('fi8 [0][0]=127 valid', i8(0n, 0n, [127n], [1n]));
    await eq('fi8 [0][0]=128 dirty', i8(0n, 0n, [128n], [1n]));
    await eq('fi8 [0][0]=0x1ff dirty', i8(0n, 0n, [0x1ffn], [1n]));
    const A = 0x1234567890abcdef1234567890abcdef12345678n;
    const ad = (i: bigint, j: bigint, i0: bigint[], i1: bigint[]) =>
      '0x' + sel('faddrAt(address[][2],uint256,uint256)') + pad(0x60n) + pad(i) + pad(j) + region(i0, i1);
    await eq('faddr clean', ad(0n, 0n, [A], [A]));
    await eq('faddr dirty high96', ad(0n, 0n, [(1n << 200n) | A], [A]));
    await eq('faddr all set', ad(0n, 0n, [M - 1n], [A]));
    const b4 = 0xdeadbeefn << (28n * 8n);
    const b4f = (i: bigint, j: bigint, i0: bigint[], i1: bigint[]) =>
      '0x' + sel('fb4At(bytes4[][2],uint256,uint256)') + pad(0x60n) + pad(i) + pad(j) + region(i0, i1);
    await eq('fb4 clean', b4f(0n, 0n, [b4], [b4]));
    await eq('fb4 dirty low', b4f(0n, 0n, [b4 | 1n], [b4]));
    await eq('fb4 all set', b4f(0n, 0n, [M - 1n], [b4]));
  });

  // ============================================================================
  // FOCUS 4: cross-check element access vs whole echo on the SAME input.
  // For each crafted region, run a[i] / a[i].length AND echo, asserting both agree
  // with solc (the element and echo decoders are separate code paths that must both
  // match solc on the identical bytes).
  // ============================================================================
  it('fb2: echo vs element access agree across well-formed & edge regions', async () => {
    const cases: Uint8Array[][] = [
      [new Uint8Array(0), new Uint8Array(0)],
      [sb('a'), sb('bb')],
      [sb('A'.repeat(32)), sb('B')],
      [sb('A'.repeat(33)), sb('')],
      [sb('x'.repeat(64)), sb('y'.repeat(31))],
      [new Uint8Array(0), sb('only second')],
    ];
    for (const items of cases) {
      const region = fixedBytesRegion(items);
      const tag = items.map((x) => x.length).join(',');
      await eq(`fb2Echo [${tag}]`, '0x' + sel('fb2Echo(bytes[2])') + pad(0x20n) + region);
      await eq(`fb2At[0] [${tag}]`, '0x' + sel('fb2At(bytes[2],uint256)') + pad(0x40n) + pad(0n) + region);
      await eq(`fb2At[1] [${tag}]`, '0x' + sel('fb2At(bytes[2],uint256)') + pad(0x40n) + pad(1n) + region);
      await eq(`fb2Len[0] [${tag}]`, '0x' + sel('fb2Len(bytes[2],uint256)') + pad(0x40n) + pad(0n) + region);
      await eq(`fb2Len[1] [${tag}]`, '0x' + sel('fb2Len(bytes[2],uint256)') + pad(0x40n) + pad(1n) + region);
    }
  });

  it('fod / fb3 / fs3: echo vs element access agree', async () => {
    const fodCases: bigint[][][] = [
      [[], []],
      [[1n], [2n, 3n]],
      [[M - 1n, 0n, 7n], []],
    ];
    for (const rows of fodCases) {
      const region = fixedU256ArrRegion(rows);
      const tag = rows.map((r) => r.length).join(',');
      await eq(`fodEcho [${tag}]`, '0x' + sel('fodEcho(uint256[][2])') + pad(0x20n) + region);
      for (let i = 0; i < 2; i++) {
        await eq(`fodLen[${i}] [${tag}]`, '0x' + sel('fodLen(uint256[][2],uint256)') + pad(0x40n) + pad(BigInt(i)) + region);
        for (let j = 0; j < rows[i]!.length; j++)
          await eq(`fodAt[${i}][${j}] [${tag}]`, '0x' + sel('fodAt(uint256[][2],uint256,uint256)') + pad(0x60n) + pad(BigInt(i)) + pad(BigInt(j)) + region);
      }
    }
    // fb3 echo vs element
    const r3 = fixedBytesRegion([sb('one'), sb(''), sb('three!!')]);
    await eq('fb3Echo', '0x' + sel('fb3Echo(bytes[3])') + pad(0x20n) + r3);
    for (let i = 0n; i < 3n; i++) await eq(`fb3At[${i}]`, '0x' + sel('fb3At(bytes[3],uint256)') + pad(0x40n) + pad(i) + r3);
    // fs3 element access
    const s3 = fixedBytesRegion([sb('alpha'), sb('beta'), sb('')]);
    for (let i = 0n; i < 3n; i++) await eq(`fs3At[${i}]`, '0x' + sel('fs3At(string[3],uint256)') + pad(0x40n) + pad(i) + s3);
  });

  // ============================================================================
  // FOCUS 1d: TRUNCATED N-word table (the exact bug class of fix #2): a head that
  // fits its FIRST word but runs past calldatasize for words 1..N-1 must EMPTY-revert.
  // ============================================================================
  it('fb2/fb3/fod TRUNCATED table (only first word(s) present)', async () => {
    // fb2: provide off + i + ONLY off0 (table word 0), no off1 -> head straddles end.
    const slf = sel('fb2At(bytes[2],uint256)');
    const sll = sel('fb2Len(bytes[2],uint256)');
    const sle = sel('fb2Echo(bytes[2])');
    await eq('fb2At no table', '0x' + slf + pad(0x40n) + pad(0n));
    await eq('fb2At 1 of 2 table words', '0x' + slf + pad(0x40n) + pad(0n) + pad(0x40n));
    await eq('fb2Len 1 of 2 table words', '0x' + sll + pad(0x40n) + pad(0n) + pad(0x40n));
    await eq('fb2Echo 1 of 2 table words', '0x' + sle + pad(0x20n) + pad(0x40n));
    await eq('fb2At 2 table words no payload [0]', '0x' + slf + pad(0x40n) + pad(0n) + pad(0x40n) + pad(0x60n));
    await eq('fb2At 2 table words no payload [1]', '0x' + slf + pad(0x40n) + pad(1n) + pad(0x40n) + pad(0x60n));
    // fb3: 1 and 2 of 3 table words
    const sf3 = sel('fb3At(bytes[3],uint256)');
    await eq('fb3At 1 of 3 table words', '0x' + sf3 + pad(0x40n) + pad(0n) + pad(0x60n));
    await eq('fb3At 2 of 3 table words', '0x' + sf3 + pad(0x40n) + pad(0n) + pad(0x60n) + pad(0x80n));
    await eq('fb3At 3 of 3 no payload [2]', '0x' + sf3 + pad(0x40n) + pad(2n) + pad(0x60n) + pad(0x80n) + pad(0xa0n));
    // fod: 1 of 2 table words
    const sfod = sel('fodLen(uint256[][2],uint256)');
    await eq('fodLen 1 of 2 table words', '0x' + sfod + pad(0x40n) + pad(0n) + pad(0x40n));
    await eq('fodLen 2 of 2 no payload [0]', '0x' + sfod + pad(0x40n) + pad(0n) + pad(0x40n) + pad(0x60n));
  });

  // ============================================================================
  // FOCUS 5: adjacent-shape REGRESSION (must stay byte-identical).
  // ============================================================================
  it('regression: u256[] / u256[][] / u256[][][] / Arr<u256,2>[] basic + OOB', async () => {
    // u256[]
    const v = dynValRegion([10n, 20n, 30n]);
    for (let i = 0n; i < 3n; i++) await eq(`vAt[${i}]`, '0x' + sel('vAt(uint256[],uint256)') + pad(0x40n) + pad(i) + v);
    await eq('vAt[3] OOB', '0x' + sel('vAt(uint256[],uint256)') + pad(0x40n) + pad(3n) + v);
    await eq('vAt off=2^64', '0x' + sel('vAt(uint256[],uint256)') + pad(1n << 64n) + pad(0n) + v);
    // u256[][]
    function nested2(rows: bigint[][]): string {
      const L = rows.length;
      const inner = rows.map(dynValRegion);
      let off = L * 32;
      let table = '';
      for (const ir of inner) { table += pad(BigInt(off)); off += blen(ir); }
      return pad(BigInt(L)) + table + inner.join('');
    }
    const m2 = nested2([[1n, 2n], [], [9n]]);
    await eq('m2At[0][1]', '0x' + sel('m2At(uint256[][],uint256,uint256)') + pad(0x60n) + pad(0n) + pad(1n) + m2);
    await eq('m2At[2][0]', '0x' + sel('m2At(uint256[][],uint256,uint256)') + pad(0x60n) + pad(2n) + pad(0n) + m2);
    await eq('m2At[0][2] OOB', '0x' + sel('m2At(uint256[][],uint256,uint256)') + pad(0x60n) + pad(0n) + pad(2n) + m2);
    // u256[][][]
    function nested3(cube: bigint[][][]): string {
      const L = cube.length;
      const inner = cube.map(nested2);
      let off = L * 32;
      let table = '';
      for (const ir of inner) { table += pad(BigInt(off)); off += blen(ir); }
      return pad(BigInt(L)) + table + inner.join('');
    }
    const m3 = nested3([[[1n, 2n], [3n]], [[7n]]]);
    await eq('m3At[0][0][1]', '0x' + sel('m3At(uint256[][][],uint256,uint256,uint256)') + pad(0x80n) + pad(0n) + pad(0n) + pad(1n) + m3);
    await eq('m3At[1][0][0]', '0x' + sel('m3At(uint256[][][],uint256,uint256,uint256)') + pad(0x80n) + pad(1n) + pad(0n) + pad(0n) + m3);
    await eq('m3At[0][1][0] OOB-ish', '0x' + sel('m3At(uint256[][][],uint256,uint256,uint256)') + pad(0x80n) + pad(0n) + pad(2n) + pad(0n) + m3);
    // Arr<u256,2>[] dynamic-of-fixed
    const dof = pad(2n) + pad(1n) + pad(2n) + pad(3n) + pad(4n); // [len=2][e0w0][e0w1][e1w0][e1w1]
    await eq('dofAt[0][0]', '0x' + sel('dofAt(uint256[2][],uint256,uint256)') + pad(0x60n) + pad(0n) + pad(0n) + dof);
    await eq('dofAt[1][1]', '0x' + sel('dofAt(uint256[2][],uint256,uint256)') + pad(0x60n) + pad(1n) + pad(1n) + dof);
    await eq('dofAt[2][0] OOB', '0x' + sel('dofAt(uint256[2][],uint256,uint256)') + pad(0x60n) + pad(2n) + pad(0n) + dof);
    await eq('dofAt[0][2] j OOB', '0x' + sel('dofAt(uint256[2][],uint256,uint256)') + pad(0x60n) + pad(0n) + pad(2n) + dof);
  });

  it('regression: static struct (fixed-array field) + dynamic struct echo', async () => {
    // WithArr static head: [id][data0][data1][data2][tag]
    const head = pad(7n) + pad(100n) + pad(200n) + pad(300n) + pad(9n);
    for (let j = 0n; j < 3n; j++) await eq(`waData[${j}]`, '0x' + sel('waData((uint64,uint256[3],uint64),uint256)') + head + pad(j));
    await eq('waData[3] OOB', '0x' + sel('waData((uint64,uint256[3],uint64),uint256)') + head + pad(3n));
    // dirty id (uint64 high bits) read during nothing (waData doesn't read id) -> matches solc
    const dirtyHead = pad(M - 1n) + pad(100n) + pad(200n) + pad(300n) + pad(9n);
    await eq('waData dirty id not read', '0x' + sel('waData((uint64,uint256[3],uint64),uint256)') + dirtyHead + pad(0n));
    // WithDyn echo
    const tuple = (a: bigint, xs: bigint[], b: bigint) => pad(a) + pad(0x60n) + pad(b) + dynValRegion(xs);
    await eq('wdEcho 3', '0x' + sel('wdEcho((uint64,uint256[],uint64))') + pad(0x20n) + tuple(1n, [10n, 20n, 30n], 2n));
    await eq('wdEcho empty', '0x' + sel('wdEcho((uint64,uint256[],uint64))') + pad(0x20n) + tuple(5n, [], 6n));
    await eq('wdEcho dirty a', '0x' + sel('wdEcho((uint64,uint256[],uint64))') + pad(0x20n) + (pad(M - 1n) + pad(0x60n) + pad(2n) + dynValRegion([1n])));
    await eq('wdEcho outer off=2^64', '0x' + sel('wdEcho((uint64,uint256[],uint64))') + pad(1n << 64n) + tuple(1n, [1n], 2n));
    await eq('wdEcho xs off=2^256-1', '0x' + sel('wdEcho((uint64,uint256[],uint64))') + pad(0x20n) + (pad(1n) + pad(M - 1n) + pad(2n) + dynValRegion([1n])));
  });

  // ============================================================================
  // FOCUS 1e: aliasing the outer offset onto the head words (off=0x00 / 0x20).
  // ============================================================================
  it('fb2 outer offset aliasing head (off=0x00/0x20) echo & element', async () => {
    const region = fixedBytesRegion([sb('aa'), sb('bb')]);
    // off=0x20 -> table starts AT the i word (overlap). off=0x00 -> at the offset word.
    await eq('fb2At off=0x20 overlap i', '0x' + sel('fb2At(bytes[2],uint256)') + pad(0x20n) + pad(0n) + region);
    await eq('fb2At off=0x00 at off word', '0x' + sel('fb2At(bytes[2],uint256)') + pad(0x00n) + pad(0n) + region);
    await eq('fb2Echo off=0x20', '0x' + sel('fb2Echo(bytes[2])') + pad(0x20n) + region);
    await eq('fb2Echo off=0x00', '0x' + sel('fb2Echo(bytes[2])') + pad(0x00n) + region);
  });

  it('reports zero divergences', () => {
    if (divergences.length) {
      throw new Error(`\n${divergences.length} DIVERGENCE(S) of ${nCases} cases:\n\n` + divergences.join('\n\n'));
    }
    // eslint-disable-next-line no-console
    console.log(`_reaudit_calldata: ${nCases} cases, 0 divergences`);
  });
});
