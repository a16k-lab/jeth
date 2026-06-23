// ADVERSARIAL return-encode audit (family: return-encode).
//
// Differential vs solc on RETURN / ECHO ABI encoding across every shape:
//   - value scalars, bytes/string (empty/short/32/long), dynamic arrays,
//     nested dynamic arrays, fixed arrays of value/packed/struct/nested kinds,
//     static & dynamic structs, struct-with-dynamic-field, fixed arrays of
//     dynamic structs, arrays of dynamic byte sequences,
//   - whole storage aggregates, whole mapping values,
//   - multi-value tuples mixing bytes/string/array/struct/CALLDATA-ARRAY components.
//
// KEY INVARIANT under test: a RETURN echo of a value-typed calldata ARRAY CLEANS
// dirty leaf bits (matching solc decode-to-memory masking) and does NOT revert,
// while a STRUCT or STRUCT-ELEMENT field VALIDATES (reverts on dirty bits). We
// probe the SAME narrow leaf both as a bare value-array element and as a struct
// field, in both single-return and tuple-component positions, and compare to
// solc byte-for-byte (success/revert parity + identical returndata).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity, readSlot } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const enc = new TextEncoder();
const sb = (s: string) => enc.encode(s);
const MAX = M - 1n;
const TOP = 1n << 255n;
const U64 = 1n << 64n; // 2^64 boundary (Panic-0x41 region for lengths/offsets)
// arbitrary high-garbage word with low byte 0x42
const DIRTY = (1n << 255n) | (1n << 200n) | (1n << 130n) | 0xabn;
// left-aligned bytesN word from low bytes
const bytesN = (lo: bigint, n: number) => ((lo % (1n << BigInt(8 * n))) << BigInt(8 * (32 - n))) % M;

// right-pad raw bytes to 32-multiple; empty -> no payload word
function padData(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';
  const words = Math.ceil(bytes.length / 32);
  let h = '';
  for (let i = 0; i < words * 32; i++) h += (bytes[i] ?? 0).toString(16).padStart(2, '0');
  return h;
}
const dynElem = (b: Uint8Array) => pad(BigInt(b.length)) + padData(b);
// [len][offtable][payloads] for bytes[]/string[]
function encArrRegion(items: Uint8Array[]): string {
  const L = items.length;
  const payloads = items.map(dynElem);
  let off = L * 32;
  let table = '';
  for (const p of payloads) {
    table += pad(BigInt(off));
    off += p.length / 2;
  }
  return pad(BigInt(L)) + table + payloads.join('');
}
const encU256Arr = (xs: bigint[]) => pad(BigInt(xs.length)) + xs.map(pad).join('');
// build calldata: selector + flat inline words, then optional raw-hex tail
const call = (sig: string, words: bigint[] = [], extra = '') => '0x' + sel(sig) + words.map(pad).join('') + extra;

const JETH = `
@struct class P { a: u256; b: u8; c: address; }
@struct class Mixed { a: u128; b: u64; c: bool; d: address; e: bytes8; f: i40; }
@struct class FD { a: u256; s: string; }                  // fixed then dynamic
@struct class DF { s: string; a: u256; }                  // dynamic then fixed
@struct class TwoDyn { s: string; t: string; }            // two dynamic fields
@struct class Nest { x: u256; inner: FD; y: u256; }        // dynamic struct field
@struct class WithArr { id: u64; data: Arr<u256, 3>; tag: bytes4; } // fixed-array field
@struct class WithNarrArr { id: u64; data: Arr<u8, 3>; tag: bytes4; } // narrow fixed-array field
@contract class C {
  @state vals: u256[];
  @state names: string[];
  @state blobs: bytes[];
  @state grid: u256[][];
  @state recs: FD[];
  @state fd1: FD;
  @state fd2: FD;
  @state nums: Arr<u256, 3>;
  @state m: mapping<u256, u256[]>;
  @state ms: mapping<u256, FD>;
  @state mb: mapping<u256, bytes>;

  // ---- seeders ----
  @external pushVal(v: u256): void { this.vals.push(v); }
  @external pushName(s: string): void { this.names.push(s); }
  @external pushBlob(b: bytes): void { this.blobs.push(b); }
  @external gridPush(): void { this.grid.push(); }
  @external gridPushInner(i: u256, v: u256): void { this.grid[i].push(v); }
  @external pushFD(a: u256, s: string): void { this.recs.push(FD(a, s)); }
  @external setFd1(a: u256, s: string): void { this.fd1 = FD(a, s); }
  @external setFd2(a: u256, s: string): void { this.fd2 = FD(a, s); }
  @external setNums(a: u256, b: u256, c: u256): void { this.nums = [a, b, c]; }
  @external setM(k: u256, a: u256, b: u256): void { this.m[k] = [a, b]; }
  @external setMs(k: u256, a: u256, s: string): void { this.ms[k] = FD(a, s); }
  @external setMb(k: u256, b: bytes): void { this.mb[k] = b; }

  // ---- VALUE-ARRAY ECHO (CLEANS dirty leaves) ----
  @external @pure echoU8Fix(a: Arr<u8, 4>): Arr<u8, 4> { return a; }
  @external @pure echoU8Dyn(a: u8[]): u8[] { return a; }
  @external @pure echoBoolDyn(a: bool[]): bool[] { return a; }
  @external @pure echoI8Dyn(a: i8[]): i8[] { return a; }
  @external @pure echoB4Dyn(a: bytes4[]): bytes4[] { return a; }
  @external @pure echoAddrDyn(a: address[]): address[] { return a; }
  @external @pure echoU16Nest(a: Arr<u16[], 2>): Arr<u16[], 2> { return a; }   // fixed-of-dynamic narrow
  @external @pure echoU8DynNest(a: u8[][]): u8[][] { return a; }                // dyn-of-dyn narrow

  // ---- STRUCT / STRUCT-ELEMENT ECHO (VALIDATES dirty fields) ----
  @external @pure echoStruct(p: P): P { return p; }
  @external @pure echoMixed(p: Mixed): Mixed { return p; }
  @external @pure echoStructArr(a: P[]): P[] { return a; }      // DYNAMIC array of struct
  @external @pure echoStructFix(a: Arr<P, 2>): Arr<P, 2> { return a; }
  @external @pure echoWithNarrArr(p: WithNarrArr): WithNarrArr { return p; }

  // ---- dynamic-struct echoes ----
  @external @pure echoFD(d: FD): FD { return d; }
  @external @pure echoNest(d: Nest): Nest { return d; }
  @external @pure echoFDArr(a: FD[]): FD[] { return a; }          // arr of dynamic struct
  @external @pure echoFDFix(a: Arr<FD, 2>): Arr<FD, 2> { return a; } // fixed arr of dynamic struct

  // ---- bytes/string echoes ----
  @external @pure echoBytes(b: bytes): bytes { return b; }
  @external @pure echoStr(s: string): string { return s; }
  @external @pure echoBytesArr(a: bytes[]): bytes[] { return a; }
  @external @pure echoStrArr(a: string[]): string[] { return a; }
  @external @pure echoGrid(a: u256[][]): u256[][] { return a; }

  // ---- literal / constructed returns (no calldata cleaning involved) ----
  @external @pure mkFD(a: u256, s: string): FD { return FD(a, s); }
  @external @pure mkDF(s: string, a: u256): DF { return DF(s, a); }
  @external @pure mkTwoDyn(s: string, t: string): TwoDyn { return TwoDyn(s, t); }
  @external @pure mkNest(x: u256, a: u256, s: string, y: u256): Nest { return Nest(x, FD(a, s), y); }
  @external @pure emptyStr(): string { return ""; }
  @external @pure emptyStructStr(): FD { return FD(0n, ""); }

  // ---- WHOLE STORAGE aggregate returns ----
  @external @view allVals(): u256[] { return this.vals; }
  @external @view allNames(): string[] { return this.names; }
  @external @view allBlobs(): bytes[] { return this.blobs; }
  @external @view allGrid(): u256[][] { return this.grid; }
  @external @view allFD(): FD[] { return this.recs; }
  @external @view getFd1(): FD { return this.fd1; }
  @external @view getNums(): Arr<u256, 3> { return this.nums; }

  // ---- WHOLE MAPPING-value returns ----
  @external @view getM(k: u256): u256[] { return this.m[k]; }
  @external @view getMs(k: u256): FD { return this.ms[k]; }
  @external @view getMb(k: u256): bytes { return this.mb[k]; }

  // ---- MULTI-VALUE TUPLES mixing components ----
  @external @pure mvValStr(n: u256, s: string): [u256, string] { return [n, s]; }
  @external @pure mvStrVal(s: string, n: u256): [string, u256] { return [s, n]; }
  @external @pure mvValBytesVal(n: u256, b: bytes, m: u256): [u256, bytes, u256] { return [n, b, m]; }
  @external @pure mvCdArrVal(xs: u256[], n: u256): [u256[], u256] { return [xs, n]; }       // value-array cd component (CLEANS)
  @external @pure mvCdNarrArrVal(xs: u8[], n: u256): [u8[], u256] { return [xs, n]; }        // narrow value-array cd component (CLEANS)
  @external @pure mvAllStatic(a: u256, b: address, c: bool): [u256, address, bool] { return [a, b, c]; }
  @external @view mvStructVal(n: u256): [FD, u256] { return [this.fd1, n]; }
  @external @view mvArrVal(n: u256): [u256[], u256] { return [this.vals, n]; }
  @external @view mvStrArr(n: u256): [string[], u256] { return [this.names, n]; }
  @external @pure mvBytesCdArr(b: bytes, xs: u256[]): [bytes, u256[]] { return [b, xs]; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 a; uint8 b; address c; }
  struct Mixed { uint128 a; uint64 b; bool c; address d; bytes8 e; int40 f; }
  struct FD { uint256 a; string s; }
  struct DF { string s; uint256 a; }
  struct TwoDyn { string s; string t; }
  struct Nest { uint256 x; FD inner; uint256 y; }
  struct WithArr { uint64 id; uint256[3] data; bytes4 tag; }
  struct WithNarrArr { uint64 id; uint8[3] data; bytes4 tag; }
  uint256[] vals;
  string[] names;
  bytes[] blobs;
  uint256[][] grid;
  FD[] recs;
  FD fd1;
  FD fd2;
  uint256[3] nums;
  mapping(uint256 => uint256[]) m;
  mapping(uint256 => FD) ms;
  mapping(uint256 => bytes) mb;

  function pushVal(uint256 v) external { vals.push(v); }
  function pushName(string calldata s) external { names.push(s); }
  function pushBlob(bytes calldata b) external { blobs.push(b); }
  function gridPush() external { grid.push(); }
  function gridPushInner(uint256 i, uint256 v) external { grid[i].push(v); }
  function pushFD(uint256 a, string calldata s) external { recs.push(FD(a, s)); }
  function setFd1(uint256 a, string calldata s) external { fd1 = FD(a, s); }
  function setFd2(uint256 a, string calldata s) external { fd2 = FD(a, s); }
  function setNums(uint256 a, uint256 b, uint256 c) external { nums = [a, b, c]; }
  function setM(uint256 k, uint256 a, uint256 b) external { uint256[] memory t = new uint256[](2); t[0]=a; t[1]=b; m[k] = t; }
  function setMs(uint256 k, uint256 a, string calldata s) external { ms[k] = FD(a, s); }
  function setMb(uint256 k, bytes calldata b) external { mb[k] = b; }

  function echoU8Fix(uint8[4] calldata a) external pure returns (uint8[4] memory){ return a; }
  function echoU8Dyn(uint8[] calldata a) external pure returns (uint8[] memory){ return a; }
  function echoBoolDyn(bool[] calldata a) external pure returns (bool[] memory){ return a; }
  function echoI8Dyn(int8[] calldata a) external pure returns (int8[] memory){ return a; }
  function echoB4Dyn(bytes4[] calldata a) external pure returns (bytes4[] memory){ return a; }
  function echoAddrDyn(address[] calldata a) external pure returns (address[] memory){ return a; }
  function echoU16Nest(uint16[][2] calldata a) external pure returns (uint16[][2] memory){ return a; }
  function echoU8DynNest(uint8[][] calldata a) external pure returns (uint8[][] memory){ return a; }

  function echoStruct(P calldata p) external pure returns (P memory){ return p; }
  function echoMixed(Mixed calldata p) external pure returns (Mixed memory){ return p; }
  function echoStructArr(P[] calldata a) external pure returns (P[] memory){ return a; }
  function echoStructFix(P[2] calldata a) external pure returns (P[2] memory){ return a; }
  function echoWithNarrArr(WithNarrArr calldata p) external pure returns (WithNarrArr memory){ return p; }

  function echoFD(FD calldata d) external pure returns (FD memory){ return d; }
  function echoNest(Nest calldata d) external pure returns (Nest memory){ return d; }
  function echoFDArr(FD[] calldata a) external pure returns (FD[] memory){ return a; }
  function echoFDFix(FD[2] calldata a) external pure returns (FD[2] memory){ return a; }

  function echoBytes(bytes calldata b) external pure returns (bytes memory){ return b; }
  function echoStr(string calldata s) external pure returns (string memory){ return s; }
  function echoBytesArr(bytes[] calldata a) external pure returns (bytes[] memory){ return a; }
  function echoStrArr(string[] calldata a) external pure returns (string[] memory){ return a; }
  function echoGrid(uint256[][] calldata a) external pure returns (uint256[][] memory){ return a; }

  function mkFD(uint256 a, string calldata s) external pure returns (FD memory){ return FD(a, s); }
  function mkDF(string calldata s, uint256 a) external pure returns (DF memory){ return DF(s, a); }
  function mkTwoDyn(string calldata s, string calldata t) external pure returns (TwoDyn memory){ return TwoDyn(s, t); }
  function mkNest(uint256 x, uint256 a, string calldata s, uint256 y) external pure returns (Nest memory){ return Nest(x, FD(a, s), y); }
  function emptyStr() external pure returns (string memory){ return ""; }
  function emptyStructStr() external pure returns (FD memory){ return FD(0, ""); }

  function allVals() external view returns (uint256[] memory){ return vals; }
  function allNames() external view returns (string[] memory){ return names; }
  function allBlobs() external view returns (bytes[] memory){ return blobs; }
  function allGrid() external view returns (uint256[][] memory){ return grid; }
  function allFD() external view returns (FD[] memory){ return recs; }
  function getFd1() external view returns (FD memory){ return fd1; }
  function getNums() external view returns (uint256[3] memory){ return nums; }

  function getM(uint256 k) external view returns (uint256[] memory){ return m[k]; }
  function getMs(uint256 k) external view returns (FD memory){ return ms[k]; }
  function getMb(uint256 k) external view returns (bytes memory){ return mb[k]; }

  function mvValStr(uint256 n, string calldata s) external pure returns (uint256, string memory){ return (n, s); }
  function mvStrVal(string calldata s, uint256 n) external pure returns (string memory, uint256){ return (s, n); }
  function mvValBytesVal(uint256 n, bytes calldata b, uint256 mm) external pure returns (uint256, bytes memory, uint256){ return (n, b, mm); }
  function mvCdArrVal(uint256[] calldata xs, uint256 n) external pure returns (uint256[] memory, uint256){ return (xs, n); }
  function mvCdNarrArrVal(uint8[] calldata xs, uint256 n) external pure returns (uint8[] memory, uint256){ return (xs, n); }
  function mvAllStatic(uint256 a, address b, bool c) external pure returns (uint256, address, bool){ return (a, b, c); }
  function mvStructVal(uint256 n) external view returns (FD memory, uint256){ return (fd1, n); }
  function mvArrVal(uint256 n) external view returns (uint256[] memory, uint256){ return (vals, n); }
  function mvStrArr(uint256 n) external view returns (string[] memory, uint256){ return (names, n); }
  function mvBytesCdArr(bytes calldata b, uint256[] calldata xs) external pure returns (bytes memory, uint256[] memory){ return (b, xs); }
}`;

describe('AUDIT return-encode vs Solidity', () => {
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
          ': jeth{ok=' +
          j.success +
          ',ret=' +
          j.returnHex +
          ',err=' +
          j.exceptionError +
          '} sol{ok=' +
          s.success +
          ',ret=' +
          s.returnHex +
          '}',
      );
  }
  async function send(data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success)
      mism.push(
        'SEND ' + data.slice(0, 12) + ': jeth ok=' + j.success + ' err=' + j.exceptionError + ' sol ok=' + s.success,
      );
  }

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sbld = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sbld.creation);
  });

  it('value-array echo CLEANS dirty leaves; struct/element VALIDATES', async () => {
    // ===== value-array echoes: dirty high bits => solc MASKS => success, cleaned return =====
    // uint8[4] fixed
    const u8c = [1n, 2n, 3n, 4n];
    await eq('echoU8Fix clean', call('echoU8Fix(uint8[4])', u8c));
    for (let i = 0; i < 4; i++) {
      const d = [...u8c];
      d[i] = (DIRTY << 8n) | 0x42n;
      await eq('echoU8Fix dirty[' + i + ']', call('echoU8Fix(uint8[4])', d));
    }
    await eq('echoU8Fix all-max', call('echoU8Fix(uint8[4])', [MAX, MAX, MAX, MAX]));

    // uint8[] DYNAMIC value array: dirty leaves CLEAN (key target vs struct)
    for (const xs of [[], [0n], [0xffn, 0n, 0x7fn], [1n, 2n, 3n, 4n, 5n]]) {
      await eq('echoU8Dyn clean[' + xs.length + ']', '0x' + sel('echoU8Dyn(uint8[])') + buildDynArr(xs));
    }
    for (const dv of [DIRTY, (1n << 8n) | 0x42n, MAX, TOP, U64 | 0x99n]) {
      await eq(
        'echoU8Dyn dirty(' + dv.toString(16) + ')',
        call('echoU8Dyn(uint8[])', [], buildDynArr([dv, 0x11n, dv])),
      );
    }
    // bool[] : non-canonical bool values => solc CLEANS via iszero(iszero)
    for (const dv of [2n, 0xffn, DIRTY, TOP, MAX]) {
      await eq('echoBoolDyn(' + dv.toString(16) + ')', call('echoBoolDyn(bool[])', [], buildDynArr([1n, dv, 0n, dv])));
    }
    // int8[] : sign-extend from bit 7 (mask) => success
    for (const dv of [1n << 7n, (1n << 8n) | 0x7fn, MAX, TOP | 0x80n, U64]) {
      await eq('echoI8Dyn(' + dv.toString(16) + ')', call('echoI8Dyn(int8[])', [], buildDynArr([0n, 0x7fn, dv])));
    }
    // bytes4[] : dirty LOW bytes => solc masks unused low 28 bytes => success
    for (const dv of [0xffffffffffffffn, (1n << 224n) - 1n, MAX, 1n]) {
      await eq(
        'echoB4Dyn(' + dv.toString(16) + ')',
        call('echoB4Dyn(bytes4[])', [], buildDynArr([bytesN(0x11223344n, 4) | dv])),
      );
    }
    // address[] : dirty above 160 bits => masked
    for (const dv of [1n << 200n, 1n << 160n, MAX, TOP]) {
      await eq(
        'echoAddrDyn(' + dv.toString(16) + ')',
        call('echoAddrDyn(address[])', [], buildDynArr([dv | 0x1234n, 0n])),
      );
    }

    // ===== struct / struct-element echoes: dirty => solc VALIDATES => REVERT =====
    await eq('echoStruct clean', call('echoStruct((uint256,uint8,address))', [42n, 7n, 0x1234n]));
    await eq('echoStruct dirty b', call('echoStruct((uint256,uint8,address))', [42n, (1n << 8n) | 7n, 0x1234n]));
    await eq(
      'echoStruct dirty b high',
      call('echoStruct((uint256,uint8,address))', [42n, (DIRTY << 8n) | 7n, 0x1234n]),
    );
    await eq('echoStruct dirty c', call('echoStruct((uint256,uint8,address))', [42n, 7n, (1n << 200n) | 0x1234n]));
    await eq('echoStruct dirty c top', call('echoStruct((uint256,uint8,address))', [42n, 7n, TOP | 0x1234n]));
    await eq('echoStruct max-ok', call('echoStruct((uint256,uint8,address))', [MAX, 0xffn, (1n << 160n) - 1n]));

    // P[] DYNAMIC array of struct: dirty element field VALIDATES (revert), unlike a value array
    const psig = 'echoStructArr((uint256,uint8,address)[])';
    await eq(
      'echoStructArr clean',
      call(
        psig,
        [],
        buildStructArr([
          [1n, 2n, 0xaaaan],
          [3n, 4n, 0xbbbbn],
        ]),
      ),
    );
    await eq(
      'echoStructArr dirty[0].b',
      call(
        psig,
        [],
        buildStructArr([
          [1n, (1n << 8n) | 2n, 0xaaaan],
          [3n, 4n, 0xbbbbn],
        ]),
      ),
    );
    await eq(
      'echoStructArr dirty[1].c',
      call(
        psig,
        [],
        buildStructArr([
          [1n, 2n, 0xaaaan],
          [3n, 4n, (1n << 161n) | 0xbbbbn],
        ]),
      ),
    );
    await eq('echoStructArr empty', call(psig, [], buildStructArr([])));

    // P[2] fixed array of struct
    await eq(
      'echoStructFix clean',
      call('echoStructFix((uint256,uint8,address)[2])', [1n, 2n, 0xaaaan, 3n, 4n, 0xbbbbn]),
    );
    await eq(
      'echoStructFix dirty[1].b',
      call('echoStructFix((uint256,uint8,address)[2])', [1n, 2n, 0xaaaan, 3n, (1n << 9n) | 4n, 0xbbbbn]),
    );
    await eq(
      'echoStructFix dirty[0].c',
      call('echoStructFix((uint256,uint8,address)[2])', [1n, 2n, (1n << 200n) | 0xaaaan, 3n, 4n, 0xbbbbn]),
    );

    // Mixed: every narrow field validated
    const mc = [0x1122n, 0x33n, 1n, BigInt('0x' + 'a1'.repeat(20)), bytesN(0xdeadbeefcafef00dn, 8), 0x1234n];
    const MS = 'echoMixed((uint128,uint64,bool,address,bytes8,int40))';
    await eq('echoMixed clean', call(MS, mc));
    await eq('echoMixed dirty a u128', call(MS, withIdx(mc, 0, (U64 * U64) | 0x1122n)));
    await eq('echoMixed dirty b u64', call(MS, withIdx(mc, 1, U64 | 0x33n)));
    await eq('echoMixed dirty c bool2', call(MS, withIdx(mc, 2, 2n)));
    await eq('echoMixed dirty c boolHigh', call(MS, withIdx(mc, 2, DIRTY)));
    await eq('echoMixed dirty d addr', call(MS, withIdx(mc, 3, (1n << 160n) | BigInt('0x' + 'a1'.repeat(20)))));
    await eq('echoMixed dirty e bytes8 low', call(MS, withIdx(mc, 4, bytesN(0xdeadbeefcafef00dn, 8) | 0xffn)));
    await eq('echoMixed dirty f i40 above40', call(MS, withIdx(mc, 5, (1n << 40n) | 0x10n)));
    await eq('echoMixed f i40 bit39-no-ext', call(MS, withIdx(mc, 5, (1n << 39n) | 0x3n)));
    await eq('echoMixed f i40 pos-allones', call(MS, withIdx(mc, 5, (M - 1n) ^ ((1n << 40n) - 1n))));
    // valid i40 sign-extensions echo unchanged
    const se = (v: bigint) => ((v % M) + M) % M;
    for (const v of [0n, 1n, -1n, (1n << 39n) - 1n, -(1n << 39n)]) {
      await eq('echoMixed i40 valid(' + v + ')', call(MS, withIdx(mc, 5, se(v))));
    }
    // bytes8 unused-byte validation per byte
    for (let b = 1; b <= 8; b++) {
      await eq(
        'echoMixed bytes8 dirty(b' + b + ')',
        call(MS, withIdx(mc, 4, bytesN(0xdeadbeefcafef00dn, 8) | (1n << BigInt(8 * (24 - 1) + b)))),
      );
    }

    // WithNarrArr { u64 id; u8[3] data; bytes4 tag }: data is a STRUCT-FIELD fixed narrow array.
    // CRITICAL: inside a struct, solc VALIDATES the u8 leaves (revert on dirty), unlike a bare u8[N] echo.
    const wsig = 'echoWithNarrArr((uint64,uint8[3],bytes4))';
    const wc = [0x99n, 0x11n, 0x22n, 0x33n, bytesN(0xcafebaben, 4)];
    await eq('echoWithNarrArr clean', call(wsig, wc));
    await eq('echoWithNarrArr dirty data[0]', call(wsig, withIdx(wc, 1, (1n << 8n) | 0x11n)));
    await eq('echoWithNarrArr dirty data[2]', call(wsig, withIdx(wc, 3, (DIRTY << 8n) | 0x33n)));
    await eq('echoWithNarrArr dirty id', call(wsig, withIdx(wc, 0, U64 | 0x99n)));
    await eq('echoWithNarrArr dirty tag', call(wsig, withIdx(wc, 4, bytesN(0xcafebaben, 4) | 0x1n)));
  });

  it('nested value-array echoes clean; nested narrow arrays', async () => {
    // u16[][2] fixed-of-dynamic narrow: solc decodes => cleans u16 leaves
    const sig = 'echoU16Nest(uint16[][2])';
    // build: [off0][off1] then two dyn u16 arrays
    function nest2(a: bigint[], b: bigint[]): string {
      const ea = encU256Arr(a),
        eb = encU256Arr(b);
      const off0 = 0x40n,
        off1 = 0x40n + BigInt(ea.length / 2);
      return '0x' + sel(sig) + pad(0x20n) + pad(off0) + pad(off1) + ea + eb;
    }
    await eq('echoU16Nest clean', nest2([0n, 0xffffn], [0x1234n]));
    await eq('echoU16Nest dirty', nest2([(DIRTY << 16n) | 0x99n], [(1n << 16n) | 0x1n, MAX]));
    await eq('echoU16Nest empty', nest2([], []));

    // u8[][] dyn-of-dyn narrow
    function dyn2(rows: bigint[][]): string {
      const inner = rows.map(encU256Arr);
      let off = rows.length * 32;
      const table: string[] = [];
      for (const e of inner) {
        table.push(pad(BigInt(off)));
        off += e.length / 2;
      }
      return (
        '0x' + sel('echoU8DynNest(uint8[][])') + pad(0x20n) + pad(BigInt(rows.length)) + table.join('') + inner.join('')
      );
    }
    await eq('echoU8DynNest clean', dyn2([[1n, 2n], [3n]]));
    await eq('echoU8DynNest dirty', dyn2([[(DIRTY << 8n) | 0x5n], [MAX, 0n]]));
    await eq('echoU8DynNest empty-outer', dyn2([]));
    await eq('echoU8DynNest empty-inner', dyn2([[], []]));

    // u256[][] echo (full-width leaves: pure offset re-encode)
    function grid(rows: bigint[][]): string {
      const inner = rows.map(encU256Arr);
      let off = rows.length * 32;
      const table: string[] = [];
      for (const e of inner) {
        table.push(pad(BigInt(off)));
        off += e.length / 2;
      }
      return (
        '0x' + sel('echoGrid(uint256[][])') + pad(0x20n) + pad(BigInt(rows.length)) + table.join('') + inner.join('')
      );
    }
    await eq('echoGrid clean', grid([[1n, 2n, 3n], [], [MAX]]));
    await eq('echoGrid empty', grid([]));
  });

  it('dynamic-struct echoes (FD / Nest / arrays of dyn struct)', async () => {
    const strs: [string, Uint8Array][] = [
      ['empty', sb('')],
      ['1', sb('a')],
      ['31', sb('Y'.repeat(31))],
      ['32', sb('Z'.repeat(32))],
      ['33', sb('W'.repeat(33))],
      ['64', sb('r'.repeat(64))],
      ['100', sb('X'.repeat(100))],
    ];
    // echoFD: head[off=0x20] then tuple [a][off=0x40][s]
    for (const [ln, s] of strs)
      for (const a of [0n, 7n, MAX]) {
        const data = '0x' + sel('echoFD((uint256,string))') + pad(0x20n) + pad(a) + pad(0x40n) + dynElem(s);
        await eq('echoFD a=' + a + ' s=' + ln, data);
      }
    // echoNest: Nest{ x; FD inner; y }. head[off=0x20]; tuple[x][off_inner=0x80][y] then FD tail
    for (const [ln, s] of strs) {
      const fd = pad(2n) + pad(0x40n) + dynElem(s); // FD inner: [a][off][s]
      const tuple = pad(1n) + pad(0x80n) + pad(3n) + fd;
      const data = '0x' + sel('echoNest((uint256,(uint256,string),uint256))') + pad(0x20n) + tuple;
      await eq('echoNest s=' + ln, data);
    }
    // FD[] dynamic array of dynamic struct
    function fdArr(items: [bigint, Uint8Array][]): string {
      const L = items.length;
      const encs = items.map(([a, s]) => pad(a) + pad(0x40n) + dynElem(s));
      let off = L * 32;
      const table: string[] = [];
      for (const e of encs) {
        table.push(pad(BigInt(off)));
        off += e.length / 2;
      }
      return '0x' + sel('echoFDArr((uint256,string)[])') + pad(0x20n) + pad(BigInt(L)) + table.join('') + encs.join('');
    }
    await eq('echoFDArr empty', fdArr([]));
    await eq('echoFDArr 1', fdArr([[10n, sb('hi')]]));
    await eq(
      'echoFDArr 3',
      fdArr([
        [10n, sb('')],
        [20n, sb('Z'.repeat(40))],
        [30n, sb('q'.repeat(33))],
      ]),
    );
    // Arr<FD,2> fixed array of dynamic struct: offset table of 2 then tails
    function fdFix(items: [bigint, Uint8Array][]): string {
      const encs = items.map(([a, s]) => pad(a) + pad(0x40n) + dynElem(s));
      let off = 2 * 32;
      const table: string[] = [];
      for (const e of encs) {
        table.push(pad(BigInt(off)));
        off += e.length / 2;
      }
      return '0x' + sel('echoFDFix((uint256,string)[2])') + pad(0x20n) + table.join('') + encs.join('');
    }
    await eq(
      'echoFDFix',
      fdFix([
        [1n, sb('a')],
        [2n, sb('B'.repeat(50))],
      ]),
    );

    // echoFD with truncated string tail: claims len=64 but provides no payload words -> revert parity
    await eq(
      'echoFD trunc tail',
      '0x' + sel('echoFD((uint256,string))') + pad(0x20n) + pad(1n) + pad(0x40n) + pad(64n),
    );
  });

  it('bytes/string echoes (boundary lengths) + arrays of dyn byte sequences', async () => {
    const lens = [0, 1, 31, 32, 33, 63, 64, 65, 100, 128, 200];
    for (const n of lens) {
      const b = new Uint8Array(n).map((_, k) => (k * 7 + 1) & 0xff);
      await eq('echoBytes ' + n, '0x' + sel('echoBytes(bytes)') + pad(0x20n) + dynElem(b));
      await eq('echoStr ' + n, '0x' + sel('echoStr(string)') + pad(0x20n) + dynElem(b));
    }
    // bytes[] / string[]
    const seqs = [sb(''), sb('a'), new Uint8Array(32).fill(0xab), new Uint8Array(40).map((_, k) => (k * 13) & 0xff)];
    await eq('echoBytesArr', '0x' + sel('echoBytesArr(bytes[])') + pad(0x20n) + encArrRegion(seqs));
    await eq('echoBytesArr empty', '0x' + sel('echoBytesArr(bytes[])') + pad(0x20n) + encArrRegion([]));
    await eq(
      'echoStrArr',
      '0x' +
        sel('echoStrArr(string[])') +
        pad(0x20n) +
        encArrRegion([sb(''), sb('hello world this is a long string element over 32 bytes!!!')]),
    );

    // constructed / literal returns
    for (const [ln, s] of [
      ['empty', sb('')],
      ['33', sb('m'.repeat(33))],
    ] as [string, Uint8Array][])
      for (const a of [0n, MAX]) {
        await eq('mkFD ' + ln + ' a=' + a, '0x' + sel('mkFD(uint256,string)') + pad(a) + pad(0x40n) + dynElem(s));
        await eq('mkDF ' + ln + ' a=' + a, '0x' + sel('mkDF(string,uint256)') + pad(0x40n) + pad(a) + dynElem(s));
      }
    await eq(
      'mkTwoDyn',
      '0x' +
        sel('mkTwoDyn(string,string)') +
        pad(0x40n) +
        pad(0x40n + BigInt(dynElem(sb('first')).length / 2)) +
        dynElem(sb('first')) +
        dynElem(sb('a long second string element well over thirty-two bytes for sure')),
    );
    await eq(
      'mkNest',
      '0x' +
        sel('mkNest(uint256,uint256,string,uint256)') +
        pad(1n) +
        pad(2n) +
        pad(0x80n) +
        pad(3n) +
        dynElem(sb('nested')),
    );
    await eq('emptyStr', encodeCall(sel('emptyStr()'), []));
    await eq('emptyStructStr', encodeCall(sel('emptyStructStr()'), []));
  });

  it('whole STORAGE aggregate returns (raw-slot + returndata parity)', async () => {
    // empty first
    await eq('allVals empty', encodeCall(sel('allVals()'), []));
    await eq('allNames empty', encodeCall(sel('allNames()'), []));
    await eq('allFD empty', encodeCall(sel('allFD()'), []));
    await eq('getNums zero', encodeCall(sel('getNums()'), []));
    // seed
    for (const v of [0n, 1n, MAX, 1n << 200n, 42n]) await send(call('pushVal(uint256)', [v]));
    for (const s of ['', 'hi', 'Z'.repeat(40), 'q'.repeat(33)])
      await send('0x' + sel('pushName(string)') + pad(0x20n) + dynElem(sb(s)));
    for (const [a, s] of [
      [10n, ''],
      [20n, 'aa'],
      [30n, 'W'.repeat(50)],
    ] as [bigint, string][])
      await send('0x' + sel('pushFD(uint256,string)') + pad(a) + pad(0x40n) + dynElem(sb(s)));
    for (const b of ['', 'ff', 'ab'.repeat(40)])
      await send('0x' + sel('pushBlob(bytes)') + pad(0x20n) + dynElem(Uint8Array.from(Buffer.from(b, 'hex'))));
    await send(encodeCall(sel('gridPush()'), []));
    await send(encodeCall(sel('gridPush()'), []));
    for (const v of [5n, 6n, 7n]) await send(call('gridPushInner(uint256,uint256)', [0n, v]));
    await send(call('setNums(uint256,uint256,uint256)', [11n, 22n, 33n]));
    await send(
      call('setFd1(uint256,string)', [7n], dynElem(sb('field one string longer than thirty-two bytes to span slots'))),
    );

    await eq('allVals', encodeCall(sel('allVals()'), []));
    await eq('allNames', encodeCall(sel('allNames()'), []));
    await eq('allBlobs', encodeCall(sel('allBlobs()'), []));
    await eq('allGrid', encodeCall(sel('allGrid()'), []));
    await eq('allFD', encodeCall(sel('allFD()'), []));
    await eq('getFd1', encodeCall(sel('getFd1()'), []));
    await eq('getNums', encodeCall(sel('getNums()'), []));

    // raw-slot parity for a couple of state vars (vals slot 0, nums fixed array slot 7..9)
    // identify slots from solc layout would be ideal; here compare jeth vs sol raw slots directly.
    for (const slot of [0n, 1n, 2n, 7n, 8n, 9n]) {
      const sj = await readSlot(jeth, aj, slot);
      const ss = await readSlot(sol, as, slot);
      if (sj !== ss) mism.push('SLOT ' + slot + ': jeth ' + sj + ' sol ' + ss);
    }
  });

  it('whole MAPPING-value returns', async () => {
    await eq('getM unset', call('getM(uint256)', [99n]));
    await eq('getMs unset', call('getMs(uint256)', [99n]));
    await eq('getMb unset', call('getMb(uint256)', [99n]));
    await send(call('setM(uint256,uint256,uint256)', [1n, 111n, 222n]));
    await send(
      call(
        'setMs(uint256,uint256,string)',
        [2n],
        dynElem(sb('mapping struct string field over thirty-two bytes long!!!')),
      ),
    );
    await send('0x' + sel('setMb(uint256,bytes)') + pad(3n) + pad(0x40n) + dynElem(new Uint8Array(40).fill(0xcd)));
    await eq('getM set', call('getM(uint256)', [1n]));
    await eq('getMs set', call('getMs(uint256)', [2n]));
    await eq('getMb set', call('getMb(uint256)', [3n]));
  });

  it('multi-value tuples mixing components (CLEAN cd-array vs VALIDATE struct)', async () => {
    // mvValStr / mvStrVal
    for (const [ln, s] of [
      ['empty', sb('')],
      ['short', sb('hi')],
      ['long', sb('x'.repeat(70))],
    ] as [string, Uint8Array][]) {
      await eq('mvValStr ' + ln, '0x' + sel('mvValStr(uint256,string)') + pad(42n) + pad(0x40n) + dynElem(s));
      await eq('mvStrVal ' + ln, '0x' + sel('mvStrVal(string,uint256)') + pad(0x40n) + pad(42n) + dynElem(s));
    }
    // mvValBytesVal
    await eq(
      'mvValBytesVal',
      '0x' +
        sel('mvValBytesVal(uint256,bytes,uint256)') +
        pad(1n) +
        pad(0x60n) +
        pad(2n) +
        dynElem(new Uint8Array(33).fill(0x7)),
    );

    // mvCdArrVal: value-array component => CLEANS dirty leaves (no revert)
    await eq(
      'mvCdArrVal clean',
      '0x' + sel('mvCdArrVal(uint256[],uint256)') + pad(0x40n) + pad(9n) + encU256Arr([1n, 2n, 3n]),
    );
    // mvCdNarrArrVal: u8[] component => CLEANS (the key: even as a tuple component)
    await eq(
      'mvCdNarrArrVal clean',
      '0x' + sel('mvCdNarrArrVal(uint8[],uint256)') + pad(0x40n) + pad(9n) + encU256Arr([1n, 2n, 3n]),
    );
    await eq(
      'mvCdNarrArrVal dirty',
      '0x' +
        sel('mvCdNarrArrVal(uint8[],uint256)') +
        pad(0x40n) +
        pad(9n) +
        encU256Arr([(DIRTY << 8n) | 0x5n, MAX, U64 | 0x1n]),
    );

    // mvAllStatic
    await eq('mvAllStatic clean', call('mvAllStatic(uint256,address,bool)', [42n, 0x1234n, 1n]));
    await eq('mvAllStatic dirty addr', call('mvAllStatic(uint256,address,bool)', [42n, (1n << 200n) | 0x1234n, 1n]));
    await eq('mvAllStatic dirty bool', call('mvAllStatic(uint256,address,bool)', [42n, 0x1234n, 2n]));

    // mvBytesCdArr: bytes + cd value array
    await eq(
      'mvBytesCdArr',
      '0x' +
        sel('mvBytesCdArr(bytes,uint256[])') +
        pad(0x40n) +
        pad(BigInt(0x40 + dynElem(sb('payload')).length / 2)) +
        dynElem(sb('payload')) +
        encU256Arr([7n, 8n]),
    );
    // mvBytesCdArr with DIRTY u256 elems (full-width => no change, success)
    await eq(
      'mvBytesCdArr dirtyu256',
      '0x' +
        sel('mvBytesCdArr(bytes,uint256[])') +
        pad(0x40n) +
        pad(BigInt(0x40 + dynElem(sb('p')).length / 2)) +
        dynElem(sb('p')) +
        encU256Arr([DIRTY, MAX]),
    );
  });

  it('storage-backed tuple components (need seeding first)', async () => {
    await send(call('setFd1(uint256,string)', [7n], dynElem(sb('stored fd1 string'))));
    for (const v of [1n, 2n, 3n]) await send(call('pushVal(uint256)', [v]));
    for (const s of ['n0', 'n1']) await send('0x' + sel('pushName(string)') + pad(0x20n) + dynElem(sb(s)));
    await eq('mvStructVal', call('mvStructVal(uint256)', [99n]));
    await eq('mvArrVal', call('mvArrVal(uint256)', [99n]));
    await eq('mvStrArr', call('mvStrArr(uint256)', [99n]));
  });

  it('adversarial offsets / lengths / truncation on echoes', async () => {
    // echoBytes with malformed offset / length forms
    const base = (off: bigint, tail = '') => '0x' + sel('echoBytes(bytes)') + pad(off) + tail;
    await eq('echoBytes off=0', base(0n, dynElem(sb('x')))); // offset points at selector-relative 0 (the offset word itself)
    await eq('echoBytes off high-bit', base(TOP, dynElem(sb('x'))));
    await eq('echoBytes off 2^64', base(U64, dynElem(sb('x'))));
    await eq('echoBytes off past-end', base(0x1000n, dynElem(sb('x'))));
    await eq('echoBytes off=0x20 normal', base(0x20n, dynElem(sb('x'))));
    // length forms
    await eq('echoBytes len=2^64', '0x' + sel('echoBytes(bytes)') + pad(0x20n) + pad(U64) + '00'.repeat(32));
    await eq('echoBytes len=2^64-1', '0x' + sel('echoBytes(bytes)') + pad(0x20n) + pad(U64 - 1n) + '00'.repeat(32));
    await eq('echoBytes len past-end', '0x' + sel('echoBytes(bytes)') + pad(0x20n) + pad(0x40n) + '00'.repeat(32)); // claims 64 but only 32 follow
    await eq(
      'echoBytes len truncated tail',
      '0x' + sel('echoBytes(bytes)') + pad(0x20n) + pad(0x20n) + '00'.repeat(16),
    ); // claims 32, 16 present
    await eq('echoBytes empty payload', '0x' + sel('echoBytes(bytes)') + pad(0x20n) + pad(0n));
    await eq('echoBytes no payload at all', '0x' + sel('echoBytes(bytes)') + pad(0x20n)); // offset valid but no len word

    // dynamic value-array malformed length / offset
    await eq('echoU8Dyn len=2^64', '0x' + sel('echoU8Dyn(uint8[])') + pad(0x20n) + pad(U64));
    await eq('echoU8Dyn len=2^64-1', '0x' + sel('echoU8Dyn(uint8[])') + pad(0x20n) + pad(U64 - 1n));
    await eq('echoU8Dyn len past-end', '0x' + sel('echoU8Dyn(uint8[])') + pad(0x20n) + pad(3n) + pad(1n)); // claims 3 elems, 1 present
    await eq('echoU8Dyn off 2^255', '0x' + sel('echoU8Dyn(uint8[])') + pad(TOP) + encU256Arr([1n]));
    await eq('echoU8Dyn off aliased', '0x' + sel('echoU8Dyn(uint8[])') + pad(0x40n) + pad(0n) + encU256Arr([1n, 2n])); // offset points past first word

    // struct-array malformed offset (inner element offset out of range)
    await eq(
      'echoStructArr off len huge',
      '0x' + sel('echoStructArr((uint256,uint8,address)[])') + pad(0x20n) + pad(U64),
    );

    // FD echo: inner string offset malformed
    await eq(
      'echoFD inner off 2^64',
      '0x' + sel('echoFD((uint256,string))') + pad(0x20n) + pad(1n) + pad(U64) + dynElem(sb('x')),
    );
    await eq(
      'echoFD inner off high',
      '0x' + sel('echoFD((uint256,string))') + pad(0x20n) + pad(1n) + pad(TOP) + dynElem(sb('x')),
    );
    await eq(
      'echoFD outer off past',
      '0x' + sel('echoFD((uint256,string))') + pad(0x1000n) + pad(1n) + pad(0x40n) + dynElem(sb('x')),
    );

    // echoStr trailing extra (solc ignores trailing) and a mid-word truncated tail
    await eq(
      'echoStr trailing extra',
      '0x' + sel('echoStr(string)') + pad(0x20n) + dynElem(sb('hi')) + 'de'.repeat(40),
    );
    // len=33 with only 33 bytes (not 64) of payload -> tail is short by 31 bytes -> revert parity
    await eq('echoBytes short pad', '0x' + sel('echoBytes(bytes)') + pad(0x20n) + pad(0x21n) + 'ff'.repeat(33));
    // len=33 with full 64-byte payload present -> success, echoes 33 bytes
    await eq(
      'echoBytes ok 33',
      '0x' + sel('echoBytes(bytes)') + pad(0x20n) + pad(0x21n) + 'ff'.repeat(33) + '00'.repeat(31),
    );
  });

  it('WAVE2: bytes[]/string[] echo with pathological inner offsets/lengths', async () => {
    const bsel = sel('echoBytesArr(bytes[])');
    // valid 2-element bytes[]: outer off 0x20, [len=2][off0][off1][el0][el1]
    const okData = '0x' + bsel + pad(0x20n) + encArrRegion([sb('aa'), sb('bbbb')]);
    await eq('echoBytesArr ok', okData);
    // inner element offset = 2^64 (echo-decode uses unsigned gt cap -> revert)
    await eq(
      'echoBytesArr inner off 2^64',
      '0x' + bsel + pad(0x20n) + pad(2n) + pad(U64) + pad(0x80n) + dynElem(sb('a')) + dynElem(sb('b')),
    );
    // inner element offset = 2^64-1
    await eq(
      'echoBytesArr inner off 2^64-1',
      '0x' + bsel + pad(0x20n) + pad(2n) + pad(U64 - 1n) + pad(0x80n) + dynElem(sb('a')) + dynElem(sb('b')),
    );
    // inner element offset high-bit (2^255) -> echo-decode unsigned cap rejects
    await eq('echoBytesArr inner off 2^255', '0x' + bsel + pad(0x20n) + pad(1n) + pad(TOP) + dynElem(sb('a')));
    // inner element offset aliased: both point to same payload word
    await eq(
      'echoBytesArr inner aliased',
      '0x' + bsel + pad(0x20n) + pad(2n) + pad(0x40n) + pad(0x40n) + dynElem(sb('shared')),
    );
    // inner element offset points back into the offset table (off=0 -> reads off0 as length)
    await eq('echoBytesArr inner off=0', '0x' + bsel + pad(0x20n) + pad(1n) + pad(0n) + dynElem(sb('x')));
    // inner element length = 2^64 -> Panic(0x41) region
    await eq(
      'echoBytesArr inner len 2^64',
      '0x' + bsel + pad(0x20n) + pad(1n) + pad(0x40n) + pad(U64) + '00'.repeat(32),
    );
    // inner element length = 2^64-1 -> oversized alloc Panic(0x41)
    await eq(
      'echoBytesArr inner len 2^64-1',
      '0x' + bsel + pad(0x20n) + pad(1n) + pad(0x40n) + pad(U64 - 1n) + '00'.repeat(32),
    );
    // inner element payload runs past calldatasize -> revert
    await eq(
      'echoBytesArr inner len past-end',
      '0x' + bsel + pad(0x20n) + pad(1n) + pad(0x40n) + pad(0x60n) + '00'.repeat(32),
    );
    // outer length = 2^64 -> revert (gt cap)
    await eq('echoBytesArr outer len 2^64', '0x' + bsel + pad(0x20n) + pad(U64));
    // outer length huge but offset table doesn't fit -> revert
    await eq('echoBytesArr outer len 100 no table', '0x' + bsel + pad(0x20n) + pad(100n));
    // outer offset malformed
    await eq('echoBytesArr outer off 2^64', '0x' + bsel + pad(U64) + encArrRegion([sb('x')]));
    await eq('echoBytesArr outer off 2^255', '0x' + bsel + pad(TOP) + encArrRegion([sb('x')]));
    await eq('echoBytesArr outer off past-end', '0x' + bsel + pad(0x4000n) + encArrRegion([sb('x')]));

    // same battery on string[] echo
    const ssel = sel('echoStrArr(string[])');
    await eq('echoStrArr ok', '0x' + ssel + pad(0x20n) + encArrRegion([sb('hi'), sb('Z'.repeat(40))]));
    await eq('echoStrArr inner off 2^64', '0x' + ssel + pad(0x20n) + pad(1n) + pad(U64) + dynElem(sb('a')));
    await eq(
      'echoStrArr inner len 2^64-1',
      '0x' + ssel + pad(0x20n) + pad(1n) + pad(0x40n) + pad(U64 - 1n) + '00'.repeat(32),
    );
    await eq('echoStrArr empty len0', '0x' + ssel + pad(0x20n) + pad(0n));

    // grid (uint256[][]) echo malformed inner offsets/lengths
    const gsel = sel('echoGrid(uint256[][])');
    await eq('echoGrid inner off 2^64', '0x' + gsel + pad(0x20n) + pad(1n) + pad(U64) + encU256Arr([1n]));
    await eq('echoGrid inner off 2^255', '0x' + gsel + pad(0x20n) + pad(1n) + pad(TOP) + encU256Arr([1n]));
    await eq('echoGrid inner len 2^64', '0x' + gsel + pad(0x20n) + pad(1n) + pad(0x40n) + pad(U64) + pad(0n));
    await eq('echoGrid inner len past-end', '0x' + gsel + pad(0x20n) + pad(1n) + pad(0x40n) + pad(5n) + pad(0n)); // claims 5, 1 present
    await eq('echoGrid outer len 2^64', '0x' + gsel + pad(0x20n) + pad(U64));
  });

  it('WAVE3: FD[] / Nest dynamic-struct echo malformed offsets', async () => {
    // FD[] echo: outer off, [len][off-table][FD tuples]. FD inner string offset malformed.
    const fsel = sel('echoFDArr((uint256,string)[])');
    const goodFD = (a: bigint, s: Uint8Array) => pad(a) + pad(0x40n) + dynElem(s);
    // valid 1-elem
    await eq('echoFDArr ok', '0x' + fsel + pad(0x20n) + pad(1n) + pad(0x20n) + goodFD(7n, sb('hi')));
    // element offset 2^64 (whole-array echo unsigned cap)
    await eq('echoFDArr elem-off 2^64', '0x' + fsel + pad(0x20n) + pad(1n) + pad(U64) + goodFD(7n, sb('hi')));
    // element offset 2^255
    await eq('echoFDArr elem-off 2^255', '0x' + fsel + pad(0x20n) + pad(1n) + pad(TOP) + goodFD(7n, sb('hi')));
    // FD inner string offset 2^64
    await eq(
      'echoFDArr inner-str-off 2^64',
      '0x' + fsel + pad(0x20n) + pad(1n) + pad(0x20n) + pad(7n) + pad(U64) + dynElem(sb('hi')),
    );
    // FD inner string len 2^64-1
    await eq(
      'echoFDArr inner-str-len 2^64-1',
      '0x' + fsel + pad(0x20n) + pad(1n) + pad(0x20n) + pad(7n) + pad(0x40n) + pad(U64 - 1n) + '00'.repeat(32),
    );
    // outer length 2^64
    await eq('echoFDArr outer-len 2^64', '0x' + fsel + pad(0x20n) + pad(U64));
    // empty FD[]
    await eq('echoFDArr empty', '0x' + fsel + pad(0x20n) + pad(0n));

    // Nest echo: outer off, tuple [x][off_inner][y], FD inner tail. inner FD offset malformed.
    const nsel = sel('echoNest((uint256,(uint256,string),uint256))');
    const okNest = (s: Uint8Array) => {
      const fd = pad(2n) + pad(0x40n) + dynElem(s);
      return pad(1n) + pad(0x80n) + pad(3n) + fd;
    };
    await eq('echoNest ok', '0x' + nsel + pad(0x20n) + okNest(sb('z')));
    await eq(
      'echoNest inner-off 2^64',
      '0x' + nsel + pad(0x20n) + pad(1n) + pad(U64) + pad(3n) + pad(2n) + pad(0x40n) + dynElem(sb('z')),
    );
    await eq(
      'echoNest inner-off 2^255',
      '0x' + nsel + pad(0x20n) + pad(1n) + pad(TOP) + pad(3n) + pad(2n) + pad(0x40n) + dynElem(sb('z')),
    );
    await eq(
      'echoNest str-off 2^64',
      '0x' + nsel + pad(0x20n) + pad(1n) + pad(0x80n) + pad(3n) + pad(2n) + pad(U64) + dynElem(sb('z')),
    );
    await eq('echoNest outer-off past', '0x' + nsel + pad(0x8000n) + okNest(sb('z')));
  });

  it('WAVE4: FD echo (single dynamic struct) offset boundary sweep', async () => {
    const fsel = sel('echoFD((uint256,string))');
    // outer struct offset variants
    for (const off of [0x20n, 0n, TOP, U64, U64 - 1n, 0x21n, 0x1000n]) {
      await eq(
        'echoFD outer-off ' + off.toString(16),
        '0x' + fsel + pad(off) + pad(7n) + pad(0x40n) + dynElem(sb('hello')),
      );
    }
    // inner string offset variants (relative to tuple start)
    for (const off of [0x40n, 0x41n, 0n, 0x20n, TOP, U64, U64 - 1n, 0x2000n]) {
      await eq(
        'echoFD inner-off ' + off.toString(16),
        '0x' + fsel + pad(0x20n) + pad(7n) + pad(off) + dynElem(sb('world')),
      );
    }
    // inner string length variants
    for (const len of [0n, 1n, 32n, 33n, U64, U64 - 1n, 0x40n]) {
      // provide a generous payload so only length validation triggers
      await eq(
        'echoFD inner-len ' + len.toString(16),
        '0x' + fsel + pad(0x20n) + pad(7n) + pad(0x40n) + pad(len) + '11'.repeat(64),
      );
    }
  });

  it('FINALIZE: report all mismatches', async () => {
    if (mism.length) {
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 60)) console.log(m);
    } else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 20).join('\n')).toEqual([]);
  });
});

// ---- helpers that build dynamic-array calldata regions (appended as raw hex) ----
// uint8[]/etc dynamic array: [off=0x20][len][elems]
function buildDynArr(xs: bigint[]): string {
  return pad(0x20n) + pad(BigInt(xs.length)) + xs.map(pad).join('');
}
// P[] dynamic array of static struct: [off=0x20][len][elem words...]
function buildStructArr(rows: bigint[][]): string {
  let h = pad(0x20n) + pad(BigInt(rows.length));
  for (const r of rows) h += r.map(pad).join('');
  return h;
}
function withIdx(arr: bigint[], i: number, v: bigint): bigint[] {
  const d = [...arr];
  d[i] = v;
  return d;
}
