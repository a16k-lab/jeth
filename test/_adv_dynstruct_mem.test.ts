// ADVERSARIAL differential test for DYNAMIC-FIELD STRUCT MEMORY LOCALS (G10):
//   let d: D = D(x, str); return d;  where D mixes value fields (u256/u8/iN/address/
//   bool/bytesN) with bytes/string fields. We hammer field-order permutations, narrow/
//   signed value-field boundaries, dynamic payload word-boundary lengths in every dyn
//   position, value-field write/read-modify-write (incl. a value field AFTER a dyn field),
//   byte indexing (in-bounds + OOB), .length, construction from a memory-string local and
//   from string literals (short/long, same local in two fields), multiple distinct structs,
//   and a struct used in multiple functions. Every JETH function has an exact Solidity twin;
//   we diff (success, returnHex) over a large input matrix. Goal: ZERO divergence.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
// encode a dynamic [len][right-padded data] tail block from a raw byte buffer.
const encBytes = (buf: Buffer) => {
  const h = buf.toString('hex');
  return pad(BigInt(buf.length)) + h.padEnd(Math.ceil(buf.length / 32) * 64, '0');
};
const encStr = (s: string) => encBytes(Buffer.from(s, 'utf8'));
const wordsFor = (byteLen: number) => 32 + Math.ceil(byteLen / 32) * 32; // tail size of one dyn block

// ------- calldata builders for the various param shapes ----------------------
// One leading value word, one trailing string: head=[v][off=0x40], tail=[len][data].
const cd_v_s = (sig: string, v: bigint, s: string) => '0x' + sel(sig) + pad(v) + pad(0x40n) + encStr(s);
// One leading string, one trailing value: head=[off=0x40][v], tail=[len][data].
const cd_s_v = (sig: string, s: string, v: bigint) => '0x' + sel(sig) + pad(0x40n) + pad(v) + encStr(s);
// (value, string, value): head=[v][off=0x60][n], tail=[len][data].
const cd_v_s_v = (sig: string, v: bigint, s: string, n: bigint) =>
  '0x' + sel(sig) + pad(v) + pad(0x60n) + pad(n) + encStr(s);
// (string, value, string): head=[off1][v][off2], tail two blocks.
const cd_s_v_s = (sig: string, s1: string, v: bigint, s2: string) => {
  const off1 = 0x60;
  const off2 = off1 + wordsFor(Buffer.byteLength(s1, 'utf8'));
  return '0x' + sel(sig) + pad(BigInt(off1)) + pad(v) + pad(BigInt(off2)) + encStr(s1) + encStr(s2);
};
// (string, string): head=[off1][off2], two tail blocks.
const cd_s_s = (sig: string, s1: string, s2: string) => {
  const off1 = 0x40;
  const off2 = off1 + wordsFor(Buffer.byteLength(s1, 'utf8'));
  return '0x' + sel(sig) + pad(BigInt(off1)) + pad(BigInt(off2)) + encStr(s1) + encStr(s2);
};
// (value, string, bytes, value): head=[a][off_s][off_b][n], two tail blocks.
const cd_v_s_b_v = (sig: string, a: bigint, s: string, b: Buffer, n: bigint) => {
  const offS = 0x80;
  const offB = offS + wordsFor(Buffer.byteLength(s, 'utf8'));
  return '0x' + sel(sig) + pad(a) + pad(BigInt(offS)) + pad(BigInt(offB)) + pad(n) + encStr(s) + encBytes(b);
};
// (bytes, uint256): head=[off=0x40][i], tail=[len][data].
const cd_b_u = (sig: string, b: Buffer, i: bigint) => '0x' + sel(sig) + pad(0x40n) + pad(i) + encBytes(b);
// single string param: head=[off=0x20], tail=[len][data].
const cd_s1 = (sig: string, s: string) => '0x' + sel(sig) + pad(0x20n) + encStr(s);
// single bytes param (raw buffer): head=[off=0x20], tail=[len][data].
const cd_b1 = (sig: string, b: Buffer) => '0x' + sel(sig) + pad(0x20n) + encBytes(b);

// ----------------------- JETH + Solidity sources -----------------------------
const JETH = `
type VS = { a: u256; s: string; };
type SV = { s: string; a: u256; };
type VSV = { a: u256; s: string; b: u256; };
type SVS = { s: string; a: u256; t: string; };
type SS = { s: string; t: string; };
type DVD = { s: string; a: u256; t: string; };
type NU8 = { a: u8;  s: string; };
type NU16 = { a: u16; s: string; };
type NI8 = { a: i8;  s: string; };
type NI16 = { a: i16; s: string; };
type NI64 = { a: i64; s: string; };
type NI128 = { a: i128; s: string; };
type NADDR = { a: address; s: string; };
type NBOOL = { a: bool; s: string; };
type NB4 = { a: bytes4; s: string; };
type POST = { s: string; a: u8; };
type MIX = { a: u8; s: string; b: i16; t: bytes; c: address; n: bool; };
type D3 = { a: u8; s: string; b: bytes; n: u64; };
type B1S = { a: bytes1; s: string; };
type B16S = { a: bytes16; s: string; };
type B32S = { a: bytes32; s: string; };
type LB = { s: string; b: bytes; };
type VB = { a: u256; b: bytes; };
class C {
  get mkVS(a: u256, s: string): External<VS> { let d: VS = VS(a, s); return d; }
  get mkSV(s: string, a: u256): External<SV> { let d: SV = SV(s, a); return d; }
  get mkVSV(a: u256, s: string, b: u256): External<VSV> { let d: VSV = VSV(a, s, b); return d; }
  get mkSVS(s: string, a: u256, t: string): External<SVS> { let d: SVS = SVS(s, a, t); return d; }
  get mkSS(s: string, t: string): External<SS> { let d: SS = SS(s, t); return d; }
  get mkDVD(s: string, a: u256, t: string): External<DVD> { let d: DVD = DVD(s, a, t); return d; }

  get mkU8(a: u8, s: string): External<NU8> { let d: NU8 = NU8(a, s); return d; }
  get mkU16(a: u16, s: string): External<NU16> { let d: NU16 = NU16(a, s); return d; }
  get mkI8(a: i8, s: string): External<NI8> { let d: NI8 = NI8(a, s); return d; }
  get mkI16(a: i16, s: string): External<NI16> { let d: NI16 = NI16(a, s); return d; }
  get mkI64(a: i64, s: string): External<NI64> { let d: NI64 = NI64(a, s); return d; }
  get mkI128(a: i128, s: string): External<NI128> { let d: NI128 = NI128(a, s); return d; }
  get mkADDR(a: address, s: string): External<NADDR> { let d: NADDR = NADDR(a, s); return d; }
  get mkBOOL(a: bool, s: string): External<NBOOL> { let d: NBOOL = NBOOL(a, s); return d; }
  get mkB4(a: bytes4, s: string): External<NB4> { let d: NB4 = NB4(a, s); return d; }

  get getVSa(a: u256, s: string): External<u256> { let d: VS = VS(a, s); return d.a; }
  get getVSs(a: u256, s: string): External<string> { let d: VS = VS(a, s); return d.s; }
  get getSVa(s: string, a: u256): External<u256> { let d: SV = SV(s, a); return d.a; }
  get getSVs(s: string, a: u256): External<string> { let d: SV = SV(s, a); return d.s; }
  get getVSVb(a: u256, s: string, b: u256): External<u256> { let d: VSV = VSV(a, s, b); return d.b; }
  get getSVSt(s: string, a: u256, t: string): External<string> { let d: SVS = SVS(s, a, t); return d.t; }
  get getU8a(a: u8, s: string): External<u8> { let d: NU8 = NU8(a, s); return d.a; }
  get getI16a(a: i16, s: string): External<i16> { let d: NI16 = NI16(a, s); return d.a; }

  get writeVSa(a: u256, s: string, na: u256): External<VS> { let d: VS = VS(a, s); d.a = na; return d; }
  get rwVSa(a: u256, s: string, na: u256): External<VS> { let d: VS = VS(a, s); d.a = d.a + na; return d; }
  // value field that sits AFTER the dynamic field (head-offset under write):
  get writeSVa(s: string, a: u256, na: u256): External<SV> { let d: SV = SV(s, a); d.a = na; return d; }
  get rwSVa(s: string, a: u256, na: u256): External<SV> { let d: SV = SV(s, a); d.a = d.a + na; return d; }
  // narrow field write after dyn field:
  get writePOSTa(s: string, a: u8, na: u8): External<POST> { let d: POST = POST(s, a); d.a = na; return d; }
  // write the MIDDLE value field of VSV then return:
  get writeVSVa(a: u256, s: string, b: u256, na: u256): External<VSV> { let d: VSV = VSV(a, s, b); d.a = na; return d; }
  get writeVSVb(a: u256, s: string, b: u256, nb: u256): External<VSV> { let d: VSV = VSV(a, s, b); d.b = nb; return d; }

  get bLen(b: bytes, n: u64): External<u256> { let d: D3 = D3(0n, "", b, n); return d.b.length; }
  get bAt(b: bytes, i: u256): External<u8> { let d: D3 = D3(0n, "", b, 0n); return u8(d.b[i]); }

  // construct a dyn field from a memory-string LOCAL (alias), and the SAME local in two fields:
  get fromLocal(a: u256, s: string): External<VS> { let t: string = s; let d: VS = VS(a, t); return d; }
  get twoFromLocal(s: string): External<SS> { let t: string = s; let d: SS = SS(t, t); return d; }
  // string LITERAL fields (short and >32 bytes):
  get litShort(a: u256): External<VS> { let d: VS = VS(a, "short"); return d; }
  get litLong(a: u256): External<VS> { let d: VS = VS(a, "this string literal is definitely longer than thirty-two bytes!!"); return d; }
  get litTwo(): External<SS> { let d: SS = SS("first literal piece", "second literal piece is long enough to cross thirty-two bytes!"); return d; }

  // many distinct fields of differing widths interspersed with two dyn fields:
  get mkMIX(a: u8, s: string, b: i16, t: bytes, c: address, n: bool): External<MIX> { let d: MIX = MIX(a, s, b, t, c, n); return d; }
  get mk3(a: u8, s: string, b: bytes, n: u64): External<D3> { let d: D3 = D3(a, s, b, n); return d; }
  // one struct used in TWO functions:
  get mkVSagain(a: u256, s: string): External<VS> { let d: VS = VS(a, s); return d; }
  // other bytesN widths interspersed:
  get mkB1(a: bytes1, s: string): External<B1S> { let d: B1S = B1S(a, s); return d; }
  get mkB16(a: bytes16, s: string): External<B16S> { let d: B16S = B16S(a, s); return d; }
  get mkB32(a: bytes32, s: string): External<B32S> { let d: B32S = B32S(a, s); return d; }
  // HARD aliasing: a long string LITERAL field next to a long calldata string field:
  get litPlusArg(arg: string): External<SS> { let d: SS = SS("a long string literal that exceeds thirty-two bytes for aliasing!", arg); return d; }
  get argPlusLit(arg: string): External<SS> { let d: SS = SS(arg, "a long string literal that exceeds thirty-two bytes for aliasing!"); return d; }
  // .length / byte index on a LITERAL-constructed dyn field (not calldata):
  get litLen(): External<u256> { let d: LB = LB("", "literal bytes payload exceeding thirty-two bytes for length test!"); return d.b.length; }
  get litAt(i: u256): External<u8> { let d: LB = LB("", "literal bytes payload exceeding thirty-two bytes for length test!"); return u8(d.b[i]); }
  // cross-field: read a bytes local's .length, store it into a value field of a struct
  // whose dyn field IS that same bytes payload:
  get lenIntoVal(x: bytes): External<VB> { let b: bytes = x; let k: u256 = b.length; let d: VB = VB(k, b); return d; }
  // ALIASING STRESS: construct the struct, then allocate MORE memory (another string
  // local + a literal), then return the original struct. The struct's dyn pointers must
  // still be intact (the later allocs must not clobber them).
  get allocAfter(a: u256, s: string): External<VS> { let d: VS = VS(a, s); let junk: string = "padding allocation that grows the free pointer well past the head"; let more: string = s; return d; }
  // construct TWO dyn-struct locals, return the FIRST (its blob must survive the second's allocs):
  get twoStructs(a: u256, s: string, t: string): External<VS> { let d1: VS = VS(a, s); let d2: SS = SS(t, t); return d1; }
  // write a value field AFTER reading a byte of the dyn field, then return:
  get byteThenWrite(s: string, a: u256): External<SV> { let d: SV = SV(s, a); let k: u256 = d.a + a; d.a = k; return d; }
  // construct, read a value field, write another, return - all in one body:
  get combo(a: u256, s: string, b: u256): External<VSV> { let d: VSV = VSV(a, s, b); let k: u256 = d.a; d.b = d.b + k; return d; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct VS  { uint256 a; string s; }
  struct SV  { string s; uint256 a; }
  struct VSV { uint256 a; string s; uint256 b; }
  struct SVS { string s; uint256 a; string t; }
  struct SS  { string s; string t; }
  struct DVD { string s; uint256 a; string t; }
  struct NU8  { uint8 a;  string s; }
  struct NU16 { uint16 a; string s; }
  struct NI8  { int8 a;  string s; }
  struct NI16 { int16 a; string s; }
  struct NI64 { int64 a; string s; }
  struct NI128{ int128 a; string s; }
  struct NADDR{ address a; string s; }
  struct NBOOL{ bool a; string s; }
  struct NB4  { bytes4 a; string s; }
  struct POST { string s; uint8 a; }
  struct MIX  { uint8 a; string s; int16 b; bytes t; address c; bool n; }
  struct D3   { uint8 a; string s; bytes b; uint64 n; }
  struct B1S  { bytes1 a; string s; }
  struct B16S { bytes16 a; string s; }
  struct B32S { bytes32 a; string s; }
  struct LB   { string s; bytes b; }
  struct VB   { uint256 a; bytes b; }

  function mkVS(uint256 a, string calldata s) external pure returns (VS memory){ VS memory d = VS(a, s); return d; }
  function mkSV(string calldata s, uint256 a) external pure returns (SV memory){ SV memory d = SV(s, a); return d; }
  function mkVSV(uint256 a, string calldata s, uint256 b) external pure returns (VSV memory){ VSV memory d = VSV(a, s, b); return d; }
  function mkSVS(string calldata s, uint256 a, string calldata t) external pure returns (SVS memory){ SVS memory d = SVS(s, a, t); return d; }
  function mkSS(string calldata s, string calldata t) external pure returns (SS memory){ SS memory d = SS(s, t); return d; }
  function mkDVD(string calldata s, uint256 a, string calldata t) external pure returns (DVD memory){ DVD memory d = DVD(s, a, t); return d; }

  function mkU8(uint8 a, string calldata s) external pure returns (NU8 memory){ NU8 memory d = NU8(a, s); return d; }
  function mkU16(uint16 a, string calldata s) external pure returns (NU16 memory){ NU16 memory d = NU16(a, s); return d; }
  function mkI8(int8 a, string calldata s) external pure returns (NI8 memory){ NI8 memory d = NI8(a, s); return d; }
  function mkI16(int16 a, string calldata s) external pure returns (NI16 memory){ NI16 memory d = NI16(a, s); return d; }
  function mkI64(int64 a, string calldata s) external pure returns (NI64 memory){ NI64 memory d = NI64(a, s); return d; }
  function mkI128(int128 a, string calldata s) external pure returns (NI128 memory){ NI128 memory d = NI128(a, s); return d; }
  function mkADDR(address a, string calldata s) external pure returns (NADDR memory){ NADDR memory d = NADDR(a, s); return d; }
  function mkBOOL(bool a, string calldata s) external pure returns (NBOOL memory){ NBOOL memory d = NBOOL(a, s); return d; }
  function mkB4(bytes4 a, string calldata s) external pure returns (NB4 memory){ NB4 memory d = NB4(a, s); return d; }

  function getVSa(uint256 a, string calldata s) external pure returns (uint256){ VS memory d = VS(a, s); return d.a; }
  function getVSs(uint256 a, string calldata s) external pure returns (string memory){ VS memory d = VS(a, s); return d.s; }
  function getSVa(string calldata s, uint256 a) external pure returns (uint256){ SV memory d = SV(s, a); return d.a; }
  function getSVs(string calldata s, uint256 a) external pure returns (string memory){ SV memory d = SV(s, a); return d.s; }
  function getVSVb(uint256 a, string calldata s, uint256 b) external pure returns (uint256){ VSV memory d = VSV(a, s, b); return d.b; }
  function getSVSt(string calldata s, uint256 a, string calldata t) external pure returns (string memory){ SVS memory d = SVS(s, a, t); return d.t; }
  function getU8a(uint8 a, string calldata s) external pure returns (uint8){ NU8 memory d = NU8(a, s); return d.a; }
  function getI16a(int16 a, string calldata s) external pure returns (int16){ NI16 memory d = NI16(a, s); return d.a; }

  function writeVSa(uint256 a, string calldata s, uint256 na) external pure returns (VS memory){ VS memory d = VS(a, s); d.a = na; return d; }
  function rwVSa(uint256 a, string calldata s, uint256 na) external pure returns (VS memory){ VS memory d = VS(a, s); d.a = d.a + na; return d; }
  function writeSVa(string calldata s, uint256 a, uint256 na) external pure returns (SV memory){ SV memory d = SV(s, a); d.a = na; return d; }
  function rwSVa(string calldata s, uint256 a, uint256 na) external pure returns (SV memory){ SV memory d = SV(s, a); d.a = d.a + na; return d; }
  function writePOSTa(string calldata s, uint8 a, uint8 na) external pure returns (POST memory){ POST memory d = POST(s, a); d.a = na; return d; }
  function writeVSVa(uint256 a, string calldata s, uint256 b, uint256 na) external pure returns (VSV memory){ VSV memory d = VSV(a, s, b); d.a = na; return d; }
  function writeVSVb(uint256 a, string calldata s, uint256 b, uint256 nb) external pure returns (VSV memory){ VSV memory d = VSV(a, s, b); d.b = nb; return d; }

  function bLen(bytes calldata b, uint64 n) external pure returns (uint256){ D3 memory d = D3(0, "", b, n); return d.b.length; }
  function bAt(bytes calldata b, uint256 i) external pure returns (uint8){ D3 memory d = D3(0, "", b, 0); return uint8(d.b[i]); }

  function fromLocal(uint256 a, string calldata s) external pure returns (VS memory){ string memory t = s; VS memory d = VS(a, t); return d; }
  function twoFromLocal(string calldata s) external pure returns (SS memory){ string memory t = s; SS memory d = SS(t, t); return d; }
  function litShort(uint256 a) external pure returns (VS memory){ VS memory d = VS(a, "short"); return d; }
  function litLong(uint256 a) external pure returns (VS memory){ VS memory d = VS(a, "this string literal is definitely longer than thirty-two bytes!!"); return d; }
  function litTwo() external pure returns (SS memory){ SS memory d = SS("first literal piece", "second literal piece is long enough to cross thirty-two bytes!"); return d; }

  function mkMIX(uint8 a, string calldata s, int16 b, bytes calldata t, address c, bool n) external pure returns (MIX memory){ MIX memory d = MIX(a, s, b, t, c, n); return d; }
  function mk3(uint8 a, string calldata s, bytes calldata b, uint64 n) external pure returns (D3 memory){ D3 memory d = D3(a, s, b, n); return d; }
  function mkVSagain(uint256 a, string calldata s) external pure returns (VS memory){ VS memory d = VS(a, s); return d; }
  function mkB1(bytes1 a, string calldata s) external pure returns (B1S memory){ B1S memory d = B1S(a, s); return d; }
  function mkB16(bytes16 a, string calldata s) external pure returns (B16S memory){ B16S memory d = B16S(a, s); return d; }
  function mkB32(bytes32 a, string calldata s) external pure returns (B32S memory){ B32S memory d = B32S(a, s); return d; }
  function litPlusArg(string calldata arg) external pure returns (SS memory){ SS memory d = SS("a long string literal that exceeds thirty-two bytes for aliasing!", arg); return d; }
  function argPlusLit(string calldata arg) external pure returns (SS memory){ SS memory d = SS(arg, "a long string literal that exceeds thirty-two bytes for aliasing!"); return d; }
  function litLen() external pure returns (uint256){ LB memory d = LB("", "literal bytes payload exceeding thirty-two bytes for length test!"); return d.b.length; }
  function litAt(uint256 i) external pure returns (uint8){ LB memory d = LB("", "literal bytes payload exceeding thirty-two bytes for length test!"); return uint8(d.b[i]); }
  function lenIntoVal(bytes calldata x) external pure returns (VB memory){ bytes memory b = x; uint256 k = b.length; VB memory d = VB(k, b); return d; }
  function allocAfter(uint256 a, string calldata s) external pure returns (VS memory){ VS memory d = VS(a, s); string memory junk = "padding allocation that grows the free pointer well past the head"; string memory more = s; junk; more; return d; }
  function twoStructs(uint256 a, string calldata s, string calldata t) external pure returns (VS memory){ VS memory d1 = VS(a, s); SS memory d2 = SS(t, t); d2; return d1; }
  function byteThenWrite(string calldata s, uint256 a) external pure returns (SV memory){ SV memory d = SV(s, a); uint256 k = d.a + a; d.a = k; return d; }
  function combo(uint256 a, string calldata s, uint256 b) external pure returns (VSV memory){ VSV memory d = VSV(a, s, b); uint256 k = d.a; d.b = d.b + k; return d; }
}`;

// ----------------------- payload-length corpus -------------------------------
// empty, 1, 31, 32, 33 (word-boundary padding), 63, 64, 65, multi-word.
const LENS = [0, 1, 31, 32, 33, 63, 64, 65, 96, 100];
const strOf = (n: number) => Array.from({ length: n }, (_, i) => String.fromCharCode(97 + (i % 26))).join('');
const bufOf = (n: number) => Buffer.from(Array.from({ length: n }, (_, i) => (i * 37 + 11) & 0xff));
const STRS = LENS.map(strOf);
const BUFS = LENS.map(bufOf);

describe('ADV dynamic-field struct memory locals vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  let divergence = 0;
  let nOk = 0,
    nRevert = 0;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (s.success) nOk++;
    else nRevert++;
    if (j.success !== s.success || j.returnHex !== s.returnHex) {
      divergence++;
      console.error(
        `DIVERGENCE @ ${label}\n  data=${data}\n  jeth success=${j.success} err=${j.exceptionError} ret=${j.returnHex}\n  sol  success=${s.success} ret=${s.returnHex}`,
      );
    }
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('1+2: field-order permutations, whole-struct return, all dyn lengths', async () => {
    for (const s of STRS) {
      for (const a of [0n, 1n, M - 1n, 1n << 200n]) {
        await eq(`mkVS len=${s.length}`, cd_v_s('mkVS(uint256,string)', a, s));
        await eq(`mkSV len=${s.length}`, cd_s_v('mkSV(string,uint256)', s, a));
      }
      for (const a of [0n, 42n])
        for (const b of [0n, M - 1n]) {
          await eq(`mkVSV len=${s.length}`, cd_v_s_v('mkVSV(uint256,string,uint256)', a, s, b));
        }
    }
  });

  it('1: two-dynamic and dyn-value-dyn permutations, every length in each position', async () => {
    for (const s1 of STRS)
      for (const s2 of [STRS[0], STRS[3], STRS[4], STRS[8]] as string[]) {
        await eq(`mkSS ${s1.length}/${s2.length}`, cd_s_s('mkSS(string,string)', s1, s2));
        for (const a of [0n, M - 1n]) {
          await eq(`mkSVS ${s1.length}/${s2.length}`, cd_s_v_s('mkSVS(string,uint256,string)', s1, a, s2));
          await eq(`mkDVD ${s1.length}/${s2.length}`, cd_s_v_s('mkDVD(string,uint256,string)', s1, a, s2));
        }
      }
  });

  it('2+3: narrow/signed/address/bool/bytesN value fields, boundary values', async () => {
    const s = 'differential narrow field test string over thirty-two bytes ok';
    const sShort = 'hi';
    for (const s2 of [sShort, s, '']) {
      for (const v of [0n, 1n, 127n, 128n, 200n, 255n]) await eq(`mkU8 ${v}`, cd_v_s('mkU8(uint8,string)', v, s2));
      for (const v of [0n, 1n, 255n, 256n, 32767n, 32768n, 65535n])
        await eq(`mkU16 ${v}`, cd_v_s('mkU16(uint16,string)', v, s2));
      // signed i8: min=-128, -1, 0, 1, max=127. encode as two's complement word.
      for (const v of [-128n, -1n, 0n, 1n, 127n]) await eq(`mkI8 ${v}`, cd_v_s('mkI8(int8,string)', v, s2));
      for (const v of [-32768n, -1n, 0n, 1n, 32767n]) await eq(`mkI16 ${v}`, cd_v_s('mkI16(int16,string)', v, s2));
      for (const v of [-(1n << 63n), -1n, 0n, 1n, (1n << 63n) - 1n])
        await eq(`mkI64 ${v}`, cd_v_s('mkI64(int64,string)', v, s2));
      for (const v of [-(1n << 127n), -1n, 0n, 1n, (1n << 127n) - 1n])
        await eq(`mkI128 ${v}`, cd_v_s('mkI128(int128,string)', v, s2));
      for (const v of [0n, 1n, (1n << 160n) - 1n, 0xdeadbeefn])
        await eq(`mkADDR ${v}`, cd_v_s('mkADDR(address,string)', v, s2));
      for (const v of [0n, 1n]) await eq(`mkBOOL ${v}`, cd_v_s('mkBOOL(bool,string)', v, s2));
      // bytes4 is left-aligned: low 28 bytes must be zero. test a few clean values.
      for (const v of [0n, 0xaabbccddn << 224n, 0xffffffffn << 224n, 0x01000000n << 224n]) {
        await eq(`mkB4 ${v.toString(16)}`, cd_v_s('mkB4(bytes4,string)', v, s2));
      }
    }
  });

  it('3b: DIRTY narrow/bool/address/bytesN inputs must revert identically', async () => {
    const s = 'x';
    // uint8 with high bit set above 255 -> solc reverts; JETH should too.
    await eq('mkU8 dirty 256', cd_v_s('mkU8(uint8,string)', 256n, s));
    await eq('mkU8 dirty max', cd_v_s('mkU8(uint8,string)', M - 1n, s));
    await eq('mkU16 dirty', cd_v_s('mkU16(uint16,string)', 65536n, s));
    // int8 not a valid sign-extension (e.g. 128 = 0x80 unextended) -> revert.
    await eq('mkI8 dirty 128', cd_v_s('mkI8(int8,string)', 128n, s));
    await eq('mkI8 dirty 255', cd_v_s('mkI8(int8,string)', 255n, s));
    await eq('mkI16 dirty', cd_v_s('mkI16(int16,string)', 32768n, s));
    // bool > 1 -> revert.
    await eq('mkBOOL dirty', cd_v_s('mkBOOL(bool,string)', 2n, s));
    await eq('mkBOOL dirty big', cd_v_s('mkBOOL(bool,string)', M - 1n, s));
    // address high bits set -> revert.
    await eq('mkADDR dirty', cd_v_s('mkADDR(address,string)', 1n << 160n, s));
    await eq('mkADDR dirty full', cd_v_s('mkADDR(address,string)', M - 1n, s));
    // bytes4 with low bytes nonzero -> revert.
    await eq('mkB4 dirty', cd_v_s('mkB4(bytes4,string)', 0xffn, s));
    await eq('mkB4 dirty2', cd_v_s('mkB4(bytes4,string)', 1n, s));
  });

  it('4: value+string reads (value before/after dyn), .length, whole dyn field', async () => {
    for (const s of STRS)
      for (const a of [0n, 42n, M - 1n]) {
        await eq('getVSa', cd_v_s('getVSa(uint256,string)', a, s));
        await eq('getVSs', cd_v_s('getVSs(uint256,string)', a, s));
        await eq('getSVa', cd_s_v('getSVa(string,uint256)', s, a));
        await eq('getSVs', cd_s_v('getSVs(string,uint256)', s, a));
        await eq('getVSVb', cd_v_s_v('getVSVb(uint256,string,uint256)', a, s, a ^ 0x1234n));
        await eq('getU8a', cd_v_s('getU8a(uint8,string)', a & 0xffn, s));
        await eq('getI16a', cd_v_s('getI16a(int16,string)', (a & 0x7fffn) - (a & 0x8000n), s));
      }
    for (const s1 of [STRS[1], STRS[4]] as string[])
      for (const s2 of [STRS[0], STRS[5]] as string[]) {
        await eq('getSVSt', cd_s_v_s('getSVSt(string,uint256,string)', s1, 9n, s2));
      }
    for (const b of BUFS)
      for (const n of [0n, 1n, M - 1n]) {
        await eq(`bLen ${b.length}`, cd_b_u('bLen(bytes,uint64)', b, n & 0xffffffffffffffffn));
      }
  });

  it('5: value field write / read-modify-write, value field BEFORE and AFTER dyn', async () => {
    for (const s of STRS) {
      await eq('writeVSa', cd_v_s_v('writeVSa(uint256,string,uint256)', 7n, s, 123456789n));
      await eq('rwVSa', cd_v_s_v('rwVSa(uint256,string,uint256)', 1000n, s, 1n));
      await eq('writeSVa', cd_s_v_s_helper('writeSVa(string,uint256,uint256)', s, 7n, 999n));
      await eq('rwSVa', cd_s_v_s_helper('rwSVa(string,uint256,uint256)', s, 1000n, 1n));
      await eq('writeVSVa', cd_v_s_v_v('writeVSVa(uint256,string,uint256,uint256)', 1n, s, 2n, 3n));
      await eq('writeVSVb', cd_v_s_v_v('writeVSVb(uint256,string,uint256,uint256)', 1n, s, 2n, 3n));
    }
    // narrow field write after dyn field (POST.a is u8 at the SECOND head word):
    for (const s of [STRS[0], STRS[1], STRS[4]] as string[])
      for (const a of [0n, 200n])
        for (const na of [0n, 1n, 255n]) {
          await eq('writePOSTa', cd_s_v_v_narrow('writePOSTa(string,uint8,uint8)', s, a, na));
        }
  });

  it('6: byte indexing in-bounds across length, and OOB reverts identically', async () => {
    for (const b of [bufOf(5), bufOf(32), bufOf(33), bufOf(64)]) {
      for (let i = 0n; i < BigInt(b.length); i++) await eq(`bAt ${b.length}@${i}`, cd_b_u('bAt(bytes,uint256)', b, i));
      await eq(`bAt OOB ${b.length}`, cd_b_u('bAt(bytes,uint256)', b, BigInt(b.length)));
      await eq(`bAt OOB+ ${b.length}`, cd_b_u('bAt(bytes,uint256)', b, BigInt(b.length) + 5n));
      await eq(`bAt OOB huge ${b.length}`, cd_b_u('bAt(bytes,uint256)', b, M - 1n));
    }
    await eq('bAt empty@0', cd_b_u('bAt(bytes,uint256)', Buffer.alloc(0), 0n));
  });

  it('8: construct from memory-string local, same local twice, string literals', async () => {
    for (const s of STRS) {
      await eq('fromLocal', cd_v_s('fromLocal(uint256,string)', 88n, s));
      await eq('twoFromLocal', cd_s1('twoFromLocal(string)', s));
    }
    for (const a of [0n, 1n, M - 1n]) {
      await eq('litShort', encodeCall(sel('litShort(uint256)'), [a]));
      await eq('litLong', encodeCall(sel('litLong(uint256)'), [a]));
    }
    await eq('litTwo', encodeCall(sel('litTwo()'), []));
  });

  it('9+10: multiple distinct structs, same struct two functions, combo body, MIX/D3', async () => {
    for (const s of [STRS[0], STRS[2], STRS[4], STRS[7]] as string[])
      for (const a of [0n, 7n, M - 1n]) {
        await eq('mkVSagain', cd_v_s('mkVSagain(uint256,string)', a, s));
      }
    for (const s of STRS)
      for (const a of [0n, 42n])
        for (const b of [0n, M - 1n]) {
          await eq('combo', cd_v_s_v('combo(uint256,string,uint256)', a, s, b));
        }
    // MIX: u8, string, i16, bytes, address, bool. head=[a][off_s][b][off_t][c][n].
    for (const s of [STRS[0], STRS[3], STRS[5]] as string[])
      for (const t of [BUFS[0], BUFS[4], BUFS[6]] as Buffer[]) {
        const data = mkMIXcalldata(s, t, 200n, -5n, 0xcafen, 1n);
        await eq(`mkMIX ${s.length}/${t.length}`, data);
      }
    // mk3: u8, string, bytes, u64.
    for (const s of [STRS[0], STRS[2], STRS[6]] as string[])
      for (const b of [BUFS[0], BUFS[3], BUFS[7]] as Buffer[]) {
        await eq(`mk3 ${s.length}/${b.length}`, cd_v_s_b_v('mk3(uint8,string,bytes,uint64)', 9n, s, b, 0x1234n));
      }
  });

  it('EXTRA: other bytesN widths interspersed with a dyn field', async () => {
    const ss = [STRS[0], STRS[1], STRS[3], STRS[4]] as string[];
    for (const s of ss) {
      // bytes1: top byte significant, low 31 must be zero.
      for (const v of [0n, 0xffn << 248n, 0x01n << 248n]) await eq('mkB1', cd_v_s('mkB1(bytes1,string)', v, s));
      // bytes16: top 16 bytes significant.
      for (const v of [0n, ((1n << 128n) - 1n) << 128n, 0xabcdef0123456789n << 192n])
        await eq('mkB16', cd_v_s('mkB16(bytes16,string)', v, s));
      // bytes32: full word, no masking.
      for (const v of [0n, M - 1n, 1n, 1n << 200n]) await eq('mkB32', cd_v_s('mkB32(bytes32,string)', v, s));
    }
    // dirty bytes1/bytes16 (low bytes nonzero) -> revert on both.
    await eq('mkB1 dirty', cd_v_s('mkB1(bytes1,string)', 1n, 'x'));
    await eq('mkB16 dirty', cd_v_s('mkB16(bytes16,string)', 1n, 'x'));
  });

  it('EXTRA: hard aliasing - long literal next to long calldata string (both orders)', async () => {
    for (const s of STRS) {
      await eq('litPlusArg', cd_s1('litPlusArg(string)', s));
      await eq('argPlusLit', cd_s1('argPlusLit(string)', s));
    }
  });

  it('EXTRA: .length / byte index on a LITERAL-constructed dyn field', async () => {
    await eq('litLen', encodeCall(sel('litLen()'), []));
    const litLen = Buffer.byteLength('literal bytes payload exceeding thirty-two bytes for length test!', 'utf8');
    for (let i = 0n; i < BigInt(litLen); i++) await eq(`litAt@${i}`, encodeCall(sel('litAt(uint256)'), [i]));
    await eq('litAt OOB', encodeCall(sel('litAt(uint256)'), [BigInt(litLen)]));
    await eq('litAt OOB huge', encodeCall(sel('litAt(uint256)'), [M - 1n]));
  });

  it('EXTRA: cross-field - bytes .length into a value field of the same struct', async () => {
    for (const b of BUFS) await eq(`lenIntoVal ${b.length}`, cd_b1('lenIntoVal(bytes)', b));
  });

  it('EXTRA: aliasing stress - allocate after construct, two structs, byte-then-write', async () => {
    for (const s of STRS)
      for (const a of [0n, 7n, M - 1n]) {
        await eq('allocAfter', cd_v_s('allocAfter(uint256,string)', a, s));
        await eq('byteThenWrite', cd_s_v('byteThenWrite(string,uint256)', s, a));
      }
    for (const s of [STRS[0], STRS[3], STRS[4]] as string[])
      for (const t of [STRS[0], STRS[4], STRS[7]] as string[]) {
        await eq('twoStructs', mkTwoStructs(5n, s, t));
      }
  });

  it('summary: zero divergence', () => {
    console.log(
      `[adv-dynstruct] cases: ${nOk + nRevert} total, ${nOk} succeeded, ${nRevert} reverted (both sides), ${divergence} divergences`,
    );
    expect(divergence, 'total divergences').toBe(0);
  });
});

// ---- a couple of extra calldata builders defined after use (hoisted) --------
// (string, uint256, uint256): head=[off=0x60][a][na], tail=[len][data].
function cd_s_v_s_helper(sig: string, s: string, a: bigint, na: bigint) {
  return '0x' + sel(sig) + pad(0x60n) + pad(a) + pad(na) + encStr(s);
}
// (uint256, string, uint256, uint256): head=[a][off=0x80][b][na], tail=[len][data].
function cd_v_s_v_v(sig: string, a: bigint, s: string, b: bigint, na: bigint) {
  return '0x' + sel(sig) + pad(a) + pad(0x80n) + pad(b) + pad(na) + encStr(s);
}
// (string, uint8, uint8): head=[off=0x60][a][na], tail=[len][data].
function cd_s_v_v_narrow(sig: string, s: string, a: bigint, na: bigint) {
  return '0x' + sel(sig) + pad(0x60n) + pad(a) + pad(na) + encStr(s);
}
// twoStructs(uint256 a, string s, string t): head=[a][off_s][off_t], two tail blocks.
function mkTwoStructs(a: bigint, s: string, t: string) {
  const off1 = 0x60;
  const off2 = off1 + 32 + Math.ceil(Buffer.byteLength(s, 'utf8') / 32) * 32;
  return (
    '0x' +
    functionSelector('twoStructs(uint256,string,string)') +
    pad(a) +
    pad(BigInt(off1)) +
    pad(BigInt(off2)) +
    encStr(s) +
    encStr(t)
  );
}
// MIX(uint8 a, string s, int16 b, bytes t, address c, bool n):
// head=[a][off_s][b][off_t][c][n] (6 words), tail two blocks.
function mkMIXcalldata(s: string, t: Buffer, a: bigint, b: bigint, c: bigint, n: bigint) {
  const head = 6 * 32; // 0xc0
  const offS = head;
  const offT = offS + wordsFor(Buffer.byteLength(s, 'utf8'));
  return (
    '0x' +
    sel('mkMIX(uint8,string,int16,bytes,address,bool)') +
    pad(a) +
    pad(BigInt(offS)) +
    pad(b) +
    pad(BigInt(offT)) +
    pad(c) +
    pad(n) +
    encStr(s) +
    encBytes(t)
  );
}
