// Dynamic-field struct MEMORY locals: `let d: D = D(x, str)` where D has bytes/string fields.
// The image is a pointer-headed tuple (value fields inline, bytes/string fields a [len][data]
// pointer). Covers whole return, value-field read/write, dynamic-field read (.length / [i] /
// whole), value field before AND after the dynamic field (head offsets), construction from a
// memory-string local (alias), and multi-dynamic structs. Byte-identical to solc; short / long
// / empty payloads and boundary value fields.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const encStr = (s: string) => { const h = Buffer.from(s, 'utf8').toString('hex'); return pad(BigInt(h.length / 2)) + h.padEnd(Math.ceil(h.length / 64) * 64, '0'); };
// (uint256 a, string s): head [a][offset=0x40], then [len][data]
const cdUS = (sig: string, a: bigint, s: string) => '0x' + sel(sig) + pad(a) + pad(0x40n) + encStr(s);
// (string s, uint256 a): head [offset=0x40][a], then [len][data]
const cdSU = (sig: string, s: string, a: bigint) => '0x' + sel(sig) + pad(0x40n) + pad(a) + encStr(s);
// (bytes b, uint256 i): head [offset=0x40][i], then [len][data]
const cdBU = (sig: string, b: string, i: bigint) => '0x' + sel(sig) + pad(0x40n) + pad(i) + encStr(b);
// (uint256 a, string s, uint256 na): head [a][offset=0x60][na], then [len][data]
const cdUSU = (sig: string, a: bigint, s: string, na: bigint) => '0x' + sel(sig) + pad(a) + pad(0x60n) + pad(na) + encStr(s);

const JETH = `@struct class D1 { a: u256; s: string; }
@struct class D2 { s: string; a: u256; }
@struct class D3 { a: u8; s: string; b: bytes; n: u64; }
@contract class C {
  @external @pure mk(a: u256, s: string): D1 { let d: D1 = D1(a, s); return d; }
  @external @pure getA(a: u256, s: string): u256 { let d: D1 = D1(a, s); return d.a; }
  @external @pure getS(a: u256, s: string): string { let d: D1 = D1(a, s); return d.s; }
  @external @pure bLen(b: bytes, n: u64): u256 { let d: D3 = D3(0n, "", b, n); return d.b.length; }
  @external @pure writeA(a: u256, s: string, na: u256): D1 { let d: D1 = D1(a, s); d.a = na; return d; }
  @external @pure rwBoth(a: u256, s: string, na: u256): u256 { let d: D1 = D1(a, s); d.a = d.a + na; return d.a; }
  @external @pure mk2(s: string, a: u256): D2 { let d: D2 = D2(s, a); return d; }
  @external @pure get2A(s: string, a: u256): u256 { let d: D2 = D2(s, a); return d.a; }
  @external @pure get2S(s: string, a: u256): string { let d: D2 = D2(s, a); return d.s; }
  @external @pure mk3(a: u8, s: string, b: bytes, n: u64): D3 { let d: D3 = D3(a, s, b, n); return d; }
  @external @pure bAt(b: bytes, i: u256): u8 { let d: D3 = D3(0n, "", b, 0n); return u8(d.b[i]); }
  @external @pure fromLocal(a: u256, s: string): D1 { let t: string = s; let d: D1 = D1(a, t); return d; }
  @external @pure litField(a: u256): D1 { let d: D1 = D1(a, "a string literal that is over thirty-two bytes long!!"); return d; }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct D1 { uint256 a; string s; }
  struct D2 { string s; uint256 a; }
  struct D3 { uint8 a; string s; bytes b; uint64 n; }
  function mk(uint256 a, string calldata s) external pure returns (D1 memory){ D1 memory d = D1(a, s); return d; }
  function getA(uint256 a, string calldata s) external pure returns (uint256){ D1 memory d = D1(a, s); return d.a; }
  function getS(uint256 a, string calldata s) external pure returns (string memory){ D1 memory d = D1(a, s); return d.s; }
  function bLen(bytes calldata b, uint64 n) external pure returns (uint256){ D3 memory d = D3(0, "", b, n); return d.b.length; }
  function writeA(uint256 a, string calldata s, uint256 na) external pure returns (D1 memory){ D1 memory d = D1(a, s); d.a = na; return d; }
  function rwBoth(uint256 a, string calldata s, uint256 na) external pure returns (uint256){ D1 memory d = D1(a, s); d.a = d.a + na; return d.a; }
  function mk2(string calldata s, uint256 a) external pure returns (D2 memory){ D2 memory d = D2(s, a); return d; }
  function get2A(string calldata s, uint256 a) external pure returns (uint256){ D2 memory d = D2(s, a); return d.a; }
  function get2S(string calldata s, uint256 a) external pure returns (string memory){ D2 memory d = D2(s, a); return d.s; }
  function mk3(uint8 a, string calldata s, bytes calldata b, uint64 n) external pure returns (D3 memory){ D3 memory d = D3(a, s, b, n); return d; }
  function bAt(bytes calldata b, uint256 i) external pure returns (uint8){ D3 memory d = D3(0, "", b, 0); return uint8(d.b[i]); }
  function fromLocal(uint256 a, string calldata s) external pure returns (D1 memory){ string memory t = s; D1 memory d = D1(a, t); return d; }
  function litField(uint256 a) external pure returns (D1 memory){ D1 memory d = D1(a, "a string literal that is over thirty-two bytes long!!"); return d; }
}`;

describe('dynamic-field struct memory locals vs Solidity', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  async function eq(label: string, data: string) {
    const j = await jeth.call(aj, data); const s = await sol.call(as, data);
    expect(j.success, `${label} success (jeth err=${j.exceptionError})`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create(); sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode); as = await sol.deploy(sb.creation);
  });

  const STRS = ['', 'a', 'abcdefghijklmnopqrstuvwxyz012345', 'this string is definitely longer than thirty-two bytes for differential testing'];
  const VALS = [0n, 1n, 255n, (1n << 255n), M - 1n];
  it('whole return: value+string (D1), string+value (D2)', async () => {
    for (const s of STRS) for (const a of VALS) {
      await eq(`mk(${a},"${s.slice(0, 4)}")`, cdUS('mk(uint256,string)', a, s));
      await eq(`mk2("${s.slice(0, 4)}",${a})`, cdSU('mk2(string,uint256)', s, a));
    }
  });
  it('field reads: value before/after dynamic, .length, whole dynamic field', async () => {
    for (const s of STRS) for (const a of [0n, 42n, M - 1n]) {
      await eq(`getA`, cdUS('getA(uint256,string)', a, s));
      await eq(`getS`, cdUS('getS(uint256,string)', a, s));
      await eq(`bLen`, cdBU('bLen(bytes,uint64)', s, a & 0xffffffffffffffffn));
      await eq(`get2A`, cdSU('get2A(string,uint256)', s, a));
      await eq(`get2S`, cdSU('get2S(string,uint256)', s, a));
    }
  });
  it('value field write then return / read-modify-write', async () => {
    for (const s of STRS) {
      await eq(`writeA`, cdUSU('writeA(uint256,string,uint256)', 7n, s, 123456789n));
      await eq(`rwBoth`, cdUSU('rwBoth(uint256,string,uint256)', 1000n, s, 1n));
    }
  });
  it('multi-dynamic D3 (uint8, string, bytes, uint64) + byte index', async () => {
    // mk3: head [a][off_s][off_b][n]; off_s=0x80, then s, then b.
    for (const s of ['', 'xy', 'a longer string spanning more than thirty-two bytes here ok']) {
      for (const b of ['', 'Q', 'bytes payload longer than thirty-two bytes for the second dynamic field']) {
        const sLenPadded = Math.ceil((s.length) / 32) * 64;
        const offB = 0x80 + 32 + sLenPadded / 2; // off_b = head(0x80) + s.len-word + s.data
        const data = '0x' + sel('mk3(uint8,string,bytes,uint64)')
          + pad(9n) + pad(0x80n) + pad(BigInt(offB)) + pad(0x1234n)
          + encStr(s) + encStr(b);
        await eq(`mk3("${s.slice(0, 3)}","${b.slice(0, 3)}")`, data);
      }
    }
    for (let i = 0n; i < 5n; i++) await eq(`bAt(${i})`, cdBU('bAt(bytes,uint256)', 'abcde', i));
    await eq('bAt OOB', cdBU('bAt(bytes,uint256)', 'abcde', 9n));
  });
  it('construct from a memory-string local (alias) / from a string literal field', async () => {
    for (const s of STRS) {
      await eq(`fromLocal`, cdUS('fromLocal(uint256,string)', 88n, s));
      await eq(`litField`, encodeCall(sel('litField(uint256)'), [99n]));
    }
  });
});
