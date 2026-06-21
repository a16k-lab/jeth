// _vf_mappings: adversarial differential test of mapping codegen vs solc 0.8.x
// (cancun, optimizer on). Covers: nested mapping<K1,mapping<K2,V>>, mapping to
// struct (whole + per-field), mapping to dynamic array (push/pop/index), mapping
// to bytes/string (short + long, shrink), keys of address/bytesN/bool/uintN/intN
// (incl. dirty high bits in calldata), default reads of never-written keys, and
// per-key isolation / adjacency. Solidity is the oracle; every probe must be
// byte-identical in (success, returndata).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const U = (n: number) => (1n << BigInt(n)) - 1n; // max unsigned for n bits
const IMIN = (n: number) => -(1n << BigInt(n - 1)); // min signed for n bits
const IMAX = (n: number) => (1n << BigInt(n - 1)) - 1n;

// addresses / keys
const A1 = BigInt('0x' + '11'.repeat(20));
const A2 = BigInt('0x' + '22'.repeat(20));
const A3 = BigInt('0x' + 'ff'.repeat(20));
const B32a = BigInt('0x' + 'de'.repeat(32));
const B32b = BigInt('0x' + 'ab'.repeat(16) + '00'.repeat(16));
const B4 = BigInt('0xdeadbeef' + '00'.repeat(28));

// Build raw calldata where each arg word is given EXACTLY as provided (allows
// dirty high bits beyond the declared key/value width).
function rawCall(sig: string, words: bigint[]): string {
  return '0x' + functionSelector(sig) + words.map(pad).join('');
}
// Build calldata for a function with a trailing dynamic bytes/string arg, after
// `head` static head words. Produces canonical ABI encoding.
function dynCall(sig: string, head: bigint[], s: string): string {
  const b = Buffer.from(s, 'utf8');
  const nwords = Math.ceil(b.length / 32);
  let data = '';
  for (let i = 0; i < nwords; i++)
    data += Buffer.concat([b.subarray(i * 32, i * 32 + 32), Buffer.alloc(32)]).subarray(0, 32).toString('hex');
  let h = '0x' + functionSelector(sig);
  for (const w of head) h += pad(w);
  h += pad(BigInt((head.length + 1) * 32)) + pad(BigInt(b.length)) + data;
  return h;
}

const JETH = `@struct class P { x: u128; y: u128; }
@struct class Q { a: u64; b: i64; c: bool; d: address; }
@struct class D { n: u256; s: string; }
@contract class C {
  @state allow: mapping<address, mapping<u256, u256>>;
  @state deep: mapping<u256, mapping<i256, mapping<bool, u256>>>;
  @state mp: mapping<address, P>;
  @state mq: mapping<u256, Q>;
  @state md: mapping<bytes4, D>;
  @state nums: mapping<address, u256[]>;
  @state mbytes: mapping<address, bytes>;
  @state mstr: mapping<u256, string>;
  @state ku8: mapping<u8, u256>;
  @state ki8: mapping<i8, u256>;
  @state ki32: mapping<i32, u256>;
  @state ku16: mapping<u16, u256>;
  @state kb1: mapping<bytes1, u256>;
  @state kbool: mapping<bool, u256>;
  @state vu8: mapping<u256, u8>;
  @state vi16: mapping<u256, i16>;
  @state vb4: mapping<u256, bytes4>;
  @state adj0: mapping<u256, u256>;
  @state adj1: mapping<u256, u256>;

  @external setAllow(o: address, k: u256, v: u256): void { this.allow[o][k] = v; }
  @external incAllow(o: address, k: u256, d: u256): void { this.allow[o][k] += d; }
  @external @view getAllow(o: address, k: u256): u256 { return this.allow[o][k]; }
  @external setDeep(a: u256, b: i256, c: bool, v: u256): void { this.deep[a][b][c] = v; }
  @external @view getDeep(a: u256, b: i256, c: bool): u256 { return this.deep[a][b][c]; }

  @external setP(k: address, x: u128, y: u128): void { this.mp[k] = P(x, y); }
  @external setPx(k: address, x: u128): void { this.mp[k].x = x; }
  @external @view getPx(k: address): u128 { return this.mp[k].x; }
  @external @view getPy(k: address): u128 { return this.mp[k].y; }
  @external @view getP(k: address): P { return this.mp[k]; }
  @external setQ(k: u256, a: u64, b: i64, c: bool, d: address): void { this.mq[k] = Q(a, b, c, d); }
  @external setQb(k: u256, b: i64): void { this.mq[k].b = b; }
  @external @view getQ(k: u256): Q { return this.mq[k]; }
  @external @view getQb(k: u256): i64 { return this.mq[k].b; }
  @external setD(k: bytes4, n: u256, s: string): void { this.md[k] = D(n, s); }
  @external @view getDn(k: bytes4): u256 { return this.md[k].n; }
  @external @view getDs(k: bytes4): string { return this.md[k].s; }

  @external push(k: address, v: u256): void { this.nums[k].push(v); }
  @external pop(k: address): void { this.nums[k].pop(); }
  @external setNum(k: address, i: u256, v: u256): void { this.nums[k][i] = v; }
  @external @view numLen(k: address): u256 { return this.nums[k].length; }
  @external @view numAt(k: address, i: u256): u256 { return this.nums[k][i]; }

  @external setBytes(k: address, v: bytes): void { this.mbytes[k] = v; }
  @external @view getBytes(k: address): bytes { return this.mbytes[k]; }
  @external @view lenBytes(k: address): u256 { return this.mbytes[k].length; }
  @external setStr(k: u256, v: string): void { this.mstr[k] = v; }
  @external @view getStr(k: u256): string { return this.mstr[k]; }

  @external setKu8(k: u8, v: u256): void { this.ku8[k] = v; }
  @external @view getKu8(k: u8): u256 { return this.ku8[k]; }
  @external setKi8(k: i8, v: u256): void { this.ki8[k] = v; }
  @external @view getKi8(k: i8): u256 { return this.ki8[k]; }
  @external setKi32(k: i32, v: u256): void { this.ki32[k] = v; }
  @external @view getKi32(k: i32): u256 { return this.ki32[k]; }
  @external setKu16(k: u16, v: u256): void { this.ku16[k] = v; }
  @external @view getKu16(k: u16): u256 { return this.ku16[k]; }
  @external setKb1(k: bytes1, v: u256): void { this.kb1[k] = v; }
  @external @view getKb1(k: bytes1): u256 { return this.kb1[k]; }
  @external setKbool(k: bool, v: u256): void { this.kbool[k] = v; }
  @external @view getKbool(k: bool): u256 { return this.kbool[k]; }

  @external setVu8(k: u256, v: u8): void { this.vu8[k] = v; }
  @external @view getVu8(k: u256): u8 { return this.vu8[k]; }
  @external setVi16(k: u256, v: i16): void { this.vi16[k] = v; }
  @external @view getVi16(k: u256): i16 { return this.vi16[k]; }
  @external setVb4(k: u256, v: bytes4): void { this.vb4[k] = v; }
  @external @view getVb4(k: u256): bytes4 { return this.vb4[k]; }

  @external setAdj(v0: u256, v1: u256): void { this.adj0[0n] = v0; this.adj1[0n] = v1; }
  @external @view getAdj0(): u256 { return this.adj0[0n]; }
  @external @view getAdj1(): u256 { return this.adj1[0n]; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint128 x; uint128 y; }
  struct Q { uint64 a; int64 b; bool c; address d; }
  struct D { uint256 n; string s; }
  mapping(address => mapping(uint256 => uint256)) allow;
  mapping(uint256 => mapping(int256 => mapping(bool => uint256))) deep;
  mapping(address => P) mp;
  mapping(uint256 => Q) mq;
  mapping(bytes4 => D) md;
  mapping(address => uint256[]) nums;
  mapping(address => bytes) mbytes;
  mapping(uint256 => string) mstr;
  mapping(uint8 => uint256) ku8;
  mapping(int8 => uint256) ki8;
  mapping(int32 => uint256) ki32;
  mapping(uint16 => uint256) ku16;
  mapping(bytes1 => uint256) kb1;
  mapping(bool => uint256) kbool;
  mapping(uint256 => uint8) vu8;
  mapping(uint256 => int16) vi16;
  mapping(uint256 => bytes4) vb4;
  mapping(uint256 => uint256) adj0;
  mapping(uint256 => uint256) adj1;

  function setAllow(address o, uint256 k, uint256 v) external { allow[o][k] = v; }
  function incAllow(address o, uint256 k, uint256 d) external { allow[o][k] += d; }
  function getAllow(address o, uint256 k) external view returns (uint256){ return allow[o][k]; }
  function setDeep(uint256 a, int256 b, bool c, uint256 v) external { deep[a][b][c] = v; }
  function getDeep(uint256 a, int256 b, bool c) external view returns (uint256){ return deep[a][b][c]; }

  function setP(address k, uint128 x, uint128 y) external { mp[k] = P(x, y); }
  function setPx(address k, uint128 x) external { mp[k].x = x; }
  function getPx(address k) external view returns (uint128){ return mp[k].x; }
  function getPy(address k) external view returns (uint128){ return mp[k].y; }
  function getP(address k) external view returns (P memory){ return mp[k]; }
  function setQ(uint256 k, uint64 a, int64 b, bool c, address d) external { mq[k] = Q(a, b, c, d); }
  function setQb(uint256 k, int64 b) external { mq[k].b = b; }
  function getQ(uint256 k) external view returns (Q memory){ return mq[k]; }
  function getQb(uint256 k) external view returns (int64){ return mq[k].b; }
  function setD(bytes4 k, uint256 n, string calldata s) external { md[k] = D(n, s); }
  function getDn(bytes4 k) external view returns (uint256){ return md[k].n; }
  function getDs(bytes4 k) external view returns (string memory){ return md[k].s; }

  function push(address k, uint256 v) external { nums[k].push(v); }
  function pop(address k) external { nums[k].pop(); }
  function setNum(address k, uint256 i, uint256 v) external { nums[k][i] = v; }
  function numLen(address k) external view returns (uint256){ return nums[k].length; }
  function numAt(address k, uint256 i) external view returns (uint256){ return nums[k][i]; }

  function setBytes(address k, bytes calldata v) external { mbytes[k] = v; }
  function getBytes(address k) external view returns (bytes memory){ return mbytes[k]; }
  function lenBytes(address k) external view returns (uint256){ return mbytes[k].length; }
  function setStr(uint256 k, string calldata v) external { mstr[k] = v; }
  function getStr(uint256 k) external view returns (string memory){ return mstr[k]; }

  function setKu8(uint8 k, uint256 v) external { ku8[k] = v; }
  function getKu8(uint8 k) external view returns (uint256){ return ku8[k]; }
  function setKi8(int8 k, uint256 v) external { ki8[k] = v; }
  function getKi8(int8 k) external view returns (uint256){ return ki8[k]; }
  function setKi32(int32 k, uint256 v) external { ki32[k] = v; }
  function getKi32(int32 k) external view returns (uint256){ return ki32[k]; }
  function setKu16(uint16 k, uint256 v) external { ku16[k] = v; }
  function getKu16(uint16 k) external view returns (uint256){ return ku16[k]; }
  function setKb1(bytes1 k, uint256 v) external { kb1[k] = v; }
  function getKb1(bytes1 k) external view returns (uint256){ return kb1[k]; }
  function setKbool(bool k, uint256 v) external { kbool[k] = v; }
  function getKbool(bool k) external view returns (uint256){ return kbool[k]; }

  function setVu8(uint256 k, uint8 v) external { vu8[k] = v; }
  function getVu8(uint256 k) external view returns (uint8){ return vu8[k]; }
  function setVi16(uint256 k, int16 v) external { vi16[k] = v; }
  function getVi16(uint256 k) external view returns (int16){ return vi16[k]; }
  function setVb4(uint256 k, bytes4 v) external { vb4[k] = v; }
  function getVb4(uint256 k) external view returns (bytes4){ return vb4[k]; }

  function setAdj(uint256 v0, uint256 v1) external { adj0[0] = v0; adj1[0] = v1; }
  function getAdj0() external view returns (uint256){ return adj0[0]; }
  function getAdj1() external view returns (uint256){ return adj1[0]; }
}`;

const SHORT = 'hi there';
const LONG = 'a value string definitely much longer than thirty-two bytes to exercise the long keccak data-slot path';

describe('probe', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;
  async function eq(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    if (j.success !== s.success || j.returnHex !== s.returnHex)
      mism.push(
        label + ': jeth{ok=' + j.success + ',ret=' + j.returnHex + ',err=' + j.exceptionError + '} sol{ok=' + s.success + ',ret=' + s.returnHex + '}',
      );
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
    // ---- default reads: never-written keys for every mapping shape ----
    await eq('def allow', encodeCall(sel('getAllow(address,uint256)'), [A1, 5n]));
    await eq('def deep', encodeCall(sel('getDeep(uint256,int256,bool)'), [1n, 2n, 1n]));
    await eq('def getP', encodeCall(sel('getP(address)'), [A1]));
    await eq('def getPx', encodeCall(sel('getPx(address)'), [A1]));
    await eq('def getQ', encodeCall(sel('getQ(uint256)'), [7n]));
    await eq('def getDn', encodeCall(sel('getDn(bytes4)'), [B4]));
    await eq('def getDs', encodeCall(sel('getDs(bytes4)'), [B4]));
    await eq('def numLen', encodeCall(sel('numLen(address)'), [A1]));
    await eq('def numAt', encodeCall(sel('numAt(address,uint256)'), [A1, 0n])); // OOB on empty
    await eq('def getBytes', encodeCall(sel('getBytes(address)'), [A1]));
    await eq('def lenBytes', encodeCall(sel('lenBytes(address)'), [A1]));
    await eq('def getStr', encodeCall(sel('getStr(uint256)'), [99n]));
    await eq('def getVu8', encodeCall(sel('getVu8(uint256)'), [3n]));
    await eq('def getVi16', encodeCall(sel('getVi16(uint256)'), [3n]));
    await eq('def getVb4', encodeCall(sel('getVb4(uint256)'), [3n]));

    // ---- nested mapping<address, mapping<u256,u256>> ----
    for (const [o, k, v] of [
      [A1, 0n, 0n], [A1, U(256), U(256)], [A2, 1n, 12345n], [A3, U(256), 1n], [A1, 5n, 500n],
    ] as [bigint, bigint, bigint][]) {
      await eq(`setAllow ${o} ${k}`, encodeCall(sel('setAllow(address,uint256,uint256)'), [o, k, v]));
      await eq(`getAllow ${o} ${k}`, encodeCall(sel('getAllow(address,uint256)'), [o, k]));
    }
    await eq('incAllow', encodeCall(sel('incAllow(address,uint256,uint256)'), [A1, 5n, 25n]));
    await eq('getAllow after inc', encodeCall(sel('getAllow(address,uint256)'), [A1, 5n]));
    // overwrite-then-read
    await eq('setAllow overwrite', encodeCall(sel('setAllow(address,uint256,uint256)'), [A1, 5n, 7n]));
    await eq('getAllow overwrite', encodeCall(sel('getAllow(address,uint256)'), [A1, 5n]));

    // ---- 3-level mapping with signed + bool inner keys, INT_MIN boundary ----
    for (const [a, b, c, v] of [
      [0n, 0n, 0n, 1n], [1n, -1n, 1n, 2n], [U(256), IMIN(256), 0n, 3n], [9n, IMAX(256), 1n, 4n], [9n, IMIN(256), 1n, 5n],
    ] as [bigint, bigint, bigint, bigint][]) {
      await eq(`setDeep ${a},${b},${c}`, encodeCall(sel('setDeep(uint256,int256,bool,uint256)'), [a, b, c, v]));
      await eq(`getDeep ${a},${b},${c}`, encodeCall(sel('getDeep(uint256,int256,bool)'), [a, b, c]));
    }
    // bool key with dirty high bits (c=2) must map to true == 1 like solc (after clean)
    await eq('setDeep dirty-bool', rawCall('setDeep(uint256,int256,bool,uint256)', [9n, 7n, 2n, 77n]));
    await eq('getDeep dirty-bool read as 1', encodeCall(sel('getDeep(uint256,int256,bool)'), [9n, 7n, 1n]));

    // ---- mapping to struct P (static): whole assign + per-field RMW ----
    await eq('setP', encodeCall(sel('setP(address,uint128,uint128)'), [A1, U(128), 0xbeefn]));
    await eq('getP', encodeCall(sel('getP(address)'), [A1]));
    await eq('getPx', encodeCall(sel('getPx(address)'), [A1]));
    await eq('getPy', encodeCall(sel('getPy(address)'), [A1]));
    await eq('setPx (preserve y)', encodeCall(sel('setPx(address,uint128)'), [A1, 0x1234n]));
    await eq('getPx after', encodeCall(sel('getPx(address)'), [A1]));
    await eq('getPy preserved', encodeCall(sel('getPy(address)'), [A1]));
    await eq('getP after field set', encodeCall(sel('getP(address)'), [A1]));

    // ---- mapping to struct Q (packed multi-field incl. signed + address + bool) ----
    await eq('setQ', encodeCall(sel('setQ(uint256,uint64,int64,bool,address)'), [1n, U(64), -5n & U(256), 1n, A3]));
    await eq('getQ', encodeCall(sel('getQ(uint256)'), [1n]));
    await eq('getQb', encodeCall(sel('getQb(uint256)'), [1n]));
    await eq('setQb negative', encodeCall(sel('setQb(uint256,int64)'), [1n, IMIN(64) & U(256)]));
    await eq('getQb after (signext)', encodeCall(sel('getQb(uint256)'), [1n]));
    await eq('getQ after field set', encodeCall(sel('getQ(uint256)'), [1n]));

    // ---- mapping bytesN key -> dynamic struct D (short + long string field) ----
    await eq('setD short', dynCall('setD(bytes4,uint256,string)', [B4, 42n], SHORT));
    await eq('getDn short', encodeCall(sel('getDn(bytes4)'), [B4]));
    await eq('getDs short', encodeCall(sel('getDs(bytes4)'), [B4]));
    await eq('setD long', dynCall('setD(bytes4,uint256,string)', [B4, 99n], LONG));
    await eq('getDn long', encodeCall(sel('getDn(bytes4)'), [B4]));
    await eq('getDs long', encodeCall(sel('getDs(bytes4)'), [B4]));
    await eq('setD shrink long->short', dynCall('setD(bytes4,uint256,string)', [B4, 1n], 'x'));
    await eq('getDs after shrink', encodeCall(sel('getDs(bytes4)'), [B4]));

    // ---- mapping to dynamic array: push/pop/index/grow/shrink, per-key isolation ----
    for (let i = 0; i < 4; i++) await eq(`push A1 ${i}`, encodeCall(sel('push(address,uint256)'), [A1, BigInt(100 + i)]));
    await eq('push A2', encodeCall(sel('push(address,uint256)'), [A2, 7n]));
    await eq('numLen A1', encodeCall(sel('numLen(address)'), [A1]));
    await eq('numLen A2', encodeCall(sel('numLen(address)'), [A2]));
    for (const i of [0n, 1n, 3n, 4n /*OOB*/]) await eq(`numAt A1 ${i}`, encodeCall(sel('numAt(address,uint256)'), [A1, i]));
    await eq('setNum A1 2', encodeCall(sel('setNum(address,uint256,uint256)'), [A1, 2n, 9999n]));
    await eq('numAt A1 2 after set', encodeCall(sel('numAt(address,uint256)'), [A1, 2n]));
    await eq('numAt A1 OOB set', encodeCall(sel('setNum(address,uint256,uint256)'), [A1, 99n, 1n])); // Panic 0x32
    await eq('pop A1', encodeCall(sel('pop(address)'), [A1]));
    await eq('numLen A1 after pop', encodeCall(sel('numLen(address)'), [A1]));
    await eq('numAt A1 3 after pop (OOB)', encodeCall(sel('numAt(address,uint256)'), [A1, 3n]));
    // drain then pop-empty -> Panic 0x31
    await eq('pop A1 #2', encodeCall(sel('pop(address)'), [A1]));
    await eq('pop A1 #3', encodeCall(sel('pop(address)'), [A1]));
    await eq('pop A1 #4 (empty)', encodeCall(sel('pop(address)'), [A1]));
    await eq('numLen A2 isolated', encodeCall(sel('numLen(address)'), [A2]));

    // ---- mapping to bytes / string: short, long, shrink, length, default ----
    await eq('setBytes short', dynCall('setBytes(address,bytes)', [A1], SHORT));
    await eq('getBytes short', encodeCall(sel('getBytes(address)'), [A1]));
    await eq('lenBytes short', encodeCall(sel('lenBytes(address)'), [A1]));
    await eq('setBytes long', dynCall('setBytes(address,bytes)', [A1], LONG));
    await eq('getBytes long', encodeCall(sel('getBytes(address)'), [A1]));
    await eq('lenBytes long', encodeCall(sel('lenBytes(address)'), [A1]));
    await eq('setBytes shrink', dynCall('setBytes(address,bytes)', [A1], SHORT));
    await eq('getBytes after shrink', encodeCall(sel('getBytes(address)'), [A1]));
    await eq('setBytes empty', dynCall('setBytes(address,bytes)', [A1], ''));
    await eq('getBytes empty', encodeCall(sel('getBytes(address)'), [A1]));
    await eq('exactly32 setBytes', dynCall('setBytes(address,bytes)', [A2], 'x'.repeat(32)));
    await eq('exactly32 getBytes', encodeCall(sel('getBytes(address)'), [A2]));
    await eq('exactly31 setBytes', dynCall('setBytes(address,bytes)', [A3], 'y'.repeat(31)));
    await eq('exactly31 getBytes', encodeCall(sel('getBytes(address)'), [A3]));
    await eq('setStr short', dynCall('setStr(uint256,string)', [3n], SHORT));
    await eq('getStr short', encodeCall(sel('getStr(uint256)'), [3n]));
    await eq('setStr long', dynCall('setStr(uint256,string)', [3n], LONG));
    await eq('getStr long', encodeCall(sel('getStr(uint256)'), [3n]));

    // ---- key types: uintN/intN/bytesN/bool, boundary values ----
    // u8 key: 0, max, plus dirty-high-bit calldata that must clean to in-range
    for (const k of [0n, 1n, U(8)]) {
      await eq(`setKu8 ${k}`, encodeCall(sel('setKu8(uint8,uint256)'), [k, k + 1n]));
      await eq(`getKu8 ${k}`, encodeCall(sel('getKu8(uint8)'), [k]));
    }
    // dirty u8 key: high bits set, low byte == 5 -> must alias key 5
    await eq('setKu8 clean5', encodeCall(sel('setKu8(uint8,uint256)'), [5n, 555n]));
    await eq('getKu8 dirty->5', rawCall('getKu8(uint8)', [0xffffff00n | 5n]));
    // i8 key: sign-extension boundaries
    for (const k of [0n, -1n, IMIN(8), IMAX(8)]) {
      await eq(`setKi8 ${k}`, encodeCall(sel('setKi8(int8,uint256)'), [k & U(256), (k & 0xffn) + 1n]));
      await eq(`getKi8 ${k}`, encodeCall(sel('getKi8(int8)'), [k & U(256)]));
    }
    // i8 dirty: pass -1 as int8 with garbage high bits (canonical sign-ext is 0xff..ff)
    await eq('getKi8 dirty -1', rawCall('getKi8(int8)', [U(256)])); // already canonical for -1
    // i32 key boundaries
    for (const k of [0n, -1n, IMIN(32), IMAX(32), 123456n]) {
      await eq(`setKi32 ${k}`, encodeCall(sel('setKi32(int32,uint256)'), [k & U(256), 1n]));
      await eq(`getKi32 ${k}`, encodeCall(sel('getKi32(int32)'), [k & U(256)]));
    }
    // u16 key
    for (const k of [0n, U(16), 256n]) {
      await eq(`setKu16 ${k}`, encodeCall(sel('setKu16(uint16,uint256)'), [k, 2n]));
      await eq(`getKu16 ${k}`, encodeCall(sel('getKu16(uint16)'), [k]));
    }
    // bytes1 key (left-aligned): 0x00, 0xff, plus dirty low bits beyond width
    for (const k of [0n, 0xffn << 248n, 0xa5n << 248n]) {
      await eq(`setKb1 ${k}`, encodeCall(sel('setKb1(bytes1,uint256)'), [k, 3n]));
      await eq(`getKb1 ${k}`, encodeCall(sel('getKb1(bytes1)'), [k]));
    }
    // bytes1 dirty: only top byte significant; pass garbage in lower 31 bytes
    await eq('setKb1 0xa5 clean', encodeCall(sel('setKb1(bytes1,uint256)'), [0xa5n << 248n, 42n]));
    await eq('getKb1 0xa5 dirty', rawCall('getKb1(bytes1)', [(0xa5n << 248n) | 0xdeadbeefn]));
    // bool key true/false + dirty (>1) must alias true
    await eq('setKbool true', encodeCall(sel('setKbool(bool,uint256)'), [1n, 11n]));
    await eq('setKbool false', encodeCall(sel('setKbool(bool,uint256)'), [0n, 22n]));
    await eq('getKbool true', encodeCall(sel('getKbool(bool)'), [1n]));
    await eq('getKbool false', encodeCall(sel('getKbool(bool)'), [0n]));
    await eq('getKbool dirty(255)->true', rawCall('getKbool(bool)', [255n]));

    // ---- narrow VALUE types packed in mapping value slot ----
    for (const v of [0n, U(8)]) {
      await eq(`setVu8 ${v}`, encodeCall(sel('setVu8(uint256,uint8)'), [1n, v]));
      await eq(`getVu8 ${v}`, encodeCall(sel('getVu8(uint256)'), [1n]));
    }
    for (const v of [0n, -1n, IMIN(16), IMAX(16)]) {
      await eq(`setVi16 ${v}`, encodeCall(sel('setVi16(uint256,int16)'), [2n, v & U(256)]));
      await eq(`getVi16 ${v}`, encodeCall(sel('getVi16(uint256)'), [2n]));
    }
    await eq('setVb4', encodeCall(sel('setVb4(uint256,bytes4)'), [3n, B4]));
    await eq('getVb4', encodeCall(sel('getVb4(uint256)'), [3n]));

    // ---- adjacent mappings: no slot collision ----
    await eq('setAdj', encodeCall(sel('setAdj(uint256,uint256)'), [111n, 222n]));
    await eq('getAdj0', encodeCall(sel('getAdj0()')));
    await eq('getAdj1', encodeCall(sel('getAdj1()')));

    // ---- dirty-high-bit keys in the WRITE path must alias the clean key ----
    // write at u8 key 200 via dirty calldata; read at clean 200 must see it.
    await eq('setKu8 dirty-write', rawCall('setKu8(uint8,uint256)', [0xdeadbe00n | 200n, 1234n]));
    await eq('getKu8 200 after dirty-write', encodeCall(sel('getKu8(uint8)'), [200n]));
    // dirty address key (garbage in top 12 bytes); both set+get dirty must agree
    // with clean, since solc masks address to 160 bits.
    const dirtyAddr = (BigInt('0x' + 'cc'.repeat(12)) << 160n) | A1; // top 12 bytes dirty
    await eq('setAllow dirty-addr', rawCall('setAllow(address,uint256,uint256)', [dirtyAddr, 9n, 8765n]));
    await eq('getAllow clean-addr after dirty', encodeCall(sel('getAllow(address,uint256)'), [A1, 9n]));
    // dirty bytes1 key in write path: lower 31 bytes garbage, top byte 0x77
    await eq('setKb1 dirty-write', rawCall('setKb1(bytes1,uint256)', [(0x77n << 248n) | 0xcafebaben]));
    await eq('getKb1 0x77 clean after dirty-write', encodeCall(sel('getKb1(bytes1)'), [0x77n << 248n]));
    // dirty bool key write (value 9) must alias true; read true must see it
    await eq('setKbool dirty-write(9)', rawCall('setKbool(bool,uint256)', [9n, 4242n]));
    await eq('getKbool true after dirty bool write', encodeCall(sel('getKbool(bool)'), [1n]));

    // ---- narrow VALUE dirty write: extra high bits must be masked on store ----
    // vu8 set with a uint8 arg carrying dirty high bits -> stored value must be low byte
    await eq('setVu8 dirty', rawCall('setVu8(uint256,uint8)', [5n, 0xffffff00n | 0x2an]));
    await eq('getVu8 dirty (masked to 0x2a)', encodeCall(sel('getVu8(uint256)'), [5n]));
    await eq('setVi16 dirty', rawCall('setVi16(uint256,int16)', [6n, (0xdeadn << 16n) | 0x8000n]));
    await eq('getVi16 dirty (sign-ext from low 16)', encodeCall(sel('getVi16(uint256)'), [6n]));
    await eq('setVb4 dirty', rawCall('setVb4(uint256,bytes4)', [7n, B4 | 0xffffffffn]));
    await eq('getVb4 dirty (low 28 bytes masked off)', encodeCall(sel('getVb4(uint256)'), [7n]));

    // ---- i256 nested-key INT_MIN/-1 distinct slots, overwrite-then-read ----
    await eq('setDeep min', encodeCall(sel('setDeep(uint256,int256,bool,uint256)'), [0n, IMIN(256) & U(256), 0n, 1n]));
    await eq('setDeep neg1', encodeCall(sel('setDeep(uint256,int256,bool,uint256)'), [0n, U(256), 0n, 2n]));
    await eq('getDeep min distinct', encodeCall(sel('getDeep(uint256,int256,bool)'), [0n, IMIN(256) & U(256), 0n]));
    await eq('getDeep neg1 distinct', encodeCall(sel('getDeep(uint256,int256,bool)'), [0n, U(256), 0n]));

    void B32a; void B32b;

    if (mism.length) {
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 40)) console.log(m);
    } else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
