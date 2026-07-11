// Adversarial differential: errors + events. Compares (success, returnHex) AND
// emitted logs (topics + data) byte-for-byte against solc 0.8.x (cancun, opt on).
// Area: reverts/errors/events. Probes Error(string), Panic(uint256), custom errors
// (static + dynamic bytes/string args, eager eval), and events with 0..3 indexed
// topics, non-indexed value/bytes/string/bytesN data, declaration-order reshuffle,
// multiple emits per call, sign-extended int topics, dirty high bits.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall, type LogEntry } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);
const U256_MAX = M - 1n;
const I256_MIN = -(1n << 255n);
const I256_MAX = (1n << 255n) - 1n;
const A = BigInt('0x' + 'aa'.repeat(20));
const B = BigInt('0x' + 'bb'.repeat(20));
const ADDR = BigInt('0x' + 'de'.repeat(20));
const pad = (v: bigint) => (((v % M) + M) % M).toString(16).padStart(64, '0');
const strip = (s: string) => (s.startsWith('0x') ? s.slice(2) : s);

// Encode a dynamic string tail (len word + padded data words).
function strTail(s: string): string {
  const bytes = Buffer.from(s, 'utf8');
  const nwords = Math.ceil(bytes.length / 32);
  let dataWords = '';
  for (let i = 0; i < nwords; i++) {
    dataWords += Buffer.concat([bytes.subarray(i * 32, i * 32 + 32), Buffer.alloc(32)])
      .subarray(0, 32)
      .toString('hex');
  }
  return pad(BigInt(bytes.length)) + dataWords;
}

const JETH = `class C {
  Insufficient: error<{ available: u256; required: u256 }>;
  Unauthorized: error<{ who: address }>;
  Flag: error<{ ok: bool }>;
  Three: error<{ a: u256; b: address; c: bool }>;
  Narrow: error<{ a: u8; b: i8 }>;
  NoArgs: error<{}>;
  WideMix: error<{ a: i256; b: bytes32; c: u128; d: i16 }>;
  WithStr: error<{ code: u256; note: string; flag: bool }>;
  TwoStr: error<{ a: string; b: string }>;
  JustBytes: error<{ b: bytes }>;
  StrThenStatic: error<{ s: string; x: u256 }>;
  BytesAddr: error<{ b: bytes; w: address }>;

  // ---- require / revert (Error(string) + empty + Panic) ----
  get reqTrue(a: u256): External<u256> { require(a > 0n); return a; }
  get reqTrueMsg(a: u256): External<u256> { require(a > 0n, "must be positive"); return a; }
  reqFalseShort(): External<void> { require(false, "hello"); }
  reqFalseExact32(): External<void> { require(false, "abcdefghijklmnopqrstuvwxyz012345"); }
  reqFalseExact33(): External<void> { require(false, "abcdefghijklmnopqrstuvwxyz0123456"); }
  reqFalseLong(): External<void> { require(false, "this string is definitely longer than thirty-two bytes for testing"); }
  reqFalseUtf8(): External<void> { require(false, "héllo 世界"); }
  revertShort(): External<void> { revert("hello"); }
  revertEmptyStr(): External<void> { revert(""); }
  revertBare(): External<void> { revert(); }
  get reqCond(a: u256, b: u256): External<u256> { require(a >= b, "underflow guard"); return a - b; }

  // ---- Panic codes ----
  get panicOverflowAdd(a: u256, b: u256): External<u256> { return a + b; }
  get panicOverflowMul(a: u256, b: u256): External<u256> { return a * b; }
  get panicDivZero(a: u256, b: u256): External<u256> { return a / b; }
  get panicModZero(a: u256, b: u256): External<u256> { return a % b; }
  get panicSub(a: u256, b: u256): External<u256> { return a - b; }
  get panicExp(a: u256, b: u256): External<u256> { return a ** b; }
  get panicNegI(a: i256, b: i256): External<i256> { return a / b; }

  // ---- custom errors: static args ----
  r1(a: u256, b: u256): External<void> { revert(Insufficient(a, b)); }
  r2(w: address): External<void> { revert(Unauthorized(w)); }
  r3(ok: bool): External<void> { revert(Flag(ok)); }
  r4(a: u256, b: address, c: bool): External<void> { revert(Three(a, b, c)); }
  r5(a: u8, b: i8): External<void> { revert(Narrow(a, b)); }
  r6(a: i256, b: bytes32, c: u128, d: i16): External<void> { revert(WideMix(a, b, c, d)); }
  r7(): External<void> { revert(NoArgs()); }
  get rq(a: u256, b: u256): External<u256> { require(a > b, Insufficient(a, b)); return a; }
  get rqEager(a: u256, b: u256): External<u256> { require(true, Insufficient(a, 10n / b)); return a; }
  get reqThenAdd(a: u256): External<u256> { require(a > 0n, "nz"); return a + 1n; }

  // ---- custom errors: dynamic args ----
  eWithStr(code: u256, s: string, f: bool): External<void> { revert(WithStr(code, s, f)); }
  eTwoStr(a: string, b: string): External<void> { revert(TwoStr(a, b)); }
  eJustBytes(b: bytes): External<void> { revert(JustBytes(b)); }
  eStrThenStatic(s: string, x: u256): External<void> { revert(StrThenStatic(s, x)); }
  eBytesAddr(b: bytes, w: address): External<void> { revert(BytesAddr(b, w)); }
  eStrLit(): External<void> { revert(WithStr(7n, "literal note here", true)); }

  // ---- events: indexed counts 0..3 ----
  NoIdx: event<{ value: u256 }>;
  OneIdx: event<{ key: indexed<u256>; value: u256 }>;
  Transfer: event<{ from: indexed<address>; to: indexed<address>; value: u256 }>;
  ThreeIdx: event<{ a: indexed<u256>; b: indexed<u256>; c: indexed<u256>; d: u256 }>;
  Bare: event<{}>;
  OneIdxNoData: event<{ who: indexed<address> }>;
  Mixed: event<{ flag: indexed<u8>; s: indexed<i16>; ok: indexed<bool>; who: address; sig: bytes4 }>;
  Order: event<{ a: u256; b: indexed<u256>; c: u256; d: indexed<u256>; e: u256 }>;
  IdxInt: event<{ s: indexed<i256>; value: u256 }>;
  IdxBytes: event<{ b: indexed<bytes32>; value: u256 }>;
  DataStr: event<{ key: indexed<u256>; note: string }>;
  DataBytes: event<{ value: u256; b: bytes }>;
  StrAndBytes: event<{ s: string; b: bytes }>;
  MultiData: event<{ a: u256; b: bytes; c: u256; d: string }>;
  IdxAndStr: event<{ who: indexed<address>; code: indexed<u256>; note: string }>;
  AllStatic: event<{ a: indexed<u8>; b: indexed<i8>; c: u256; d: bytes32; e: bool }>;

  evNoIdx(v: u256): External<void> { emit(NoIdx(v)); }
  evOneIdx(k: u256, v: u256): External<void> { emit(OneIdx(k, v)); }
  evTransfer(f: address, t: address, v: u256): External<void> { emit(Transfer(f, t, v)); }
  evThreeIdx(a: u256, b: u256, c: u256, d: u256): External<void> { emit(ThreeIdx(a, b, c, d)); }
  evBare(): External<void> { emit(Bare()); }
  evOneIdxNoData(w: address): External<void> { emit(OneIdxNoData(w)); }
  evMixed(fl: u8, s: i16, ok: bool, w: address, sig: bytes4): External<void> { emit(Mixed(fl, s, ok, w, sig)); }
  evOrder(a: u256, b: u256, c: u256, d: u256, e: u256): External<void> { emit(Order(a, b, c, d, e)); }
  evIdxInt(s: i256, v: u256): External<void> { emit(IdxInt(s, v)); }
  evIdxBytes(b: bytes32, v: u256): External<void> { emit(IdxBytes(b, v)); }
  evDataStr(k: u256, s: string): External<void> { emit(DataStr(k, s)); }
  evDataBytes(v: u256, b: bytes): External<void> { emit(DataBytes(v, b)); }
  evStrAndBytes(s: string, b: bytes): External<void> { emit(StrAndBytes(s, b)); }
  evMultiData(a: u256, b: bytes, c: u256, d: string): External<void> { emit(MultiData(a, b, c, d)); }
  evIdxAndStr(w: address, code: u256, s: string): External<void> { emit(IdxAndStr(w, code, s)); }
  evAllStatic(a: u8, b: i8, c: u256, d: bytes32, e: bool): External<void> { emit(AllStatic(a, b, c, d, e)); }
  evTwice(v: u256): External<void> { emit(NoIdx(v)); emit(NoIdx(v)); }
  evMulti(a: u256, w: address, t: address): External<void> { emit(NoIdx(a)); emit(Transfer(w, t, a)); emit(Bare()); }
  evThenRevert(v: u256): External<void> { emit(NoIdx(v)); revert("after emit"); }
  evCond(v: u256): External<void> { if (v > 10n) { emit(NoIdx(v)); } else { emit(Bare()); } }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  error Insufficient(uint256 available, uint256 required);
  error Unauthorized(address who);
  error Flag(bool ok);
  error Three(uint256 a, address b, bool c);
  error Narrow(uint8 a, int8 b);
  error NoArgs();
  error WideMix(int256 a, bytes32 b, uint128 c, int16 d);
  error WithStr(uint256 code, string note, bool flag);
  error TwoStr(string a, string b);
  error JustBytes(bytes b);
  error StrThenStatic(string s, uint256 x);
  error BytesAddr(bytes b, address w);

  function reqTrue(uint256 a) external pure returns (uint256){ require(a > 0); return a; }
  function reqTrueMsg(uint256 a) external pure returns (uint256){ require(a > 0, "must be positive"); return a; }
  function reqFalseShort() external pure { require(false, "hello"); }
  function reqFalseExact32() external pure { require(false, "abcdefghijklmnopqrstuvwxyz012345"); }
  function reqFalseExact33() external pure { require(false, "abcdefghijklmnopqrstuvwxyz0123456"); }
  function reqFalseLong() external pure { require(false, "this string is definitely longer than thirty-two bytes for testing"); }
  function reqFalseUtf8() external pure { require(false, unicode"héllo 世界"); }
  function revertShort() external pure { revert("hello"); }
  function revertEmptyStr() external pure { revert(""); }
  function revertBare() external pure { revert(); }
  function reqCond(uint256 a, uint256 b) external pure returns (uint256){ require(a >= b, "underflow guard"); return a - b; }

  function panicOverflowAdd(uint256 a, uint256 b) external pure returns (uint256){ return a + b; }
  function panicOverflowMul(uint256 a, uint256 b) external pure returns (uint256){ return a * b; }
  function panicDivZero(uint256 a, uint256 b) external pure returns (uint256){ return a / b; }
  function panicModZero(uint256 a, uint256 b) external pure returns (uint256){ return a % b; }
  function panicSub(uint256 a, uint256 b) external pure returns (uint256){ return a - b; }
  function panicExp(uint256 a, uint256 b) external pure returns (uint256){ return a ** b; }
  function panicNegI(int256 a, int256 b) external pure returns (int256){ return a / b; }

  function r1(uint256 a, uint256 b) external pure { revert Insufficient(a, b); }
  function r2(address w) external pure { revert Unauthorized(w); }
  function r3(bool ok) external pure { revert Flag(ok); }
  function r4(uint256 a, address b, bool c) external pure { revert Three(a, b, c); }
  function r5(uint8 a, int8 b) external pure { revert Narrow(a, b); }
  function r6(int256 a, bytes32 b, uint128 c, int16 d) external pure { revert WideMix(a, b, c, d); }
  function r7() external pure { revert NoArgs(); }
  function rq(uint256 a, uint256 b) external pure returns (uint256){ require(a > b, Insufficient(a, b)); return a; }
  function rqEager(uint256 a, uint256 b) external pure returns (uint256){ require(true, Insufficient(a, 10 / b)); return a; }
  function reqThenAdd(uint256 a) external pure returns (uint256){ require(a > 0, "nz"); return a + 1; }

  function eWithStr(uint256 code, string calldata s, bool f) external pure { revert WithStr(code, s, f); }
  function eTwoStr(string calldata a, string calldata b) external pure { revert TwoStr(a, b); }
  function eJustBytes(bytes calldata b) external pure { revert JustBytes(b); }
  function eStrThenStatic(string calldata s, uint256 x) external pure { revert StrThenStatic(s, x); }
  function eBytesAddr(bytes calldata b, address w) external pure { revert BytesAddr(b, w); }
  function eStrLit() external pure { revert WithStr(7, "literal note here", true); }

  event NoIdx(uint256 value);
  event OneIdx(uint256 indexed key, uint256 value);
  event Transfer(address indexed from, address indexed to, uint256 value);
  event ThreeIdx(uint256 indexed a, uint256 indexed b, uint256 indexed c, uint256 d);
  event Bare();
  event OneIdxNoData(address indexed who);
  event Mixed(uint8 indexed flag, int16 indexed s, bool indexed ok, address who, bytes4 sig);
  event Order(uint256 a, uint256 indexed b, uint256 c, uint256 indexed d, uint256 e);
  event IdxInt(int256 indexed s, uint256 value);
  event IdxBytes(bytes32 indexed b, uint256 value);
  event DataStr(uint256 indexed key, string note);
  event DataBytes(uint256 value, bytes b);
  event StrAndBytes(string s, bytes b);
  event MultiData(uint256 a, bytes b, uint256 c, string d);
  event IdxAndStr(address indexed who, uint256 indexed code, string note);
  event AllStatic(uint8 indexed a, int8 indexed b, uint256 c, bytes32 d, bool e);

  function evNoIdx(uint256 v) external { emit NoIdx(v); }
  function evOneIdx(uint256 k, uint256 v) external { emit OneIdx(k, v); }
  function evTransfer(address f, address t, uint256 v) external { emit Transfer(f, t, v); }
  function evThreeIdx(uint256 a, uint256 b, uint256 c, uint256 d) external { emit ThreeIdx(a,b,c,d); }
  function evBare() external { emit Bare(); }
  function evOneIdxNoData(address w) external { emit OneIdxNoData(w); }
  function evMixed(uint8 fl, int16 s, bool ok, address w, bytes4 sig) external { emit Mixed(fl,s,ok,w,sig); }
  function evOrder(uint256 a, uint256 b, uint256 c, uint256 d, uint256 e) external { emit Order(a,b,c,d,e); }
  function evIdxInt(int256 s, uint256 v) external { emit IdxInt(s, v); }
  function evIdxBytes(bytes32 b, uint256 v) external { emit IdxBytes(b, v); }
  function evDataStr(uint256 k, string calldata s) external { emit DataStr(k, s); }
  function evDataBytes(uint256 v, bytes calldata b) external { emit DataBytes(v, b); }
  function evStrAndBytes(string calldata s, bytes calldata b) external { emit StrAndBytes(s, b); }
  function evMultiData(uint256 a, bytes calldata b, uint256 c, string calldata d) external { emit MultiData(a, b, c, d); }
  function evIdxAndStr(address w, uint256 code, string calldata s) external { emit IdxAndStr(w, code, s); }
  function evAllStatic(uint8 a, int8 b, uint256 c, bytes32 d, bool e) external { emit AllStatic(a, b, c, d, e); }
  function evTwice(uint256 v) external { emit NoIdx(v); emit NoIdx(v); }
  function evMulti(uint256 a, address w, address t) external { emit NoIdx(a); emit Transfer(w, t, a); emit Bare(); }
  function evThenRevert(uint256 v) external { emit NoIdx(v); revert("after emit"); }
  function evCond(uint256 v) external { if (v > 10) { emit NoIdx(v); } else { emit Bare(); } }
}`;

function eqLogs(a: LogEntry[], b: LogEntry[]): boolean {
  if (a.length !== b.length) return false;
  return a.every((l, i) => l.data === b[i]!.data && JSON.stringify(l.topics) === JSON.stringify(b[i]!.topics));
}

describe('errors+events adversarial', () => {
  let jeth: Harness, sol: Harness, aj: Address, as: Address;
  const mism: string[] = [];
  let count = 0;

  // Compare success, returnHex (revert data), AND emitted logs.
  async function eq(label: string, data: string) {
    count++;
    const j = await jeth.call(aj, data);
    const s = await sol.call(as, data);
    const probs: string[] = [];
    if (j.success !== s.success) probs.push('ok j=' + j.success + ' s=' + s.success);
    if (j.returnHex !== s.returnHex) probs.push('ret j=' + j.returnHex + ' s=' + s.returnHex);
    if (!eqLogs(j.logs, s.logs)) probs.push('logs j=' + JSON.stringify(j.logs) + ' s=' + JSON.stringify(s.logs));
    if (probs.length) mism.push(label + ' {jethErr=' + j.exceptionError + '} :: ' + probs.join(' | '));
  }
  function raw(s: string) {
    return '0x' + strip(s);
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
    // ---------- require / revert: Error(string) + empty + Panic ----------
    await eq('reqTrue 7', encodeCall(sel('reqTrue(uint256)'), [7n]));
    await eq('reqTrue 0', encodeCall(sel('reqTrue(uint256)'), [0n]));
    await eq('reqTrueMsg 5', encodeCall(sel('reqTrueMsg(uint256)'), [5n]));
    await eq('reqTrueMsg 0', encodeCall(sel('reqTrueMsg(uint256)'), [0n]));
    await eq('reqFalseShort', encodeCall(sel('reqFalseShort()')));
    await eq('reqFalseExact32', encodeCall(sel('reqFalseExact32()')));
    await eq('reqFalseExact33', encodeCall(sel('reqFalseExact33()')));
    await eq('reqFalseLong', encodeCall(sel('reqFalseLong()')));
    await eq('reqFalseUtf8', encodeCall(sel('reqFalseUtf8()')));
    await eq('revertShort', encodeCall(sel('revertShort()')));
    await eq('revertEmptyStr', encodeCall(sel('revertEmptyStr()')));
    await eq('revertBare', encodeCall(sel('revertBare()')));
    for (const [a, b] of [
      [5n, 3n],
      [3n, 5n],
      [0n, 0n],
      [U256_MAX, 0n],
      [0n, U256_MAX],
      [10n, 10n],
    ] as [bigint, bigint][]) {
      await eq('reqCond ' + a + ',' + b, encodeCall(sel('reqCond(uint256,uint256)'), [a, b]));
    }

    // ---------- Panic codes 0x11/0x12/0x01? ----------
    const pairs: [bigint, bigint][] = [
      [1n, 2n],
      [U256_MAX, 0n],
      [U256_MAX, 1n],
      [U256_MAX, 2n],
      [0n, 0n],
      [I256_MAX % M, 0n],
      [2n, U256_MAX],
    ];
    for (const [a, b] of pairs) {
      await eq('add ' + a + ',' + b, encodeCall(sel('panicOverflowAdd(uint256,uint256)'), [a, b]));
      await eq('mul ' + a + ',' + b, encodeCall(sel('panicOverflowMul(uint256,uint256)'), [a, b]));
      await eq('div ' + a + ',' + b, encodeCall(sel('panicDivZero(uint256,uint256)'), [a, b]));
      await eq('mod ' + a + ',' + b, encodeCall(sel('panicModZero(uint256,uint256)'), [a, b]));
      await eq('sub ' + a + ',' + b, encodeCall(sel('panicSub(uint256,uint256)'), [a, b]));
      await eq('exp ' + a + ',' + b, encodeCall(sel('panicExp(uint256,uint256)'), [a, b]));
    }
    // signed div: INT_MIN / -1 overflow Panic(0x11), x/0 Panic(0x12)
    for (const [a, b] of [
      [I256_MIN, -1n],
      [I256_MIN, 1n],
      [5n, 0n],
      [I256_MIN, 0n],
      [-7n, 2n],
      [7n, -2n],
    ] as [bigint, bigint][]) {
      await eq('idiv ' + a + ',' + b, encodeCall(sel('panicNegI(int256,int256)'), [a, b]));
    }

    // ---------- custom errors: static args ----------
    await eq('r1 5,9', encodeCall(sel('r1(uint256,uint256)'), [5n, 9n]));
    await eq('r1 max,0', encodeCall(sel('r1(uint256,uint256)'), [U256_MAX, 0n]));
    await eq('r2', encodeCall(sel('r2(address)'), [ADDR]));
    await eq('r2 zero', encodeCall(sel('r2(address)'), [0n]));
    await eq('r3 t', encodeCall(sel('r3(bool)'), [1n]));
    await eq('r3 f', encodeCall(sel('r3(bool)'), [0n]));
    await eq('r4', encodeCall(sel('r4(uint256,address,bool)'), [7n, ADDR, 1n]));
    await eq('r5 255,-1', encodeCall(sel('r5(uint8,int8)'), [255n, -1n % M]));
    await eq('r5 0,127', encodeCall(sel('r5(uint8,int8)'), [0n, 127n]));
    await eq('r5 0,-128', encodeCall(sel('r5(uint8,int8)'), [0n, -128n % M]));
    await eq(
      'r6',
      encodeCall(sel('r6(int256,bytes32,uint128,int16)'), [
        -12345n % M,
        BigInt('0x' + 'cd'.repeat(32)),
        1n << 100n,
        -30000n % M,
      ]),
    );
    await eq(
      'r6 min',
      encodeCall(sel('r6(int256,bytes32,uint128,int16)'), [I256_MIN % M, 0n, (1n << 128n) - 1n, -32768n % M]),
    );
    await eq('r7', encodeCall(sel('r7()')));
    await eq('rq 9,3', encodeCall(sel('rq(uint256,uint256)'), [9n, 3n]));
    await eq('rq 3,9', encodeCall(sel('rq(uint256,uint256)'), [3n, 9n]));
    await eq('rqEager 7,0', encodeCall(sel('rqEager(uint256,uint256)'), [7n, 0n]));
    await eq('rqEager 7,2', encodeCall(sel('rqEager(uint256,uint256)'), [7n, 2n]));
    await eq('reqThenAdd 0', encodeCall(sel('reqThenAdd(uint256)'), [0n]));
    await eq('reqThenAdd 5', encodeCall(sel('reqThenAdd(uint256)'), [5n]));
    await eq('reqThenAdd max', encodeCall(sel('reqThenAdd(uint256)'), [U256_MAX]));

    // ---------- dirty high bits in narrow custom-error args (r5 takes u8,i8) ----------
    // Solidity validates incoming calldata; clean here, dirty bits set in word.
    const dirty8 = pad(0x1234567890n); // high bits set beyond 8 bits
    await eq('r5 dirtyU8', '0x' + sel('r5(uint8,int8)') + dirty8 + pad(5n));
    await eq('r5 dirtyI8', '0x' + sel('r5(uint8,int8)') + pad(3n) + pad(0xffffff00n));

    // ---------- custom errors: dynamic (bytes/string) args ----------
    const strCases = [
      '',
      'hi',
      'abcdefghijklmnopqrstuvwxyz012345',
      'this string is definitely longer than thirty-two bytes to force multi-word padding',
    ];
    for (const s of strCases) {
      // eWithStr(uint256, string, bool): head [code][off=0x60][flag] + tail
      const cd = '0x' + sel('eWithStr(uint256,string,bool)') + pad(42n) + pad(0x60n) + pad(1n) + strTail(s);
      await eq('eWithStr "' + s.slice(0, 8) + '" len' + s.length, cd);
    }
    // eTwoStr(string,string): head [off1=0x40][off2] + tail1 + tail2
    for (const [a, b] of [
      ['', ''],
      ['x', 'yy'],
      ['first', 'second longer string value goes here for padding test ok'],
    ] as [string, string][]) {
      const t1 = strTail(a);
      const off2 = 0x40n + BigInt(t1.length / 2);
      const cd = '0x' + sel('eTwoStr(string,string)') + pad(0x40n) + pad(off2) + t1 + strTail(b);
      await eq('eTwoStr "' + a + '","' + b.slice(0, 6) + '"', cd);
    }
    // eJustBytes(bytes): head [off=0x20] + tail
    for (const s of [
      '',
      'ab',
      'deadbeefdeadbeefdeadbeefdeadbeef00',
      'a longer bytes blob that exceeds a single thirty-two byte word for sure yes',
    ]) {
      const cd = '0x' + sel('eJustBytes(bytes)') + pad(0x20n) + strTail(s);
      await eq('eJustBytes len' + s.length, cd);
    }
    // eStrThenStatic(string,uint256): head [off=0x40][x] + tail
    for (const s of ['', 'short', 'a string spanning more than thirty two bytes to test the tail offset math here']) {
      const cd = '0x' + sel('eStrThenStatic(string,uint256)') + pad(0x40n) + pad(U256_MAX) + strTail(s);
      await eq('eStrThenStatic len' + s.length, cd);
    }
    // eBytesAddr(bytes,address): head [off=0x40][w] + tail
    for (const s of ['', 'zz', 'bytes data here that is longer than one word for multi word tail test ok yes']) {
      const cd = '0x' + sel('eBytesAddr(bytes,address)') + pad(0x40n) + pad(ADDR) + strTail(s);
      await eq('eBytesAddr len' + s.length, cd);
    }
    await eq('eStrLit', encodeCall(sel('eStrLit()')));

    // ---------- events: 0..3 indexed ----------
    await eq('evNoIdx 0', encodeCall(sel('evNoIdx(uint256)'), [0n]));
    await eq('evNoIdx max', encodeCall(sel('evNoIdx(uint256)'), [U256_MAX]));
    await eq('evOneIdx', encodeCall(sel('evOneIdx(uint256,uint256)'), [5n, 99n]));
    await eq('evTransfer', encodeCall(sel('evTransfer(address,address,uint256)'), [A, B, 1000n]));
    await eq('evTransfer zero', encodeCall(sel('evTransfer(address,address,uint256)'), [0n, 0n, 0n]));
    await eq('evThreeIdx', encodeCall(sel('evThreeIdx(uint256,uint256,uint256,uint256)'), [7n, 8n, 9n, 42n]));
    await eq(
      'evThreeIdx max',
      encodeCall(sel('evThreeIdx(uint256,uint256,uint256,uint256)'), [U256_MAX, 0n, U256_MAX, U256_MAX]),
    );
    await eq('evBare', encodeCall(sel('evBare()')));
    await eq('evOneIdxNoData', encodeCall(sel('evOneIdxNoData(address)'), [A]));

    // mixed indexed value/int/bool/bytesN topics, dirty high bits
    await eq(
      'evMixed',
      encodeCall(sel('evMixed(uint8,int16,bool,address,bytes4)'), [
        255n,
        -3n % M,
        1n,
        A,
        BigInt('0xdeadbeef' + '00'.repeat(28)),
      ]),
    );
    await eq('evMixed min', encodeCall(sel('evMixed(uint8,int16,bool,address,bytes4)'), [0n, -32768n % M, 0n, 0n, 0n]));
    await eq(
      'evMixed maxbytes',
      encodeCall(sel('evMixed(uint8,int16,bool,address,bytes4)'), [
        128n,
        32767n,
        1n,
        B,
        BigInt('0xffffffff' + '00'.repeat(28)),
      ]),
    );

    // declaration order reshuffle (indexed interleaved with data)
    await eq('evOrder', encodeCall(sel('evOrder(uint256,uint256,uint256,uint256,uint256)'), [1n, 2n, 3n, 4n, 5n]));
    await eq(
      'evOrder max',
      encodeCall(sel('evOrder(uint256,uint256,uint256,uint256,uint256)'), [U256_MAX, U256_MAX, 0n, U256_MAX, 7n]),
    );

    // indexed signed int topic (sign-extension into 32-byte topic)
    for (const s of [0n, -1n, 1n, I256_MIN, I256_MAX, -123456789n]) {
      await eq('evIdxInt ' + s, encodeCall(sel('evIdxInt(int256,uint256)'), [s % M, 9n]));
    }
    // indexed bytes32 topic
    await eq('evIdxBytes', encodeCall(sel('evIdxBytes(bytes32,uint256)'), [BigInt('0x' + 'ab'.repeat(32)), 1n]));
    await eq('evIdxBytes zero', encodeCall(sel('evIdxBytes(bytes32,uint256)'), [0n, 0n]));

    // ---------- events: non-indexed dynamic data (string / bytes) ----------
    for (const s of strCases) {
      const cd = '0x' + sel('evDataStr(uint256,string)') + pad(123n) + pad(0x40n) + strTail(s);
      await eq('evDataStr len' + s.length, cd);
    }
    for (const s of strCases) {
      const cd = '0x' + sel('evDataBytes(uint256,bytes)') + pad(77n) + pad(0x40n) + strTail(s);
      await eq('evDataBytes len' + s.length, cd);
    }
    // event with two dynamic data fields (string + bytes)
    for (const [a, b] of [
      ['', ''],
      ['s', 'b'],
      [
        'a string here longer than thirty-two bytes for tail spread test ok',
        'bytes blob also longer than one full word goes here for the test',
      ],
    ] as [string, string][]) {
      const t1 = strTail(a);
      const off2 = 0x40n + BigInt(t1.length / 2);
      const cd = '0x' + sel('evStrAndBytes(string,bytes)') + pad(0x40n) + pad(off2) + t1 + strTail(b);
      await eq('evStrAndBytes "' + a.slice(0, 4) + '"', cd);
    }
    // multi data: static, dynamic, static, dynamic interleaved
    for (const [bs, ds] of [
      ['', ''],
      ['xx', 'yy'],
      [
        'some bytes here that span more than thirty two bytes total for the test',
        'and a string that also is quite long enough to need two words at least',
      ],
    ] as [string, string][]) {
      const t1 = strTail(bs);
      // head: [a][off_b][c][off_d]; off_b = 0x80; off_d = 0x80 + |tail_b|
      const offB = 0x80n;
      const offD = offB + BigInt(t1.length / 2);
      const cd =
        '0x' +
        sel('evMultiData(uint256,bytes,uint256,string)') +
        pad(11n) +
        pad(offB) +
        pad(22n) +
        pad(offD) +
        t1 +
        strTail(ds);
      await eq('evMultiData "' + bs.slice(0, 4) + '"', cd);
    }
    // indexed topics + dynamic data
    for (const s of strCases) {
      const cd = '0x' + sel('evIdxAndStr(address,uint256,string)') + pad(A) + pad(999n) + pad(0x60n) + strTail(s);
      await eq('evIdxAndStr len' + s.length, cd);
    }
    // all static, two indexed + three data incl bytes32/bool
    await eq(
      'evAllStatic',
      encodeCall(sel('evAllStatic(uint8,int8,uint256,bytes32,bool)'), [
        200n,
        -5n % M,
        U256_MAX,
        BigInt('0x' + '7f'.repeat(32)),
        1n,
      ]),
    );
    await eq('evAllStatic2', encodeCall(sel('evAllStatic(uint8,int8,uint256,bytes32,bool)'), [0n, 127n, 0n, 0n, 0n]));

    // ---------- multiple events per call / event then revert / conditional ----------
    await eq('evTwice', encodeCall(sel('evTwice(uint256)'), [7n]));
    await eq('evMulti', encodeCall(sel('evMulti(uint256,address,address)'), [55n, A, B]));
    await eq('evThenRevert', encodeCall(sel('evThenRevert(uint256)'), [3n])); // logs must roll back
    await eq('evCond gt', encodeCall(sel('evCond(uint256)'), [20n]));
    await eq('evCond le', encodeCall(sel('evCond(uint256)'), [2n]));

    // ---------- unknown selector / non-payable value reject ----------
    await eq('unknownSelector', raw('deadbeef'));
    await eq('emptyCalldata', raw(''));
    await eq('shortSelector3', raw('aabbcc'));

    // ---------- value sent to non-payable event/error fns must revert empty ----------
    async function eqVal(label: string, data: string, value: bigint) {
      count++;
      const j = await jeth.call(aj, data, { value });
      const s = await sol.call(as, data, { value });
      const probs: string[] = [];
      if (j.success !== s.success) probs.push('ok j=' + j.success + ' s=' + s.success);
      if (j.returnHex !== s.returnHex) probs.push('ret j=' + j.returnHex + ' s=' + s.returnHex);
      if (!eqLogs(j.logs, s.logs)) probs.push('logs differ');
      if (probs.length) mism.push(label + ' :: ' + probs.join(' | '));
    }
    await eqVal('valToEvNoIdx', encodeCall(sel('evNoIdx(uint256)'), [3n]), 1n);
    await eqVal('valToReqTrue', encodeCall(sel('reqTrue(uint256)'), [5n]), 7n);
    await eqVal('valToRevertBare', encodeCall(sel('revertBare()')), 100n);

    // ---------- ADVERSARIAL malformed dynamic-arg calldata (decoder parity) ----------
    // Both compilers must reject identically (same success + same returndata).
    const msel = sel('eWithStr(uint256,string,bool)'); // (uint256, string, bool)
    // garbage in head[1] (the string offset) -> out-of-bounds / non-canonical
    const badOffsets: bigint[] = [0x0n, 0x20n, 0x40n, 0x80n, 0xffffffffn, U256_MAX, 1n << 64n, 1n << 255n];
    for (const off of badOffsets) {
      // head: [code=1][offset][flag=1], then a 1-word "tail" claiming len=0x20 but no data
      const cd = '0x' + msel + pad(1n) + pad(off) + pad(1n) + pad(0x20n);
      await eq('eWithStr badOff ' + off.toString(16), cd);
    }
    // valid offset (0x60) but length larger than remaining calldata
    for (const len of [0x21n, 0x100n, U256_MAX, 1n << 64n]) {
      const cd = '0x' + msel + pad(1n) + pad(0x60n) + pad(1n) + pad(len) + pad(0xabcdn);
      await eq('eWithStr badLen ' + len.toString(16), cd);
    }
    // truncated tail: offset 0x60 but calldata ends right after the length word
    await eq('eWithStr truncTail', '0x' + msel + pad(1n) + pad(0x60n) + pad(1n) + pad(0x40n));
    // dirty bool arg (high bits set) in error - solc reverts on out-of-range bool
    await eq('eWithStr dirtyBool', '0x' + msel + pad(1n) + pad(0x60n) + pad(2n) + pad(0n));
    await eq('eWithStr dirtyBoolHi', '0x' + msel + pad(1n) + pad(0x60n) + pad(U256_MAX) + pad(0n));

    // malformed event dynamic-arg calldata: evDataStr(uint256, string)
    const esel = sel('evDataStr(uint256,string)');
    for (const off of [0x20n, 0x60n, 0xffffffffn, U256_MAX, 1n << 64n]) {
      const cd = '0x' + esel + pad(7n) + pad(off) + pad(0x20n);
      await eq('evDataStr badOff ' + off.toString(16), cd);
    }
    for (const len of [0x21n, U256_MAX, 1n << 64n]) {
      const cd = '0x' + esel + pad(7n) + pad(0x40n) + pad(len) + pad(0xeeeen);
      await eq('evDataStr badLen ' + len.toString(16), cd);
    }
    await eq('evDataStr truncTail', '0x' + esel + pad(7n) + pad(0x40n));

    // malformed eJustBytes(bytes): bad offset / overlong length
    const bsel = sel('eJustBytes(bytes)');
    for (const off of [0x0n, 0x40n, U256_MAX, 1n << 64n]) {
      await eq('eJustBytes badOff ' + off.toString(16), '0x' + bsel + pad(off) + pad(0n));
    }
    for (const len of [0x21n, U256_MAX]) {
      await eq('eJustBytes badLen ' + len.toString(16), '0x' + bsel + pad(0x20n) + pad(len) + pad(1n));
    }

    // dirty high bits on narrow params for error/event narrow types (decode validation)
    // r5(uint8,int8): supply full 32-byte garbage words
    await eq('r5 garbageBoth', '0x' + sel('r5(uint8,int8)') + pad(U256_MAX) + pad(U256_MAX));
    await eq('r5 hiU8only', '0x' + sel('r5(uint8,int8)') + pad(0x100n) + pad(5n));
    await eq('r5 i8outRange', '0x' + sel('r5(uint8,int8)') + pad(5n) + pad(0x80n)); // 0x80 = 128, out of int8 range
    // evMixed narrow indexed topics with dirty high bits
    await eq(
      'evMixed garbage',
      '0x' +
        sel('evMixed(uint8,int16,bool,address,bytes4)') +
        pad(U256_MAX) +
        pad(U256_MAX) +
        pad(U256_MAX) +
        pad(U256_MAX) +
        pad(U256_MAX),
    );
    await eq(
      'evMixed boolHi',
      '0x' + sel('evMixed(uint8,int16,bool,address,bytes4)') + pad(1n) + pad(1n) + pad(2n) + pad(A) + pad(0n),
    );

    // ---------- boundary-length sweep for dynamic string/bytes encoding ----------
    // off-by-one padding bugs hide at word boundaries: 0,1,31,32,33,63,64,65,95,96.
    const boundLens = [0, 1, 31, 32, 33, 63, 64, 65, 95, 96, 127, 128];
    for (const n of boundLens) {
      const s = 'q'.repeat(n);
      // revert string of length n
      const cdErr = '0x' + msel + pad(1n) + pad(0x60n) + pad(1n) + strTail(s);
      await eq('eWithStr boundLen ' + n, cdErr);
      // event string of length n
      const cdEv = '0x' + esel + pad(9n) + pad(0x40n) + strTail(s);
      await eq('evDataStr boundLen ' + n, cdEv);
      // bytes of length n
      const cdB = '0x' + bsel + pad(0x20n) + strTail(s);
      await eq('eJustBytes boundLen ' + n, cdB);
    }
    // non-ascii / embedded NUL / all-0xff bytes payload (no UTF-8 normalization)
    const rawBytesHex = (hex: string) => {
      const nb = hex.length / 2;
      const words = Math.ceil(nb / 32);
      return pad(BigInt(nb)) + hex.padEnd(words * 64, '0');
    };
    for (const hexPay of [
      '00',
      'ff',
      '00ff00ff',
      'ff'.repeat(40),
      '0011223344556677889900112233445566778899aabbccddeeff',
    ]) {
      const cdB = '0x' + bsel + pad(0x20n) + rawBytesHex(hexPay);
      await eq('eJustBytes rawHex ' + hexPay.slice(0, 8) + ':' + hexPay.length / 2, cdB);
      const cdEvB = '0x' + sel('evDataBytes(uint256,bytes)') + pad(1n) + pad(0x40n) + rawBytesHex(hexPay);
      await eq('evDataBytes rawHex ' + hexPay.slice(0, 8), cdEvB);
    }
    // two interleaved dynamic event fields at boundary lengths (tail offset arithmetic)
    for (const [na, nb] of [
      [31, 33],
      [32, 32],
      [0, 64],
      [65, 1],
    ] as [number, number][]) {
      const a = 'a'.repeat(na),
        b = 'b'.repeat(nb);
      const t1 = strTail(a);
      const off2 = 0x40n + BigInt(t1.length / 2);
      const cd = '0x' + sel('evStrAndBytes(string,bytes)') + pad(0x40n) + pad(off2) + t1 + strTail(b);
      await eq('evStrAndBytes ' + na + '/' + nb, cd);
    }

    if (mism.length) {
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 40)) console.log(m);
    } else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
