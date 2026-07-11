import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);

const JETH = `class C {
  acc: u256;
  cnt: u256;

  // ---- value helpers, nesting, long chains -------------------------------
  a4(x: u256): u256 { return this.b4(x) + 1n; }
  b4(x: u256): u256 { return this.c4(x) + 2n; }
  c4(x: u256): u256 { return this.d4(x) + 4n; }
  d4(x: u256): u256 { return x * 8n; }
  get chain4(x: u256): External<u256> { return this.a4(x); }
  // bare-name form of the same chain
  ba(x: u256): u256 { return bb(x) + 1n; }
  bb(x: u256): u256 { return bc(x) + 2n; }
  bc(x: u256): u256 { return bd(x) + 4n; }
  bd(x: u256): u256 { return x * 8n; }
  get chain4bare(x: u256): External<u256> { return ba(x); }

  // ---- deep recursion ----------------------------------------------------
  fib(n: u256): u256 { if (n < 2n) { return n; } return this.fib(n - 1n) + this.fib(n - 2n); }
  get fibE(n: u256): External<u256> { return this.fib(n); }
  fact(n: u256): u256 { if (n == 0n) { return 1n; } return n * this.fact(n - 1n); }
  get factE(n: u256): External<u256> { return this.fact(n); }
  // factorial that overflows for large n -> checked mul revert in a callee
  factU(n: u8): u256 { if (n == 0n) { return 1n; } return u256(n) * this.factU(n - 1n); }
  get factUE(n: u8): External<u256> { return this.factU(n); }
  // ackermann-lite (bounded)
  ack(m: u256, n: u256): u256 {
    if (m == 0n) { return n + 1n; }
    if (n == 0n) { return this.ack(m - 1n, 1n); }
    return this.ack(m - 1n, this.ack(m, n - 1n));
  }
  get ackE(m: u256, n: u256): External<u256> { return this.ack(m, n); }

  // ---- mutual recursion --------------------------------------------------
  isEven(n: u256): bool { if (n == 0n) { return true; } return this.isOdd(n - 1n); }
  isOdd(n: u256): bool { if (n == 0n) { return false; } return this.isEven(n - 1n); }
  get evenE(n: u256): External<bool> { return this.isEven(n); }
  ping(n: u256): u256 { if (n == 0n) { return 100n; } return this.pong(n - 1n) + 1n; }
  pong(n: u256): u256 { if (n == 0n) { return 200n; } return this.ping(n - 1n) + 2n; }
  get pingE(n: u256): External<u256> { return this.ping(n); }

  // ---- many params (4-8) -------------------------------------------------
  s5(a: u256, b: u256, c: u256, d: u256, e: u256): u256 { return a + b * 2n + c * 3n + d * 4n + e * 5n; }
  get s5E(a: u256, b: u256, c: u256, d: u256, e: u256): External<u256> { return this.s5(a, b, c, d, e); }
  s8(a: u256, b: u256, c: u256, d: u256, e: u256, f: u256, g: u256, h: u256): u256 {
    return a + b + c + d + e + f + g + h;
  }
  get s8E(a: u256, b: u256, c: u256, d: u256, e: u256, f: u256, g: u256, h: u256): External<u256> {
    return this.s8(a, b, c, d, e, f, g, h);
  }
  // many params, non-commutative to catch arg-order/slot bugs
  mix6(a: u256, b: u256, c: u256, d: u256, e: u256, f: u256): u256 {
    return ((a * 31n + b) * 31n + c) * 31n + d * 7n + e * 3n + f;
  }
  get mix6E(a: u256, b: u256, c: u256, d: u256, e: u256, f: u256): External<u256> { return this.mix6(a, b, c, d, e, f); }

  // ---- args that are themselves internal calls ---------------------------
  add(a: u256, b: u256): u256 { return a + b; }
  mul(a: u256, b: u256): u256 { return a * b; }
  get nestArgs(a: u256, b: u256, c: u256): External<u256> {
    return this.add(this.mul(a, b), this.mul(this.add(a, c), b));
  }
  // a function called from many sites
  dbl(x: u256): u256 { return x * 2n; }
  get manySites(a: u256, b: u256): External<u256> {
    return this.dbl(a) + this.dbl(b) + this.dbl(this.dbl(a)) + this.dbl(a + b);
  }

  // ---- internal call inside loop / conditional / ternary -----------------
  get loopSum(n: u256): External<u256> {
    let s: u256 = 0n;
    let i: u256 = 0n;
    while (i < n) { s = this.add(s, this.dbl(i)); i = i + 1n; }
    return s;
  }
  get condCall(flag: bool, x: u256): External<u256> {
    if (flag) { return this.dbl(x); }
    return this.add(x, 7n);
  }
  get ternCall(flag: bool, x: u256): External<u256> { return flag ? this.dbl(x) : this.add(x, 9n); }
  get forCall(n: u256): External<u256> {
    let s: u256 = 0n;
    for (let i: u256 = 0n; i < n; i = i + 1n) { s = this.add(s, this.mul(i, i)); }
    return s;
  }

  // ---- internal call result in arithmetic that overflows (checked) -------
  get ovf(a: u256, b: u256): External<u256> { return this.add(a, b) + 1n; }
  get ovfMul(a: u256, b: u256): External<u256> { return this.mul(a, b) * 2n; }
  // callee does the overflowing op
  addStrict(a: u256, b: u256): u256 { return a + b; }
  get addStrictE(a: u256, b: u256): External<u256> { return this.addStrict(a, b); }

  // ---- signed + narrow params/returns ------------------------------------
  negate(x: i64): i64 { return -x; }
  get negateE(x: i64): External<i64> { return this.negate(x); }
  absI8(x: i8): i8 { if (x < 0n) { return -x; } return x; }
  get absI8E(x: i8): External<i8> { return this.absI8(x); }
  sumI8(a: i8, b: i8): i8 { return a + b; }
  get sumI8E(a: i8, b: i8): External<i8> { return this.sumI8(a, b); }
  addU8(a: u8, b: u8): u8 { return a + b; }
  get addU8E(a: u8, b: u8): External<u8> { return this.addU8(a, b); }
  clamp(x: i256): i256 { if (x < 0n) { return 0n; } return x; }
  get clampE(x: i256): External<i256> { return this.clamp(x); }
  widen(x: i8): i256 { return i256(x); }
  get widenE(x: i8): External<i256> { return this.widen(x); }
  // narrow return truncation through a call
  narrow(x: u256): u8 { return u8(x); }
  get narrowE(x: u256): External<u8> { return this.narrow(x); }

  // ---- void returns + state propagation ----------------------------------
  bump(by: u256): void { this.acc = this.acc + by; }
  doBump(x: u256): External<void> { this.bump(x); this.bump(x); this.bump(x); }
  bumpBare(by: u256): void { this.acc = this.acc + by; }
  doBumpBare(x: u256): External<void> { bumpBare(x); bumpBare(x); }
  get getAcc(): External<u256> { return this.acc; }
  // writer in a loop
  addLoop(n: u256): External<void> { let i: u256 = 0n; while (i < n) { this.bump(i); i = i + 1n; } }
  // transitive writer
  innerWrite(v: u256): void { this.cnt = this.cnt + v; }
  outerWrite(v: u256): void { this.innerWrite(v); this.innerWrite(v * 2n); }
  doTrans(v: u256): External<void> { this.outerWrite(v); }
  get getCnt(): External<u256> { return this.cnt; }
  // internal view read transitively -> external view
  readAcc(): u256 { return this.acc; }
  get doubleAcc(): External<u256> { return this.add(this.readAcc(), this.readAcc()); }
  // call that reads-then-writes via void then returns a value
  bumpAndGet(x: u256): External<u256> { this.bump(x); return this.acc; }

  // ---- bool returns used in control flow ---------------------------------
  gt(a: u256, b: u256): bool { return a > b; }
  get pick(a: u256, b: u256): External<u256> { if (this.gt(a, b)) { return a; } return b; }

  // ---- deep nesting of same call (compose) -------------------------------
  inc(x: u256): u256 { return x + 1n; }
  get inc8(x: u256): External<u256> {
    return this.inc(this.inc(this.inc(this.inc(this.inc(this.inc(this.inc(this.inc(x))))))));
  }

  // ---- callee that reverts via require -----------------------------------
  mustPos(x: u256): u256 { require(x > 0n, "nonpos"); return x; }
  get mustPosE(x: u256): External<u256> { return this.mustPos(x) * 2n; }
  // callee that does checked subtraction (underflow revert)
  subc(a: u256, b: u256): u256 { return a - b; }
  get subcE(a: u256, b: u256): External<u256> { return this.subc(a, b); }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256 acc;
  uint256 cnt;

  function a4(uint256 x) internal pure returns (uint256){ return b4(x) + 1; }
  function b4(uint256 x) internal pure returns (uint256){ return c4(x) + 2; }
  function c4(uint256 x) internal pure returns (uint256){ return d4(x) + 4; }
  function d4(uint256 x) internal pure returns (uint256){ return x * 8; }
  function chain4(uint256 x) external pure returns (uint256){ return a4(x); }
  function ba(uint256 x) internal pure returns (uint256){ return bb(x) + 1; }
  function bb(uint256 x) internal pure returns (uint256){ return bc(x) + 2; }
  function bc(uint256 x) internal pure returns (uint256){ return bd(x) + 4; }
  function bd(uint256 x) internal pure returns (uint256){ return x * 8; }
  function chain4bare(uint256 x) external pure returns (uint256){ return ba(x); }

  function fib(uint256 n) internal pure returns (uint256){ if (n < 2) { return n; } return fib(n - 1) + fib(n - 2); }
  function fibE(uint256 n) external pure returns (uint256){ return fib(n); }
  function fact(uint256 n) internal pure returns (uint256){ if (n == 0) { return 1; } return n * fact(n - 1); }
  function factE(uint256 n) external pure returns (uint256){ return fact(n); }
  function factU(uint8 n) internal pure returns (uint256){ if (n == 0) { return 1; } return uint256(n) * factU(n - 1); }
  function factUE(uint8 n) external pure returns (uint256){ return factU(n); }
  function ack(uint256 m, uint256 n) internal pure returns (uint256){
    if (m == 0) { return n + 1; }
    if (n == 0) { return ack(m - 1, 1); }
    return ack(m - 1, ack(m, n - 1));
  }
  function ackE(uint256 m, uint256 n) external pure returns (uint256){ return ack(m, n); }

  function isEven(uint256 n) internal pure returns (bool){ if (n == 0) { return true; } return isOdd(n - 1); }
  function isOdd(uint256 n) internal pure returns (bool){ if (n == 0) { return false; } return isEven(n - 1); }
  function evenE(uint256 n) external pure returns (bool){ return isEven(n); }
  function ping(uint256 n) internal pure returns (uint256){ if (n == 0) { return 100; } return pong(n - 1) + 1; }
  function pong(uint256 n) internal pure returns (uint256){ if (n == 0) { return 200; } return ping(n - 1) + 2; }
  function pingE(uint256 n) external pure returns (uint256){ return ping(n); }

  function s5(uint256 a, uint256 b, uint256 c, uint256 d, uint256 e) internal pure returns (uint256){ return a + b * 2 + c * 3 + d * 4 + e * 5; }
  function s5E(uint256 a, uint256 b, uint256 c, uint256 d, uint256 e) external pure returns (uint256){ return s5(a, b, c, d, e); }
  function s8(uint256 a, uint256 b, uint256 c, uint256 d, uint256 e, uint256 f, uint256 g, uint256 h) internal pure returns (uint256){
    return a + b + c + d + e + f + g + h;
  }
  function s8E(uint256 a, uint256 b, uint256 c, uint256 d, uint256 e, uint256 f, uint256 g, uint256 h) external pure returns (uint256){
    return s8(a, b, c, d, e, f, g, h);
  }
  function mix6(uint256 a, uint256 b, uint256 c, uint256 d, uint256 e, uint256 f) internal pure returns (uint256){
    return ((a * 31 + b) * 31 + c) * 31 + d * 7 + e * 3 + f;
  }
  function mix6E(uint256 a, uint256 b, uint256 c, uint256 d, uint256 e, uint256 f) external pure returns (uint256){ return mix6(a, b, c, d, e, f); }

  function add(uint256 a, uint256 b) internal pure returns (uint256){ return a + b; }
  function mul(uint256 a, uint256 b) internal pure returns (uint256){ return a * b; }
  function nestArgs(uint256 a, uint256 b, uint256 c) external pure returns (uint256){
    return add(mul(a, b), mul(add(a, c), b));
  }
  function dbl(uint256 x) internal pure returns (uint256){ return x * 2; }
  function manySites(uint256 a, uint256 b) external pure returns (uint256){
    return dbl(a) + dbl(b) + dbl(dbl(a)) + dbl(a + b);
  }

  function loopSum(uint256 n) external pure returns (uint256){
    uint256 s = 0;
    uint256 i = 0;
    while (i < n) { s = add(s, dbl(i)); i = i + 1; }
    return s;
  }
  function condCall(bool flag, uint256 x) external pure returns (uint256){
    if (flag) { return dbl(x); }
    return add(x, 7);
  }
  function ternCall(bool flag, uint256 x) external pure returns (uint256){ return flag ? dbl(x) : add(x, 9); }
  function forCall(uint256 n) external pure returns (uint256){
    uint256 s = 0;
    for (uint256 i = 0; i < n; i = i + 1) { s = add(s, mul(i, i)); }
    return s;
  }

  function ovf(uint256 a, uint256 b) external pure returns (uint256){ return add(a, b) + 1; }
  function ovfMul(uint256 a, uint256 b) external pure returns (uint256){ return mul(a, b) * 2; }
  function addStrict(uint256 a, uint256 b) internal pure returns (uint256){ return a + b; }
  function addStrictE(uint256 a, uint256 b) external pure returns (uint256){ return addStrict(a, b); }

  function negate(int64 x) internal pure returns (int64){ return -x; }
  function negateE(int64 x) external pure returns (int64){ return negate(x); }
  function absI8(int8 x) internal pure returns (int8){ if (x < 0) { return -x; } return x; }
  function absI8E(int8 x) external pure returns (int8){ return absI8(x); }
  function sumI8(int8 a, int8 b) internal pure returns (int8){ return a + b; }
  function sumI8E(int8 a, int8 b) external pure returns (int8){ return sumI8(a, b); }
  function addU8(uint8 a, uint8 b) internal pure returns (uint8){ return a + b; }
  function addU8E(uint8 a, uint8 b) external pure returns (uint8){ return addU8(a, b); }
  function clamp(int256 x) internal pure returns (int256){ if (x < 0) { return 0; } return x; }
  function clampE(int256 x) external pure returns (int256){ return clamp(x); }
  function widen(int8 x) internal pure returns (int256){ return int256(x); }
  function widenE(int8 x) external pure returns (int256){ return widen(x); }
  function narrow(uint256 x) internal pure returns (uint8){ return uint8(x); }
  function narrowE(uint256 x) external pure returns (uint8){ return narrow(x); }

  function bump(uint256 by) internal { acc = acc + by; }
  function doBump(uint256 x) external { bump(x); bump(x); bump(x); }
  function bumpBare(uint256 by) internal { acc = acc + by; }
  function doBumpBare(uint256 x) external { bumpBare(x); bumpBare(x); }
  function getAcc() external view returns (uint256){ return acc; }
  function addLoop(uint256 n) external { uint256 i = 0; while (i < n) { bump(i); i = i + 1; } }
  function innerWrite(uint256 v) internal { cnt = cnt + v; }
  function outerWrite(uint256 v) internal { innerWrite(v); innerWrite(v * 2); }
  function doTrans(uint256 v) external { outerWrite(v); }
  function getCnt() external view returns (uint256){ return cnt; }
  function readAcc() internal view returns (uint256){ return acc; }
  function doubleAcc() external view returns (uint256){ return add(readAcc(), readAcc()); }
  function bumpAndGet(uint256 x) external returns (uint256){ bump(x); return acc; }

  function gt(uint256 a, uint256 b) internal pure returns (bool){ return a > b; }
  function pick(uint256 a, uint256 b) external pure returns (uint256){ if (gt(a, b)) { return a; } return b; }

  function inc(uint256 x) internal pure returns (uint256){ return x + 1; }
  function inc8(uint256 x) external pure returns (uint256){
    return inc(inc(inc(inc(inc(inc(inc(inc(x))))))));
  }

  function mustPos(uint256 x) internal pure returns (uint256){ require(x > 0, "nonpos"); return x; }
  function mustPosE(uint256 x) external pure returns (uint256){ return mustPos(x) * 2; }
  function subc(uint256 a, uint256 b) internal pure returns (uint256){ return a - b; }
  function subcE(uint256 a, uint256 b) external pure returns (uint256){ return subc(a, b); }
}`;

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
  // For stateful tests: drive both, then compare a view.
  async function drive(data: string) {
    await jeth.call(aj, data);
    await sol.call(as, data);
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
    // chains (both forms)
    for (const x of [0n, 1n, 2n, 5n, 100n, M - 1n, M >> 4n]) {
      await eq('chain4(' + x + ')', encodeCall(sel('chain4(uint256)'), [x]));
      await eq('chain4bare(' + x + ')', encodeCall(sel('chain4bare(uint256)'), [x]));
    }
    // d4 multiplies by 8 -> overflow boundary
    await eq('chain4 ovf', encodeCall(sel('chain4(uint256)'), [(M - 1n) / 8n + 1n]));

    // recursion: fib, fact (incl overflow), ack
    for (const n of [0n, 1n, 2n, 5n, 10n, 15n, 18n, 20n, 24n])
      await eq('fibE(' + n + ')', encodeCall(sel('fibE(uint256)'), [n]));
    for (const n of [0n, 1n, 5n, 10n, 20n, 50n, 57n, 58n, 59n])
      await eq('factE(' + n + ')', encodeCall(sel('factE(uint256)'), [n]));
    // factU(n: u8): for n>=58 the u256 product overflows -> checked revert in callee
    for (let n = 0n; n <= 60n; n++) await eq('factUE(' + n + ')', encodeCall(sel('factUE(uint8)'), [n]));
    // dirty high bits on the u8 param
    await eq('factUE dirty', encodeCall(sel('factUE(uint8)'), [(0xffn << 8n) | 5n]));
    for (const [m, n] of [
      [0n, 0n],
      [0n, 5n],
      [1n, 0n],
      [1n, 3n],
      [2n, 0n],
      [2n, 2n],
      [2n, 3n],
      [3n, 1n],
      [3n, 2n],
      [3n, 3n],
    ] as [bigint, bigint][])
      await eq('ackE(' + m + ',' + n + ')', encodeCall(sel('ackE(uint256,uint256)'), [m, n]));

    // mutual recursion
    for (const n of [0n, 1n, 2n, 3n, 10n, 11n, 50n])
      await eq('evenE(' + n + ')', encodeCall(sel('evenE(uint256)'), [n]));
    for (const n of [0n, 1n, 2n, 3n, 4n, 5n, 6n, 20n])
      await eq('pingE(' + n + ')', encodeCall(sel('pingE(uint256)'), [n]));

    // many params
    const five: bigint[][] = [
      [1n, 2n, 3n, 4n, 5n],
      [0n, 0n, 0n, 0n, 0n],
      [M - 1n, 0n, 0n, 0n, 0n],
      [100n, 200n, 300n, 400n, 500n],
    ];
    for (const p of five)
      await eq('s5E(' + p.join(',') + ')', encodeCall(sel('s5E(uint256,uint256,uint256,uint256,uint256)'), p));
    // s5 with values that overflow at e*5
    await eq('s5E ovf', encodeCall(sel('s5E(uint256,uint256,uint256,uint256,uint256)'), [0n, 0n, 0n, 0n, M - 1n]));
    const eight: bigint[] = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n];
    await eq('s8E', encodeCall(sel('s8E(uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256)'), eight));
    await eq(
      's8E ovf',
      encodeCall(sel('s8E(uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256)'), [
        M - 1n,
        1n,
        1n,
        0n,
        0n,
        0n,
        0n,
        0n,
      ]),
    );
    for (const p of [
      [1n, 2n, 3n, 4n, 5n, 6n],
      [9n, 8n, 7n, 6n, 5n, 4n],
      [M - 1n, 1n, 1n, 1n, 1n, 1n],
    ] as bigint[][])
      await eq(
        'mix6E(' + p.join(',') + ')',
        encodeCall(sel('mix6E(uint256,uint256,uint256,uint256,uint256,uint256)'), p),
      );

    // args that are internal calls
    for (const [a, b, c] of [
      [1n, 2n, 3n],
      [10n, 20n, 30n],
      [0n, 0n, 0n],
      [M - 1n, 1n, 0n],
    ] as [bigint, bigint, bigint][])
      await eq(
        'nestArgs(' + a + ',' + b + ',' + c + ')',
        encodeCall(sel('nestArgs(uint256,uint256,uint256)'), [a, b, c]),
      );
    for (const [a, b] of [
      [1n, 2n],
      [100n, 50n],
      [M >> 3n, 0n],
      [M - 1n, 0n],
    ] as [bigint, bigint][])
      await eq('manySites(' + a + ',' + b + ')', encodeCall(sel('manySites(uint256,uint256)'), [a, b]));

    // call in loop / cond / ternary / for
    for (const n of [0n, 1n, 5n, 10n, 50n]) {
      await eq('loopSum(' + n + ')', encodeCall(sel('loopSum(uint256)'), [n]));
      await eq('forCall(' + n + ')', encodeCall(sel('forCall(uint256)'), [n]));
    }
    for (const f of [0n, 1n])
      for (const x of [3n, 100n, M - 1n]) {
        await eq('condCall(' + f + ',' + x + ')', encodeCall(sel('condCall(bool,uint256)'), [f, x]));
        await eq('ternCall(' + f + ',' + x + ')', encodeCall(sel('ternCall(bool,uint256)'), [f, x]));
      }
    // dirty bool high bits (nonzero -> true)
    await eq('condCall dirty', encodeCall(sel('condCall(bool,uint256)'), [0xffn, 5n]));
    await eq('ternCall dirty', encodeCall(sel('ternCall(bool,uint256)'), [256n, 5n]));

    // overflow via call result in arithmetic
    for (const [a, b] of [
      [M - 1n, 1n],
      [M - 2n, 1n],
      [M - 1n, 0n],
      [M >> 1n, M >> 1n],
    ] as [bigint, bigint][]) {
      await eq('ovf(' + a + ',' + b + ')', encodeCall(sel('ovf(uint256,uint256)'), [a, b]));
      await eq('ovfMul(' + a + ',' + b + ')', encodeCall(sel('ovfMul(uint256,uint256)'), [a, b]));
      await eq('addStrictE(' + a + ',' + b + ')', encodeCall(sel('addStrictE(uint256,uint256)'), [a, b]));
    }

    // signed/narrow params + returns, INT_MIN / type-max boundaries
    const i64min = -(1n << 63n),
      i64max = (1n << 63n) - 1n;
    for (const x of [0n, 1n, -1n, 100n, -100n, i64max, i64min, i64min + 1n]) {
      const xv = ((x % M) + M) % M;
      await eq('negateE(' + x + ')', encodeCall(sel('negateE(int64)'), [xv]));
    }
    const i8min = -128n,
      i8max = 127n;
    for (const x of [0n, 1n, -1n, 5n, -5n, i8max, i8min, i8min + 1n]) {
      const xv = ((x % M) + M) % M;
      await eq('absI8E(' + x + ')', encodeCall(sel('absI8E(int8)'), [xv]));
    }
    for (const [a, b] of [
      [1n, 2n],
      [127n, 1n],
      [-128n, -1n],
      [100n, 100n],
      [-100n, -100n],
      [127n, 127n],
    ] as [bigint, bigint][]) {
      const av = ((a % M) + M) % M,
        bv = ((b % M) + M) % M;
      await eq('sumI8E(' + a + ',' + b + ')', encodeCall(sel('sumI8E(int8,int8)'), [av, bv]));
    }
    for (const [a, b] of [
      [1n, 2n],
      [255n, 1n],
      [200n, 100n],
      [255n, 255n],
      [128n, 128n],
    ] as [bigint, bigint][])
      await eq('addU8E(' + a + ',' + b + ')', encodeCall(sel('addU8E(uint8,uint8)'), [a, b]));
    // dirty high bits on narrow signed param (sign-extension correctness)
    await eq('sumI8E dirty', encodeCall(sel('sumI8E(int8,int8)'), [(0xffffn << 8n) | 0x7fn, 1n])); // payload 0x7f=127
    await eq('absI8E dirty', encodeCall(sel('absI8E(int8)'), [(0xffn << 8n) | 0x80n])); // payload 0x80=-128
    const i256min = -(1n << 255n),
      i256max = (1n << 255n) - 1n;
    for (const x of [0n, 1n, -1n, i256max, i256min, i256min + 1n]) {
      const xv = ((x % M) + M) % M;
      await eq('clampE(' + x + ')', encodeCall(sel('clampE(int256)'), [xv]));
    }
    for (const x of [0n, 1n, -1n, 127n, -128n, 100n, -100n]) {
      const xv = ((x % M) + M) % M;
      await eq('widenE(' + x + ')', encodeCall(sel('widenE(int8)'), [xv]));
    }
    for (const x of [0n, 1n, 255n, 256n, 257n, M - 1n, 0x1ffn])
      await eq('narrowE(' + x + ')', encodeCall(sel('narrowE(uint256)'), [x]));

    // bool return used in control flow
    for (const [a, b] of [
      [5n, 3n],
      [3n, 5n],
      [0n, 0n],
      [M - 1n, 0n],
    ] as [bigint, bigint][])
      await eq('pick(' + a + ',' + b + ')', encodeCall(sel('pick(uint256,uint256)'), [a, b]));

    // deep compose of inc
    for (const x of [0n, 100n, M - 9n, M - 8n]) await eq('inc8(' + x + ')', encodeCall(sel('inc8(uint256)'), [x]));

    // callee reverting via require / checked sub underflow
    for (const x of [0n, 1n, 100n]) await eq('mustPosE(' + x + ')', encodeCall(sel('mustPosE(uint256)'), [x]));
    for (const [a, b] of [
      [5n, 3n],
      [3n, 5n],
      [0n, 1n],
      [1n, 0n],
      [M - 1n, M - 1n],
    ] as [bigint, bigint][])
      await eq('subcE(' + a + ',' + b + ')', encodeCall(sel('subcE(uint256,uint256)'), [a, b]));

    // ---- void / state propagation (drive both, compare a view) -----------
    await drive(encodeCall(sel('doBump(uint256)'), [3n]));
    await drive(encodeCall(sel('doBump(uint256)'), [10n]));
    await drive(encodeCall(sel('doBumpBare(uint256)'), [7n]));
    await drive(encodeCall(sel('addLoop(uint256)'), [10n]));
    await eq('getAcc after bumps', encodeCall(sel('getAcc()'), []));
    await eq('doubleAcc', encodeCall(sel('doubleAcc()'), []));
    await eq('bumpAndGet', encodeCall(sel('bumpAndGet(uint256)'), [5n]));
    await eq('getAcc after bumpAndGet', encodeCall(sel('getAcc()'), []));
    await drive(encodeCall(sel('doTrans(uint256)'), [4n]));
    await drive(encodeCall(sel('doTrans(uint256)'), [11n]));
    await eq('getCnt after trans', encodeCall(sel('getCnt()'), []));

    if (mism.length) {
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 40)) console.log(m);
    } else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
