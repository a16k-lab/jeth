import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
const M = 1n << 256n;
const U = M - 1n;
const I256_MIN = -(1n << 255n);
const I256_MAX = (1n << 255n) - 1n;
const sel = (s: string) => functionSelector(s);
const asWord = (v: bigint) => ((v % M) + M) % M;

const JETH = `@contract class C {
  @state acc: u256;
  @state sacc: i256;
  @state hits: u256;

  // --- body runs once even when cond is false on entry ---
  @external @pure runsOnce(n: u256): u256 { let c: u256 = 0n; do { c = c + 1n; } while (c < n); return c; }
  @external @pure runsOnceFalse(): u256 { let c: u256 = 0n; do { c = c + 7n; } while (false); return c; }
  @external @pure bodyOnceCondVar(flag: bool): u256 { let c: u256 = 0n; do { c = c + 1n; } while (flag); return c; }

  // --- basic accumulation ---
  @external @pure sumTo(n: u256): u256 { let s: u256 = 0n; let i: u256 = 0n; do { i = i + 1n; s = s + i; } while (i < n); return s; }
  @external @pure countDown(n: u256): u256 { let c: u256 = n; let steps: u256 = 0n; do { if (c > 0n) { c = c - 1n; } steps = steps + 1n; } while (c > 0n); return steps; }

  // --- continue must RE-EVALUATE the condition (not skip it) ---
  @external @pure skipEvens(n: u256): u256 { let s: u256 = 0n; let i: u256 = 0n; do { i = i + 1n; if (i % 2n == 0n) { continue; } s = s + i; } while (i < n); return s; }
  @external @pure contManyTimes(n: u256): u256 { let i: u256 = 0n; let body: u256 = 0n; do { body = body + 1n; i = i + 1n; if (i < n) { continue; } } while (i < n); return body * 1000000n + i; }
  // continue where the post-continue work would otherwise change the loop variable
  @external @pure contNoInc(n: u256): u256 { let i: u256 = 0n; let guard: u256 = 0n; do { i = i + 1n; if (i >= n) { continue; } guard = guard + 1n; } while (i < n); return guard * 1000000n + i; }

  // --- break exits immediately ---
  @external @pure breakAt(n: u256, lim: u256): u256 { let i: u256 = 0n; do { i = i + 1n; if (i == lim) { break; } } while (i < n); return i; }
  @external @pure breakFirst(n: u256): u256 { let i: u256 = 0n; do { i = i + 1n; break; } while (i < n); return i; }
  @external @pure breakInElse(n: u256): u256 { let s: u256 = 0n; let i: u256 = 0n; do { i = i + 1n; if (i % 2n == 0n) { s = s + i; } else { if (i > n) { break; } } } while (i < 100n); return s * 1000n + i; }

  // --- deeply nested do-while with break/continue at each level ---
  @external @pure grid(a: u256, b: u256): u256 {
    let total: u256 = 0n; let i: u256 = 0n;
    do { i = i + 1n; let j: u256 = 0n;
      do { j = j + 1n; if (j == 3n) { continue; } total = total + i * j; } while (j < b);
    } while (i < a);
    return total;
  }
  @external @pure triple(a: u256, b: u256, c: u256): u256 {
    let t: u256 = 0n; let i: u256 = 0n;
    do { i = i + 1n; let j: u256 = 0n;
      do { j = j + 1n; let k: u256 = 0n;
        do { k = k + 1n; if (k == 2n) { continue; } if (k > 4n) { break; } t = t + 1n; } while (k < c);
        if (j == b) { break; }
      } while (j < b);
      if (i > a) { break; }
    } while (i < a);
    return t;
  }
  @external @pure innerBreakOuterContinue(a: u256, b: u256): u256 {
    let t: u256 = 0n; let i: u256 = 0n;
    do { i = i + 1n; if (i % 2n == 0n) { continue; } let j: u256 = 0n;
      do { j = j + 1n; if (j == b) { break; } t = t + 1n; } while (j < 50n);
    } while (i < a);
    return t;
  }

  // --- do-while that MUTATES state and whose CONDITION reads state ---
  @external pumpState(steps: u256): void { let k: u256 = 0n; do { this.acc = this.acc + k; k = k + 1n; } while (k < steps); }
  @external drainWhileState(): void { do { this.acc = this.acc - 1n; } while (this.acc > 0n); }
  @external condReadsState(target: u256): void { do { this.acc = this.acc + 1n; } while (this.acc < target); }
  @external @view getAcc(): u256 { return this.acc; }
  @external setAcc(v: u256): void { this.acc = v; }

  // --- do-while with a SIDE-EFFECTING condition ---
  @external sideCond(n: u256): void { let i: u256 = 0n; do { i = i + 1n; } while ((this.hits = this.hits + 1n) < n); }
  @external @view getHits(): u256 { return this.hits; }
  @external resetHits(): void { this.hits = 0n; }
  // condition that increments the loop var as a side effect
  @external @pure sideIncCond(n: u256): u256 { let i: u256 = 0n; let body: u256 = 0n; do { body = body + 1n; } while ((i = i + 1n) < n); return body * 1000n + i; }
  @external @pure sideCondPostfix(n: u256): u256 { let i: u256 = 0n; let body: u256 = 0n; do { body = body + 1n; } while (i++ < n); return body * 1000n + i; }
  @external @pure sideCondPrefix(n: u256): u256 { let i: u256 = 0n; let body: u256 = 0n; do { body = body + 1n; } while (++i < n); return body * 1000n + i; }

  // --- large iteration counts ---
  @external @pure bigLoop(n: u256): u256 { let s: u256 = 0n; let i: u256 = 0n; do { i = i + 1n; s = s + 1n; } while (i < n); return s; }
  @external @pure bigLoopMul(n: u256): u256 { let s: u256 = 0n; let i: u256 = 0n; do { i = i + 1n; s = s + i * 2n - 1n; } while (i < n); return s; }

  // --- do-while INSIDE for/while and vice versa ---
  @external @pure dwInFor(n: u256, m: u256): u256 { let t: u256 = 0n; for (let i: u256 = 0n; i < n; i = i + 1n) { let j: u256 = 0n; do { j = j + 1n; t = t + 1n; } while (j < m); } return t; }
  @external @pure dwInWhile(n: u256, m: u256): u256 { let t: u256 = 0n; let i: u256 = 0n; while (i < n) { i = i + 1n; let j: u256 = 0n; do { j = j + 1n; t = t + 1n; } while (j < m); } return t; }
  @external @pure forInDw(n: u256, m: u256): u256 { let t: u256 = 0n; let i: u256 = 0n; do { i = i + 1n; for (let j: u256 = 0n; j < m; j = j + 1n) { t = t + 1n; } } while (i < n); return t; }
  @external @pure whileInDw(n: u256, m: u256): u256 { let t: u256 = 0n; let i: u256 = 0n; do { i = i + 1n; let j: u256 = 0n; while (j < m) { j = j + 1n; t = t + 1n; } } while (i < n); return t; }
  @external @pure dwInForWithBreak(n: u256, m: u256): u256 { let t: u256 = 0n; for (let i: u256 = 0n; i < n; i = i + 1n) { let j: u256 = 0n; do { j = j + 1n; if (j == 3n) { break; } t = t + 1n; } while (j < m); if (i == 5n) { break; } } return t; }

  // --- EARLY RETURN from inside a do-while ---
  @external @pure earlyReturn(n: u256, k: u256): u256 { let i: u256 = 0n; do { i = i + 1n; if (i == k) { return i * 100n; } } while (i < n); return 999n; }
  @external @pure returnFromNestedDw(a: u256, b: u256): u256 { let i: u256 = 0n; do { i = i + 1n; let j: u256 = 0n; do { j = j + 1n; if (i * j > 6n) { return i * 10n + j; } } while (j < b); } while (i < a); return 0n; }
  @external @pure returnInCondPath(n: u256): u256 { let i: u256 = 0n; do { i = i + 1n; } while (i < n ? true : returnHelper()); return i; }
  @pure returnHelper(): bool { return false; }

  // --- UNCHECKED arithmetic inside the body ---
  @external @pure uncheckedSum(n: u256): u256 { let s: u256 = 0n; let i: u256 = 0n; unchecked: { do { i = i + 1n; s = s + i; } while (i < n); } return s; }
  @external @pure uncheckedWrapBody(start: u256, n: u256): u256 { let x: u256 = start; let i: u256 = 0n; do { i = i + 1n; unchecked: { x = x - 1n; } } while (i < n); return x; }
  @external @pure uncheckedCountUp(start: u256, n: u256): u256 { let x: u256 = start; let i: u256 = 0n; do { unchecked: { x = x + 1n; } i = i + 1n; } while (i < n); return x; }

  // --- counter UNDERFLOW / OVERFLOW boundaries (checked => revert) ---
  @external @pure checkedUnderflow(start: u256, n: u256): u256 { let x: u256 = start; let i: u256 = 0n; do { x = x - 1n; i = i + 1n; } while (i < n); return x; }
  @external @pure checkedOverflow(start: u256, n: u256): u256 { let x: u256 = start; let i: u256 = 0n; do { x = x + 1n; i = i + 1n; } while (i < n); return x; }
  // signed body
  @external @pure signedDown(start: i256, n: u256): i256 { let x: i256 = start; let i: u256 = 0n; do { x = x - 1n; i = i + 1n; } while (i < n); return x; }
  @external @pure signedUp(start: i256, n: u256): i256 { let x: i256 = start; let i: u256 = 0n; do { x = x + 1n; i = i + 1n; } while (i < n); return x; }

  // --- condition with complex / dirty boolean expressions ---
  @external @pure condAnd(n: u256, m: u256): u256 { let i: u256 = 0n; do { i = i + 1n; } while (i < n && i < m); return i; }
  @external @pure condOr(n: u256, m: u256): u256 { let i: u256 = 0n; do { i = i + 1n; } while (i < n || i < m); return i; }
  @external @pure condNot(n: u256): u256 { let i: u256 = 0n; do { i = i + 1n; } while (!(i >= n)); return i; }
  @external @pure condShortCircuitRevert(n: u256): u256 { let i: u256 = 0n; do { i = i + 1n; } while (i < n && (100n / (n - i + 1n)) > 0n); return i; }

  // --- nested do-while where inner uses outer loop var ---
  @external @pure triangleDw(n: u256): u256 { let t: u256 = 0n; let i: u256 = 0n; do { i = i + 1n; let j: u256 = 0n; do { j = j + 1n; t = t + 1n; } while (j < i); } while (i < n); return t; }

  // --- prefix/postfix in the body, value-position effects ---
  @external @pure postfixBody(n: u256): u256 { let i: u256 = 0n; let s: u256 = 0n; do { s = s + i++; } while (i < n); return s * 1000n + i; }
  @external @pure prefixBody(n: u256): u256 { let i: u256 = 0n; let s: u256 = 0n; do { s = s + ++i; } while (i < n); return s * 1000n + i; }

  // --- do-while with no observable variable, just side effects to multiple state slots ---
  @external multiState(n: u256): void { let i: u256 = 0n; do { this.acc = this.acc + 1n; this.hits = this.hits + this.acc; i = i + 1n; } while (i < n); }

  // === WAVE 2: revert-timing & exotic conditions ===
  // condition itself divides by a value that hits zero exactly at the boundary -> revert in condition
  @external @pure condDivZero(n: u256): u256 { let i: u256 = 0n; do { i = i + 1n; } while ((100n / (n - i)) >= 0n); return i; }
  // body reverts (checked) at a precise iteration; verify same iteration as solc
  @external @pure bodyRevertAt(start: u256, step: u256): u256 { let x: u256 = start; let i: u256 = 0n; do { x = x - step; i = i + 1n; } while (true); return x; }
  // do-while with require inside body
  @external @pure requireInBody(n: u256, fail: u256): u256 { let i: u256 = 0n; do { i = i + 1n; require(i != fail, "boom"); } while (i < n); return i; }
  // condition reads a postfix that wraps in unchecked
  @external @pure uncheckedCondWrap(start: u256): u256 { let i: u256 = start; let body: u256 = 0n; unchecked: { do { body = body + 1n; } while (i++ != 0n ? false : (i < 3n)); } return body * 1000n + i; }
  // nested do-while, inner condition has side effect that the outer condition reads
  @external @pure sharedSideEffect(n: u256): u256 { let i: u256 = 0n; let t: u256 = 0n; do { let j: u256 = 0n; do { j = j + 1n; t = t + 1n; } while ((i = i + 1n) < n && j < 2n); } while (i < n); return t * 1000n + i; }
  // do-while inside a for whose body early-returns from deep inside
  @external @pure deepEarlyReturn(n: u256, m: u256, target: u256): u256 {
    for (let i: u256 = 0n; i < n; i = i + 1n) {
      let j: u256 = 0n;
      do { j = j + 1n; let k: u256 = 0n;
        do { k = k + 1n; if (i * 100n + j * 10n + k == target) { return i * 100n + j * 10n + k; } } while (k < m);
      } while (j < m);
    }
    return 999999n;
  }
  // empty body do-while (only condition has effect)
  @external @pure emptyBody(n: u256): u256 { let i: u256 = 0n; do { } while ((i = i + 1n) < n); return i; }
  // do-while where the only break is reached via the condition being a comma-like chained assign
  @external @pure chainedAssignCond(n: u256): u256 { let a: u256 = 0n; let b: u256 = 0n; do { b = b + 1n; } while ((a = b) < n); return a * 1000n + b; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  uint256 acc;
  int256 sacc;
  uint256 hits;

  function runsOnce(uint256 n) external pure returns (uint256){ uint256 c = 0; do { c = c + 1; } while (c < n); return c; }
  function runsOnceFalse() external pure returns (uint256){ uint256 c = 0; do { c = c + 7; } while (false); return c; }
  function bodyOnceCondVar(bool flag) external pure returns (uint256){ uint256 c = 0; do { c = c + 1; } while (flag); return c; }

  function sumTo(uint256 n) external pure returns (uint256){ uint256 s = 0; uint256 i = 0; do { i = i + 1; s = s + i; } while (i < n); return s; }
  function countDown(uint256 n) external pure returns (uint256){ uint256 c = n; uint256 steps = 0; do { if (c > 0) { c = c - 1; } steps = steps + 1; } while (c > 0); return steps; }

  function skipEvens(uint256 n) external pure returns (uint256){ uint256 s = 0; uint256 i = 0; do { i = i + 1; if (i % 2 == 0) { continue; } s = s + i; } while (i < n); return s; }
  function contManyTimes(uint256 n) external pure returns (uint256){ uint256 i = 0; uint256 body = 0; do { body = body + 1; i = i + 1; if (i < n) { continue; } } while (i < n); return body * 1000000 + i; }
  function contNoInc(uint256 n) external pure returns (uint256){ uint256 i = 0; uint256 guard = 0; do { i = i + 1; if (i >= n) { continue; } guard = guard + 1; } while (i < n); return guard * 1000000 + i; }

  function breakAt(uint256 n, uint256 lim) external pure returns (uint256){ uint256 i = 0; do { i = i + 1; if (i == lim) { break; } } while (i < n); return i; }
  function breakFirst(uint256 n) external pure returns (uint256){ uint256 i = 0; do { i = i + 1; break; } while (i < n); return i; }
  function breakInElse(uint256 n) external pure returns (uint256){ uint256 s = 0; uint256 i = 0; do { i = i + 1; if (i % 2 == 0) { s = s + i; } else { if (i > n) { break; } } } while (i < 100); return s * 1000 + i; }

  function grid(uint256 a, uint256 b) external pure returns (uint256){
    uint256 total = 0; uint256 i = 0;
    do { i = i + 1; uint256 j = 0;
      do { j = j + 1; if (j == 3) { continue; } total = total + i * j; } while (j < b);
    } while (i < a);
    return total;
  }
  function triple(uint256 a, uint256 b, uint256 c) external pure returns (uint256){
    uint256 t = 0; uint256 i = 0;
    do { i = i + 1; uint256 j = 0;
      do { j = j + 1; uint256 k = 0;
        do { k = k + 1; if (k == 2) { continue; } if (k > 4) { break; } t = t + 1; } while (k < c);
        if (j == b) { break; }
      } while (j < b);
      if (i > a) { break; }
    } while (i < a);
    return t;
  }
  function innerBreakOuterContinue(uint256 a, uint256 b) external pure returns (uint256){
    uint256 t = 0; uint256 i = 0;
    do { i = i + 1; if (i % 2 == 0) { continue; } uint256 j = 0;
      do { j = j + 1; if (j == b) { break; } t = t + 1; } while (j < 50);
    } while (i < a);
    return t;
  }

  function pumpState(uint256 steps) external { uint256 k = 0; do { acc = acc + k; k = k + 1; } while (k < steps); }
  function drainWhileState() external { do { acc = acc - 1; } while (acc > 0); }
  function condReadsState(uint256 target) external { do { acc = acc + 1; } while (acc < target); }
  function getAcc() external view returns (uint256){ return acc; }
  function setAcc(uint256 v) external { acc = v; }

  function sideCond(uint256 n) external { uint256 i = 0; do { i = i + 1; } while ((hits = hits + 1) < n); }
  function getHits() external view returns (uint256){ return hits; }
  function resetHits() external { hits = 0; }
  function sideIncCond(uint256 n) external pure returns (uint256){ uint256 i = 0; uint256 body = 0; do { body = body + 1; } while ((i = i + 1) < n); return body * 1000 + i; }
  function sideCondPostfix(uint256 n) external pure returns (uint256){ uint256 i = 0; uint256 body = 0; do { body = body + 1; } while (i++ < n); return body * 1000 + i; }
  function sideCondPrefix(uint256 n) external pure returns (uint256){ uint256 i = 0; uint256 body = 0; do { body = body + 1; } while (++i < n); return body * 1000 + i; }

  function bigLoop(uint256 n) external pure returns (uint256){ uint256 s = 0; uint256 i = 0; do { i = i + 1; s = s + 1; } while (i < n); return s; }
  function bigLoopMul(uint256 n) external pure returns (uint256){ uint256 s = 0; uint256 i = 0; do { i = i + 1; s = s + i * 2 - 1; } while (i < n); return s; }

  function dwInFor(uint256 n, uint256 m) external pure returns (uint256){ uint256 t = 0; for (uint256 i = 0; i < n; i = i + 1) { uint256 j = 0; do { j = j + 1; t = t + 1; } while (j < m); } return t; }
  function dwInWhile(uint256 n, uint256 m) external pure returns (uint256){ uint256 t = 0; uint256 i = 0; while (i < n) { i = i + 1; uint256 j = 0; do { j = j + 1; t = t + 1; } while (j < m); } return t; }
  function forInDw(uint256 n, uint256 m) external pure returns (uint256){ uint256 t = 0; uint256 i = 0; do { i = i + 1; for (uint256 j = 0; j < m; j = j + 1) { t = t + 1; } } while (i < n); return t; }
  function whileInDw(uint256 n, uint256 m) external pure returns (uint256){ uint256 t = 0; uint256 i = 0; do { i = i + 1; uint256 j = 0; while (j < m) { j = j + 1; t = t + 1; } } while (i < n); return t; }
  function dwInForWithBreak(uint256 n, uint256 m) external pure returns (uint256){ uint256 t = 0; for (uint256 i = 0; i < n; i = i + 1) { uint256 j = 0; do { j = j + 1; if (j == 3) { break; } t = t + 1; } while (j < m); if (i == 5) { break; } } return t; }

  function earlyReturn(uint256 n, uint256 k) external pure returns (uint256){ uint256 i = 0; do { i = i + 1; if (i == k) { return i * 100; } } while (i < n); return 999; }
  function returnFromNestedDw(uint256 a, uint256 b) external pure returns (uint256){ uint256 i = 0; do { i = i + 1; uint256 j = 0; do { j = j + 1; if (i * j > 6) { return i * 10 + j; } } while (j < b); } while (i < a); return 0; }
  function returnInCondPath(uint256 n) external pure returns (uint256){ uint256 i = 0; do { i = i + 1; } while (i < n ? true : returnHelper()); return i; }
  function returnHelper() internal pure returns (bool){ return false; }

  function uncheckedSum(uint256 n) external pure returns (uint256){ uint256 s = 0; uint256 i = 0; unchecked { do { i = i + 1; s = s + i; } while (i < n); } return s; }
  function uncheckedWrapBody(uint256 start, uint256 n) external pure returns (uint256){ uint256 x = start; uint256 i = 0; do { i = i + 1; unchecked { x = x - 1; } } while (i < n); return x; }
  function uncheckedCountUp(uint256 start, uint256 n) external pure returns (uint256){ uint256 x = start; uint256 i = 0; do { unchecked { x = x + 1; } i = i + 1; } while (i < n); return x; }

  function checkedUnderflow(uint256 start, uint256 n) external pure returns (uint256){ uint256 x = start; uint256 i = 0; do { x = x - 1; i = i + 1; } while (i < n); return x; }
  function checkedOverflow(uint256 start, uint256 n) external pure returns (uint256){ uint256 x = start; uint256 i = 0; do { x = x + 1; i = i + 1; } while (i < n); return x; }
  function signedDown(int256 start, uint256 n) external pure returns (int256){ int256 x = start; uint256 i = 0; do { x = x - 1; i = i + 1; } while (i < n); return x; }
  function signedUp(int256 start, uint256 n) external pure returns (int256){ int256 x = start; uint256 i = 0; do { x = x + 1; i = i + 1; } while (i < n); return x; }

  function condAnd(uint256 n, uint256 m) external pure returns (uint256){ uint256 i = 0; do { i = i + 1; } while (i < n && i < m); return i; }
  function condOr(uint256 n, uint256 m) external pure returns (uint256){ uint256 i = 0; do { i = i + 1; } while (i < n || i < m); return i; }
  function condNot(uint256 n) external pure returns (uint256){ uint256 i = 0; do { i = i + 1; } while (!(i >= n)); return i; }
  function condShortCircuitRevert(uint256 n) external pure returns (uint256){ uint256 i = 0; do { i = i + 1; } while (i < n && (100 / (n - i + 1)) > 0); return i; }

  function triangleDw(uint256 n) external pure returns (uint256){ uint256 t = 0; uint256 i = 0; do { i = i + 1; uint256 j = 0; do { j = j + 1; t = t + 1; } while (j < i); } while (i < n); return t; }

  function postfixBody(uint256 n) external pure returns (uint256){ uint256 i = 0; uint256 s = 0; do { s = s + i++; } while (i < n); return s * 1000 + i; }
  function prefixBody(uint256 n) external pure returns (uint256){ uint256 i = 0; uint256 s = 0; do { s = s + ++i; } while (i < n); return s * 1000 + i; }

  function multiState(uint256 n) external { uint256 i = 0; do { acc = acc + 1; hits = hits + acc; i = i + 1; } while (i < n); }

  function condDivZero(uint256 n) external pure returns (uint256){ uint256 i = 0; do { i = i + 1; } while ((100 / (n - i)) >= 0); return i; }
  function bodyRevertAt(uint256 start, uint256 step) external pure returns (uint256){ uint256 x = start; uint256 i = 0; do { x = x - step; i = i + 1; } while (true); return x; }
  function requireInBody(uint256 n, uint256 fail) external pure returns (uint256){ uint256 i = 0; do { i = i + 1; require(i != fail, "boom"); } while (i < n); return i; }
  function uncheckedCondWrap(uint256 start) external pure returns (uint256){ uint256 i = start; uint256 body = 0; unchecked { do { body = body + 1; } while (i++ != 0 ? false : (i < 3)); } return body * 1000 + i; }
  function sharedSideEffect(uint256 n) external pure returns (uint256){ uint256 i = 0; uint256 t = 0; do { uint256 j = 0; do { j = j + 1; t = t + 1; } while ((i = i + 1) < n && j < 2); } while (i < n); return t * 1000 + i; }
  function deepEarlyReturn(uint256 n, uint256 m, uint256 target) external pure returns (uint256){
    for (uint256 i = 0; i < n; i = i + 1) {
      uint256 j = 0;
      do { j = j + 1; uint256 k = 0;
        do { k = k + 1; if (i * 100 + j * 10 + k == target) { return i * 100 + j * 10 + k; } } while (k < m);
      } while (j < m);
    }
    return 999999;
  }
  function emptyBody(uint256 n) external pure returns (uint256){ uint256 i = 0; do { } while ((i = i + 1) < n); return i; }
  function chainedAssignCond(uint256 n) external pure returns (uint256){ uint256 a = 0; uint256 b = 0; do { b = b + 1; } while ((a = b) < n); return a * 1000 + b; }
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
  // stateful: send to BOTH, then read back from both and compare
  async function sendBoth(data: string) {
    await jeth.call(aj, data);
    await sol.call(as, data);
  }
  async function eqRead(label: string, readData: string) {
    count++;
    const j = await jeth.call(aj, readData);
    const s = await sol.call(as, readData);
    if (j.success !== s.success || j.returnHex !== s.returnHex)
      mism.push(
        label +
          ': jeth{ok=' +
          j.success +
          ',ret=' +
          j.returnHex +
          '} sol{ok=' +
          s.success +
          ',ret=' +
          s.returnHex +
          '}',
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
    const smalls = [0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 13n, 16n, 20n, 31n, 32n, 50n, 64n, 100n];
    // body-runs-once family
    for (const n of smalls) {
      await eq(`runsOnce(${n})`, encodeCall(sel('runsOnce(uint256)'), [n]));
      await eq(`sumTo(${n})`, encodeCall(sel('sumTo(uint256)'), [n]));
      await eq(`countDown(${n})`, encodeCall(sel('countDown(uint256)'), [n]));
      await eq(`skipEvens(${n})`, encodeCall(sel('skipEvens(uint256)'), [n]));
      await eq(`contManyTimes(${n})`, encodeCall(sel('contManyTimes(uint256)'), [n]));
      await eq(`contNoInc(${n})`, encodeCall(sel('contNoInc(uint256)'), [n]));
      await eq(`breakFirst(${n})`, encodeCall(sel('breakFirst(uint256)'), [n]));
      await eq(`condNot(${n})`, encodeCall(sel('condNot(uint256)'), [n]));
      await eq(`sideIncCond(${n})`, encodeCall(sel('sideIncCond(uint256)'), [n]));
      await eq(`sideCondPostfix(${n})`, encodeCall(sel('sideCondPostfix(uint256)'), [n]));
      await eq(`sideCondPrefix(${n})`, encodeCall(sel('sideCondPrefix(uint256)'), [n]));
      await eq(`bigLoop(${n})`, encodeCall(sel('bigLoop(uint256)'), [n]));
      await eq(`bigLoopMul(${n})`, encodeCall(sel('bigLoopMul(uint256)'), [n]));
      await eq(`triangleDw(${n})`, encodeCall(sel('triangleDw(uint256)'), [n]));
      await eq(`postfixBody(${n})`, encodeCall(sel('postfixBody(uint256)'), [n]));
      await eq(`prefixBody(${n})`, encodeCall(sel('prefixBody(uint256)'), [n]));
      await eq(`condShortCircuitRevert(${n})`, encodeCall(sel('condShortCircuitRevert(uint256)'), [n]));
      await eq(`returnInCondPath(${n})`, encodeCall(sel('returnInCondPath(uint256)'), [n]));
    }
    await eq('runsOnceFalse', encodeCall(sel('runsOnceFalse()'), []));
    await eq('bodyOnceCondVar(true)', encodeCall(sel('bodyOnceCondVar(bool)'), [1n]));
    await eq('bodyOnceCondVar(false)', encodeCall(sel('bodyOnceCondVar(bool)'), [0n]));
    // dirty bool high bits
    await eq(
      'bodyOnceCondVar(dirty)',
      '0x' +
        sel('bodyOnceCondVar(bool)').slice(2) +
        asWord((0xffn << 8n) | 1n)
          .toString(16)
          .padStart(64, '0'),
    );

    // breakAt / earlyReturn with (n, lim)
    for (const n of [0n, 1n, 3n, 5n, 8n, 13n, 50n])
      for (const lim of [0n, 1n, 2n, 3n, 5n, 8n, 100n]) {
        await eq(`breakAt(${n},${lim})`, encodeCall(sel('breakAt(uint256,uint256)'), [n, lim]));
        await eq(`earlyReturn(${n},${lim})`, encodeCall(sel('earlyReturn(uint256,uint256)'), [n, lim]));
      }
    for (const n of [0n, 1n, 2n, 5n, 10n]) await eq(`breakInElse(${n})`, encodeCall(sel('breakInElse(uint256)'), [n]));

    // nested grid / triple / innerBreakOuterContinue / returnFromNestedDw
    for (const a of [1n, 2n, 3n, 4n, 5n])
      for (const b of [1n, 2n, 3n, 4n, 5n, 6n]) {
        await eq(`grid(${a},${b})`, encodeCall(sel('grid(uint256,uint256)'), [a, b]));
        await eq(
          `innerBreakOuterContinue(${a},${b})`,
          encodeCall(sel('innerBreakOuterContinue(uint256,uint256)'), [a, b]),
        );
        await eq(`returnFromNestedDw(${a},${b})`, encodeCall(sel('returnFromNestedDw(uint256,uint256)'), [a, b]));
        await eq(`condAnd(${a},${b})`, encodeCall(sel('condAnd(uint256,uint256)'), [a, b]));
        await eq(`condOr(${a},${b})`, encodeCall(sel('condOr(uint256,uint256)'), [a, b]));
      }
    for (const a of [1n, 2n, 3n, 4n])
      for (const b of [1n, 2n, 3n, 4n])
        for (const c of [1n, 2n, 3n, 5n, 6n]) {
          await eq(`triple(${a},${b},${c})`, encodeCall(sel('triple(uint256,uint256,uint256)'), [a, b, c]));
        }

    // dw nesting with for/while, (n, m)
    for (const n of [0n, 1n, 2n, 3n, 5n])
      for (const m of [0n, 1n, 2n, 3n, 4n]) {
        await eq(`dwInFor(${n},${m})`, encodeCall(sel('dwInFor(uint256,uint256)'), [n, m]));
        await eq(`dwInWhile(${n},${m})`, encodeCall(sel('dwInWhile(uint256,uint256)'), [n, m]));
        await eq(`forInDw(${n},${m})`, encodeCall(sel('forInDw(uint256,uint256)'), [n, m]));
        await eq(`whileInDw(${n},${m})`, encodeCall(sel('whileInDw(uint256,uint256)'), [n, m]));
        await eq(`dwInForWithBreak(${n},${m})`, encodeCall(sel('dwInForWithBreak(uint256,uint256)'), [n, m]));
      }

    // unchecked arithmetic in body
    for (const n of [0n, 1n, 2n, 5n, 10n, 256n]) {
      await eq(`uncheckedSum(${n})`, encodeCall(sel('uncheckedSum(uint256)'), [n]));
    }
    for (const start of [0n, 1n, 5n, 100n, U])
      for (const n of [0n, 1n, 2n, 5n, 10n]) {
        await eq(`uncheckedWrapBody(${start},${n})`, encodeCall(sel('uncheckedWrapBody(uint256,uint256)'), [start, n]));
        await eq(`uncheckedCountUp(${start},${n})`, encodeCall(sel('uncheckedCountUp(uint256,uint256)'), [start, n]));
      }

    // checked under/overflow boundaries (must revert at the right iteration)
    for (const start of [0n, 1n, 2n, 3n, 5n, U, U - 1n, U - 2n])
      for (const n of [0n, 1n, 2n, 3n, 4n, 6n]) {
        await eq(`checkedUnderflow(${start},${n})`, encodeCall(sel('checkedUnderflow(uint256,uint256)'), [start, n]));
        await eq(`checkedOverflow(${start},${n})`, encodeCall(sel('checkedOverflow(uint256,uint256)'), [start, n]));
      }
    // signed boundaries
    for (const start of [I256_MIN, I256_MIN + 1n, I256_MIN + 2n, 0n, I256_MAX, I256_MAX - 1n, I256_MAX - 2n, -1n, 1n]) {
      for (const n of [0n, 1n, 2n, 3n]) {
        await eq(`signedDown(${start},${n})`, encodeCall(sel('signedDown(int256,uint256)'), [asWord(start), n]));
        await eq(`signedUp(${start},${n})`, encodeCall(sel('signedUp(int256,uint256)'), [asWord(start), n]));
      }
    }

    // --- stateful: pumpState ---
    for (const s of [0n, 1n, 2n, 4n, 7n]) {
      await sendBoth(encodeCall(sel('setAcc(uint256)'), [0n]));
      await sendBoth(encodeCall(sel('pumpState(uint256)'), [s]));
      await eqRead(`pumpState(${s})->acc`, encodeCall(sel('getAcc()'), []));
    }
    // condReadsState: starts from current acc, runs body once, reads acc condition
    for (const init of [0n, 5n, 10n])
      for (const target of [0n, 1n, 3n, 8n, 12n]) {
        await sendBoth(encodeCall(sel('setAcc(uint256)'), [init]));
        await sendBoth(encodeCall(sel('condReadsState(uint256)'), [target]));
        await eqRead(`condReadsState(init=${init},t=${target})->acc`, encodeCall(sel('getAcc()'), []));
      }
    // drainWhileState: body runs once even if acc==0, so acc=0 underflows on entry-1
    for (const init of [0n, 1n, 2n, 3n, 5n]) {
      await sendBoth(encodeCall(sel('setAcc(uint256)'), [init]));
      await sendBoth(encodeCall(sel('drainWhileState()'), []));
      await eqRead(`drainWhileState(init=${init})->acc`, encodeCall(sel('getAcc()'), []));
    }
    // sideCond: side-effecting condition writes hits
    for (const n of [0n, 1n, 2n, 5n, 10n]) {
      await sendBoth(encodeCall(sel('resetHits()'), []));
      await sendBoth(encodeCall(sel('sideCond(uint256)'), [n]));
      await eqRead(`sideCond(${n})->hits`, encodeCall(sel('getHits()'), []));
    }
    // multiState writes two slots
    for (const n of [0n, 1n, 2n, 4n, 8n]) {
      await sendBoth(encodeCall(sel('setAcc(uint256)'), [0n]));
      await sendBoth(encodeCall(sel('resetHits()'), []));
      await sendBoth(encodeCall(sel('multiState(uint256)'), [n]));
      await eqRead(`multiState(${n})->acc`, encodeCall(sel('getAcc()'), []));
      await eqRead(`multiState(${n})->hits`, encodeCall(sel('getHits()'), []));
    }

    // === WAVE 2 calls ===
    for (const n of [0n, 1n, 2n, 3n, 5n, 10n, 50n]) {
      await eq(`condDivZero(${n})`, encodeCall(sel('condDivZero(uint256)'), [n]));
      await eq(`requireInBody(${n},0)`, encodeCall(sel('requireInBody(uint256,uint256)'), [n, 0n]));
      await eq(`emptyBody(${n})`, encodeCall(sel('emptyBody(uint256)'), [n]));
      await eq(`chainedAssignCond(${n})`, encodeCall(sel('chainedAssignCond(uint256)'), [n]));
    }
    for (const n of [1n, 2n, 3n, 5n, 8n])
      for (const fail of [0n, 1n, 2n, 3n, 5n, 8n, 100n]) {
        await eq(`requireInBody(${n},${fail})`, encodeCall(sel('requireInBody(uint256,uint256)'), [n, fail]));
      }
    // body reverts via checked underflow at a precise iteration (start/step)
    for (const start of [0n, 1n, 3n, 5n, 10n, 100n])
      for (const step of [1n, 2n, 3n, 4n, 7n]) {
        await eq(`bodyRevertAt(${start},${step})`, encodeCall(sel('bodyRevertAt(uint256,uint256)'), [start, step]));
      }
    for (const start of [0n, 1n, 2n, 3n, U, U - 1n]) {
      await eq(`uncheckedCondWrap(${start})`, encodeCall(sel('uncheckedCondWrap(uint256)'), [start]));
    }
    for (const n of [0n, 1n, 2n, 3n, 4n, 5n, 6n]) {
      await eq(`sharedSideEffect(${n})`, encodeCall(sel('sharedSideEffect(uint256)'), [n]));
    }
    for (const n of [0n, 1n, 2n, 3n])
      for (const m of [1n, 2n, 3n])
        for (const target of [0n, 111n, 121n, 211n, 232n, 999999n]) {
          await eq(
            `deepEarlyReturn(${n},${m},${target})`,
            encodeCall(sel('deepEarlyReturn(uint256,uint256,uint256)'), [n, m, target]),
          );
        }

    // sanity: confirm the revert-path cases actually revert on BOTH sides (not silent no-ops)
    {
      const rj = await jeth.call(aj, encodeCall(sel('bodyRevertAt(uint256,uint256)'), [3n, 2n]));
      const rs = await sol.call(as, encodeCall(sel('bodyRevertAt(uint256,uint256)'), [3n, 2n]));
      console.log('SANITY bodyRevertAt(3,2): jeth.success=' + rj.success + ' sol.success=' + rs.success);
      const cj = await jeth.call(aj, encodeCall(sel('condDivZero(uint256)'), [3n]));
      const cs = await sol.call(as, encodeCall(sel('condDivZero(uint256)'), [3n]));
      console.log('SANITY condDivZero(3): jeth.success=' + cj.success + ' sol.success=' + cs.success);
      const qj = await jeth.call(aj, encodeCall(sel('requireInBody(uint256,uint256)'), [5n, 3n]));
      const qs = await sol.call(as, encodeCall(sel('requireInBody(uint256,uint256)'), [5n, 3n]));
      console.log('SANITY requireInBody(5,3): jeth.success=' + qj.success + ' sol.success=' + qs.success);
    }
    if (mism.length) {
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 40)) console.log(m);
    } else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
