// Adversarial control-flow & expression-evaluation-order differential vs solc.
// Area: control. Covers for/while loops, nested break/continue, early return,
// fall-through, short-circuit && / || (RHS-revert non-evaluation proof), ternary
// (nested, mixed-width, in value position), prefix/postfix ++/-- in expression
// position and as statements, every compound-assign operator, boolean negation,
// boundary values (0, max, INT_MIN, wrap), unchecked wrapping.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const U256_MAX = M - 1n;
const I256_MIN = -(1n << 255n);
const I256_MAX = (1n << 255n) - 1n;
const sel = (s: string) => functionSelector(s);

// Bit pattern of an int as a 256-bit word (two's complement) for calldata.
const asWord = (v: bigint) => ((v % M) + M) % M;

const JETH = `class C {
  // ---- loops ----
  get sumTo(n: u256): External<u256> { let s: u256 = 0n; for (let i: u256 = 0n; i < n; i += 1n) { s += i; } return s; }
  get whileSum(n: u256): External<u256> { let s: u256 = 0n; let i: u256 = 0n; while (i < n) { s += i; i += 1n; } return s; }
  get emptyBodyFor(n: u256): External<u256> { let i: u256 = 0n; for (let k: u256 = 0n; k < n; k += 1n) { i += 1n; } return i; }
  get noInitFor(n: u256): External<u256> { let i: u256 = 0n; let s: u256 = 0n; for (; i < n; i += 1n) { s += i; } return s; }
  get noPostFor(n: u256): External<u256> { let s: u256 = 0n; for (let i: u256 = 0n; i < n;) { s += i; i += 1n; } return s; }
  get noCondFor(n: u256): External<u256> { let s: u256 = 0n; for (let i: u256 = 0n; ; i += 1n) { if (i >= n) { break; } s += i; } return s; }

  // ---- break / continue, nested ----
  get breakAt(n: u256, k: u256): External<u256> { let s: u256 = 0n; for (let i: u256 = 0n; i < n; i += 1n) { if (i == k) { break; } s += i; } return s; }
  get skipMul3(n: u256): External<u256> { let s: u256 = 0n; for (let i: u256 = 0n; i < n; i += 1n) { if (i % 3n == 0n) { continue; } s += i; } return s; }
  get whileBreak(n: u256): External<u256> { let i: u256 = 0n; while (true) { if (i >= n) { break; } i += 1n; } return i; }
  get whileContinue(n: u256): External<u256> { let s: u256 = 0n; let i: u256 = 0n; while (i < n) { i += 1n; if (i % 2n == 1n) { continue; } s += i; } return s; }
  get nestedBreak(n: u256): External<u256> { let s: u256 = 0n; for (let i: u256 = 0n; i < n; i += 1n) { for (let j: u256 = 0n; j < n; j += 1n) { if (j == i) { break; } s += 1n; } } return s; }
  get nestedContinue(n: u256): External<u256> { let s: u256 = 0n; for (let i: u256 = 0n; i < n; i += 1n) { for (let j: u256 = 0n; j < n; j += 1n) { if (j % 2n == 0n) { continue; } s += j; } } return s; }
  get innerBreakOnlyInner(n: u256): External<u256> { let s: u256 = 0n; for (let i: u256 = 0n; i < n; i += 1n) { for (let j: u256 = 0n; j < 5n; j += 1n) { if (j == 2n) { break; } s += 1n; } s += 100n; } return s; }
  get tripleNest(n: u256): External<u256> { let s: u256 = 0n; for (let i: u256 = 0n; i < n; i += 1n) { for (let j: u256 = 0n; j < n; j += 1n) { for (let k: u256 = 0n; k < n; k += 1n) { if (k == j) { break; } if (i == 0n) { continue; } s += 1n; } } } return s; }
  get continueThenBreak(n: u256): External<u256> { let s: u256 = 0n; for (let i: u256 = 0n; i < n; i += 1n) { if (i % 2n == 0n) { continue; } if (i > 7n) { break; } s += i; } return s; }
  get whileNestedBC(n: u256): External<u256> { let s: u256 = 0n; let i: u256 = 0n; while (i < n) { i += 1n; let j: u256 = 0n; while (j < n) { j += 1n; if (j == i) { continue; } if (j > 4n) { break; } s += 1n; } } return s; }

  // ---- early return ----
  get earlyReturn(n: u256, k: u256): External<u256> { for (let i: u256 = 0n; i < n; i += 1n) { if (i == k) { return i; } } return 999n; }
  get returnFromNested(n: u256): External<u256> { for (let i: u256 = 0n; i < n; i += 1n) { for (let j: u256 = 0n; j < n; j += 1n) { if (i * j > 6n) { return i * 10n + j; } } } return 0n; }
  get classify(x: u256): External<u256> { if (x < 10n) { return 1n; } else if (x < 20n) { return 2n; } else if (x < 30n) { return 3n; } else { return 4n; } }
  get fallThrough(x: u256): External<u256> { if (x > 100n) { return 7n; } }
  get fallThroughLoop(n: u256): External<u256> { for (let i: u256 = 0n; i < n; i += 1n) { if (i == 50n) { return 5n; } } }

  // ---- short-circuit (RHS reverts => non-evaluation proof) ----
  get andDivGuard(a: u256): External<bool> { return (a != 0n) && ((10n / a) > 0n); }
  get orDivGuard(a: u256): External<bool> { return (a == 0n) || ((10n / a) > 0n); }
  get andOverflow(c: bool, a: u256): External<bool> { return c && ((a + 1n) > a); }
  get orOverflow(c: bool, a: u256): External<bool> { return c || ((a + 1n) > a); }
  get chainAnd(a: u256, b: u256): External<bool> { return (a != 0n) && (b != 0n) && ((100n / (a * b)) > 0n); }
  get chainOr(a: u256, b: u256): External<bool> { return (a == 0n) || (b == 0n) || ((100n / (a * b)) > 0n); }
  get mixAndOr(a: u256, b: u256): External<bool> { return (a != 0n) || ((b != 0n) && ((10n / b) > 0n)); }
  get negShort(c: bool, a: u256): External<bool> { return !c && ((a + 1n) > a); }

  // ---- ternary (nested, mixed-width, value position) ----
  get ternMax(a: u256, b: u256): External<u256> { return a > b ? a : b; }
  get ternNested(x: u256): External<u256> { return x < 10n ? 1n : (x < 20n ? 2n : (x < 30n ? 3n : 4n)); }
  get ternArith(a: u256, b: u256): External<u256> { return (a > b ? a - b : b - a) + 1n; }
  get ternMixedWidth(c: bool, a: u8, b: u256): External<u256> { return c ? a : b; }
  get ternShortRevert(c: bool, a: u256): External<u256> { return c ? a + 1n : a; }
  get ternDivGuard(a: u256): External<u256> { return a == 0n ? 0n : 100n / a; }
  get ternInCond(a: u256, b: u256): External<u256> { if ((a > b ? a : b) > 50n) { return 1n; } return 0n; }
  get ternDeep(x: u256): External<u256> { return x < 2n ? (x < 1n ? 10n : 20n) : (x < 4n ? (x < 3n ? 30n : 40n) : 50n); }

  // ---- prefix/postfix ++ / -- as statements and in loops ----
  get localIncDec(a: u256): External<u256> { let x: u256 = a; x++; x++; x--; ++x; --x; return x; }
  get preVsPost(a: u256): External<u256> { let x: u256 = a; let y: u256 = 0n; x++; y += x; ++x; y += x; x--; y += x; --x; y += x; return y; }
  get forPostInc(n: u256): External<u256> { let s: u256 = 0n; for (let i: u256 = 0n; i < n; i++) { s += i; } return s; }
  get forPreInc(n: u256): External<u256> { let s: u256 = 0n; for (let i: u256 = 0n; i < n; ++i) { s += i; } return s; }
  get forDec(n: u256): External<u256> { let s: u256 = 0n; for (let i: u256 = n; i > 0n; i--) { s += i; } return s; }
  get incOverflow(a: u256): External<u256> { let x: u256 = a; x++; return x; }
  get decUnderflow(a: u256): External<u256> { let x: u256 = a; x--; return x; }
  get incSigned(a: i256): External<i256> { let x: i256 = a; x++; return x; }
  get decSigned(a: i256): External<i256> { let x: i256 = a; x--; return x; }

  // ---- compound assignment, every operator ----
  get cAdd(a: u256, b: u256): External<u256> { let x: u256 = a; x += b; return x; }
  get cSub(a: u256, b: u256): External<u256> { let x: u256 = a; x -= b; return x; }
  get cMul(a: u256, b: u256): External<u256> { let x: u256 = a; x *= b; return x; }
  get cDiv(a: u256, b: u256): External<u256> { let x: u256 = a; x /= b; return x; }
  get cMod(a: u256, b: u256): External<u256> { let x: u256 = a; x %= b; return x; }
  get cAnd(a: u256, b: u256): External<u256> { let x: u256 = a; x &= b; return x; }
  get cOr(a: u256, b: u256): External<u256> { let x: u256 = a; x |= b; return x; }
  get cXor(a: u256, b: u256): External<u256> { let x: u256 = a; x ^= b; return x; }
  get cShl(a: u256, b: u256): External<u256> { let x: u256 = a; x <<= b; return x; }
  get cShr(a: u256, b: u256): External<u256> { let x: u256 = a; x >>= b; return x; }
  get cAddSigned(a: i256, b: i256): External<i256> { let x: i256 = a; x += b; return x; }
  get cSubSigned(a: i256, b: i256): External<i256> { let x: i256 = a; x -= b; return x; }
  get cMulSigned(a: i256, b: i256): External<i256> { let x: i256 = a; x *= b; return x; }
  get cDivSigned(a: i256, b: i256): External<i256> { let x: i256 = a; x /= b; return x; }
  get cModSigned(a: i256, b: i256): External<i256> { let x: i256 = a; x %= b; return x; }
  get cShrSigned(a: i256, b: u256): External<i256> { let x: i256 = a; x >>= b; return x; }
  get cChain(a: u256): External<u256> { let x: u256 = a; x += 5n; x *= 2n; x -= 3n; x /= 2n; x %= 7n; return x; }

  // ---- boolean negation ----
  get notNot(c: bool): External<bool> { return !!c; }
  get notTriple(c: bool): External<bool> { return !!!c; }
  get negCond(x: u256): External<u256> { if (!(x > 5n)) { return 1n; } return 2n; }
  get deMorgan(a: u256, b: u256): External<bool> { return !((a > 0n) && (b > 0n)); }

  // ---- unchecked wrapping in loops/expressions ----
  get uncheckedSum(n: u256): External<u256> { let s: u256 = 0n; unchecked: { for (let i: u256 = 0n; i < n; i += 1n) { s += i; } } return s; }
  get uncheckedWrap(a: u256): External<u256> { let x: u256 = a; unchecked: { x += 1n; } return x; }
  get uncheckedIncStmt(a: u256): External<u256> { let x: u256 = a; unchecked: { x++; } return x; }

  // ---- ++ / -- in EXPRESSION position (value = old for post, new for pre) ----
  get postInExpr(a: u256): External<u256> { let x: u256 = a; let y: u256 = x++ + 5n; return x * 1000n + y; }
  get preInExpr(a: u256): External<u256> { let x: u256 = a; let y: u256 = ++x + 5n; return x * 1000n + y; }
  get postDecExpr(a: u256): External<u256> { let x: u256 = a; let y: u256 = x-- + 5n; return x * 1000n + y; }
  get preDecExpr(a: u256): External<u256> { let x: u256 = a; let y: u256 = --x + 5n; return x * 1000n + y; }
  get postTimes(a: u256): External<u256> { let x: u256 = a; let y: u256 = x++ * 2n; return x * 1000n + y; }
  get ternWithInc(c: bool, a: u256): External<u256> { let x: u256 = a; let y: u256 = c ? x++ : x--; return x * 1000n + y; }
  get andIncChain(a: u256): External<u256> { let x: u256 = a; let r: bool = (x++ > 0n) && (x++ > 100n) && (x++ > 200n); return x * 10n + (r ? 1n : 0n); }

  // ---- mixed: loop with compound + ternary + break ----
  get collatzSteps(n: u256): External<u256> { let x: u256 = n; let steps: u256 = 0n; for (let i: u256 = 0n; i < 1000n; i += 1n) { if (x <= 1n) { break; } x = (x % 2n == 0n) ? x / 2n : 3n * x + 1n; steps += 1n; } return steps; }
  get gcd(a: u256, b: u256): External<u256> { let x: u256 = a; let y: u256 = b; while (y != 0n) { let t: u256 = y; y = x % y; x = t; } return x; }
}`;

const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  function sumTo(uint256 n) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<n;i+=1){ s+=i; } return s; }
  function whileSum(uint256 n) external pure returns (uint256){ uint256 s=0; uint256 i=0; while(i<n){ s+=i; i+=1; } return s; }
  function emptyBodyFor(uint256 n) external pure returns (uint256){ uint256 i=0; for(uint256 k=0;k<n;k+=1){ i+=1; } return i; }
  function noInitFor(uint256 n) external pure returns (uint256){ uint256 i=0; uint256 s=0; for(; i<n; i+=1){ s+=i; } return s; }
  function noPostFor(uint256 n) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<n;){ s+=i; i+=1; } return s; }
  function noCondFor(uint256 n) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;;i+=1){ if(i>=n){break;} s+=i; } return s; }

  function breakAt(uint256 n, uint256 k) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<n;i+=1){ if(i==k){break;} s+=i; } return s; }
  function skipMul3(uint256 n) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<n;i+=1){ if(i%3==0){continue;} s+=i; } return s; }
  function whileBreak(uint256 n) external pure returns (uint256){ uint256 i=0; while(true){ if(i>=n){break;} i+=1; } return i; }
  function whileContinue(uint256 n) external pure returns (uint256){ uint256 s=0; uint256 i=0; while(i<n){ i+=1; if(i%2==1){continue;} s+=i; } return s; }
  function nestedBreak(uint256 n) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<n;i+=1){ for(uint256 j=0;j<n;j+=1){ if(j==i){break;} s+=1; } } return s; }
  function nestedContinue(uint256 n) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<n;i+=1){ for(uint256 j=0;j<n;j+=1){ if(j%2==0){continue;} s+=j; } } return s; }
  function innerBreakOnlyInner(uint256 n) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<n;i+=1){ for(uint256 j=0;j<5;j+=1){ if(j==2){break;} s+=1; } s+=100; } return s; }
  function tripleNest(uint256 n) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<n;i+=1){ for(uint256 j=0;j<n;j+=1){ for(uint256 k=0;k<n;k+=1){ if(k==j){break;} if(i==0){continue;} s+=1; } } } return s; }
  function continueThenBreak(uint256 n) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<n;i+=1){ if(i%2==0){continue;} if(i>7){break;} s+=i; } return s; }
  function whileNestedBC(uint256 n) external pure returns (uint256){ uint256 s=0; uint256 i=0; while(i<n){ i+=1; uint256 j=0; while(j<n){ j+=1; if(j==i){continue;} if(j>4){break;} s+=1; } } return s; }

  function earlyReturn(uint256 n, uint256 k) external pure returns (uint256){ for(uint256 i=0;i<n;i+=1){ if(i==k){ return i; } } return 999; }
  function returnFromNested(uint256 n) external pure returns (uint256){ for(uint256 i=0;i<n;i+=1){ for(uint256 j=0;j<n;j+=1){ if(i*j>6){ return i*10+j; } } } return 0; }
  function classify(uint256 x) external pure returns (uint256){ if(x<10){return 1;} else if(x<20){return 2;} else if(x<30){return 3;} else {return 4;} }
  function fallThrough(uint256 x) external pure returns (uint256){ if(x>100){ return 7; } }
  function fallThroughLoop(uint256 n) external pure returns (uint256){ for(uint256 i=0;i<n;i+=1){ if(i==50){ return 5; } } }

  function andDivGuard(uint256 a) external pure returns (bool){ return (a!=0) && ((10/a)>0); }
  function orDivGuard(uint256 a) external pure returns (bool){ return (a==0) || ((10/a)>0); }
  function andOverflow(bool c, uint256 a) external pure returns (bool){ return c && ((a+1)>a); }
  function orOverflow(bool c, uint256 a) external pure returns (bool){ return c || ((a+1)>a); }
  function chainAnd(uint256 a, uint256 b) external pure returns (bool){ return (a!=0) && (b!=0) && ((100/(a*b))>0); }
  function chainOr(uint256 a, uint256 b) external pure returns (bool){ return (a==0) || (b==0) || ((100/(a*b))>0); }
  function mixAndOr(uint256 a, uint256 b) external pure returns (bool){ return (a!=0) || ((b!=0) && ((10/b)>0)); }
  function negShort(bool c, uint256 a) external pure returns (bool){ return !c && ((a+1)>a); }

  function ternMax(uint256 a, uint256 b) external pure returns (uint256){ return a>b ? a : b; }
  function ternNested(uint256 x) external pure returns (uint256){ return x<10 ? 1 : (x<20 ? 2 : (x<30 ? 3 : 4)); }
  function ternArith(uint256 a, uint256 b) external pure returns (uint256){ return (a>b ? a-b : b-a) + 1; }
  function ternMixedWidth(bool c, uint8 a, uint256 b) external pure returns (uint256){ return c ? a : b; }
  function ternShortRevert(bool c, uint256 a) external pure returns (uint256){ return c ? a+1 : a; }
  function ternDivGuard(uint256 a) external pure returns (uint256){ return a==0 ? 0 : 100/a; }
  function ternInCond(uint256 a, uint256 b) external pure returns (uint256){ if((a>b ? a : b)>50){ return 1; } return 0; }
  function ternDeep(uint256 x) external pure returns (uint256){ return x<2 ? (x<1 ? 10 : 20) : (x<4 ? (x<3 ? 30 : 40) : 50); }

  function localIncDec(uint256 a) external pure returns (uint256){ uint256 x=a; x++; x++; x--; ++x; --x; return x; }
  function preVsPost(uint256 a) external pure returns (uint256){ uint256 x=a; uint256 y=0; x++; y+=x; ++x; y+=x; x--; y+=x; --x; y+=x; return y; }
  function forPostInc(uint256 n) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<n;i++){ s+=i; } return s; }
  function forPreInc(uint256 n) external pure returns (uint256){ uint256 s=0; for(uint256 i=0;i<n;++i){ s+=i; } return s; }
  function forDec(uint256 n) external pure returns (uint256){ uint256 s=0; for(uint256 i=n;i>0;i--){ s+=i; } return s; }
  function incOverflow(uint256 a) external pure returns (uint256){ uint256 x=a; x++; return x; }
  function decUnderflow(uint256 a) external pure returns (uint256){ uint256 x=a; x--; return x; }
  function incSigned(int256 a) external pure returns (int256){ int256 x=a; x++; return x; }
  function decSigned(int256 a) external pure returns (int256){ int256 x=a; x--; return x; }

  function cAdd(uint256 a, uint256 b) external pure returns (uint256){ uint256 x=a; x+=b; return x; }
  function cSub(uint256 a, uint256 b) external pure returns (uint256){ uint256 x=a; x-=b; return x; }
  function cMul(uint256 a, uint256 b) external pure returns (uint256){ uint256 x=a; x*=b; return x; }
  function cDiv(uint256 a, uint256 b) external pure returns (uint256){ uint256 x=a; x/=b; return x; }
  function cMod(uint256 a, uint256 b) external pure returns (uint256){ uint256 x=a; x%=b; return x; }
  function cAnd(uint256 a, uint256 b) external pure returns (uint256){ uint256 x=a; x&=b; return x; }
  function cOr(uint256 a, uint256 b) external pure returns (uint256){ uint256 x=a; x|=b; return x; }
  function cXor(uint256 a, uint256 b) external pure returns (uint256){ uint256 x=a; x^=b; return x; }
  function cShl(uint256 a, uint256 b) external pure returns (uint256){ uint256 x=a; x<<=b; return x; }
  function cShr(uint256 a, uint256 b) external pure returns (uint256){ uint256 x=a; x>>=b; return x; }
  function cAddSigned(int256 a, int256 b) external pure returns (int256){ int256 x=a; x+=b; return x; }
  function cSubSigned(int256 a, int256 b) external pure returns (int256){ int256 x=a; x-=b; return x; }
  function cMulSigned(int256 a, int256 b) external pure returns (int256){ int256 x=a; x*=b; return x; }
  function cDivSigned(int256 a, int256 b) external pure returns (int256){ int256 x=a; x/=b; return x; }
  function cModSigned(int256 a, int256 b) external pure returns (int256){ int256 x=a; x%=b; return x; }
  function cShrSigned(int256 a, uint256 b) external pure returns (int256){ int256 x=a; x>>=b; return x; }
  function cChain(uint256 a) external pure returns (uint256){ uint256 x=a; x+=5; x*=2; x-=3; x/=2; x%=7; return x; }

  function notNot(bool c) external pure returns (bool){ return !!c; }
  function notTriple(bool c) external pure returns (bool){ return !!!c; }
  function negCond(uint256 x) external pure returns (uint256){ if(!(x>5)){ return 1; } return 2; }
  function deMorgan(uint256 a, uint256 b) external pure returns (bool){ return !((a>0) && (b>0)); }

  function uncheckedSum(uint256 n) external pure returns (uint256){ uint256 s=0; unchecked { for(uint256 i=0;i<n;i+=1){ s+=i; } } return s; }
  function uncheckedWrap(uint256 a) external pure returns (uint256){ uint256 x=a; unchecked { x+=1; } return x; }
  function uncheckedIncStmt(uint256 a) external pure returns (uint256){ uint256 x=a; unchecked { x++; } return x; }

  function postInExpr(uint256 a) external pure returns (uint256){ uint256 x=a; uint256 y=x++ + 5; return x*1000+y; }
  function preInExpr(uint256 a) external pure returns (uint256){ uint256 x=a; uint256 y=++x + 5; return x*1000+y; }
  function postDecExpr(uint256 a) external pure returns (uint256){ uint256 x=a; uint256 y=x-- + 5; return x*1000+y; }
  function preDecExpr(uint256 a) external pure returns (uint256){ uint256 x=a; uint256 y=--x + 5; return x*1000+y; }
  function postTimes(uint256 a) external pure returns (uint256){ uint256 x=a; uint256 y=x++ * 2; return x*1000+y; }
  function ternWithInc(bool c, uint256 a) external pure returns (uint256){ uint256 x=a; uint256 y=c ? x++ : x--; return x*1000+y; }
  function andIncChain(uint256 a) external pure returns (uint256){ uint256 x=a; bool r = (x++ > 0) && (x++ > 100) && (x++ > 200); return x*10 + (r ? 1 : 0); }

  function collatzSteps(uint256 n) external pure returns (uint256){ uint256 x=n; uint256 steps=0; for(uint256 i=0;i<1000;i+=1){ if(x<=1){break;} x = (x%2==0) ? x/2 : 3*x+1; steps+=1; } return steps; }
  function gcd(uint256 a, uint256 b) external pure returns (uint256){ uint256 x=a; uint256 y=b; while(y!=0){ uint256 t=y; y=x%y; x=t; } return x; }
}`;

describe('control flow & expr order vs solc', () => {
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
  const C = (sig: string, args: bigint[] = []) => encodeCall(sel(sig), args);

  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });

  it('runs', async () => {
    const NS = [0n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 10n, 13n, 20n, 50n];

    // loops
    for (const n of NS) {
      await eq('sumTo ' + n, C('sumTo(uint256)', [n]));
      await eq('whileSum ' + n, C('whileSum(uint256)', [n]));
      await eq('emptyBodyFor ' + n, C('emptyBodyFor(uint256)', [n]));
      await eq('noInitFor ' + n, C('noInitFor(uint256)', [n]));
      await eq('noPostFor ' + n, C('noPostFor(uint256)', [n]));
      await eq('noCondFor ' + n, C('noCondFor(uint256)', [n]));
      await eq('whileBreak ' + n, C('whileBreak(uint256)', [n]));
      await eq('whileContinue ' + n, C('whileContinue(uint256)', [n]));
      await eq('skipMul3 ' + n, C('skipMul3(uint256)', [n]));
      await eq('nestedBreak ' + n, C('nestedBreak(uint256)', [n]));
      await eq('nestedContinue ' + n, C('nestedContinue(uint256)', [n]));
      await eq('innerBreakOnlyInner ' + n, C('innerBreakOnlyInner(uint256)', [n]));
      await eq('tripleNest ' + n, C('tripleNest(uint256)', [n]));
      await eq('continueThenBreak ' + n, C('continueThenBreak(uint256)', [n]));
      await eq('whileNestedBC ' + n, C('whileNestedBC(uint256)', [n]));
      await eq('classify ' + n, C('classify(uint256)', [n]));
      await eq('fallThrough ' + n, C('fallThrough(uint256)', [n]));
      await eq('fallThroughLoop ' + n, C('fallThroughLoop(uint256)', [n]));
      await eq('returnFromNested ' + n, C('returnFromNested(uint256)', [n]));
      await eq('uncheckedSum ' + n, C('uncheckedSum(uint256)', [n]));
      await eq('forPostInc ' + n, C('forPostInc(uint256)', [n]));
      await eq('forPreInc ' + n, C('forPreInc(uint256)', [n]));
      await eq('forDec ' + n, C('forDec(uint256)', [n]));
      await eq('collatzSteps ' + n, C('collatzSteps(uint256)', [n]));
    }
    // larger n for fallThrough boundary at 100
    await eq('fallThrough 101', C('fallThrough(uint256)', [101n]));
    await eq('fallThroughLoop 60', C('fallThroughLoop(uint256)', [60n]));

    // break/early-return with k
    const PAIRS = [
      [10n, 3n],
      [10n, 0n],
      [10n, 9n],
      [10n, 100n],
      [0n, 0n],
      [5n, 5n],
      [1n, 0n],
    ] as [bigint, bigint][];
    for (const [n, k] of PAIRS) {
      await eq('breakAt ' + n + ',' + k, C('breakAt(uint256,uint256)', [n, k]));
      await eq('earlyReturn ' + n + ',' + k, C('earlyReturn(uint256,uint256)', [n, k]));
    }

    // short-circuit: a==0 must NOT divide (no revert); RHS overflow not taken
    for (const a of [0n, 1n, 2n, 5n, 10n, U256_MAX]) {
      await eq('andDivGuard ' + a, C('andDivGuard(uint256)', [a]));
      await eq('orDivGuard ' + a, C('orDivGuard(uint256)', [a]));
      await eq('ternDivGuard ' + a, C('ternDivGuard(uint256)', [a]));
    }
    for (const c of [0n, 1n]) {
      for (const a of [0n, 5n, U256_MAX]) {
        await eq('andOverflow ' + c + ',' + a, C('andOverflow(bool,uint256)', [c, a]));
        await eq('orOverflow ' + c + ',' + a, C('orOverflow(bool,uint256)', [c, a]));
        await eq('negShort ' + c + ',' + a, C('negShort(bool,uint256)', [c, a]));
      }
    }
    const SCPAIRS = [
      [0n, 0n],
      [0n, 5n],
      [5n, 0n],
      [3n, 4n],
      [1n, 1n],
      [U256_MAX, 2n],
    ] as [bigint, bigint][];
    for (const [a, b] of SCPAIRS) {
      await eq('chainAnd ' + a + ',' + b, C('chainAnd(uint256,uint256)', [a, b]));
      await eq('chainOr ' + a + ',' + b, C('chainOr(uint256,uint256)', [a, b]));
      await eq('mixAndOr ' + a + ',' + b, C('mixAndOr(uint256,uint256)', [a, b]));
      await eq('deMorgan ' + a + ',' + b, C('deMorgan(uint256,uint256)', [a, b]));
    }

    // ternary
    for (const [a, b] of [
      [5n, 9n],
      [9n, 5n],
      [5n, 5n],
      [0n, U256_MAX],
      [60n, 10n],
      [10n, 60n],
    ] as [bigint, bigint][]) {
      await eq('ternMax ' + a + ',' + b, C('ternMax(uint256,uint256)', [a, b]));
      await eq('ternArith ' + a + ',' + b, C('ternArith(uint256,uint256)', [a, b]));
      await eq('ternInCond ' + a + ',' + b, C('ternInCond(uint256,uint256)', [a, b]));
    }
    for (const x of [0n, 1n, 2n, 3n, 4n, 5n, 9n, 10n, 15n, 19n, 20n, 25n, 30n, 100n]) {
      await eq('ternNested ' + x, C('ternNested(uint256)', [x]));
      await eq('ternDeep ' + x, C('ternDeep(uint256)', [x]));
    }
    for (const c of [0n, 1n]) {
      await eq('ternMixedWidth ' + c, C('ternMixedWidth(bool,uint8,uint256)', [c, 200n, 99999n]));
      await eq('ternShortRevert ' + c + ' max', C('ternShortRevert(bool,uint256)', [c, U256_MAX]));
      await eq('ternShortRevert ' + c + ' 41', C('ternShortRevert(bool,uint256)', [c, 41n]));
    }

    // ++ / -- boundaries (overflow/underflow revert parity, signed INT_MIN/MAX)
    for (const a of [0n, 1n, 7n, U256_MAX, U256_MAX - 1n]) {
      await eq('localIncDec ' + a, C('localIncDec(uint256)', [a]));
      await eq('preVsPost ' + a, C('preVsPost(uint256)', [a]));
      await eq('incOverflow ' + a, C('incOverflow(uint256)', [a]));
      await eq('decUnderflow ' + a, C('decUnderflow(uint256)', [a]));
      await eq('uncheckedWrap ' + a, C('uncheckedWrap(uint256)', [a]));
      await eq('uncheckedIncStmt ' + a, C('uncheckedIncStmt(uint256)', [a]));
    }
    for (const a of [0n, 1n, -1n, I256_MAX, I256_MIN, I256_MAX - 1n, I256_MIN + 1n]) {
      await eq('incSigned ' + a, C('incSigned(int256)', [asWord(a)]));
      await eq('decSigned ' + a, C('decSigned(int256)', [asWord(a)]));
    }

    // compound assign, every operator
    const UPAIRS = [
      [0n, 0n],
      [5n, 3n],
      [3n, 5n],
      [U256_MAX, 1n],
      [1n, U256_MAX],
      [10n, 0n],
      [0n, 10n],
      [100n, 7n],
      [U256_MAX, U256_MAX],
      [1n << 200n, 1n << 100n],
      [0xffn, 0x0fn],
      [0n, 256n],
      [1n, 255n],
      [1n, 256n],
      [U256_MAX, 5n],
    ] as [bigint, bigint][];
    for (const [a, b] of UPAIRS) {
      await eq('cAdd ' + a + ',' + b, C('cAdd(uint256,uint256)', [a, b]));
      await eq('cSub ' + a + ',' + b, C('cSub(uint256,uint256)', [a, b]));
      await eq('cMul ' + a + ',' + b, C('cMul(uint256,uint256)', [a, b]));
      await eq('cDiv ' + a + ',' + b, C('cDiv(uint256,uint256)', [a, b]));
      await eq('cMod ' + a + ',' + b, C('cMod(uint256,uint256)', [a, b]));
      await eq('cAnd ' + a + ',' + b, C('cAnd(uint256,uint256)', [a, b]));
      await eq('cOr ' + a + ',' + b, C('cOr(uint256,uint256)', [a, b]));
      await eq('cXor ' + a + ',' + b, C('cXor(uint256,uint256)', [a, b]));
      await eq('cShl ' + a + ',' + b, C('cShl(uint256,uint256)', [a, b]));
      await eq('cShr ' + a + ',' + b, C('cShr(uint256,uint256)', [a, b]));
    }
    for (const a of [0n, 3n, 100n, U256_MAX, 1024n]) {
      await eq('cChain ' + a, C('cChain(uint256)', [a]));
    }
    // signed compound
    const IPAIRS = [
      [5n, 3n],
      [3n, 5n],
      [-5n, 3n],
      [-5n, -3n],
      [I256_MIN, 1n],
      [I256_MIN, -1n],
      [I256_MAX, 1n],
      [I256_MAX, -1n],
      [-1n, I256_MIN],
      [I256_MIN, I256_MIN],
      [10n, 0n],
      [-10n, 3n],
      [-10n, -3n],
      [I256_MIN, -1n],
      [7n, -2n],
    ] as [bigint, bigint][];
    for (const [a, b] of IPAIRS) {
      await eq('cAddSigned ' + a + ',' + b, C('cAddSigned(int256,int256)', [asWord(a), asWord(b)]));
      await eq('cSubSigned ' + a + ',' + b, C('cSubSigned(int256,int256)', [asWord(a), asWord(b)]));
      await eq('cMulSigned ' + a + ',' + b, C('cMulSigned(int256,int256)', [asWord(a), asWord(b)]));
      await eq('cDivSigned ' + a + ',' + b, C('cDivSigned(int256,int256)', [asWord(a), asWord(b)]));
      await eq('cModSigned ' + a + ',' + b, C('cModSigned(int256,int256)', [asWord(a), asWord(b)]));
    }
    for (const [a, b] of [
      [-8n, 1n],
      [-1n, 3n],
      [I256_MIN, 4n],
      [I256_MAX, 1n],
      [-256n, 8n],
      [-1n, 255n],
      [-1n, 256n],
    ] as [bigint, bigint][]) {
      await eq('cShrSigned ' + a + ',' + b, C('cShrSigned(int256,uint256)', [asWord(a), asWord(b)]));
    }

    // boolean negation
    for (const c of [0n, 1n]) {
      await eq('notNot ' + c, C('notNot(bool)', [c]));
      await eq('notTriple ' + c, C('notTriple(bool)', [c]));
    }
    for (const x of [0n, 5n, 6n, 100n]) {
      await eq('negCond ' + x, C('negCond(uint256)', [x]));
    }

    // ++ / -- in expression position (value semantics: post=old, pre=new)
    for (const a of [0n, 1n, 5n, 10n, 100n, 250n]) {
      await eq('postInExpr ' + a, C('postInExpr(uint256)', [a]));
      await eq('preInExpr ' + a, C('preInExpr(uint256)', [a]));
      await eq('postDecExpr ' + a, C('postDecExpr(uint256)', [a]));
      await eq('preDecExpr ' + a, C('preDecExpr(uint256)', [a]));
      await eq('postTimes ' + a, C('postTimes(uint256)', [a]));
      await eq('andIncChain ' + a, C('andIncChain(uint256)', [a]));
      await eq('ternWithInc t ' + a, C('ternWithInc(bool,uint256)', [1n, a]));
      await eq('ternWithInc f ' + a, C('ternWithInc(bool,uint256)', [0n, a]));
    }

    // gcd
    for (const [a, b] of [
      [12n, 18n],
      [48n, 36n],
      [17n, 5n],
      [0n, 9n],
      [9n, 0n],
      [1n, 1n],
      [100n, 100n],
      [U256_MAX, 7n],
    ] as [bigint, bigint][]) {
      await eq('gcd ' + a + ',' + b, C('gcd(uint256,uint256)', [a, b]));
    }

    if (mism.length) {
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 40)) console.log(m);
    } else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
