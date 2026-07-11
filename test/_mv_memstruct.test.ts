// MV: adversarial differential check of STATIC struct MEMORY locals and internal-function
// struct params/returns (memory by-reference). Hammers aliasing chains, pass-by-ref
// mutation vs non-mutation, boundary/narrow/signed field cleanliness on whole-struct
// return, two distinct structs, same struct passed twice, recursion (modest depth),
// @pure helpers that mutate a memory param, and compound/inc-dec through aliases.
// Compared byte-for-byte against solc 0.8.x (cancun, optimizer on).
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const M = 1n << 256n;
const sel = (s: string) => functionSelector(s);

const JETH = `type P = { a: u256; b: u8; c: i64; d: address; };
type Q = { x: u128; y: u128; };
type W = { a: u8; b: i64; c: address; d: bytes4; };
type S = { a: i8; b: i16; c: i128; d: i256; };
class C {
  // ---- aliasing chains: q=p; r=q; mutate r; all three alias ----
  get chain3(a: u128): External<Q> {
    let p: Q = Q(a, a);
    let q: Q = p;
    let r: Q = q;
    r.x = 7n; r.y += 100n;
    return p;
  }
  // mutate through the MIDDLE alias, read the head
  get chainMid(a: u128, b: u128): External<Q> {
    let p: Q = Q(a, b);
    let q: Q = p;
    let r: Q = q;
    q.x++; q.y--;
    return r;
  }
  // alias then pass the ALIAS to a mutating helper; read the original
  bumpQ(p: Q): void { p.x = p.x + 1000n; p.y = p.y * 2n; }
  get aliasPass(a: u128, b: u128): External<Q> {
    let p: Q = Q(a, b);
    let q: Q = p;
    this.bumpQ(q);
    return p;
  }
  // ---- pass-by-ref: helper MUTATES param, caller sees it ----
  setFields(p: P, na: u256, nb: u8, nc: i64): void {
    p.a = na; p.b = nb; p.c = nc;
  }
  get refMutate(a: u256, b: u8, c: i64): External<P> {
    let p: P = P(0n, 0n, 0n, address(0x99n));
    this.setFields(p, a, b, c);
    return p;
  }
  // helper that does NOT mutate: builds a NEW struct, returns it; original untouched
  freshQ(p: Q): Q { return Q(p.x + 1n, p.y + 1n); }
  get noMutate(a: u128, b: u128): External<Q> {
    let p: Q = Q(a, b);
    let unused: Q = this.freshQ(p);
    return p;
  }
  // helper returns the fresh struct; we keep both, sum a field to prove distinctness
  get distinctSum(a: u128, b: u128): External<u128> {
    let p: Q = Q(a, b);
    let r: Q = this.freshQ(p);
    return p.x + r.x;
  }
  // ---- boundary / narrow / signed whole-struct return ----
  get mkP(a: u256, b: u8, c: i64, d: address): External<P> { let p: P = P(a, b, c, d); return p; }
  get mkW(a: u8, b: i64, c: address, d: bytes4): External<W> { let p: W = W(a, b, c, d); return p; }
  get mkS(a: i8, b: i16, c: i128, d: i256): External<S> { let p: S = S(a, b, c, d); return p; }
  // construct narrow/signed, mutate, return whole (bytes4 passed in as a param)
  get mutW(a: u8, b: i64, d0: bytes4, d1: bytes4): External<W> {
    let p: W = W(0n, 0n, address(0n), d0);
    p.a = a; p.b = b; p.c = address(0xCAFEn); p.d = d1;
    return p;
  }
  // ---- two distinct structs in one function (separate allocations) ----
  get twoStructs(a: u128, b: u128, c: u128, d: u128): External<u256> {
    let p: Q = Q(a, b);
    let r: Q = Q(c, d);
    p.x = p.x + 1n; r.y = r.y + 2n;
    // no aliasing: their fields stay independent
    return u256(p.x) * (1n << 192n) + u256(p.y) * (1n << 128n) + u256(r.x) * (1n << 64n) + u256(r.y);
  }
  // ---- same struct passed to a helper TWICE ----
  addX(p: Q, k: u128): void { p.x = p.x + k; }
  get twice(a: u128, b: u128): External<Q> {
    let p: Q = Q(a, b);
    this.addX(p, 10n);
    this.addX(p, 5n);
    return p;
  }
  // struct returned then re-passed
  get returnRepass(a: u128, b: u128): External<Q> {
    let p: Q = this.freshQ(Q(a, b));
    this.addX(p, 1n);
    return p;
  }
  // ---- recursion that takes AND returns a struct (modest depth) ----
  climb(p: P, n: u256): P {
    if (n == 0n) { return p; }
    return this.climb(P(p.a + 1n, u8(p.b + 1n), i64(p.c - 1n), p.d), n - 1n);
  }
  get climbE(a: u256, b: u8, c: i64, d: address, n: u256): External<P> {
    return this.climb(P(a, b, c, d), n);
  }
  // recursion that MUTATES the param in place at each level (by-ref accumulation)
  accDown(p: Q, n: u128): void {
    if (n == 0n) { return; }
    p.x = p.x + n;
    this.accDown(p, n - 1n);
  }
  get accE(a: u128, n: u128): External<Q> { let p: Q = Q(a, 0n); this.accDown(p, n); return p; }
  // ---- @pure helper mutating a memory struct param (legal in Solidity) ----
  pureBump(p: P): void { p.a = p.a + 1n; p.b = u8(p.b + 1n); }
  get pureBumpE(a: u256, b: u8): External<P> { let p: P = P(a, b, 0n, address(0n)); this.pureBump(p); return p; }
  // ---- compound + ++/-- on struct fields through aliases ----
  get compoundAlias(a: u128): External<u256> {
    let p: Q = Q(a, a);
    let q: Q = p;
    q.x += 5n; p.y -= 3n; q.x++; let z: u128 = p.x--;
    return u256(p.x) * 1000000n + u256(q.y) * 1000n + u256(z);
  }
  // chain this.outer(this.inner(...)) passing a struct through
  inner(p: P): P { return P(p.a * 2n, u8(p.b + 1n), i64(p.c + 1n), p.d); }
  outer(p: P): P { return P(p.a + 1n, u8(p.b * 2n), i64(p.c * 2n), p.d); }
  get chainCall(a: u256, b: u8, c: i64, d: address): External<P> {
    return this.outer(this.inner(P(a, b, c, d)));
  }
  // bind a struct-returning call to a local, then mutate the local (no effect on a fresh source)
  get bindMutate(a: u128, b: u128): External<u128> {
    let p: Q = Q(a, b);
    let r: Q = this.freshQ(p);
    r.x = 0n; r.y = 0n;
    return p.x + p.y;
  }
  // helper reads two struct params (distinct), combine
  combine(p: Q, r: Q): u256 { return u256(p.x) + u256(r.y); }
  get combineE(a: u128, b: u128, c: u128, d: u128): External<u256> {
    let p: Q = Q(a, b);
    let r: Q = Q(c, d);
    return this.combine(p, r);
  }
  // pass the SAME struct as both args; mutate one path -> both see it (same object)
  addBoth(p: Q, r: Q): void { p.x = p.x + 1n; r.y = r.y + 1n; }
  get sameTwice(a: u128, b: u128): External<Q> {
    let p: Q = Q(a, b);
    this.addBoth(p, p);
    return p;
  }
}`;
const SOL = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C {
  struct P { uint256 a; uint8 b; int64 c; address d; }
  struct Q { uint128 x; uint128 y; }
  struct W { uint8 a; int64 b; address c; bytes4 d; }
  struct S { int8 a; int16 b; int128 c; int256 d; }
  function chain3(uint128 a) external pure returns (Q memory) {
    Q memory p = Q(a, a);
    Q memory q = p;
    Q memory r = q;
    r.x = 7; r.y += 100;
    return p;
  }
  function chainMid(uint128 a, uint128 b) external pure returns (Q memory) {
    Q memory p = Q(a, b);
    Q memory q = p;
    Q memory r = q;
    q.x++; q.y--;
    return r;
  }
  function bumpQ(Q memory p) internal pure { p.x = p.x + 1000; p.y = p.y * 2; }
  function aliasPass(uint128 a, uint128 b) external pure returns (Q memory) {
    Q memory p = Q(a, b);
    Q memory q = p;
    bumpQ(q);
    return p;
  }
  function setFields(P memory p, uint256 na, uint8 nb, int64 nc) internal pure {
    p.a = na; p.b = nb; p.c = nc;
  }
  function refMutate(uint256 a, uint8 b, int64 c) external pure returns (P memory) {
    P memory p = P(0, 0, 0, address(0x99));
    setFields(p, a, b, c);
    return p;
  }
  function freshQ(Q memory p) internal pure returns (Q memory) { return Q(p.x + 1, p.y + 1); }
  function noMutate(uint128 a, uint128 b) external pure returns (Q memory) {
    Q memory p = Q(a, b);
    Q memory unused = freshQ(p);
    unused;
    return p;
  }
  function distinctSum(uint128 a, uint128 b) external pure returns (uint128) {
    Q memory p = Q(a, b);
    Q memory r = freshQ(p);
    return p.x + r.x;
  }
  function mkP(uint256 a, uint8 b, int64 c, address d) external pure returns (P memory) { P memory p = P(a, b, c, d); return p; }
  function mkW(uint8 a, int64 b, address c, bytes4 d) external pure returns (W memory) { W memory p = W(a, b, c, d); return p; }
  function mkS(int8 a, int16 b, int128 c, int256 d) external pure returns (S memory) { S memory p = S(a, b, c, d); return p; }
  function mutW(uint8 a, int64 b, bytes4 d0, bytes4 d1) external pure returns (W memory) {
    W memory p = W(0, 0, address(0), d0);
    p.a = a; p.b = b; p.c = address(0xCAFE); p.d = d1;
    return p;
  }
  function twoStructs(uint128 a, uint128 b, uint128 c, uint128 d) external pure returns (uint256) {
    Q memory p = Q(a, b);
    Q memory r = Q(c, d);
    p.x = p.x + 1; r.y = r.y + 2;
    return uint256(p.x) * (1 << 192) + uint256(p.y) * (1 << 128) + uint256(r.x) * (1 << 64) + uint256(r.y);
  }
  function addX(Q memory p, uint128 k) internal pure { p.x = p.x + k; }
  function twice(uint128 a, uint128 b) external pure returns (Q memory) {
    Q memory p = Q(a, b);
    addX(p, 10);
    addX(p, 5);
    return p;
  }
  function returnRepass(uint128 a, uint128 b) external pure returns (Q memory) {
    Q memory p = freshQ(Q(a, b));
    addX(p, 1);
    return p;
  }
  function climb(P memory p, uint256 n) internal pure returns (P memory) {
    if (n == 0) { return p; }
    return climb(P(p.a + 1, uint8(p.b + 1), int64(p.c - 1), p.d), n - 1);
  }
  function climbE(uint256 a, uint8 b, int64 c, address d, uint256 n) external pure returns (P memory) {
    return climb(P(a, b, c, d), n);
  }
  function accDown(Q memory p, uint128 n) internal pure {
    if (n == 0) { return; }
    p.x = p.x + n;
    accDown(p, n - 1);
  }
  function accE(uint128 a, uint128 n) external pure returns (Q memory) { Q memory p = Q(a, 0); accDown(p, n); return p; }
  function pureBump(P memory p) internal pure { p.a = p.a + 1; p.b = uint8(p.b + 1); }
  function pureBumpE(uint256 a, uint8 b) external pure returns (P memory) { P memory p = P(a, b, 0, address(0)); pureBump(p); return p; }
  function compoundAlias(uint128 a) external pure returns (uint256) {
    Q memory p = Q(a, a);
    Q memory q = p;
    q.x += 5; p.y -= 3; q.x++; uint128 z = p.x--;
    return uint256(p.x) * 1000000 + uint256(q.y) * 1000 + uint256(z);
  }
  function inner(P memory p) internal pure returns (P memory) { return P(p.a * 2, uint8(p.b + 1), int64(p.c + 1), p.d); }
  function outer(P memory p) internal pure returns (P memory) { return P(p.a + 1, uint8(p.b * 2), int64(p.c * 2), p.d); }
  function chainCall(uint256 a, uint8 b, int64 c, address d) external pure returns (P memory) {
    return outer(inner(P(a, b, c, d)));
  }
  function bindMutate(uint128 a, uint128 b) external pure returns (uint128) {
    Q memory p = Q(a, b);
    Q memory r = freshQ(p);
    r.x = 0; r.y = 0;
    return p.x + p.y;
  }
  function combine(Q memory p, Q memory r) internal pure returns (uint256) { return uint256(p.x) + uint256(r.y); }
  function combineE(uint128 a, uint128 b, uint128 c, uint128 d) external pure returns (uint256) {
    Q memory p = Q(a, b);
    Q memory r = Q(c, d);
    return combine(p, r);
  }
  function addBoth(Q memory p, Q memory r) internal pure { p.x = p.x + 1; r.y = r.y + 1; }
  function sameTwice(uint128 a, uint128 b) external pure returns (Q memory) {
    Q memory p = Q(a, b);
    addBoth(p, p);
    return p;
  }
}`;

describe('memstruct', () => {
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
  beforeAll(async () => {
    const jb = compile(JETH, { fileName: 'C.jeth' });
    const sb = compileSolidity(SOL, 'C');
    jeth = await Harness.create();
    sol = await Harness.create();
    aj = await jeth.deploy(jb.creationBytecode);
    as = await sol.deploy(sb.creation);
  });
  it('runs', async () => {
    const U128MAX = (1n << 128n) - 1n;
    const U256MAX = M - 1n;
    const U8MAX = 255n;
    const I64MAX = (1n << 63n) - 1n;
    const I64MIN_W = M - (1n << 63n); // two's-complement word for -2^63
    const u128s: bigint[] = [0n, 1n, 2n, 99n, 12345n, U128MAX, U128MAX - 1n, 1n << 100n, 1n << 127n];
    const pairs: [bigint, bigint][] = [
      [0n, 0n],
      [1n, 2n],
      [U128MAX, 0n],
      [0n, U128MAX],
      [U128MAX, U128MAX],
      [5n, 7n],
      [1n << 100n, 3n],
      [U128MAX - 1n, 1n],
      [2n, U128MAX],
    ];

    // aliasing chains
    for (const a of u128s) await eq('chain3(' + a + ')', encodeCall(sel('chain3(uint128)'), [a]));
    for (const [a, b] of pairs)
      await eq('chainMid(' + a + ',' + b + ')', encodeCall(sel('chainMid(uint128,uint128)'), [a, b]));
    for (const [a, b] of pairs)
      await eq('aliasPass(' + a + ',' + b + ')', encodeCall(sel('aliasPass(uint128,uint128)'), [a, b]));

    // pass-by-ref mutate vs no-mutate
    const ps: [bigint, bigint, bigint][] = [
      [0n, 0n, 0n],
      [1n, 2n, 3n],
      [U256MAX, U8MAX, I64MAX],
      [42n, 200n, -7n],
      [U256MAX, U8MAX, I64MIN_W - M], // c = -2^63 passed as signed bigint
      [1n << 200n, 17n, -1n],
    ];
    for (const [a, b, c] of ps) {
      const cWord = c < 0n ? c + M : c;
      void cWord;
      await eq(
        'refMutate(' + a + ',' + b + ',' + c + ')',
        encodeCall(sel('refMutate(uint256,uint8,int64)'), [a, b, c < 0n ? c + M : c]),
      );
    }
    for (const [a, b] of pairs) {
      await eq('noMutate(' + a + ',' + b + ')', encodeCall(sel('noMutate(uint128,uint128)'), [a, b]));
      await eq('distinctSum(' + a + ',' + b + ')', encodeCall(sel('distinctSum(uint128,uint128)'), [a, b]));
    }

    // boundary / narrow / signed whole-struct return
    const Pcases: [bigint, bigint, bigint, bigint][] = [
      [0n, 0n, 0n, 0n],
      [1n, 1n, 1n, 0x1n],
      [U256MAX, U8MAX, I64MAX, M - 1n],
      [U256MAX, U8MAX, I64MIN_W, 0xdeadbeefn],
      [12345n, 7n, -42n < 0n ? -42n + M : 0n, 0x5555n],
      [M - 2n, 254n, -1n + M, 0xffffffffffffffffffffffffffffffffffffffffn],
    ];
    for (const [a, b, c, d] of Pcases)
      await eq(
        'mkP(' + a + ',' + b + ',' + c + ',' + d + ')',
        encodeCall(sel('mkP(uint256,uint8,int64,address)'), [a, b, c, d]),
      );

    const Wcases: [bigint, bigint, bigint, bigint][] = [
      [0n, 0n, 0n, 0n],
      [255n, I64MAX, 0x1234n, 0xdeadbeefn << 224n],
      [128n, I64MIN_W, 0xffffffffffffffffffffffffffffffffffffffffn, 0xcafebaben << 224n],
      [1n, -1n + M, 0xabcdn, 0x00000001n << 224n],
      [200n, -2n + M, 0xffn, 0xffffffffn << 224n],
    ];
    for (const [a, b, c, d] of Wcases)
      await eq(
        'mkW(' + a + ',' + b + ',' + c + ',' + d + ')',
        encodeCall(sel('mkW(uint8,int64,address,bytes4)'), [a, b, c, d]),
      );

    const I8MAX = (1n << 7n) - 1n,
      I8MIN = M - (1n << 7n);
    const I16MAX = (1n << 15n) - 1n,
      I16MIN = M - (1n << 15n);
    const I128MAX = (1n << 127n) - 1n,
      I128MIN = M - (1n << 127n);
    const I256MAX = (1n << 255n) - 1n,
      I256MIN = M - (1n << 255n);
    const Scases: [bigint, bigint, bigint, bigint][] = [
      [0n, 0n, 0n, 0n],
      [I8MAX, I16MAX, I128MAX, I256MAX],
      [I8MIN, I16MIN, I128MIN, I256MIN],
      [-1n + M, -1n + M, -1n + M, -1n + M],
      [42n, -100n + M, 7n, -9999n + M],
    ];
    for (const [a, b, c, d] of Scases)
      await eq(
        'mkS(' + a + ',' + b + ',' + c + ',' + d + ')',
        encodeCall(sel('mkS(int8,int16,int128,int256)'), [a, b, c, d]),
      );

    const b4 = (v: bigint) => v << 224n; // left-align a 4-byte value into the 256-bit word
    for (const a of [0n, 1n, 200n, 255n])
      for (const b of [0n, 1n, I64MAX, I64MIN_W, -5n + M])
        await eq(
          'mutW(' + a + ',' + b + ')',
          encodeCall(sel('mutW(uint8,int64,bytes4,bytes4)'), [a, b, b4(0xdeadbeefn), b4(0xcafebaben)]),
        );

    // two distinct structs
    const quads: [bigint, bigint, bigint, bigint][] = [
      [0n, 0n, 0n, 0n],
      [1n, 2n, 3n, 4n],
      [U128MAX, U128MAX, U128MAX, U128MAX],
      [U128MAX, 0n, 0n, U128MAX],
      [10n, 20n, 30n, 40n],
    ];
    for (const [a, b, c, d] of quads)
      await eq(
        'twoStructs(' + a + ',' + b + ',' + c + ',' + d + ')',
        encodeCall(sel('twoStructs(uint128,uint128,uint128,uint128)'), [a, b, c, d]),
      );

    // same struct passed twice / return then repass / sameTwice
    for (const [a, b] of pairs) {
      await eq('twice(' + a + ',' + b + ')', encodeCall(sel('twice(uint128,uint128)'), [a, b]));
      await eq('returnRepass(' + a + ',' + b + ')', encodeCall(sel('returnRepass(uint128,uint128)'), [a, b]));
      await eq('sameTwice(' + a + ',' + b + ')', encodeCall(sel('sameTwice(uint128,uint128)'), [a, b]));
    }

    // recursion take+return / recursion mutate-by-ref
    for (const n of [0n, 1n, 2n, 5n, 10n, 32n, 50n]) {
      await eq(
        'climbE(n=' + n + ')',
        encodeCall(sel('climbE(uint256,uint8,int64,address,uint256)'), [
          1000n,
          10n,
          100n < I64MAX ? 100n : 0n,
          0x42n,
          n,
        ]),
      );
    }
    // climb where the narrow fields wrap (u8 b++ past 255, i64 c-- below min)
    for (const n of [0n, 250n, 256n, 300n])
      await eq(
        'climbWrap(n=' + n + ')',
        encodeCall(sel('climbE(uint256,uint8,int64,address,uint256)'), [0n, 250n, I64MIN_W + 3n, 0x1n, n]),
      );
    for (const a of [0n, 1n, 100n])
      for (const n of [0n, 1n, 10n, 50n, 100n])
        await eq('accE(' + a + ',' + n + ')', encodeCall(sel('accE(uint128,uint128)'), [a, n]));

    // @pure mutating helper
    for (const a of [0n, 1n, U256MAX, U256MAX - 1n])
      for (const b of [0n, 254n, 255n])
        await eq('pureBumpE(' + a + ',' + b + ')', encodeCall(sel('pureBumpE(uint256,uint8)'), [a, b]));

    // compound + inc/dec through aliases
    for (const a of [0n, 1n, 2n, 3n, 5n, 100n, U128MAX, U128MAX - 1n, 1n << 64n])
      await eq('compoundAlias(' + a + ')', encodeCall(sel('compoundAlias(uint128)'), [a]));

    // chain outer(inner(...))
    for (const [a, b, c, d] of Pcases)
      await eq(
        'chainCall(' + a + ',' + b + ',' + c + ',' + d + ')',
        encodeCall(sel('chainCall(uint256,uint8,int64,address)'), [a, b, c, d]),
      );

    // bind + mutate fresh / combine two params
    for (const [a, b] of pairs) {
      await eq('bindMutate(' + a + ',' + b + ')', encodeCall(sel('bindMutate(uint128,uint128)'), [a, b]));
    }
    for (const [a, b, c, d] of quads)
      await eq(
        'combineE(' + a + ',' + b + ',' + c + ',' + d + ')',
        encodeCall(sel('combineE(uint128,uint128,uint128,uint128)'), [a, b, c, d]),
      );

    if (mism.length) {
      console.log('MISMATCHES ' + mism.length + '/' + count);
      for (const m of mism.slice(0, 40)) console.log(m);
    } else console.log('ALL ' + count + ' byte-identical');
    expect(mism, mism.slice(0, 15).join('\n')).toEqual([]);
  });
});
