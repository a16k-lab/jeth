// W7B SOUNDNESS regression: storage-write argument-order interleave.
// solc materializes/evaluates the WHOLE RHS value (every ctor argument, in source order) BEFORE
// touching storage; JETH previously interleaved per field (evaluate arg i -> sstore field i), so
// (1) a later argument that reads the destination saw the NEW earlier fields (solc sees the OLD),
// (2) lowerStructPush GREW the length before evaluating the ctor args (an arg reading .length saw
//     old+1; ps.push(ps[0]) on an empty array aliased the freshly-grown zero element instead of
//     panicking on the source bounds check),
// (3) a value push evaluated a LAZY value expression (sload / internal call) after the grow,
// (4) mapping keys / element indices were resolved BEFORE the RHS args (solc: RHS first), and
// (5) the overwrite-clear of an old dynamic field tail ran before later args (solc clears after).
// Fixed with a two-phase prepare/emit split (prepareCtorArgs/prepareStructStore capture each arg
// at its position - values frozen, storage/calldata reference sources snapshotted to memory,
// memory reference sources aliased for the late read - then emitPrepared* performs the stores).
// Every case is NON-VACUOUS: the two orders produce different digests, verified against solc.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => '0x' + functionSelector(s);
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

async function eqCalls(jeth: string, sol: string, calls: [string, string][]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return`).toBe(rs.returnHex);
  }
}

describe('W7B: storage-write argument order matches solc 0.8.35', () => {
  it('state struct assign: a later ctor arg reading the destination sees the OLD field (A7)', async () => {
    await eqCalls(
      `@struct class P { x: u256; y: u256 }
      @contract class C {
        @state p: P;
        rd(): u256 { return this.p.x; }
        @external f(): u256 { this.p = P(5n, 0n); this.p = P(7n, this.rd()); return this.p.y; } }`,
      `struct P { uint256 x; uint256 y; }
      contract C {
        P p;
        function rd() internal view returns (uint256) { return p.x; }
        function f() external returns (uint256) { p = P(5, 0); p = P(7, rd()); return p.y; } }`,
      [['f()', '']],
    );
  });

  it('value-arg read position AND store-after-all-args (both interleave directions, P20)', async () => {
    await eqCalls(
      `@struct class P { x: u256; y: u256 }
      @contract class C {
        @state p: P;
        bump2(): u256 { this.p = P(50n, this.p.y); return 60n; }
        @external f(): u256 { this.p = P(5n, 0n); this.p = P(this.p.x + 1n, this.bump2()); return this.p.x * 100n + this.p.y; } }`,
      `struct P { uint256 x; uint256 y; }
      contract C {
        P p;
        function bump2() internal returns (uint256) { p = P(50, p.y); return 60; }
        function f() external returns (uint256) { p = P(5, 0); p = P(p.x + 1, bump2()); return p.x * 100 + p.y; } }`,
      [['f()', '']],
    );
  });

  it('struct push: ctor args evaluate BEFORE the length grow (A8)', async () => {
    await eqCalls(
      `@struct class P { x: u256; y: u256 }
      @contract class C {
        @state ps: P[];
        rd(): u256 { return this.ps.length; }
        @external f(): u256 { this.ps.push(P(5n, this.rd())); return this.ps[0n].y; } }`,
      `struct P { uint256 x; uint256 y; }
      contract C {
        P[] ps;
        function rd() internal view returns (uint256) { return ps.length; }
        function f() external returns (uint256) { ps.push(P(5, rd())); return ps[0].y; } }`,
      [['f()', '']],
    );
  });

  it('push(ps[0]) / strs.push(strs[0]) / dd.push(dd[0]) on an EMPTY array panics on the source bounds check', async () => {
    await eqCalls(
      `@struct class P { x: u256; y: u256 }
      @contract class C {
        @state ps: P[];
        @state strs: string[];
        @state dd: u256[][];
        @state gg: Arr<u256, 2>[];
        @external f(): u256 { this.ps.push(this.ps[0n]); return this.ps.length; }
        @external g(): u256 { this.strs.push(this.strs[0n]); return this.strs.length; }
        @external h(): u256 { this.dd.push(this.dd[0n]); return this.dd.length; }
        @external k(): u256 { this.gg.push(this.gg[0n]); return this.gg.length; } }`,
      `struct P { uint256 x; uint256 y; }
      contract C {
        P[] ps;
        string[] strs;
        uint256[][] dd;
        uint256[2][] gg;
        function f() external returns (uint256) { ps.push(ps[0]); return ps.length; }
        function g() external returns (uint256) { strs.push(strs[0]); return strs.length; }
        function h() external returns (uint256) { dd.push(dd[0]); return dd.length; }
        function k() external returns (uint256) { gg.push(gg[0]); return gg.length; } }`,
      [['f()', ''], ['g()', ''], ['h()', ''], ['k()', '']],
    );
  });

  it('value push: a lazy value expression reads the OLD length (sa.push(sa.length) / sa.push(rd()))', async () => {
    await eqCalls(
      `@contract class C {
        @state sa: u256[];
        rd(): u256 { return this.sa.length; }
        @external f(): u256 { this.sa.push(this.sa.length); this.sa.push(this.sa.length); return this.sa[0n] * 100n + this.sa[1n] * 10n + this.sa.length; }
        @external g(): u256 { this.sa.push(this.rd()); this.sa.push(this.rd()); return this.sa[0n] * 100n + this.sa[1n] * 10n + this.sa.length; } }`,
      `contract C {
        uint256[] sa;
        function rd() internal view returns (uint256) { return sa.length; }
        function f() external returns (uint256) { sa.push(sa.length); sa.push(sa.length); return sa[0] * 100 + sa[1] * 10 + sa.length; }
        function g() external returns (uint256) { sa.push(rd()); sa.push(rd()); return sa[0] * 100 + sa[1] * 10 + sa.length; } }`,
      [['f()', ''], ['g()', '']],
    );
  });

  it('mapping / element / place struct assigns: RHS args first, destination after (P29/P30/P17/P32)', async () => {
    await eqCalls(
      `@struct class P { x: u256; y: u256 }
      @struct class O { a: u256; inner: P }
      @contract class C {
        @state seq: u256;
        @state m: mapping<u256, P>;
        @state ps: P[];
        @state o: O;
        tick(): u256 { this.seq = this.seq + 1n; return this.seq; }
        rd(): u256 { return this.o.inner.x; }
        @external f(): u256 { this.m[this.seq] = P(this.tick(), 5n); return this.m[0n].x * 100n + this.m[1n].x * 10n + this.seq; }
        @external g(): u256 { this.ps.push(P(0n, 0n)); this.ps.push(P(0n, 0n)); this.ps[this.seq % 2n] = P(9n, 9n);
          return this.ps[0n].x * 100n + this.ps[1n].x * 10n + this.seq; }
        @external h(): u256 { this.o = O(1n, P(5n, 0n)); this.o.inner = P(7n, this.rd()); return this.o.inner.y; }
        @external k(): u256 { this.m[1n] = P(5n, 0n); this.m[1n] = P(7n, this.m[1n].x); return this.m[1n].y; } }`,
      `struct P { uint256 x; uint256 y; }
      struct O { uint256 a; P inner; }
      contract C {
        uint256 seq;
        mapping(uint256 => P) m;
        P[] ps;
        O o;
        function tick() internal returns (uint256) { seq = seq + 1; return seq; }
        function rd() internal view returns (uint256) { return o.inner.x; }
        function f() external returns (uint256) { m[seq] = P(tick(), 5); return m[0].x * 100 + m[1].x * 10 + seq; }
        function g() external returns (uint256) { ps.push(P(0, 0)); ps.push(P(0, 0)); ps[seq % 2] = P(9, 9);
          return ps[0].x * 100 + ps[1].x * 10 + seq; }
        function h() external returns (uint256) { o = O(1, P(5, 0)); o.inner = P(7, rd()); return o.inner.y; }
        function k() external returns (uint256) { m[1] = P(5, 0); m[1] = P(7, m[1].x); return m[1].y; } }`,
      [['f()', ''], ['g()', ''], ['h()', ''], ['k()', '']],
    );
  });

  it('nested ctor: ALL args (inner and outer) evaluate before any store (P18)', async () => {
    await eqCalls(
      `@struct class P { x: u256; y: u256 }
      @struct class N { p: P; z: u256 }
      @contract class C {
        @state n: N;
        rd(): u256 { return this.n.p.x; }
        @external f(): u256 { this.n = N(P(5n, 0n), 0n); this.n = N(P(7n, this.rd()), this.rd()); return this.n.p.y * 10n + this.n.z; } }`,
      `struct P { uint256 x; uint256 y; }
      struct N { P p; uint256 z; }
      contract C {
        N n;
        function rd() internal view returns (uint256) { return n.p.x; }
        function f() external returns (uint256) { n = N(P(5, 0), 0); n = N(P(7, rd()), rd()); return n.p.y * 10 + n.z; } }`,
      [['f()', '']],
    );
  });

  it('dyn-field structs: overwrite-clear happens AFTER the args ran (P7), push/elem variants (P24/P25/P21)', async () => {
    await eqCalls(
      `@struct class S { s: string; z: u256 }
      @contract class C {
        @state st: S;
        @state ss: S[];
        @state m: mapping<u256, S>;
        rdLen(): u256 { return bytes(this.st.s).length; }
        rdN(): u256 { return this.ss.length; }
        rdE(): u256 { return bytes(this.ss[0n].s).length; }
        rdM(): u256 { return bytes(this.m[1n].s).length; }
        @external f(): u256 { this.st = S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1n); this.st = S("b", this.rdLen()); return this.st.z; }
        @external g(): u256 { this.ss.push(S("b", this.rdN())); return this.ss[0n].z; }
        @external h(): u256 { this.ss[0n] = S("cc", this.rdE()); return this.ss[0n].z; }
        @external k(): u256 { this.m[1n] = S("aaaa", 1n); this.m[1n] = S("b", this.rdM()); return this.m[1n].z; } }`,
      `struct S { string s; uint256 z; }
      contract C {
        S st;
        S[] ss;
        mapping(uint256 => S) m;
        function rdLen() internal view returns (uint256) { return bytes(st.s).length; }
        function rdN() internal view returns (uint256) { return ss.length; }
        function rdE() internal view returns (uint256) { return bytes(ss[0].s).length; }
        function rdM() internal view returns (uint256) { return bytes(m[1].s).length; }
        function f() external returns (uint256) { st = S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1); st = S("b", rdLen()); return st.z; }
        function g() external returns (uint256) { ss.push(S("b", rdN())); return ss[0].z; }
        function h() external returns (uint256) { ss[0] = S("cc", rdE()); return ss[0].z; }
        function k() external returns (uint256) { m[1] = S("aaaa", 1); m[1] = S("b", rdM()); return m[1].z; } }`,
      [['f()', ''], ['g()', ''], ['h()', ''], ['k()', '']],
    );
  });

  it('a MEMORY dyn-array ctor arg is captured by reference and read late (P9b)', async () => {
    await eqCalls(
      `@struct class S { arr: u256[]; z: u256 }
      @contract class C {
        @state st: S;
        mut(xs: u256[]): u256 { xs[0n] = 9n; return 3n; }
        @external f(): u256 { let xs: u256[] = new Array<u256>(1n); xs[0n] = 1n; this.st = S(xs, this.mut(xs)); return this.st.arr[0n]; } }`,
      `struct S { uint256[] arr; uint256 z; }
      contract C {
        S st;
        function mut(uint256[] memory xs) internal pure returns (uint256) { xs[0] = 9; return 3; }
        function f() external returns (uint256) { uint256[] memory xs = new uint256[](1); xs[0] = 1; st = S(xs, mut(xs)); return st.arr[0]; } }`,
      [['f()', '']],
    );
  });

  it('a STORAGE array/string ctor arg is snapshotted at its position (early copy, P27/P8)', async () => {
    await eqCalls(
      `@struct class S { arr: u256[]; z: u256 }
      @struct class T { s: string; z: u256 }
      @contract class C {
        @state src: u256[];
        @state sb: string;
        @state st: S;
        @state tt: T;
        mutSrc(): u256 { this.src[0n] = 9n; return 3n; }
        mutSb(): u256 { this.sb = "zz"; return 3n; }
        @external f(): u256 { this.src.push(1n); this.st = S(this.src, this.mutSrc()); return this.st.arr[0n] * 10n + this.src[0n]; }
        @external g(): string { this.sb = "ab"; this.tt = T(this.sb, this.mutSb()); return this.tt.s; } }`,
      `struct S { uint256[] arr; uint256 z; }
      struct T { string s; uint256 z; }
      contract C {
        uint256[] src;
        string sb;
        S st;
        T tt;
        function mutSrc() internal returns (uint256) { src[0] = 9; return 3; }
        function mutSb() internal returns (uint256) { sb = "zz"; return 3; }
        function f() external returns (uint256) { src.push(1); st = S(src, mutSrc()); return st.arr[0] * 10 + src[0]; }
        function g() external returns (string memory) { sb = "ab"; tt = T(sb, mutSb()); return tt.s; } }`,
      [['f()', ''], ['g()', '']],
    );
  });

  it('fixed-array-literal field: elements evaluate at their position, stores after (E2/E11)', async () => {
    await eqCalls(
      `@struct class P { a: Arr<u256, 2>; z: u256 }
      @contract class C {
        @state p: P;
        @state gg: Arr<u256, 2>[];
        rd(): u256 { return this.p.a[0n]; }
        rg(): u256 { return this.gg.length; }
        @external f(): u256 { this.p = P([5n, 6n], 0n); this.p = P([7n, this.rd()], this.rd()); return this.p.a[1n] * 10n + this.p.z; }
        @external g(): u256 { this.gg.push([this.rg(), 9n]); return this.gg[0n][0n] * 10n + this.gg.length; } }`,
      `struct P { uint256[2] a; uint256 z; }
      contract C {
        P p;
        uint256[2][] gg;
        function rd() internal view returns (uint256) { return p.a[0]; }
        function rg() internal view returns (uint256) { return gg.length; }
        function f() external returns (uint256) { p = P([uint256(5), 6], 0); p = P([uint256(7), rd()], rd()); return p.a[1] * 10 + p.z; }
        function g() external returns (uint256) { gg.push([rg(), 9]); return gg[0][0] * 10 + gg.length; } }`,
      [['f()', ''], ['g()', '']],
    );
  });
});
