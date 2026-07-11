// Long-tail batch C lifts (docs/OR-CATALOGUE.md rows F-CALLEE, F-TYPES, F-CONSUMERS, F-MULTIRET),
// byte-identical to solc 0.8.35: the funcref EXPRESSION surface.
// F-CALLEE (4 spellings, one routing family): calling a funcref-valued EXPRESSION -
//   (a) `(c ? this.inc : this.dec)(v)` direct ternary callee, (b) `(c ? a : b).f(10n)` member-call
//   on a struct ternary, (c) `this.mk().f(4n)` member-call on an internal-call result, (d)
//   `this.pick(c)(v)` chained call. The checkExpr call routing now admits parenthesized /
//   CallExpression callees via funcrefCalleeSigDeep (a ternary derives its signature from its
//   branches - address-take forms via funcRefTypeOf, general values via a rolled-back trial - and
//   requires the branch signatures to agree); buildFuncRefCall checks the callee WITH the derived
//   signature so branch address-takes resolve, exactly like the let-bound form.
// ORDER FIX (bar violation caught by the batch's own witnesses): solc's legacy pipeline evaluates
//   a call's ARGUMENTS before its FUNCTION EXPRESSION. All three funcRefCall lowerings (value,
//   statement, destructure-source) now lower args first, then the callee id. This also fixes a
//   LATENT pre-existing miscompile on the already-lifted element/field callee paths
//   (`arr[idx()](a1(), a2())` logged 512 in JETH vs solc's 125 before the fix).
// F-TYPES: (t1) struct-returning funcref `let g: (a: u256) => In = this.mk` (the dispatcher
//   forwards the callee's image pointer; the struct-local init gates admit funcRefCall);
//   (t2) In[]-returning funcref (the aggregate-array init gates admit funcRefCall; u256[] and
//   bytes/string returns were already lifted); (t3) nested funcref-bearing struct `Outer { fd: Fd }`
//   (the @struct decl gate + isSupportedStructReturn admit a nested funcref-bearing dyn-struct
//   field via isSupportedDynStructLocal; o.fd.f reads/writes ride memDynNestedField(Store)).
// F-CONSUMERS: (c1) internal fn returning `[Fd, u256]` - resolveTupleCall + the funcref-pointer
//   rets gate admit SUPPORTED dyn-struct components (incl. plain `[Q, u256]`, a pre-existing OR);
//   (c2) `Fd[]` MEMORY array literal - isFuncrefDynStructLeaf (the funcref twin of isDynStructLeaf,
//   kept separate so every ABI codec route keyed on isDynStructLeaf keeps rejecting) admits the
//   local decl, literal, element read/write, and new Array<Fd>(n).
// F-MULTIRET: (m1) statement-position discard `g(a, b);` of a multi-return pointer call and (m1b)
//   `this.two(x);` of a multi-return internal call (both lower to `let r0, r1 := call` with the
//   components dropped); (m2) direct `return g(a, b)` as the function's tuple (desugared to the
//   tested destructure-then-return, evaluation order preserved).
// SOUNDNESS: every funcref-BEARING type (funcref, Fd, Outer, Fd[], [Fd, u256]) keeps rejecting at
//   EVERY ABI boundary - see the rejects() matrix below (diff-verified 33/33 BOTH-REJECT vs solc).
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint | number) => pad32(BigInt(n));
const run = async (J: string, S: string, calls: ReadonlyArray<readonly [string, string]>) => {
  const h = await Harness.create();
  await h.fund(me, 10n ** 20n);
  const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
  const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
  for (const [sg, args] of calls) {
    const jr = await h.call(ja, sel(sg) + args);
    const sr = await h.call(sa, sel(sg) + args);
    expect(jr.returnHex, `${sg} ${args.slice(0, 12)}`).toBe(sr.returnHex);
    expect(jr.success, sg).toBe(sr.success);
  }
};
const rejects = (src: string): boolean => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return false;
  } catch {
    return true;
  }
};

const FD = `type Fd = { f: (x: u256) => u256; s: string; };`;
const FD_S = `struct Fd { function(uint256) pure returns (uint256) f; string s; }`;

describe('long-tail batch C: the funcref expression surface, byte-identical to solc 0.8.35', () => {
  it('F-CALLEE: all four callee spellings + solc arg-before-callee eval order + Panic 0x51', async () => {
    const J = `${FD}
class C {
  log: u256;
  inc(x: u256): u256 { return x + 1n; }
  dec(x: u256): u256 { return x - 1n; }
  pick(c: bool): (x: u256) => u256 { return c ? this.inc : this.dec; }
  mk(): Fd { return Fd(this.inc, "z"); }
  linc(x: u256): u256 { this.log = this.log * 10n + 3n; return x + 1n; }
  ldec(x: u256): u256 { this.log = this.log * 10n + 4n; return x - 1n; }
  lcond(c: bool): bool { this.log = this.log * 10n + 1n; return c; }
  larg(v: u256): u256 { this.log = this.log * 10n + 2n; return v; }
  get a(c: bool, v: u256): External<u256> { return (c ? this.inc : this.dec)(v); }
  b(c: bool): External<u256> { let x: Fd = Fd(this.inc, "a"); let y: Fd = Fd(this.dec, "b"); return (c ? x : y).f(10n); }
  cc(): External<u256> { return this.mk().f(4n); }
  d(c: bool, v: u256): External<u256> { return this.pick(c)(v); }
  ord(c: bool, v: u256): External<u256> { let r: u256 = (this.lcond(c) ? this.linc : this.ldec)(this.larg(v)); return this.log * 1000n + r; }
  get z(c: bool, v: u256): External<u256> { let zz: (x: u256) => u256; let g: (x: u256) => u256 = this.inc; return (c ? g : zz)(v); }
}`;
    const S = `contract C {
  ${FD_S}
  uint256 log;
  function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
  function dec(uint256 x) internal pure returns (uint256) { return x - 1; }
  function pick(bool c) internal pure returns (function(uint256) pure returns (uint256)) { return c ? inc : dec; }
  function mk() internal pure returns (Fd memory) { return Fd(inc, "z"); }
  function linc(uint256 x) internal returns (uint256) { log = log * 10 + 3; return x + 1; }
  function ldec(uint256 x) internal returns (uint256) { log = log * 10 + 4; return x - 1; }
  function lcond(bool c) internal returns (bool) { log = log * 10 + 1; return c; }
  function larg(uint256 v) internal returns (uint256) { log = log * 10 + 2; return v; }
  function a(bool c, uint256 v) external pure returns (uint256) { return (c ? inc : dec)(v); }
  function b(bool c) external returns (uint256) { Fd memory x = Fd(inc, "a"); Fd memory y = Fd(dec, "b"); return (c ? x : y).f(10); }
  function cc() external returns (uint256) { return mk().f(4); }
  function d(bool c, uint256 v) external returns (uint256) { return pick(c)(v); }
  function ord(bool c, uint256 v) external returns (uint256) { uint256 r = (lcond(c) ? linc : ldec)(larg(v)); return log * 1000 + r; }
  function z(bool c, uint256 v) external pure returns (uint256) { function(uint256) pure returns (uint256) zz; function(uint256) pure returns (uint256) g = inc; return (c ? g : zz)(v); }
}`;
    await run(J, S, [
      ['a(bool,uint256)', W(1) + W(10)],
      ['a(bool,uint256)', W(0) + W(10)],
      ['b(bool)', W(1)],
      ['b(bool)', W(0)],
      ['cc()', ''],
      ['d(bool,uint256)', W(1) + W(10)],
      ['d(bool,uint256)', W(0) + W(10)],
      ['ord(bool,uint256)', W(1) + W(10)], // solc order: arg(2), cond(1), inc(3) -> 213011
      ['ord(bool,uint256)', W(0) + W(10)],
      ['z(bool,uint256)', W(1) + W(10)],
      ['z(bool,uint256)', W(0) + W(10)], // zero pointer -> Panic 0x51 parity
    ] as const);
  });

  it('F-CALLEE order fix: pre-existing element-callee miscompile (arr[idx()](a1(), a2()))', async () => {
    const J = `class C {
  log: u256;
  add2(x: u256, y: u256): u256 { return x + y; }
  idx(): u256 { this.log = this.log * 10n + 5n; return 0n; }
  a1(): u256 { this.log = this.log * 10n + 1n; return 3n; }
  a2(): u256 { this.log = this.log * 10n + 2n; return 4n; }
  go(): External<u256> {
    let arr: Arr<(x: u256, y: u256) => u256, 1> = [this.add2];
    let r: u256 = arr[this.idx()](this.a1(), this.a2());
    return this.log * 1000n + r;
  }
}`;
    const S = `contract C {
  uint256 log;
  function add2(uint256 x, uint256 y) internal pure returns (uint256) { return x + y; }
  function idx() internal returns (uint256) { log = log * 10 + 5; return 0; }
  function a1() internal returns (uint256) { log = log * 10 + 1; return 3; }
  function a2() internal returns (uint256) { log = log * 10 + 2; return 4; }
  function go() external returns (uint256) {
    function(uint256, uint256) pure returns (uint256)[1] memory arr;
    arr[0] = add2;
    uint256 r = arr[idx()](a1(), a2());
    return log * 1000 + r;
  }
}`;
    await run(J, S, [['go()', '']]); // solc: a1(1), a2(2), idx(5) -> 125007
  });

  it('F-TYPES t1/t2: struct- and array-returning funcrefs (In, Fd, In[], chained g(x).f(y))', async () => {
    const J = `${FD}
type In = { x: u256; y: u256 };
class C {
  inc(x: u256): u256 { return x + 1n; }
  mkIn(a: u256): In { return In(a, a + 1n); }
  mkArr(v: u256): In[] { let a: In[] = [In(v, 1n), In(v + 1n, 2n)]; return a; }
  mkFd(t: u256): Fd { return Fd(this.inc, "zz"); }
  get t1(v: u256): External<u256> { let g: (a: u256) => In = this.mkIn; let r: In = g(v); return r.x * 100n + r.y; }
  get t2(v: u256): External<u256> { let g: (v: u256) => In[] = this.mkArr; let r: In[] = g(v); return r[1n].x * 10n + r.length; }
  get t3(v: u256): External<u256> { let g: (t: u256) => Fd = this.mkFd; let d: Fd = g(0n); return d.f(v) * 10n + bytes(d.s).length; }
  get ch(v: u256): External<u256> { let g: (t: u256) => Fd = this.mkFd; return g(0n).f(v); }
}`;
    const S = `contract C {
  ${FD_S}
  struct In { uint256 x; uint256 y; }
  function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
  function mkIn(uint256 a) internal pure returns (In memory) { return In(a, a + 1); }
  function mkArr(uint256 v) internal pure returns (In[] memory) { In[] memory a = new In[](2); a[0] = In(v, 1); a[1] = In(v + 1, 2); return a; }
  function mkFd(uint256 t) internal pure returns (Fd memory) { return Fd(inc, "zz"); }
  function t1(uint256 v) external pure returns (uint256) { function(uint256) pure returns (In memory) g = mkIn; In memory r = g(v); return r.x * 100 + r.y; }
  function t2(uint256 v) external pure returns (uint256) { function(uint256) pure returns (In[] memory) g = mkArr; In[] memory r = g(v); return r[1].x * 10 + r.length; }
  function t3(uint256 v) external pure returns (uint256) { function(uint256) pure returns (Fd memory) g = mkFd; Fd memory d = g(0); return d.f(v) * 10 + bytes(d.s).length; }
  function ch(uint256 v) external pure returns (uint256) { function(uint256) pure returns (Fd memory) g = mkFd; return g(0).f(v); }
}`;
    await run(J, S, [
      ['t1(uint256)', W(7)],
      ['t2(uint256)', W(7)],
      ['t3(uint256)', W(6)],
      ['ch(uint256)', W(6)],
    ] as const);
  });

  it('F-TYPES t3: Outer { fd: Fd } - build, nested read/call, leaf write, alias, internal param, Panic 0x51', async () => {
    const J = `${FD}
type Outer = { fd: Fd; n: u256 };
class C {
  inc(x: u256): u256 { return x + 1n; }
  dec(x: u256): u256 { return x - 1n; }
  useO(o: Outer, v: u256): u256 { return o.fd.f(v) + o.n; }
  mkO(): Outer { return Outer(Fd(this.inc, "z"), 1n); }
  get go(v: u256): External<u256> {
    let o: Outer = Outer(Fd(this.inc, "a"), 7n);
    let p: Outer = o;
    p.fd.f = this.dec;
    return o.fd.f(v) * 100n + this.useO(o, v) + bytes(o.fd.s).length * 1000n;
  }
  get ret(v: u256): External<u256> { let o: Outer = this.mkO(); return o.fd.f(v) * 10n + o.n; }
  get zz(): External<u256> {
    let z: (x: u256) => u256;
    let o: Outer = Outer(Fd(z, "x"), 3n);
    return o.fd.f(5n);
  }
}`;
    const S = `contract C {
  ${FD_S}
  struct Outer { Fd fd; uint256 n; }
  function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
  function dec(uint256 x) internal pure returns (uint256) { return x - 1; }
  function useO(Outer memory o, uint256 v) internal pure returns (uint256) { return o.fd.f(v) + o.n; }
  function mkO() internal pure returns (Outer memory) { return Outer(Fd(inc, "z"), 1); }
  function go(uint256 v) external pure returns (uint256) {
    Outer memory o = Outer(Fd(inc, "a"), 7);
    Outer memory p = o;
    p.fd.f = dec;
    return o.fd.f(v) * 100 + useO(o, v) + bytes(o.fd.s).length * 1000;
  }
  function ret(uint256 v) external pure returns (uint256) { Outer memory o = mkO(); return o.fd.f(v) * 10 + o.n; }
  function zz() external pure returns (uint256) {
    function(uint256) pure returns (uint256) z;
    Outer memory o = Outer(Fd(z, "x"), 3);
    return o.fd.f(5);
  }
}`;
    await run(J, S, [
      ['go(uint256)', W(10)],
      ['ret(uint256)', W(4)],
      ['zz()', ''], // zero nested pointer -> Panic 0x51 parity
    ] as const);
  });

  it('F-CONSUMERS c1: internal tuples [Fd, u256] / [u256, Q] + the funcref-POINTER tuple with an Fd component', async () => {
    const J = `${FD}
type Q = { s: string; n: u256 };
class C {
  inc(x: u256): u256 { return x + 1n; }
  mkF(): [Fd, u256] { return [Fd(this.inc, "z"), 9n]; }
  mkQ(): [u256, Q] { return [4n, Q("abc", 9n)]; }
  mkP(x: u256): [Fd, u256] { return [Fd(this.inc, "z"), x]; }
  get a(): External<u256> { let [d, n] = this.mkF(); return d.f(4n) * 100n + n; }
  get b(): External<u256> { let [a2, q] = this.mkQ(); return a2 * 1000n + q.n * 10n + bytes(q.s).length; }
  get p(v: u256): External<u256> { let g: (x: u256) => [Fd, u256] = this.mkP; let [d, n] = g(v); return d.f(1n) * 100n + n; }
}`;
    const S = `contract C {
  ${FD_S}
  struct Q { string s; uint256 n; }
  function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
  function mkF() internal pure returns (Fd memory, uint256) { return (Fd(inc, "z"), 9); }
  function mkQ() internal pure returns (uint256, Q memory) { return (4, Q("abc", 9)); }
  function mkP(uint256 x) internal pure returns (Fd memory, uint256) { return (Fd(inc, "z"), x); }
  function a() external pure returns (uint256) { (Fd memory d, uint256 n) = mkF(); return d.f(4) * 100 + n; }
  function b() external pure returns (uint256) { (uint256 a2, Q memory q) = mkQ(); return a2 * 1000 + q.n * 10 + bytes(q.s).length; }
  function p(uint256 v) external pure returns (uint256) { function(uint256) pure returns (Fd memory, uint256) g = mkP; (Fd memory d, uint256 n) = g(v); return d.f(1) * 100 + n; }
}`;
    await run(J, S, [
      ['a()', ''],
      ['b()', ''],
      ['p(uint256)', W(7)],
    ] as const);
  });

  it('F-CONSUMERS c2: Fd[] memory - literal, indexed call, element write, alias, new Array, Panic 0x51/0x32', async () => {
    const J = `${FD}
class C {
  inc(x: u256): u256 { return x + 1n; }
  dec(x: u256): u256 { return x - 1n; }
  get go(i: u256, v: u256): External<u256> {
    let arr: Fd[] = [Fd(this.inc, "a"), Fd(this.dec, "b")];
    return arr[i].f(v);
  }
  get wr(v: u256): External<u256> {
    let arr: Fd[] = [Fd(this.inc, "a"), Fd(this.dec, "b")];
    arr[0n] = Fd(this.dec, "c");
    let d: Fd = arr[1n];
    d.f = this.inc;
    return arr[0n].f(v) * 100n + arr[1n].f(v) * 10n + arr.length;
  }
  get na(): External<u256> {
    let arr: Fd[] = new Array<Fd>(2n);
    arr[0n] = Fd(this.inc, "x");
    return arr[0n].f(4n) + arr.length;
  }
  get zf(i: u256): External<u256> {
    let z: (x: u256) => u256;
    let arr: Fd[] = [Fd(z, "a"), Fd(this.inc, "b")];
    return arr[i].f(5n);
  }
}`;
    const S = `contract C {
  ${FD_S}
  function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
  function dec(uint256 x) internal pure returns (uint256) { return x - 1; }
  function go(uint256 i, uint256 v) external pure returns (uint256) {
    Fd[] memory arr = new Fd[](2);
    arr[0] = Fd(inc, "a"); arr[1] = Fd(dec, "b");
    return arr[i].f(v);
  }
  function wr(uint256 v) external pure returns (uint256) {
    Fd[] memory arr = new Fd[](2);
    arr[0] = Fd(inc, "a"); arr[1] = Fd(dec, "b");
    arr[0] = Fd(dec, "c");
    Fd memory d = arr[1];
    d.f = inc;
    return arr[0].f(v) * 100 + arr[1].f(v) * 10 + arr.length;
  }
  function na() external pure returns (uint256) {
    Fd[] memory arr = new Fd[](2);
    arr[0] = Fd(inc, "x");
    return arr[0].f(4) + arr.length;
  }
  function zf(uint256 i) external pure returns (uint256) {
    function(uint256) pure returns (uint256) z;
    Fd[] memory arr = new Fd[](2);
    arr[0] = Fd(z, "a"); arr[1] = Fd(inc, "b");
    return arr[i].f(5);
  }
}`;
    await run(J, S, [
      ['go(uint256,uint256)', W(0) + W(10)],
      ['go(uint256,uint256)', W(1) + W(10)],
      ['go(uint256,uint256)', W(2) + W(10)], // OOB -> Panic 0x32 parity
      ['wr(uint256)', W(10)],
      ['na()', ''], // new Array<Fd>(2): zero funcref field in arr[1] never called; length + call parity
      ['zf(uint256)', W(0)], // zero funcref field -> Panic 0x51 parity
      ['zf(uint256)', W(1)],
    ] as const);
  });

  it('F-MULTIRET m1/m1b/m2: statement discards + direct tuple return, incl. ternary callees', async () => {
    const J = `class C {
  hits: u256;
  two(x: u256): [u256, u256] { this.hits = this.hits + 1n; return [x, x + 1n]; }
  three(x: u256): [u256, u256] { this.hits = this.hits + 2n; return [x, x]; }
  ptwo(a: u256, b: u256): [u256, u256] { return [a + b, a * b]; }
  m1(v: u256): External<u256> { let g: (x: u256) => [u256, u256] = this.two; g(v); return this.hits; }
  m1b(v: u256): External<u256> { this.two(v); return this.hits; }
  m1t(c: bool, v: u256): External<u256> { (c ? this.two : this.three)(v); return this.hits; }
  get m2(a: u256, b: u256): External<[u256, u256]> { let g: (a: u256, b: u256) => [u256, u256] = this.ptwo; return g(a, b); }
  get m2t(c: bool, v: u256): External<[u256, u256]> { return (c ? this.two2 : this.three2)(v); }
  two2(x: u256): [u256, u256] { return [x + 1n, x + 2n]; }
  three2(x: u256): [u256, u256] { return [x * 2n, x * 3n]; }
  get m2d(c: bool, v: u256): External<u256> { let [a, b] = (c ? this.two2 : this.three2)(v); return a * 100n + b; }
}`;
    const S = `contract C {
  uint256 hits;
  function two(uint256 x) internal returns (uint256, uint256) { hits = hits + 1; return (x, x + 1); }
  function three(uint256 x) internal returns (uint256, uint256) { hits = hits + 2; return (x, x); }
  function ptwo(uint256 a, uint256 b) internal pure returns (uint256, uint256) { return (a + b, a * b); }
  function m1(uint256 v) external returns (uint256) { function(uint256) returns (uint256, uint256) g = two; g(v); return hits; }
  function m1b(uint256 v) external returns (uint256) { two(v); return hits; }
  function m1t(bool c, uint256 v) external returns (uint256) { (c ? two : three)(v); return hits; }
  function m2(uint256 a, uint256 b) external pure returns (uint256, uint256) { function(uint256, uint256) pure returns (uint256, uint256) g = ptwo; return g(a, b); }
  function m2t(bool c, uint256 v) external pure returns (uint256, uint256) { return (c ? two2 : three2)(v); }
  function two2(uint256 x) internal pure returns (uint256, uint256) { return (x + 1, x + 2); }
  function three2(uint256 x) internal pure returns (uint256, uint256) { return (x * 2, x * 3); }
  function m2d(bool c, uint256 v) external pure returns (uint256) { (uint256 a, uint256 b) = (c ? two2 : three2)(v); return a * 100 + b; }
}`;
    await run(J, S, [
      ['m1(uint256)', W(3)],
      ['m1b(uint256)', W(3)],
      ['m1t(bool,uint256)', W(1) + W(9)],
      ['m1t(bool,uint256)', W(0) + W(9)],
      ['m2(uint256,uint256)', W(3) + W(4)],
      ['m2t(bool,uint256)', W(1) + W(7)],
      ['m2t(bool,uint256)', W(0) + W(7)],
      ['m2d(bool,uint256)', W(1) + W(7)],
      ['m2d(bool,uint256)', W(0) + W(7)],
    ] as const);
  });

  it('F-MULTIRET m2: mixed [u256, string] tuple through a pointer + statement discards through expression callees', async () => {
    const J = `type FdM = { f: (x: u256) => u256; s: string; };
class C {
  h: u256;
  mk(x: u256): [u256, string] { return [x + 1n, "hey"]; }
  bump(x: u256): u256 { this.h = this.h + x; return x; }
  pickB(c: bool): (x: u256) => u256 { return this.bump; }
  get go(v: u256): External<[u256, string]> { let g: (x: u256) => [u256, string] = this.mk; return g(v); }
  st(c: bool, v: u256): External<u256> {
    let a: FdM = FdM(this.bump, "a");
    let b: FdM = FdM(this.bump, "b");
    (c ? a : b).f(v);
    this.pickB(c)(v);
    return this.h;
  }
}`;
    const S = `contract C {
  struct FdM { function(uint256) returns (uint256) f; string s; }
  uint256 h;
  function mk(uint256 x) internal pure returns (uint256, string memory) { return (x + 1, "hey"); }
  function bump(uint256 x) internal returns (uint256) { h = h + x; return x; }
  function pickB(bool c) internal returns (function(uint256) returns (uint256)) { return bump; }
  function go(uint256 v) external pure returns (uint256, string memory) { function(uint256) pure returns (uint256, string memory) g = mk; return g(v); }
  function st(bool c, uint256 v) external returns (uint256) {
    FdM memory a = FdM(bump, "a");
    FdM memory b = FdM(bump, "b");
    (c ? a : b).f(v);
    pickB(c)(v);
    return h;
  }
}`;
    await run(J, S, [
      ['go(uint256)', W(6)],
      ['st(bool,uint256)', W(1) + W(5)],
      ['st(bool,uint256)', W(0) + W(5)],
    ] as const);
  });

  it('rejects(): the full ABI-leak matrix for every newly-admitted funcref-bearing type', () => {
    const PRE = `${FD}\ntype Outer = { fd: Fd; n: u256 };\n`;
    const HELP = `  inc(x: u256): u256 { return x + 1n; }\n  mkFd(): Fd { return Fd(this.inc, "z"); }\n  mkOuter(): Outer { return Outer(Fd(this.inc, "z"), 1n); }\n`;
    const C = (body: string) => `${PRE}@contract class C {\n${HELP}${body}\n}`;
    // abi.encode / encodePacked / decode / encodeWith* (solc: all reject, diff-verified BOTH-REJECT)
    expect(rejects(C(`  @external @pure go(): bytes { return abi.encode(this.mkFd()); }`))).toBe(true);
    expect(rejects(C(`  @external @pure go(): bytes { return abi.encodePacked(this.mkFd()); }`))).toBe(true);
    expect(rejects(C(`  @external @pure go(): bytes { return abi.encode(this.mkOuter()); }`))).toBe(true);
    expect(rejects(C(`  @external @pure go(): bytes { let a: Fd[] = [this.mkFd()]; return abi.encode(a); }`))).toBe(true);
    expect(rejects(C(`  @external @pure go(b: bytes): u256 { let d: Fd = abi.decode(b, Fd); return d.f(1n); }`))).toBe(true);
    expect(rejects(C(`  @external @pure go(b: bytes): u256 { let o: Outer = abi.decode(b, Outer); return o.n; }`))).toBe(true);
    expect(rejects(C(`  @external @pure go(b: bytes): u256 { let a: Fd[] = abi.decode(b, Fd[]); return a.length; }`))).toBe(true);
    expect(rejects(C(`  @external @pure go(): bytes { return abi.encodeWithSelector(0x12345678, this.mkFd()); }`))).toBe(true);
    expect(rejects(C(`  @external @pure go(): bytes { return abi.encodeWithSignature("f(uint256)", this.mkOuter()); }`))).toBe(true);
    // @external / @public params and returns (incl. the tuple)
    expect(rejects(C(`  @external go(d: Fd): u256 { return 1n; }`))).toBe(true);
    expect(rejects(C(`  @external go(o: Outer): u256 { return 1n; }`))).toBe(true);
    expect(rejects(C(`  @external go(a: Fd[]): u256 { return 1n; }`))).toBe(true);
    expect(rejects(C(`  @external @pure go(): Fd { return this.mkFd(); }`))).toBe(true);
    expect(rejects(C(`  @external @pure go(): Outer { return this.mkOuter(); }`))).toBe(true);
    expect(rejects(C(`  @external @pure go(): Fd[] { let a: Fd[] = [this.mkFd()]; return a; }`))).toBe(true);
    expect(rejects(C(`  @external @pure go(): [Fd, u256] { return [this.mkFd(), 1n]; }`))).toBe(true);
    expect(rejects(C(`  @external @pure go(): (x: u256) => u256 { return this.inc; }`))).toBe(true);
    expect(rejects(C(`  @public go(d: Fd): u256 { return 1n; }`))).toBe(true);
    // events (both arms) / errors
    expect(rejects(C(`  @event E(d: Fd);\n  @external go(): u256 { emit(E(this.mkFd())); return 1n; }`))).toBe(true);
    expect(rejects(C(`  @event E(@indexed d: Fd);\n  @external go(): u256 { emit(E(this.mkFd())); return 1n; }`))).toBe(true);
    expect(rejects(C(`  @event E(o: Outer);\n  @external go(): u256 { emit(E(this.mkOuter())); return 1n; }`))).toBe(true);
    expect(rejects(C(`  @event E(a: Fd[]);\n  @external go(): u256 { let a: Fd[] = [this.mkFd()]; emit(E(a)); return 1n; }`))).toBe(true);
    expect(rejects(C(`  @error Bad(d: Fd);\n  @external go(): u256 { revert(Bad(this.mkFd())); }`))).toBe(true);
    expect(rejects(C(`  @error Bad(o: Outer);\n  @external go(): u256 { revert(Bad(this.mkOuter())); }`))).toBe(true);
    // getters (state + mapping value) / constructor params
    expect(rejects(C(`  @public d: Fd;`))).toBe(true);
    expect(rejects(C(`  @public o: Outer;`))).toBe(true);
    expect(rejects(C(`  @public m: mapping<u256, (x: u256) => u256>;`))).toBe(true);
    expect(rejects(C(`  @public g: (x: u256) => u256;`))).toBe(true);
    expect(rejects(C(`  constructor(d: Fd) {}`))).toBe(true);
    expect(rejects(C(`  constructor(o: Outer) {}`))).toBe(true);
    expect(rejects(C(`  constructor(g: (x: u256) => u256) {}`))).toBe(true);
    // @interface method types
    expect(
      rejects(`${FD}\ninterface I { f(d: Fd): u256; }\nclass C { get go(): External<u256> { return 1n; } }`),
    ).toBe(true);
    // Arr<Fd,2> element dispatch was LIFTED by long-tail batch D (memory-local fixed array of
    // funcref structs, byte-identical incl. OOB Panic; every ABI boundary still rejects it - see
    // lift-longtail-batchD.test.ts). The old "catalogued residual" pin flips to a compile assert.
    expect(rejects(C(`  @external @pure go(v: u256): u256 { let a: Arr<Fd, 2> = [this.mkFd(), this.mkFd()]; return a[0n].f(v); }`))).toBe(false); // Arr<Fd,N> lifted (batch D)
    // @state Outer (funcref-bearing struct in STORAGE) stays a clean reject: JETH has no storage funcref layout.
    expect(rejects(`${PRE}@contract class C {\n  inc(x: u256): u256 { return x + 1n; }\n  @state o: Outer;\n  @external @view go(v: u256): u256 { let m: Outer = this.o; return m.fd.f(v); }\n}`)).toBe(true); // @state Outer
  });

  it('bonus lift: whole nested funcref-field WRITE o.fd = mkFd() with solc re-point alias semantics', async () => {
    // The batch C machinery lifted this shape (it was expected to stay a pre-existing-family
    // reject): verified byte-identical INCLUDING the alias witnesses - a previously-bound
    // `old: Fd = o.fd` keeps the OLD funcref after the write (solc re-points, never copies),
    // and a whole-struct alias `al: Outer = o` sees the NEW one through al.fd.
    const PRE = `${FD}\ntype Outer = { fd: Fd; n: u256 };\n`;
    const J = `${PRE}@contract class C {
  inc(x: u256): u256 { return x + 1n; }
  dec(x: u256): u256 { return x - 1n; }
  mkFd(): Fd { return Fd(this.dec, "w"); }
  mkOuter(): Outer { return Outer(Fd(this.inc, "z"), 7n); }
  @external @pure go(v: u256): u256 { let o: Outer = this.mkOuter(); o.fd = this.mkFd(); return o.fd.f(v); }
  @external @pure ali(v: u256): u256 { let o: Outer = this.mkOuter(); let old: Fd = o.fd; o.fd = this.mkFd(); return old.f(v) * 1000n + o.fd.f(v); }
  @external @pure ali2(v: u256): u256 { let o: Outer = this.mkOuter(); let al: Outer = o; o.fd = this.mkFd(); return al.fd.f(v); }
}`;
    const S = `struct Fd { function(uint256) pure returns (uint256) f; string s; }
struct Outer { Fd fd; uint256 n; }
contract C {
  function inc(uint256 x) internal pure returns (uint256) { return x + 1; }
  function dec(uint256 x) internal pure returns (uint256) { return x - 1; }
  function mkFd() internal pure returns (Fd memory) { return Fd(dec, "w"); }
  function mkOuter() internal pure returns (Outer memory) { return Outer(Fd(inc, "z"), 7); }
  function go(uint256 v) external pure returns (uint256) { Outer memory o = mkOuter(); o.fd = mkFd(); return o.fd.f(v); }
  function ali(uint256 v) external pure returns (uint256) { Outer memory o = mkOuter(); Fd memory old = o.fd; o.fd = mkFd(); return old.f(v) * 1000 + o.fd.f(v); }
  function ali2(uint256 v) external pure returns (uint256) { Outer memory o = mkOuter(); Outer memory al = o; o.fd = mkFd(); return al.fd.f(v); }
}`;
    await run(J, S, [['go(uint256)', W(10)], ['ali(uint256)', W(10)], ['ali2(uint256)', W(10)]] as const);
  });
});
