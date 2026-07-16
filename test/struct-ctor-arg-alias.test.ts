// W6A: struct-typed argument to a memory struct CONSTRUCTOR - reference vs copy.
// Solidity memory-to-memory assignment is BY REFERENCE: `S(1, t)` stores t's POINTER, so later
// mutations of t are visible through s.t and vice versa. JETH previously deep-copied the argument
// image (a confirmed miscompile family, 10+ variants).
//  FIXED byte-identical: a DYNAMIC struct field is pointer-headed in the constructed image, so a
//    memory source (local / param / nested field) is now captured BY POINTER (buildDynStructLocal),
//    across every consumer: local bind, encode, return, emit, storage write/push/mapping, internal
//    call arg / return, double capture, 2-level chains.
//  CLEAN JETH465 REJECT (a reject beats wrong bytes): a STATIC struct / fixed-array field is laid
//    out INLINE (flat) in the image and cannot be re-pointed, so capturing an aliasable MEMORY
//    source into it in a PERSISTENT context rejects; transient consumers (immediate return /
//    abi.encode / storage store) keep the copy (unobservable). Also rejected: a ref capture
//    combined with a side-effecting sibling argument (solc reads the reference at encode time,
//    AFTER all arguments - JETH's field-position reads would diverge), and unstable dyn sources
//    (a memory array element / call / ternary - the tuple encoders resolve fields twice).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
async function diff(J: string, S: string, calls: [string, string?][]) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  const out: string[] = [];
  for (const [sg, args] of calls) {
    const data = sel(sg) + (args || '');
    const rj = await h.call(aj, data);
    const rs = await h.call(as, data);
    expect(rj.success, sg).toBe(rs.success);
    expect(rj.returnHex, sg).toBe(rs.returnHex);
    out.push(rj.returnHex);
  }
  return out;
}
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e) {
    const d = (e as { diagnostics?: { code: string }[] }).diagnostics;
    return d ? d.map((x) => x.code) : ['THROW'];
  }
};

const JT = `type T = { n: u256; s: string };\n`;
const ST = `struct T { uint256 n; string s; }\n`;

describe('W6A: dyn-struct ctor field captures a memory reference (pointer, not copy) vs solc 0.8.35', () => {
  it('bidirectional aliasing through the captured pointer + double capture', async () => {
    const J = `${JT}type S = { a: u256; t: T };
    type S2 = { x: T; y: T };
    class C {
      get fwd(): External<u256> { let t: T = T(5n, "x"); let s: S = S(1n, t); t.n = 9n; return s.t.n; }
      get rev(): External<u256> { let t: T = T(5n, "x"); let s: S = S(1n, t); s.t.n = 9n; return t.n; }
      get str(): External<string> { let t: T = T(5n, "aa"); let s: S = S(1n, t); t.s = "bb-longer-than-32-bytes-payload-word!"; return s.t.s; }
      get dbl(): External<u256> { let t: T = T(5n, "x"); let s: S2 = S2(t, t); s.x.n = 7n; return s.y.n * 100n + t.n; } }`;
    const S = `${ST}struct S { uint256 a; T t; }
    struct S2 { T x; T y; }
    contract C {
      function fwd() external pure returns (uint256) { T memory t = T(5, "x"); S memory s = S(1, t); t.n = 9; return s.t.n; }
      function rev() external pure returns (uint256) { T memory t = T(5, "x"); S memory s = S(1, t); s.t.n = 9; return t.n; }
      function str() external pure returns (string memory) { T memory t = T(5, "aa"); S memory s = S(1, t); t.s = "bb-longer-than-32-bytes-payload-word!"; return s.t.s; }
      function dbl() external pure returns (uint256) { T memory t = T(5, "x"); S2 memory s = S2(t, t); s.x.n = 7; return s.y.n * 100 + t.n; } }`;
    const [fwd, rev, , dbl] = await diff(J, S, [['fwd()'], ['rev()'], ['str()'], ['dbl()']]);
    // NON-VACUITY: the mutation really flows through the pointer on both sides.
    expect(fwd).toBe('0x' + pad32(9n));
    expect(rev).toBe('0x' + pad32(9n));
    expect(dbl).toBe('0x' + pad32(707n));
  });

  it('dyn-array-bearing T{xs,n}: value field aliases too (whole-image pointer)', async () => {
    const J = `type T = { xs: u256[]; n: u256 };
    type S = { a: u256; t: T };
    class C { get f(): External<u256> {
      let xs: u256[] = new Array<u256>(2n); xs[0n] = 3n;
      let t: T = T(xs, 5n); let s: S = S(1n, t); t.n = 9n; xs[1n] = 4n;
      return s.t.n * 100n + s.t.xs[1n]; } }`;
    const S = `struct T { uint256[] xs; uint256 n; }
    struct S { uint256 a; T t; }
    contract C { function f() external pure returns (uint256) {
      uint256[] memory xs = new uint256[](2); xs[0] = 3;
      T memory t = T(xs, 5); S memory s = S(1, t); t.n = 9; xs[1] = 4;
      return s.t.n * 100 + s.t.xs[1]; } }`;
    await diff(J, S, [['f()']]);
  });

  it('every consumer of the captured pointer: encode / direct return / storage / push / mapping', async () => {
    const J = `${JT}type S = { a: u256; t: T };
    class C {
      sd: S; arr: S[]; m: mapping<u256, S>;
      get enc(): External<bytes> { let t: T = T(5n, "x"); let s: S = S(1n, t); t.n = 9n; return abi.encode(s); }
      get ret(): External<S> { let t: T = T(5n, "hello-there-long-string-payload!!"); return S(1n, t); }
      stor(): External<u256> { let t: T = T(5n, "x"); let s: S = S(1n, t); t.n = 9n; this.sd = s; return this.sd.t.n; }
      psh(): External<u256> { let t: T = T(5n, "x"); t.n = 9n; this.arr.push(S(1n, t)); return this.arr[0n].t.n; }
      mp(): External<u256> { let t: T = T(5n, "x"); t.n = 9n; this.m[1n] = S(1n, t); return this.m[1n].t.n; } }`;
    const S = `${ST}struct S { uint256 a; T t; }
    contract C {
      S sd; S[] arr; mapping(uint256 => S) m;
      function enc() external pure returns (bytes memory) { T memory t = T(5, "x"); S memory s = S(1, t); t.n = 9; return abi.encode(s); }
      function ret() external pure returns (S memory) { T memory t = T(5, "hello-there-long-string-payload!!"); return S(1, t); }
      function stor() external returns (uint256) { T memory t = T(5, "x"); S memory s = S(1, t); t.n = 9; sd = s; return sd.t.n; }
      function psh() external returns (uint256) { T memory t = T(5, "x"); t.n = 9; arr.push(S(1, t)); return arr[0].t.n; }
      function mp() external returns (uint256) { T memory t = T(5, "x"); t.n = 9; m[1] = S(1, t); return m[1].t.n; } }`;
    await diff(J, S, [['enc()'], ['ret()'], ['stor()'], ['psh()'], ['mp()']]);
  });

  it('internal calls: ctor as arg (callee mutates through), internal return wrapping a param', async () => {
    const J = `${JT}type S = { a: u256; t: T };
    class C {
      mut(s: S): u256 { s.t.n = 9n; return s.a; }
      mk(x: T): S { return S(1n, x); }
      get viaArg(): External<u256> { let t: T = T(5n, "x"); this.mut(S(1n, t)); return t.n; }
      get viaRet(): External<u256> { let t: T = T(5n, "x"); let s: S = this.mk(t); t.n = 9n; return s.t.n; } }`;
    const S = `${ST}struct S { uint256 a; T t; }
    contract C {
      function mut(S memory s) internal pure returns (uint256) { s.t.n = 9; return s.a; }
      function mk(T memory x) internal pure returns (S memory) { return S(1, x); }
      function viaArg() external pure returns (uint256) { T memory t = T(5, "x"); mut(S(1, t)); return t.n; }
      function viaRet() external pure returns (uint256) { T memory t = T(5, "x"); S memory s = mk(t); t.n = 9; return s.t.n; } }`;
    await diff(J, S, [['viaArg()'], ['viaRet()']]);
  });

  it('2-level chain + nested-field-ref capture + storage/calldata sources stay copies', async () => {
    const J = `${JT}type S = { a: u256; t: T };
    type U = { s: S };
    type S2 = { b: u256; s: S };
    class C {
      st: T;
      get chain(): External<u256> { let t: T = T(5n, "x"); let u: U = U(S(1n, t)); t.n = 9n; let a: u256 = u.s.t.n; u.s.t.n += 100n; return a * 1000n + t.n; }
      get nref(): External<u256> { let u: U = U(S(1n, T(5n, "x"))); let w: S2 = S2(2n, u.s); u.s.a = 7n; return w.s.a; }
      storSrc(): External<u256> { this.st = T(5n, "x"); let s: S = S(1n, this.st); this.st.n = 9n; return s.t.n; }
      get cdSrc(t: T): External<u256> { let s: S = S(1n, t); s.t.n = 9n; return s.t.n + t.n; } }`;
    const S = `${ST}struct S { uint256 a; T t; }
    struct U { S s; }
    struct S2 { uint256 b; S s; }
    contract C {
      T st;
      function chain() external pure returns (uint256) { T memory t = T(5, "x"); U memory u = U(S(1, t)); t.n = 9; uint256 a = u.s.t.n; u.s.t.n += 100; return a * 1000 + t.n; }
      function nref() external pure returns (uint256) { U memory u = U(S(1, T(5, "x"))); S2 memory w = S2(2, u.s); u.s.a = 7; return w.s.a; }
      function storSrc() external returns (uint256) { st = T(5, "x"); S memory s = S(1, st); st.n = 9; return s.t.n; }
      function cdSrc(T calldata t) external pure returns (uint256) { S memory s = S(1, t); s.t.n = 9; return s.t.n + t.n; } }`;
    const cd = pad32(0x20n) + pad32(5n) + pad32(0x40n) + pad32(1n) + '78' + '0'.repeat(62);
    await diff(J, S, [['chain()'], ['nref()'], ['storSrc()'], ['cdSrc((uint256,string))', cd]]);
  });
});

describe('W6A: static-inline captures REJECT cleanly (JETH465) instead of the old silent copy', () => {
  const HDR = `type T = { n: u256 };
  type S = { a: u256; t: T };\n`;
  it('primary family: local bind / 2-level / double / abi.encode-of-local / storage round-trip', () => {
    expect(codes(`${HDR}class C { get f(): External<u256> { let t: T = T(5n); let s: S = S(1n, t); t.n = 9n; return s.t.n; } }`)).toContain('JETH465');
    expect(codes(`type I = { n: u256 };
    type T2 = { i: I };
    type S = { t: T2 };
    class C { get f(): External<u256> { let i: I = I(5n); let s: S = S(T2(i)); i.n = 9n; return s.t.i.n; } }`)).toContain('JETH465');
    expect(codes(`type T = { n: u256 };
    type S2 = { x: T; y: T };
    class C { get f(): External<u256> { let t: T = T(5n); let s: S2 = S2(t, t); s.x.n = 7n; return s.y.n; } }`)).toContain('JETH465');
    expect(codes(`${HDR}class C { get f(): External<bytes> { let t: T = T(5n); let s: S = S(1n, t); t.n = 9n; return abi.encode(s); } }`)).toContain('JETH465');
    expect(codes(`${HDR}class C { st: S; f(): External<u256> { let t: T = T(5n); let s: S = S(1n, t); t.n = 9n; this.st = s; return this.st.t.n; } }`)).toContain('JETH465');
  });
  it('fixed-array captures: Arr<P,2> from [p,q] elements, Arr<u256,2> from a local', () => {
    expect(codes(`type P = { a: u256 };
    type S = { ps: Arr<P, 2>; z: u256 };
    class C { get f(): External<u256> { let p: P = P(5n); let q: P = P(6n); let s: S = S([p, q], 1n); p.a = 9n; return s.ps[0n].a; } }`)).toContain('JETH465');
    expect(codes(`type S = { a: u256; xs: Arr<u256, 2> };
    class C { get f(): External<u256> { let xs: Arr<u256, 2> = [u256(1n), 2n]; let s: S = S(1n, xs); xs[0n] = 9n; return s.xs[0n]; } }`)).toContain('JETH465');
  });
  it('call-result source, ctor-as-internal-arg, capture inside a transient encode arg', () => {
    expect(codes(`${HDR}class C {
      id(x: T): T { return x; }
      get f(): External<u256> { let t: T = T(5n); let s: S = S(1n, this.id(t)); t.n = 9n; return s.t.n; } }`)).toContain('JETH465');
    expect(codes(`${HDR}class C {
      mut(s: S): u256 { s.t.n = 9n; return s.a; }
      get f(): External<u256> { let t: T = T(5n); this.mut(S(1n, t)); return t.n; } }`)).toContain('JETH465');
    expect(codes(`${HDR}class C {
      mut(s: S): u256 { s.t.n = 9n; return s.a; }
      get f(): External<bytes> { let t: T = T(5n); return abi.encode(this.mut(S(1n, t))); } }`)).toContain('JETH465');
  });
  it('ref capture + side-effecting sibling arg rejects (order hazard); unstable dyn sources reject', () => {
    expect(codes(`type T = { n: u256; s: string };
    type S2 = { t: T; x: u256 };
    class C {
      bump(t: T): u256 { t.n = 77n; return 3n; }
      get f(): External<S2> { let t: T = T(5n, "x"); return S2(t, this.bump(t)); } }`)).toContain('JETH465');
    expect(codes(`type T = { n: u256; s: string };
    type S = { a: u256; t: T };
    class C { get f(): External<u256> {
      let xs: T[] = [T(5n, "x")]; let s: S = S(1n, xs[0n]); return s.t.n; } }`)).toContain('JETH465');
    expect(codes(`type T = { n: u256; s: string };
    type S = { a: u256; t: T };
    class C {
      mk(): T { return T(5n, "x"); }
      get f(): External<u256> { let s: S = S(1n, this.mk()); return s.t.n; } }`)).toContain('JETH465');
  });
});

describe('W6A: transient static captures stay accepted byte-identical (no regression)', () => {
  it('immediate return / abi.encode / direct storage write / emit / error / tuple / push', async () => {
    const J = `type T = { n: u256 };
    type S = { a: u256; t: T };
    class C {
      st: S; arr: S[];
      E: event<{ s: S }>;
      MyErr: error<{ s: S }>;
      get ret(): External<S> { let t: T = T(5n); return S(1n, t); }
      get enc(): External<bytes> { let t: T = T(5n); return abi.encode(S(1n, t)); }
      stor(): External<u256> { let t: T = T(5n); this.st = S(1n, t); t.n = 9n; return this.st.t.n; }
      emitE(): External<u256> { let t: T = T(5n); emit(E(S(1n, t))); return 1n; }
      get err(): External<u256> { let t: T = T(5n); revert(MyErr(S(1n, t))); }
      get tup(): External<[S, u256]> { let t: T = T(5n); return [S(1n, t), 7n]; }
      psh(): External<u256> { let t: T = T(5n); t.n = 9n; this.arr.push(S(1n, t)); return this.arr[0n].t.n; } }`;
    const S = `struct T { uint256 n; }
    struct S { uint256 a; T t; }
    contract C {
      S st; S[] arr;
      event E(S s);
      error MyErr(S s);
      function ret() external pure returns (S memory) { T memory t = T(5); return S(1, t); }
      function enc() external pure returns (bytes memory) { T memory t = T(5); return abi.encode(S(1, t)); }
      function stor() external returns (uint256) { T memory t = T(5); st = S(1, t); t.n = 9; return st.t.n; }
      function emitE() external returns (uint256) { T memory t = T(5); emit E(S(1, t)); return 1; }
      function err() external pure returns (uint256) { T memory t = T(5); revert MyErr(S(1, t)); }
      function tup() external pure returns (S memory, uint256) { T memory t = T(5); return (S(1, t), 7); }
      function psh() external returns (uint256) { T memory t = T(5); t.n = 9; arr.push(S(1, t)); return arr[0].t.n; } }`;
    await diff(J, S, [['ret()'], ['enc()'], ['stor()'], ['emitE()'], ['err()'], ['tup()'], ['psh()']]);
  });

  it('adjacent aliasing shapes unregressed: alias local, element store, array literal, z = m.i', async () => {
    const J = `type T = { n: u256 };
    type I = { xs: u256[] };
    type M = { i: I };
    class C {
      get alias(): External<u256> { let t: T = T(5n); let u: T = t; t.n = 9n; return u.n; }
      get elem(): External<u256> { let t: T = T(5n); let xs: T[] = new Array<T>(1n); xs[0n] = t; t.n = 9n; return xs[0n].n; }
      get lit(): External<u256> { let t: T = T(5n); let xs: T[] = [t]; t.n = 9n; return xs[0n].n; }
      get fld(): External<u256> { let m: M = M(I(new Array<u256>(1n))); let z: I = m.i; z.xs[0n] = 7n; return m.i.xs[0n]; } }`;
    const S = `struct T { uint256 n; }
    struct I { uint256[] xs; }
    struct M { I i; }
    contract C {
      function alias_() external pure returns (uint256) { T memory t = T(5); T memory u = t; t.n = 9; return u.n; }
      function elem() external pure returns (uint256) { T memory t = T(5); T[] memory xs = new T[](1); xs[0] = t; t.n = 9; return xs[0].n; }
      function lit() external pure returns (uint256) { T memory t = T(5); T[] memory xs = new T[](1); xs[0] = t; t.n = 9; return xs[0].n; }
      function fld() external pure returns (uint256) { M memory m = M(I(new uint256[](1))); I memory z = m.i; z.xs[0] = 7; return m.i.xs[0]; } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const pairs: [string, string][] = [['alias()', 'alias_()'], ['elem()', 'elem()'], ['lit()', 'lit()'], ['fld()', 'fld()']];
    for (const [js, ss] of pairs) {
      const rj = await h.call(aj, sel(js));
      const rs = await h.call(as, sel(ss));
      expect(rj.success, js).toBe(rs.success);
      expect(rj.returnHex, js).toBe(rs.returnHex);
    }
  });
});

// The NOMINAL check on inline-constructor field args: `Outer(A(9n), 6n)` with a B-typed field used to
// slip past the name check (the structNew early-return preceded it), accepting a struct-A image in a
// struct-B slot - a field read past the passed struct's size read adjacent memory. solc rejects the twin
// as not implicitly convertible. Surfaced by the v3 scoping sweep (easy to hit with cross-file same-named
// structs), but single-file too.
describe('wrong-struct inline constructor arg (nominal check)', () => {
  const codes = (src: string): string[] => {
    try { compile(src, { fileName: 'v.jeth' }); return []; } catch (e: any) { return e.diagnostics.map((d: any) => d.code); }
  };
  it('a wrong-named inline ctor arg rejects (JETH226), incl. the wider-field adjacent-read shape', () => {
    expect(codes(`type A = { z: u256 };\ntype B = { q: u256 };\ntype Outer = { i: B; y: u256 };\nclass V { get f(): External<u256> { let o: Outer = Outer(A(9n), 6n); return o.y; } }`)).toContain('JETH226');
    expect(codes(`type Small = { z: u256 };\ntype Wide = { a: u256; w: u256 };\ntype Outer = { i: Wide; y: u256 };\nclass V { get f(): External<u256> { let o: Outer = Outer(Small(9n), 6n); return o.i.w; } }`)).toContain('JETH226');
    // the v3 cross-file shape: the entry's own same-named struct into a dep's field type
    const d = (src: string, sources: Record<string, string>) => {
      try { compile(src, { fileName: 'v.jeth', sources }); return []; } catch (e: any) { return e.diagnostics.map((x: any) => x.code); }
    };
    expect(d(`import { Outer } from "./d.jeth";\ntype Inner = { z: u256 };\nclass V { get f(): External<u256> { let o: Outer = Outer(Inner(9n), 6n); return o.y; } }`,
      { 'd.jeth': `export type Inner = { a: u256; b: u256 };\nexport type Outer = { i: Inner; y: u256 };` })).toContain('JETH226');
  });
  it('same-struct inline ctors (flat + nested) and contextual object literals keep working', async () => {
    const h = await Harness.create();
    const r = compile(`type In = { a: u256 };\ntype Mid = { i: In; m: u256 };\ntype Out = { md: Mid; o: u256 };\nclass V { get f(): External<u256> { let v: Out = Out(Mid(In(1n), 2n), 3n); return v.md.i.a + v.md.m + v.o; } }`, { fileName: 'v.jeth' });
    const a = await h.deploy(r.creationBytecode);
    expect(BigInt((await h.call(a, sel('f()'))).returnHex)).toBe(6n);
    const r2 = compile(`type B = { q: u256 };\ntype Outer = { i: B; y: u256 };\nclass V { get f(): External<u256> { let o: Outer = Outer({ q: 4n }, 6n); return o.i.q + o.y; } }`, { fileName: 'v.jeth' });
    const a2 = await h.deploy(r2.creationBytecode);
    expect(BigInt((await h.call(a2, sel('f()'))).returnHex)).toBe(10n);
  });
});
