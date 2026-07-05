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

const JT = `@struct class T { n: u256; s: string }\n`;
const ST = `struct T { uint256 n; string s; }\n`;

describe('W6A: dyn-struct ctor field captures a memory reference (pointer, not copy) vs solc 0.8.35', () => {
  it('bidirectional aliasing through the captured pointer + double capture', async () => {
    const J = `${JT}@struct class S { a: u256; t: T }
    @struct class S2 { x: T; y: T }
    @contract class C {
      @external @pure fwd(): u256 { let t: T = T(5n, "x"); let s: S = S(1n, t); t.n = 9n; return s.t.n; }
      @external @pure rev(): u256 { let t: T = T(5n, "x"); let s: S = S(1n, t); s.t.n = 9n; return t.n; }
      @external @pure str(): string { let t: T = T(5n, "aa"); let s: S = S(1n, t); t.s = "bb-longer-than-32-bytes-payload-word!"; return s.t.s; }
      @external @pure dbl(): u256 { let t: T = T(5n, "x"); let s: S2 = S2(t, t); s.x.n = 7n; return s.y.n * 100n + t.n; } }`;
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
    const J = `@struct class T { xs: u256[]; n: u256 }
    @struct class S { a: u256; t: T }
    @contract class C { @external @pure f(): u256 {
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
    const J = `${JT}@struct class S { a: u256; t: T }
    @contract class C {
      @state sd: S; @state arr: S[]; @state m: mapping<u256, S>;
      @external @pure enc(): bytes { let t: T = T(5n, "x"); let s: S = S(1n, t); t.n = 9n; return abi.encode(s); }
      @external @pure ret(): S { let t: T = T(5n, "hello-there-long-string-payload!!"); return S(1n, t); }
      @external stor(): u256 { let t: T = T(5n, "x"); let s: S = S(1n, t); t.n = 9n; this.sd = s; return this.sd.t.n; }
      @external psh(): u256 { let t: T = T(5n, "x"); t.n = 9n; this.arr.push(S(1n, t)); return this.arr[0n].t.n; }
      @external mp(): u256 { let t: T = T(5n, "x"); t.n = 9n; this.m[1n] = S(1n, t); return this.m[1n].t.n; } }`;
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
    const J = `${JT}@struct class S { a: u256; t: T }
    @contract class C {
      mut(s: S): u256 { s.t.n = 9n; return s.a; }
      mk(x: T): S { return S(1n, x); }
      @external @pure viaArg(): u256 { let t: T = T(5n, "x"); this.mut(S(1n, t)); return t.n; }
      @external @pure viaRet(): u256 { let t: T = T(5n, "x"); let s: S = this.mk(t); t.n = 9n; return s.t.n; } }`;
    const S = `${ST}struct S { uint256 a; T t; }
    contract C {
      function mut(S memory s) internal pure returns (uint256) { s.t.n = 9; return s.a; }
      function mk(T memory x) internal pure returns (S memory) { return S(1, x); }
      function viaArg() external pure returns (uint256) { T memory t = T(5, "x"); mut(S(1, t)); return t.n; }
      function viaRet() external pure returns (uint256) { T memory t = T(5, "x"); S memory s = mk(t); t.n = 9; return s.t.n; } }`;
    await diff(J, S, [['viaArg()'], ['viaRet()']]);
  });

  it('2-level chain + nested-field-ref capture + storage/calldata sources stay copies', async () => {
    const J = `${JT}@struct class S { a: u256; t: T }
    @struct class U { s: S }
    @struct class S2 { b: u256; s: S }
    @contract class C {
      @state st: T;
      @external @pure chain(): u256 { let t: T = T(5n, "x"); let u: U = U(S(1n, t)); t.n = 9n; let a: u256 = u.s.t.n; u.s.t.n += 100n; return a * 1000n + t.n; }
      @external @pure nref(): u256 { let u: U = U(S(1n, T(5n, "x"))); let w: S2 = S2(2n, u.s); u.s.a = 7n; return w.s.a; }
      @external storSrc(): u256 { this.st = T(5n, "x"); let s: S = S(1n, this.st); this.st.n = 9n; return s.t.n; }
      @external @pure cdSrc(t: T): u256 { let s: S = S(1n, t); s.t.n = 9n; return s.t.n + t.n; } }`;
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
  const HDR = `@struct class T { n: u256 }
  @struct class S { a: u256; t: T }\n`;
  it('primary family: local bind / 2-level / double / abi.encode-of-local / storage round-trip', () => {
    expect(codes(`${HDR}@contract class C { @external @pure f(): u256 { let t: T = T(5n); let s: S = S(1n, t); t.n = 9n; return s.t.n; } }`)).toContain('JETH465');
    expect(codes(`@struct class I { n: u256 }
    @struct class T2 { i: I }
    @struct class S { t: T2 }
    @contract class C { @external @pure f(): u256 { let i: I = I(5n); let s: S = S(T2(i)); i.n = 9n; return s.t.i.n; } }`)).toContain('JETH465');
    expect(codes(`@struct class T { n: u256 }
    @struct class S2 { x: T; y: T }
    @contract class C { @external @pure f(): u256 { let t: T = T(5n); let s: S2 = S2(t, t); s.x.n = 7n; return s.y.n; } }`)).toContain('JETH465');
    expect(codes(`${HDR}@contract class C { @external @pure f(): bytes { let t: T = T(5n); let s: S = S(1n, t); t.n = 9n; return abi.encode(s); } }`)).toContain('JETH465');
    expect(codes(`${HDR}@contract class C { @state st: S; @external f(): u256 { let t: T = T(5n); let s: S = S(1n, t); t.n = 9n; this.st = s; return this.st.t.n; } }`)).toContain('JETH465');
  });
  it('fixed-array captures: Arr<P,2> from [p,q] elements, Arr<u256,2> from a local', () => {
    expect(codes(`@struct class P { a: u256 }
    @struct class S { ps: Arr<P, 2>; z: u256 }
    @contract class C { @external @pure f(): u256 { let p: P = P(5n); let q: P = P(6n); let s: S = S([p, q], 1n); p.a = 9n; return s.ps[0n].a; } }`)).toContain('JETH465');
    expect(codes(`@struct class S { a: u256; xs: Arr<u256, 2> }
    @contract class C { @external @pure f(): u256 { let xs: Arr<u256, 2> = [1n, 2n]; let s: S = S(1n, xs); xs[0n] = 9n; return s.xs[0n]; } }`)).toContain('JETH465');
  });
  it('call-result source, ctor-as-internal-arg, capture inside a transient encode arg', () => {
    expect(codes(`${HDR}@contract class C {
      id(x: T): T { return x; }
      @external @pure f(): u256 { let t: T = T(5n); let s: S = S(1n, this.id(t)); t.n = 9n; return s.t.n; } }`)).toContain('JETH465');
    expect(codes(`${HDR}@contract class C {
      mut(s: S): u256 { s.t.n = 9n; return s.a; }
      @external @pure f(): u256 { let t: T = T(5n); this.mut(S(1n, t)); return t.n; } }`)).toContain('JETH465');
    expect(codes(`${HDR}@contract class C {
      mut(s: S): u256 { s.t.n = 9n; return s.a; }
      @external @pure f(): bytes { let t: T = T(5n); return abi.encode(this.mut(S(1n, t))); } }`)).toContain('JETH465');
  });
  it('ref capture + side-effecting sibling arg rejects (order hazard); unstable dyn sources reject', () => {
    expect(codes(`@struct class T { n: u256; s: string }
    @struct class S2 { t: T; x: u256 }
    @contract class C {
      bump(t: T): u256 { t.n = 77n; return 3n; }
      @external @pure f(): S2 { let t: T = T(5n, "x"); return S2(t, this.bump(t)); } }`)).toContain('JETH465');
    expect(codes(`@struct class T { n: u256; s: string }
    @struct class S { a: u256; t: T }
    @contract class C { @external @pure f(): u256 {
      let xs: T[] = [T(5n, "x")]; let s: S = S(1n, xs[0n]); return s.t.n; } }`)).toContain('JETH465');
    expect(codes(`@struct class T { n: u256; s: string }
    @struct class S { a: u256; t: T }
    @contract class C {
      mk(): T { return T(5n, "x"); }
      @external @pure f(): u256 { let s: S = S(1n, this.mk()); return s.t.n; } }`)).toContain('JETH465');
  });
});

describe('W6A: transient static captures stay accepted byte-identical (no regression)', () => {
  it('immediate return / abi.encode / direct storage write / emit / error / tuple / push', async () => {
    const J = `@struct class T { n: u256 }
    @struct class S { a: u256; t: T }
    @contract class C {
      @state st: S; @state arr: S[];
      @event E(s: S);
      @error MyErr(s: S);
      @external @pure ret(): S { let t: T = T(5n); return S(1n, t); }
      @external @pure enc(): bytes { let t: T = T(5n); return abi.encode(S(1n, t)); }
      @external stor(): u256 { let t: T = T(5n); this.st = S(1n, t); t.n = 9n; return this.st.t.n; }
      @external emitE(): u256 { let t: T = T(5n); emit(E(S(1n, t))); return 1n; }
      @external @pure err(): u256 { let t: T = T(5n); revert(MyErr(S(1n, t))); }
      @external @pure tup(): [S, u256] { let t: T = T(5n); return [S(1n, t), 7n]; }
      @external psh(): u256 { let t: T = T(5n); t.n = 9n; this.arr.push(S(1n, t)); return this.arr[0n].t.n; } }`;
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
    const J = `@struct class T { n: u256 }
    @struct class I { xs: u256[] }
    @struct class M { i: I }
    @contract class C {
      @external @pure alias(): u256 { let t: T = T(5n); let u: T = t; t.n = 9n; return u.n; }
      @external @pure elem(): u256 { let t: T = T(5n); let xs: T[] = new Array<T>(1n); xs[0n] = t; t.n = 9n; return xs[0n].n; }
      @external @pure lit(): u256 { let t: T = T(5n); let xs: T[] = [t]; t.n = 9n; return xs[0n].n; }
      @external @pure fld(): u256 { let m: M = M(I(new Array<u256>(1n))); let z: I = m.i; z.xs[0n] = 7n; return m.i.xs[0n]; } }`;
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
