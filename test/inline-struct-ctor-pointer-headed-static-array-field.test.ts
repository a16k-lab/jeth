// SHAPE A: an INLINE struct-constructor value S(tag, a) whose field `a` is a POINTER-HEADED
// static-struct fixed array (Arr<In,N>, In a static struct - N absolute-pointer words in memory, NO
// [len] header, but INLINE in the ABI/return tuple head). A NON-INLINE aliasable source flat-copied into
// that field used to MISCOMPILE (the flat mcopy emitted the element POINTERS instead of the inline
// element data, dropping the payload); it was routed to a clean JETH465 reject.
//
// L7(a) LIFT: when the captured local is DEAD after the constructor (referenced exactly once - the
// capture - never mutated, never read, never passed onward), Solidity's live reference is UNOBSERVABLE,
// so a copy is byte-identical. The compiler now folds `let a = [In(..), ..]; S(tag, a)` into its
// already-accepted INLINE form `S(tag, [In(..), ..])` verbatim (same IR -> byte-identical bytecode),
// which is itself byte-identical to solc. A LIVE-reference capture (the local mutated / read after the
// ctor, or used more than once) is NOT dead - it keeps the JETH465 reject (a copy would diverge).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const codes = (src: string): string[] => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return [];
  } catch (e: any) {
    return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
  }
};
function jethBytes(src: string): string {
  return compile(src, { fileName: 'C.jeth' }).creationBytecode;
}
async function diff(J: string, S: string, sigs: string[]) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const sg of sigs) {
    const rj = await h.call(aj, sel(sg));
    const rs = await h.call(as, sel(sg));
    expect(rj.success, sg).toBe(rs.success);
    expect(rj.returnHex, sg).toBe(rs.returnHex);
  }
}

describe('L7(a): DEAD-after pointer-headed static-struct fixed-array capture folds to the inline form (byte-identical to solc)', () => {
  // ---- the DEAD-after captures now LIFT: byte-identical to solc AND to the inline-literal form ----
  it('return S(tag, a) folds to return S(tag, [..]) - byte-identical to solc', async () => {
    const bound = `type In = { x: u256; y: u256 };
    type S = { tag: u256; arr: Arr<In,2> };
    class C {
      get f(): External<S> { let a: Arr<In,2> = [In(111n,222n), In(333n,444n)]; return S(9n, a); } }`;
    const inline = `type In = { x: u256; y: u256 };
    type S = { tag: u256; arr: Arr<In,2> };
    class C {
      get f(): External<S> { return S(9n, [In(111n,222n), In(333n,444n)]); } }`;
    const S = `struct In { uint256 x; uint256 y; }
    struct S { uint256 tag; In[2] arr; }
    contract C { function f() external pure returns(S memory){ return S(9, [In(111,222),In(333,444)]); } }`;
    expect(codes(bound)).toEqual([]);
    expect(jethBytes(bound)).toBe(jethBytes(inline)); // == the already-accepted inline-literal form
    await diff(bound, S, ['f()']);
  });

  it('abi.encode(S(tag, a)) folds - byte-identical to solc', async () => {
    const bound = `type In = { x: u256; y: u256 };
    type S = { tag: u256; arr: Arr<In,2> };
    class C {
      get f(): External<bytes> { let a: Arr<In,2> = [In(111n,222n), In(333n,444n)]; return abi.encode(S(9n, a)); } }`;
    const inline = `type In = { x: u256; y: u256 };
    type S = { tag: u256; arr: Arr<In,2> };
    class C {
      get f(): External<bytes> { return abi.encode(S(9n, [In(111n,222n), In(333n,444n)])); } }`;
    const S = `struct In { uint256 x; uint256 y; }
    struct S { uint256 tag; In[2] arr; }
    contract C { function f() external pure returns(bytes memory){ return abi.encode(S(9, [In(111,222),In(333,444)])); } }`;
    expect(codes(bound)).toEqual([]);
    expect(jethBytes(bound)).toBe(jethBytes(inline));
    await diff(bound, S, ['f()']);
  });

  it('let s: S = S(9n, a); return s (whole struct) folds - byte-identical to solc', async () => {
    const bound = `type In = { x: u256; y: u256 };
    type S = { tag: u256; arr: Arr<In,2> };
    class C {
      get f(): External<S> { let a: Arr<In,2> = [In(111n,222n), In(333n,444n)]; let s: S = S(9n, a); return s; } }`;
    const inline = `type In = { x: u256; y: u256 };
    type S = { tag: u256; arr: Arr<In,2> };
    class C {
      get f(): External<S> { let s: S = S(9n, [In(111n,222n), In(333n,444n)]); return s; } }`;
    const S = `struct In { uint256 x; uint256 y; }
    struct S { uint256 tag; In[2] arr; }
    contract C { function f() external pure returns(S memory){ S memory s = S(9, [In(111,222),In(333,444)]); return s; } }`;
    expect(codes(bound)).toEqual([]);
    expect(jethBytes(bound)).toBe(jethBytes(inline));
    await diff(bound, S, ['f()']);
  });

  it('extended shapes fold: Arr<In,3>, a 3-field element struct, and a nested Arr<Arr<In,2>,2>', async () => {
    const arr3b = `type In = { x: u256; y: u256 };
    type S = { tag: u256; arr: Arr<In,3> };
    class C {
      get ret(): External<S> { let a: Arr<In,3> = [In(1n,2n), In(3n,4n), In(5n,6n)]; return S(9n, a); }
      get enc(): External<bytes> { let a: Arr<In,3> = [In(1n,2n), In(3n,4n), In(5n,6n)]; return abi.encode(S(9n, a)); } }`;
    const arr3i = `type In = { x: u256; y: u256 };
    type S = { tag: u256; arr: Arr<In,3> };
    class C {
      get ret(): External<S> { return S(9n, [In(1n,2n), In(3n,4n), In(5n,6n)]); }
      get enc(): External<bytes> { return abi.encode(S(9n, [In(1n,2n), In(3n,4n), In(5n,6n)])); } }`;
    const arr3s = `struct In { uint256 x; uint256 y; }
    struct S { uint256 tag; In[3] arr; }
    contract C {
      function ret() external pure returns(S memory){ return S(9, [In(1,2),In(3,4),In(5,6)]); }
      function enc() external pure returns(bytes memory){ return abi.encode(S(9, [In(1,2),In(3,4),In(5,6)])); } }`;
    expect(codes(arr3b)).toEqual([]);
    expect(jethBytes(arr3b)).toBe(jethBytes(arr3i));
    await diff(arr3b, arr3s, ['ret()', 'enc()']);

    const in3b = `type In3 = { x: u256; y: u256; z: u256 };
    type S = { tag: u256; arr: Arr<In3,2> };
    class C {
      get f(): External<S> { let a: Arr<In3,2> = [In3(1n,2n,3n), In3(4n,5n,6n)]; return S(9n, a); } }`;
    const in3i = `type In3 = { x: u256; y: u256; z: u256 };
    type S = { tag: u256; arr: Arr<In3,2> };
    class C {
      get f(): External<S> { return S(9n, [In3(1n,2n,3n), In3(4n,5n,6n)]); } }`;
    const in3s = `struct In3 { uint256 x; uint256 y; uint256 z; }
    struct S { uint256 tag; In3[2] arr; }
    contract C { function f() external pure returns(S memory){ return S(9, [In3(1,2,3),In3(4,5,6)]); } }`;
    expect(codes(in3b)).toEqual([]);
    expect(jethBytes(in3b)).toBe(jethBytes(in3i));
    await diff(in3b, in3s, ['f()']);

    const nestb = `type In = { x: u256; y: u256 };
    type S = { tag: u256; arr: Arr<Arr<In,2>,2> };
    class C {
      get f(): External<S> {
        let a: Arr<Arr<In,2>,2> = [[In(1n,2n),In(3n,4n)], [In(5n,6n),In(7n,8n)]];
        return S(9n, a); } }`;
    const nesti = `type In = { x: u256; y: u256 };
    type S = { tag: u256; arr: Arr<Arr<In,2>,2> };
    class C {
      get f(): External<S> { return S(9n, [[In(1n,2n),In(3n,4n)], [In(5n,6n),In(7n,8n)]]); } }`;
    const nests = `struct In { uint256 x; uint256 y; }
    struct S { uint256 tag; In[2][2] arr; }
    contract C { function f() external pure returns(S memory){ return S(9, [[In(1,2),In(3,4)],[In(5,6),In(7,8)]]); } }`;
    expect(codes(nestb)).toEqual([]);
    expect(jethBytes(nestb)).toBe(jethBytes(nesti));
    await diff(nestb, nests, ['f()']);
  });

  // ---- LIVE reference (escape): the local is NOT dead - the JETH465 reject is KEPT (a copy would diverge) ----
  it('a MUTATED after the ctor keeps the JETH465 reject (solc aliases the write; a copy would not)', () => {
    // solc: after a[0]=In(99,99), s.arr[0].x reads 99 through the live reference; a flat copy would read 111.
    const J = `type In = { x: u256; y: u256 };
    type S = { tag: u256; arr: Arr<In,2> };
    class C {
      get f(): External<u256> { let a: Arr<In,2> = [In(111n,222n), In(333n,444n)]; let s: S = S(9n, a); a[0n] = In(99n,99n); return s.arr[0n].x; } }`;
    expect(codes(J)).toContain('JETH465');
  });

  it('a READ after the ctor keeps the JETH465 reject (live use)', () => {
    const J = `type In = { x: u256; y: u256 };
    type S = { tag: u256; arr: Arr<In,2> };
    class C {
      get f(): External<u256> { let a: Arr<In,2> = [In(111n,222n), In(333n,444n)]; let s: S = S(9n, a); return s.arr[0n].x + a[1n].y; } }`;
    expect(codes(J)).toContain('JETH465');
  });

  it('captured into TWO ctors keeps the JETH465 reject (used more than once)', () => {
    const J = `type In = { x: u256; y: u256 };
    type S = { tag: u256; arr: Arr<In,2> };
    class C {
      get f(): External<u256> { let a: Arr<In,2> = [In(111n,222n), In(333n,444n)]; let s: S = S(9n, a); let t: S = S(8n, a); return s.tag + t.tag; } }`;
    expect(codes(J)).toContain('JETH465');
  });

  // ---- CONTROLS (PIN solc): these stay byte-identical MATCH and MUST NOT be swept into the reject ----
  it('CONTROL: a VALUE-array field struct S{tag; v: Arr<u256,2>} inline return + encode MATCH', async () => {
    const J = `type S = { tag: u256; v: Arr<u256,2> };
    class C {
      get ret(): External<S> { let a: Arr<u256,2> = [u256(111n), 222n]; return S(9n, a); }
      get enc(): External<bytes> { let a: Arr<u256,2> = [u256(111n), 222n]; return abi.encode(S(9n, a)); } }`;
    const S = `struct S { uint256 tag; uint256[2] v; }
    contract C {
      function ret() external pure returns(S memory){ uint256[2] memory a=[uint256(111),222]; return S(9,a); }
      function enc() external pure returns(bytes memory){ uint256[2] memory a=[uint256(111),222]; return abi.encode(S(9,a)); } }`;
    expect(codes(J)).toEqual([]);
    await diff(J, S, ['ret()', 'enc()']);
  });

  it('CONTROL: a scalar-only struct inline return MATCH', async () => {
    const J = `type S = { a: u256; b: u256 };
    class C { get f(): External<S> { return S(9n, 10n); } }`;
    const S = `struct S { uint256 a; uint256 b; }
    contract C { function f() external pure returns(S memory){ return S(9, 10); } }`;
    expect(codes(J)).toEqual([]);
    await diff(J, S, ['f()']);
  });

  it('CONTROL: a standalone Arr<In,2> return / encode (not wrapped in a struct) MATCH', async () => {
    const J = `type In = { x: u256; y: u256 };
    class C {
      get ret(): External<Arr<In,2>> { let a: Arr<In,2> = [In(111n,222n), In(333n,444n)]; return a; }
      get enc(): External<bytes> { let a: Arr<In,2> = [In(111n,222n), In(333n,444n)]; return abi.encode(a); } }`;
    const S = `struct In { uint256 x; uint256 y; }
    contract C {
      function ret() external pure returns(In[2] memory){ In[2] memory a=[In(111,222),In(333,444)]; return a; }
      function enc() external pure returns(bytes memory){ In[2] memory a=[In(111,222),In(333,444)]; return abi.encode(a); } }`;
    expect(codes(J)).toEqual([]);
    await diff(J, S, ['ret()', 'enc()']);
  });

  it('CONTROL: an inline value-array literal field S(9n, [111n,222n]) return MATCH (inline arrayLit, not swept)', async () => {
    const J = `type S = { tag: u256; v: Arr<u256,2> };
    class C { get f(): External<S> { return S(9n, [u256(111n), 222n]); } }`;
    const S = `struct S { uint256 tag; uint256[2] v; }
    contract C { function f() external pure returns(S memory){ return S(9, [uint256(111), 222]); } }`;
    expect(codes(J)).toEqual([]);
    await diff(J, S, ['f()']);
  });
});
