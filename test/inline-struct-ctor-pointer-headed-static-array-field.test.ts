// SHAPE A regression: an INLINE struct-constructor value S(tag, a) whose field `a` is a POINTER-HEADED
// static-struct fixed array (Arr<In,N>, In a static struct - N absolute-pointer words in memory, NO
// [len] header, but INLINE in the ABI/return tuple head) used DIRECTLY as a return / abi.encode operand
// used to MISCOMPILE: the flat mcopy at the aggregate-build site copied the element POINTERS (plus
// trailing garbage) instead of the inline element data, dropping the payload
// (solc: [0x20][0xa0][tag][x0][y0][x1][y1]; JETH emitted [tag][ptr][ptr][x0][y0]...). The fix routes the
// inline-constructor form to the SAME clean reject (JETH465) the var-bound form (let s: S = S(9n,a);
// return s) already emits - a clean reject beats wrong bytes. VALUE-array fields (Arr<u256,N> - flat,
// byte-invariant), scalar-only structs, and a standalone Arr<In,N> return are UNAFFECTED (stay MATCH).
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

describe('inline struct-ctor with a pointer-headed static-struct fixed-array field - clean reject, never garbage', () => {
  // ---- the two fixed miscompiles: now a CLEAN REJECT (JETH465), consistent with the var-bound form ----
  it('return S(tag, Arr<In,2>) rejects (was a payload-dropping miscompile)', () => {
    const J = `type In = { x: u256; y: u256 };
    type S = { tag: u256; arr: Arr<In,2> };
    class C {
      get f(): External<S> { let a: Arr<In,2> = [In(111n,222n), In(333n,444n)]; return S(9n, a); } }`;
    expect(codes(J)).toContain('JETH465');
  });

  it('abi.encode(S(tag, Arr<In,2>)) rejects (was a payload-dropping miscompile)', () => {
    const J = `type In = { x: u256; y: u256 };
    type S = { tag: u256; arr: Arr<In,2> };
    class C {
      get f(): External<bytes> { let a: Arr<In,2> = [In(111n,222n), In(333n,444n)]; return abi.encode(S(9n, a)); } }`;
    expect(codes(J)).toContain('JETH465');
  });

  // ---- the var-bound sibling: unchanged, still the same over-reject (proves consistency) ----
  it('the var-bound form let s: S = S(9n,a); return s stays a JETH465 reject (unchanged)', () => {
    const J = `type In = { x: u256; y: u256 };
    type S = { tag: u256; arr: Arr<In,2> };
    class C {
      get f(): External<S> { let a: Arr<In,2> = [In(111n,222n), In(333n,444n)]; let s: S = S(9n, a); return s; } }`;
    expect(codes(J)).toContain('JETH465');
  });

  // ---- extended shapes: Arr<In,3>, a 3-field element struct, and a nested Arr<Arr<In,N>,M> - all reject ----
  it('Arr<In,3> field return + encode reject (no garbage)', () => {
    const J = `type In = { x: u256; y: u256 };
    type S = { tag: u256; arr: Arr<In,3> };
    class C {
      get ret(): External<S> { let a: Arr<In,3> = [In(1n,2n), In(3n,4n), In(5n,6n)]; return S(9n, a); }
      get enc(): External<bytes> { let a: Arr<In,3> = [In(1n,2n), In(3n,4n), In(5n,6n)]; return abi.encode(S(9n, a)); } }`;
    expect(codes(J)).toContain('JETH465');
  });

  it('Arr<In3,2> (a 3-field element struct) field return rejects (no garbage)', () => {
    const J = `type In3 = { x: u256; y: u256; z: u256 };
    type S = { tag: u256; arr: Arr<In3,2> };
    class C {
      get f(): External<S> { let a: Arr<In3,2> = [In3(1n,2n,3n), In3(4n,5n,6n)]; return S(9n, a); } }`;
    expect(codes(J)).toContain('JETH465');
  });

  it('nested Arr<Arr<In,2>,2> field return rejects (no garbage)', () => {
    const J = `type In = { x: u256; y: u256 };
    type S = { tag: u256; arr: Arr<Arr<In,2>,2> };
    class C {
      get f(): External<S> {
        let a: Arr<Arr<In,2>,2> = [[In(1n,2n),In(3n,4n)], [In(5n,6n),In(7n,8n)]];
        return S(9n, a); } }`;
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
