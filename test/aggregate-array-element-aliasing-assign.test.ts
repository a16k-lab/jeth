// Cat A2: an element-to-element (or element-from-reference) assignment on a POINTER-HEADED memory
// aggregate array - xs[i] = xs[j], xs[i] = <ref of the element type> - copies the element slot's
// pointer (an ALIAS), byte-identical to solc 0.8.35: mutating one side is visible through the other,
// and re-pointing one slot leaves the other on its old image. Covers B3 dynamic-field struct arrays
// (P[]) and nested-dynamic / nested-value arrays (bytes[][], u256[][]).
// An INLINE static-struct array P[] cannot replicate this (its element write deep-copies the inline
// image), so xs[i] = <ref> there stays a sound clean reject (asserted too).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
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

describe('Cat A2: pointer-headed aggregate-array element aliasing assignment - byte-identical to solc', () => {
  it('B3 dyn-struct P[]: xs[i] = xs[j] / = local aliases (e2e + re-point + local + whole-encode)', async () => {
    const J = `@struct class P { a: u256; s: bytes; }
    @contract class C {
      @external @pure e2e(): u256 { let xs: P[] = new Array<P>(2n); xs[0n] = P(1n, bytes("x")); xs[1n] = xs[0n]; xs[0n].a = 5n; return xs[1n].a; }
      @external @pure repoint(): u256 { let xs: P[] = new Array<P>(2n); xs[0n] = P(1n, bytes("x")); xs[1n] = xs[0n]; xs[0n] = P(9n, bytes("q")); return xs[1n].a; }
      @external @pure fromlocal(): u256 { let p: P = P(3n, bytes("z")); let xs: P[] = new Array<P>(1n); xs[0n] = p; p.a = 7n; return xs[0n].a; }
      @external @pure enc(): bytes { let xs: P[] = new Array<P>(2n); xs[0n] = P(1n, bytes("xy")); xs[1n] = xs[0n]; xs[0n].a = 5n; return abi.encode(xs); } }`;
    const S = `struct P { uint256 a; bytes s; }
    contract C {
      function e2e() external pure returns(uint256){ P[] memory xs=new P[](2); xs[0]=P(1,bytes("x")); xs[1]=xs[0]; xs[0].a=5; return xs[1].a; }
      function repoint() external pure returns(uint256){ P[] memory xs=new P[](2); xs[0]=P(1,bytes("x")); xs[1]=xs[0]; xs[0]=P(9,bytes("q")); return xs[1].a; }
      function fromlocal() external pure returns(uint256){ P memory p=P(3,bytes("z")); P[] memory xs=new P[](1); xs[0]=p; p.a=7; return xs[0].a; }
      function enc() external pure returns(bytes memory){ P[] memory xs=new P[](2); xs[0]=P(1,bytes("xy")); xs[1]=xs[0]; xs[0].a=5; return abi.encode(xs); } }`;
    await diff(J, S, ['e2e()', 'repoint()', 'fromlocal()', 'enc()']);
  });

  it('nested arrays bytes[][] / u256[][]: xs[i] = xs[j] aliases (e2e + whole-encode), literal/local still work', async () => {
    const J = `@contract class C {
      @external @pure be2e(): u256 { let xs: bytes[][] = [[bytes("a")], [bytes("zz")]]; xs[1n] = xs[0n]; xs[0n][0n] = bytes("ABCDE"); return xs[1n][0n].length; }
      @external @pure benc(): bytes { let xs: bytes[][] = [[bytes("aa"), bytes("b")], [bytes("zz")]]; xs[1n] = xs[0n]; return abi.encode(xs); }
      @external @pure ue2e(): u256 { let xs: u256[][] = [[1n, 2n], [9n]]; xs[1n] = xs[0n]; xs[0n][0n] = 77n; return xs[1n][0n]; }
      @external @pure blocal(): u256 { let xs: bytes[][] = [[bytes("a")]]; let r: bytes[] = [bytes("qqq")]; xs[0n] = r; return xs[0n][0n].length; }
      @external @pure blit(): bytes { let xs: bytes[][] = [[bytes("a")]]; xs[0n] = [bytes("q"), bytes("rr")]; return abi.encode(xs); } }`;
    const S = `contract C {
      function be2e() external pure returns(uint256){ bytes[][] memory xs=new bytes[][](2); xs[0]=new bytes[](1); xs[0][0]=bytes("a"); xs[1]=new bytes[](1); xs[1][0]=bytes("zz"); xs[1]=xs[0]; xs[0][0]=bytes("ABCDE"); return xs[1][0].length; }
      function benc() external pure returns(bytes memory){ bytes[][] memory xs=new bytes[][](2); xs[0]=new bytes[](2); xs[0][0]=bytes("aa"); xs[0][1]=bytes("b"); xs[1]=new bytes[](1); xs[1][0]=bytes("zz"); xs[1]=xs[0]; return abi.encode(xs); }
      function ue2e() external pure returns(uint256){ uint256[][] memory xs=new uint256[][](2); xs[0]=new uint256[](2); xs[0][0]=1; xs[0][1]=2; xs[1]=new uint256[](1); xs[1][0]=9; xs[1]=xs[0]; xs[0][0]=77; return xs[1][0]; }
      function blocal() external pure returns(uint256){ bytes[][] memory xs=new bytes[][](1); xs[0]=new bytes[](1); xs[0][0]=bytes("a"); bytes[] memory r=new bytes[](1); r[0]=bytes("qqq"); xs[0]=r; return xs[0][0].length; }
      function blit() external pure returns(bytes memory){ bytes[][] memory xs=new bytes[][](1); xs[0]=new bytes[](1); xs[0][0]=bytes("a"); xs[0]=new bytes[](2); xs[0][0]=bytes("q"); xs[0][1]=bytes("rr"); return abi.encode(xs); } }`;
    await diff(J, S, ['be2e()', 'benc()', 'ue2e()', 'blocal()', 'blit()']);
  });

  it('SOUNDNESS: an INLINE static-struct array element ref-assign stays a clean reject; fresh RHS accepts', () => {
    const C = (body: string) => `@struct class P { a: u256; b: u256; }\n@contract class C { @external @pure f(): u256 { let xs: P[] = new Array<P>(2n); ${body} return xs[0n].a; } }`;
    expect(codes(C('xs[0n] = P(1n, 2n);'))).toEqual([]); // fresh -> accept
    expect(codes(C('xs[0n] = P(1n, 2n); xs[1n] = xs[0n];'))).toContain('JETH200'); // inline ref -> reject
    // pointer-headed (dyn-field struct) element ref-assign ACCEPTS (lifted):
    expect(codes(`@struct class P{a:u256;s:bytes;} @contract class C { @external @pure f(): u256 { let xs: P[] = new Array<P>(2n); xs[0n]=P(1n,bytes("x")); xs[1n]=xs[0n]; return xs[1n].a; } }`)).toEqual([]);
  });
});
