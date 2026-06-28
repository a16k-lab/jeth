// Cat A: binding a local to an ELEMENT of a POINTER-HEADED memory aggregate array (let row = xs[i],
// for-of) ALIASES the element (copies the element slot's absolute pointer), byte-identical to solc 0.8.35.
// Covers bytes[][]/string[][] (inner bytes[]/string[]) and B3 dynamic-field struct arrays D[].
// A STATIC-struct array P[] is INLINE, so binding cannot replicate solc's pointer-headed aliasing
// (alias fails re-point; copy fails write-through) - it stays a sound clean reject (asserted here too).
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

describe('Cat A: bind a pointer-headed aggregate-array element (alias) - byte-identical to solc 0.8.35', () => {
  it('bytes[][]: let row = xs[i], for-of, nested for-of, empty loop, OOB bind', async () => {
    const J = `@contract class C {
      @external @pure rowlen(): u256 { let xs: bytes[][] = [[bytes("a"), bytes("bbbb")]]; let row: bytes[] = xs[0n]; return row[1n].length; }
      @external @pure sumrows(): u256 { let xs: bytes[][] = [[bytes("a"), bytes("bb")], [bytes("ccc")]]; let n: u256 = 0n; for (const row of xs) { n = n + row.length; } return n; }
      @external @pure sumleaf(): u256 { let xs: bytes[][] = [[bytes("ab"), bytes("cde")]]; let n: u256 = 0n; for (const row of xs) { let k: u256 = 0n; while (k < row.length) { n = n + row[k].length; k = k + 1n; } } return n; }
      @external @pure emptyloop(): u256 { let xs: bytes[][] = []; let n: u256 = 0n; for (const row of xs) { n = n + row.length; } return n; }
      @external @pure oob(): u256 { let xs: bytes[][] = [[bytes("a")]]; let row: bytes[] = xs[5n]; return row.length; } }`;
    const S = `contract C {
      function rowlen() external pure returns(uint256){ bytes[][] memory xs=new bytes[][](1); xs[0]=new bytes[](2); xs[0][0]=bytes("a"); xs[0][1]=bytes("bbbb"); bytes[] memory row=xs[0]; return row[1].length; }
      function sumrows() external pure returns(uint256){ bytes[][] memory xs=new bytes[][](2); xs[0]=new bytes[](2); xs[0][0]=bytes("a"); xs[0][1]=bytes("bb"); xs[1]=new bytes[](1); xs[1][0]=bytes("ccc"); uint256 n=0; for(uint i=0;i<xs.length;i++){ bytes[] memory row=xs[i]; n+=row.length; } return n; }
      function sumleaf() external pure returns(uint256){ bytes[][] memory xs=new bytes[][](1); xs[0]=new bytes[](2); xs[0][0]=bytes("ab"); xs[0][1]=bytes("cde"); uint256 n=0; for(uint i=0;i<xs.length;i++){ bytes[] memory row=xs[i]; for(uint k=0;k<row.length;k++){n+=row[k].length;} } return n; }
      function emptyloop() external pure returns(uint256){ bytes[][] memory xs=new bytes[][](0); uint256 n=0; for(uint i=0;i<xs.length;i++){ bytes[] memory row=xs[i]; n+=row.length; } return n; }
      function oob() external pure returns(uint256){ bytes[][] memory xs=new bytes[][](1); xs[0]=new bytes[](1); xs[0][0]=bytes("a"); bytes[] memory row=xs[5]; return row.length; } }`;
    await diff(J, S, ['rowlen()', 'sumrows()', 'sumleaf()', 'emptyloop()', 'oob()']);
  });

  it('B3 dyn-struct D[]: let d = ps[i] reads + alias write-through + re-point + impure index + OOB', async () => {
    const J = `@struct class P { a: u256; s: bytes; }
    @contract class C {
      @external @pure read(): u256 { let ps: P[] = [P(7n, bytes("xy")), P(9n, bytes("zzz"))]; let d: P = ps[1n]; return d.a + d.s.length; }
      @external @pure aliasw(): u256 { let ps: P[] = [P(7n, bytes("xy"))]; let d: P = ps[0n]; d.a = 5n; return ps[0n].a; }
      @external @pure repoint(): u256 { let ps: P[] = [P(7n, bytes("xy"))]; let d: P = ps[0n]; ps[0n] = P(99n, bytes("q")); return d.a; }
      @state c: u256;
      bump(): u256 { this.c = this.c + 1n; return 0n; }
      @external once(): u256 { let ps: P[] = [P(7n, bytes("xy"))]; let d: P = ps[this.bump()]; return this.c; }
      @external @pure oob(): u256 { let ps: P[] = [P(7n, bytes("xy"))]; let d: P = ps[5n]; return d.a; }
      @external @pure forof(): u256 { let ps: P[] = [P(1n, bytes("a")), P(2n, bytes("bb"))]; let n: u256 = 0n; for (const d of ps) { n = n + d.a + d.s.length; } return n; } }`;
    const S = `struct P { uint256 a; bytes s; }
    contract C {
      function read() external pure returns(uint256){ P[] memory ps=new P[](2); ps[0]=P(7,bytes("xy")); ps[1]=P(9,bytes("zzz")); P memory d=ps[1]; return d.a + d.s.length; }
      function aliasw() external pure returns(uint256){ P[] memory ps=new P[](1); ps[0]=P(7,bytes("xy")); P memory d=ps[0]; d.a=5; return ps[0].a; }
      function repoint() external pure returns(uint256){ P[] memory ps=new P[](1); ps[0]=P(7,bytes("xy")); P memory d=ps[0]; ps[0]=P(99,bytes("q")); return d.a; }
      uint256 c;
      function bump() internal returns(uint256){ c+=1; return 0; }
      function once() external returns(uint256){ P[] memory ps=new P[](1); ps[0]=P(7,bytes("xy")); P memory d=ps[bump()]; return c; }
      function oob() external pure returns(uint256){ P[] memory ps=new P[](1); ps[0]=P(7,bytes("xy")); P memory d=ps[5]; return d.a; }
      function forof() external pure returns(uint256){ P[] memory ps=new P[](2); ps[0]=P(1,bytes("a")); ps[1]=P(2,bytes("bb")); uint256 n=0; for(uint i=0;i<ps.length;i++){ P memory d=ps[i]; n+=d.a+d.s.length; } return n; } }`;
    await diff(J, S, ['read()', 'aliasw()', 'repoint()', 'once()', 'oob()', 'forof()']);
  });

  it('binding a static-struct array element now ACCEPTS (static-struct arrays are pointer-headed)', () => {
    // static-struct P[] is now POINTER-HEADED like solc, so `let p = xs[i]` binds the element pointer
    // (alias): mutating p writes through to xs[i], re-pointing xs[i] leaves p on the old image.
    // Byte-identity covered in pointer-headed-static-struct-array.test.ts.
    const C = (body: string) => `@struct class P { a: u256; b: u256; }\n@contract class C { @external @pure f(): u256 { let xs: P[] = [P(1n, 2n)]; ${body} } }`;
    expect(codes(C('let p: P = xs[0n]; return p.a;'))).toEqual([]);
    expect(codes(C('let n: u256 = 0n; for (const p of xs) { n = n + p.a; } return n;'))).toEqual([]);
    // the pointer-headed dynamic forms ACCEPT too:
    expect(codes(`@contract class C { @external @pure f(): u256 { let xs: bytes[][] = [[bytes("a")]]; let row: bytes[] = xs[0n]; return row.length; } }`)).toEqual([]);
    expect(codes(`@struct class P{a:u256;s:bytes;} @contract class C { @external @pure f(): u256 { let ps: P[] = [P(1n,bytes("x"))]; let d: P = ps[0n]; return d.a; } }`)).toEqual([]);
  });
});
