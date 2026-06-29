// Batch C: (1) passing an AGGREGATE-element dynamic array (P[]/D[]/bytes[]/string[]/u256[][]) as an
// @internal/@private function ARGUMENT (the param binds by memory reference, like a value-element array);
// (2) abi.encode of a CALLDATA dyn-struct with a dynamic VALUE-array field. Byte-identical to solc 0.8.35.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
async function diff(J: string, S: string, calls: [string, string][]) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const [sg, args] of calls) {
    const data = sel(sg) + (args || '');
    const rj = await h.call(aj, data);
    const rs = await h.call(as, data);
    expect(rj.success, sg).toBe(rs.success);
    expect(rj.returnHex, sg).toBe(rs.returnHex);
  }
}

describe('Batch C: internal-fn aggregate-array args + calldata dyn-struct value-array-field encode', () => {
  it('internal/private fn taking P[] / bytes[] / D[] / u256[][] args (encode + index + length)', async () => {
    const J = `@struct class P { a: u256; b: u256; }
    @struct class D { a: u256; s: bytes; }
    @contract class C {
      enc(ps: P[]): bytes { return abi.encode(ps); }
      sum(ps: P[]): u256 { let n: u256 = 0n; let i: u256 = 0n; while (i < ps.length) { n = n + ps[i].a; i = i + 1n; } return n; }
      benc(bs: bytes[]): bytes { return abi.encode(bs); }
      denc(ds: D[]): bytes { return abi.encode(ds); }
      menc(m: u256[][]): bytes { return abi.encode(m); }
      @external @pure ps(): bytes { let xs: P[] = [P(1n, 2n), P(3n, 4n)]; return abi.encode(this.enc(xs), this.sum(xs)); }
      @external @pure bs(): bytes { let xs: bytes[] = [bytes("x"), bytes("yy")]; return this.benc(xs); }
      @external @pure ds(): bytes { let xs: D[] = new Array<D>(1n); xs[0n] = D(7n, bytes("hi")); return this.denc(xs); }
      @external @pure mm(): bytes { let xs: u256[][] = [[1n, 2n], [3n]]; return this.menc(xs); } }`;
    const S = `struct P { uint256 a; uint256 b; }
    struct D { uint256 a; bytes s; }
    contract C {
      function enc(P[] memory ps) internal pure returns(bytes memory){ return abi.encode(ps); }
      function sumf(P[] memory ps) internal pure returns(uint256){ uint256 n=0; for(uint i=0;i<ps.length;i++){n+=ps[i].a;} return n; }
      function benc(bytes[] memory bs) internal pure returns(bytes memory){ return abi.encode(bs); }
      function denc(D[] memory ds) internal pure returns(bytes memory){ return abi.encode(ds); }
      function menc(uint256[][] memory m) internal pure returns(bytes memory){ return abi.encode(m); }
      function ps() external pure returns(bytes memory){ P[] memory xs=new P[](2);xs[0]=P(1,2);xs[1]=P(3,4); return abi.encode(enc(xs), sumf(xs)); }
      function bs() external pure returns(bytes memory){ bytes[] memory xs=new bytes[](2);xs[0]=bytes("x");xs[1]=bytes("yy"); return benc(xs); }
      function ds() external pure returns(bytes memory){ D[] memory xs=new D[](1);xs[0]=D(7,bytes("hi")); return denc(xs); }
      function mm() external pure returns(bytes memory){ uint256[][] memory xs=new uint256[][](2);xs[0]=new uint256[](2);xs[0][0]=1;xs[0][1]=2;xs[1]=new uint256[](1);xs[1][0]=3; return menc(xs); } }`;
    await diff(J, S, [['ps()', ''], ['bs()', ''], ['ds()', ''], ['mm()', '']]);
  });

  it('abi.encode of a calldata dyn-struct with a value-array field', async () => {
    const J = `@struct class S { a: u256; tags: u256[]; }
    @contract class C { @external @pure f(s: S): bytes { return abi.encode(s); } @external @pure g(s: S): u256 { return s.a + s.tags.length; } }`;
    const Sol = `struct S { uint256 a; uint256[] tags; }
    contract C { function f(S calldata s) external pure returns(bytes memory){ return abi.encode(s); } function g(S calldata s) external pure returns(uint256){ return s.a + s.tags.length; } }`;
    const W = (n: bigint) => pad32(n);
    // s = (9, [5,6,7]) : head [a=9][tags offset 0x40] then [len 3][5][6][7]
    const arg = W(0x20n) + W(9n) + W(0x40n) + W(3n) + W(5n) + W(6n) + W(7n);
    await diff(J, Sol, [['f((uint256,uint256[]))', arg], ['g((uint256,uint256[]))', arg]]);
  });
});
