// Lifting rare sound over-rejections to full solc parity. Each case was rejected by JETH (often a
// clean diagnostic, one a JETH900 crash) while solc 0.8.35 accepts it; the result is now verified
// byte-identical. Differential: a JETH contract and the solc equivalent are deployed and their
// (success, returnHex) compared for the same calldata.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);

async function rt(jeth: string, sol: string, sigs: string[]) {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  for (const s of sigs) {
    const data = '0x' + sel(s);
    const rj = await hj.call(aj, data);
    const rs = await hs.call(as, data);
    expect(rj.success, `${s}: success`).toBe(rs.success);
    expect(rj.returnHex, `${s}: returndata`).toBe(rs.returnHex);
  }
}

describe('lifted over-rejections: byte-identical vs solc', () => {
  it('abi.encode of an internal call returning a value-element array [was JETH900]', async () => {
    const J = `@contract class C {
      mk(): u256[] { let a: u256[] = new Array<u256>(3n); a[0n] = 7n; a[1n] = 8n; a[2n] = 9n; return a; }
      @external @pure f(): bytes { return abi.encode(this.mk()); }
      @external @pure g(): bytes { return abi.encode(7n, this.mk(), 9n); }
      @external @pure p(): bytes { return abi.encodePacked(this.mk()); }
    }`;
    const S = `contract C {
      function mk() internal pure returns (uint256[] memory){ uint256[] memory a = new uint256[](3); a[0]=7; a[1]=8; a[2]=9; return a; }
      function f() external pure returns (bytes memory){ return abi.encode(mk()); }
      function g() external pure returns (bytes memory){ return abi.encode(uint256(7), mk(), uint256(9)); }
      function p() external pure returns (bytes memory){ return abi.encodePacked(mk()); }
    }`;
    await rt(J, S, ['f()', 'g()', 'p()']);
  });

  it('memory-array struct-element field writes xs[i].a=v / deep / compound [was JETH067]', async () => {
    const J = `@struct class P { a: u256; b: u8; }
    @struct class Q { m: u256; }
    @struct class R { q: Q; pre: Arr<u256, 2>; }
    @contract class C {
      @external @pure fa(i: u256): bytes { let xs: P[] = new Array<P>(3n); xs[i].a = 11n; xs[i].b = 222n; return abi.encode(xs[i].a, xs[i].b); }
      @external @pure fdeep(i: u256): bytes { let xs: R[] = new Array<R>(2n); xs[i].q.m = 7n; xs[i].pre[0n] = 8n; xs[i].pre[1n] = 9n; return abi.encode(xs[i].q.m, xs[i].pre[0n], xs[i].pre[1n]); }
      @external @pure fdirty(i: u256, v: u256): bytes { let xs: P[] = new Array<P>(2n); xs[i].b = u8(v); return abi.encode(xs[i].b); }
      @external @pure fcompound(i: u256): u256 { let xs: P[] = new Array<P>(3n); xs[i].a = 10n; xs[i].a += 5n; xs[i].a++; return xs[i].a; }
    }`;
    const S = `struct P { uint256 a; uint8 b; }
    struct Q { uint256 m; }
    struct R { Q q; uint256[2] pre; }
    contract C {
      function fa(uint256 i) external pure returns (bytes memory){ P[] memory xs = new P[](3); xs[i].a=11; xs[i].b=222; return abi.encode(xs[i].a, xs[i].b); }
      function fdeep(uint256 i) external pure returns (bytes memory){ R[] memory xs = new R[](2); xs[i].q.m=7; xs[i].pre[0]=8; xs[i].pre[1]=9; return abi.encode(xs[i].q.m, xs[i].pre[0], xs[i].pre[1]); }
      function fdirty(uint256 i, uint256 v) external pure returns (bytes memory){ P[] memory xs = new P[](2); xs[i].b=uint8(v); return abi.encode(xs[i].b); }
      function fcompound(uint256 i) external pure returns (uint256){ P[] memory xs = new P[](3); xs[i].a=10; xs[i].a+=5; xs[i].a++; return xs[i].a; }
    }`;
    const hj = await Harness.create();
    const hs = await Harness.create();
    const aj = await hj.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await hs.deploy(compileSolidity(SPDX + S, 'C').creation);
    const P = (await import('../src/evm.js')).pad32;
    const cases: [string, string][] = [
      ['fa(uint256)', P(1n)],
      ['fdeep(uint256)', P(1n)],
      ['fdirty(uint256,uint256)', P(0n) + P(0x1ffn)],
      ['fcompound(uint256)', P(1n)],
    ];
    for (const [sig, args] of cases) {
      const data = '0x' + sel(sig) + args;
      const rj = await hj.call(aj, data);
      const rs = await hs.call(as, data);
      expect(rj.success, sig).toBe(rs.success);
      expect(rj.returnHex, sig).toBe(rs.returnHex);
    }
  });

  it('whole memory-array struct-element write xs[i] = P(...) (incl fixed-array field, OOB, copy) [was JETH900]', async () => {
    const J = `@struct class P { a: u256; b: u256; }
    @struct class N { a: u256; pre: Arr<u256, 2>; }
    @contract class C {
      @external @pure we(i: u256): bytes { let xs: P[] = new Array<P>(3n); xs[i] = P(11n, 22n); xs[0n] = P(1n, 2n); return abi.encode(xs[i].a, xs[i].b, xs[0n].a, xs[0n].b); }
      @external @pure wn(i: u256): bytes { let xs: N[] = new Array<N>(2n); xs[i] = N(5n, [6n, 7n]); return abi.encode(xs[i].a, xs[i].pre[0n], xs[i].pre[1n]); }
      @external @pure weoob(i: u256): bytes { let xs: P[] = new Array<P>(2n); xs[i] = P(1n, 2n); return abi.encode(xs[0n].a); }
    }`;
    const S = `struct P { uint256 a; uint256 b; }
    struct N { uint256 a; uint256[2] pre; }
    contract C {
      function we(uint256 i) external pure returns (bytes memory){ P[] memory xs=new P[](3); xs[i]=P(11,22); xs[0]=P(1,2); return abi.encode(xs[i].a, xs[i].b, xs[0].a, xs[0].b); }
      function wn(uint256 i) external pure returns (bytes memory){ N[] memory xs=new N[](2); uint256[2] memory pp; pp[0]=6; pp[1]=7; xs[i]=N(5, pp); return abi.encode(xs[i].a, xs[i].pre[0], xs[i].pre[1]); }
      function weoob(uint256 i) external pure returns (bytes memory){ P[] memory xs=new P[](2); xs[i]=P(1,2); return abi.encode(xs[0].a); }
    }`;
    const hj = await Harness.create();
    const hs = await Harness.create();
    const aj = await hj.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await hs.deploy(compileSolidity(SPDX + S, 'C').creation);
    const P = (await import('../src/evm.js')).pad32;
    const cases: [string, string][] = [
      ['we(uint256)', P(1n)],
      ['wn(uint256)', P(1n)],
      ['weoob(uint256)', P(1n)],
      ['weoob(uint256)', P(2n)], // OOB i -> Panic 0x32
    ];
    for (const [sig, args] of cases) {
      const data = '0x' + sel(sig) + args;
      const rj = await hj.call(aj, data);
      const rs = await hs.call(as, data);
      expect(rj.success, sig).toBe(rs.success);
      expect(rj.returnHex, sig).toBe(rs.returnHex);
    }
  });

  it('a memory struct-array element write now ACCEPTS a reference RHS (static-struct arrays are pointer-headed)', () => {
    // static-struct memory arrays are now POINTER-HEADED like solc, so xs[i] = xs[j] / xs[i] = <local>
    // ALIASES (copies the element pointer) byte-identically (covered in pointer-headed-static-struct-array.test.ts).
    const codes = (src: string): string[] => {
      try {
        compile(src, { fileName: 'C.jeth' });
        return [];
      } catch (e: any) {
        return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
      }
    };
    const C = (body: string) => `@struct class P { a: u256; b: u256; }\n@contract class C { @external @pure f(i: u256, j: u256): u256 { let xs: P[] = new Array<P>(2n); ${body} return xs[0n].a; } }`;
    expect(codes(C('xs[i] = P(1n, 2n);'))).toEqual([]); // fresh -> accept
    expect(codes(C('xs[0n] = xs[1n];'))).toEqual([]); // element ref -> aliases
    expect(codes(C('let s: P = P(1n, 2n); xs[0n] = s;'))).toEqual([]); // local ref -> aliases
  });

  it('bytes[]/string[] memory element write bs[i] = bytes(..) (re-point, OOB, alias, re-encode) [was JETH217]', async () => {
    const J = `@contract class C {
      @external @pure wb(i: u256): bytes { let bs: bytes[] = new Array<bytes>(3n); bs[0n] = bytes("hello"); bs[i] = bytes("world!!"); return abi.encode(bs[0n], bs[i]); }
      @external @pure ws(i: u256): bytes { let ss: string[] = new Array<string>(2n); ss[i] = "set me"; return abi.encode(ss[i]); }
      @external @pure wboob(i: u256): bytes { let bs: bytes[] = new Array<bytes>(2n); bs[i] = bytes("x"); return abi.encode(bs[0n]); }
      @external @pure walias(i: u256, src: bytes): bytes { let bs: bytes[] = new Array<bytes>(2n); bs[i] = src; return abi.encode(bs[i]); }
      @external @pure wlit(): bytes { let bs: bytes[] = new Array<bytes>(2n); bs[0n] = bytes("aa"); bs[1n] = bytes("bbbb"); return abi.encode(bs); }
    }`;
    const S = `contract C {
      function wb(uint256 i) external pure returns (bytes memory){ bytes[] memory bs=new bytes[](3); bs[0]="hello"; bs[i]="world!!"; return abi.encode(bs[0], bs[i]); }
      function ws(uint256 i) external pure returns (bytes memory){ string[] memory ss=new string[](2); ss[i]="set me"; return abi.encode(ss[i]); }
      function wboob(uint256 i) external pure returns (bytes memory){ bytes[] memory bs=new bytes[](2); bs[i]="x"; return abi.encode(bs[0]); }
      function walias(uint256 i, bytes calldata src) external pure returns (bytes memory){ bytes[] memory bs=new bytes[](2); bs[i]=src; return abi.encode(bs[i]); }
      function wlit() external pure returns (bytes memory){ bytes[] memory bs=new bytes[](2); bs[0]="aa"; bs[1]="bbbb"; return abi.encode(bs); }
    }`;
    const hj = await Harness.create();
    const hs = await Harness.create();
    const aj = await hj.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await hs.deploy(compileSolidity(SPDX + S, 'C').creation);
    const P = (await import('../src/evm.js')).pad32;
    const srcblob = Buffer.from('SRCDATA').toString('hex');
    const cases: [string, string][] = [
      ['wb(uint256)', P(2n)],
      ['ws(uint256)', P(0n)],
      ['wboob(uint256)', P(1n)],
      ['wboob(uint256)', P(2n)], // OOB i -> Panic 0x32
      ['walias(uint256,bytes)', P(1n) + P(0x40n) + P(7n) + srcblob.padEnd(64, '0')],
      ['wlit()', ''],
    ];
    for (const [sig, args] of cases) {
      const data = '0x' + sel(sig) + args;
      const rj = await hj.call(aj, data);
      const rs = await hs.call(as, data);
      expect(rj.success, sig).toBe(rs.success);
      expect(rj.returnHex, sig).toBe(rs.returnHex);
    }
  });

  it('whole-aggregate field of a struct-array element: value-leaf write + whole-field READ xs[i].q / xs[i].pre [was JETH245/JETH067]', async () => {
    // value-LEAF writes (xs[i].q.m = v, xs[i].pre[j] = v) followed by a whole-field READ (abi.encode(xs[i].q))
    // stay byte-identical. The whole-field WRITE (xs[i].q = Q(..), xs[i].pre = [..]) is a copy-vs-re-point
    // miscompile on the INLINE static-struct-array element, so it is a sound clean reject now (asserted below).
    const J = `@struct class Q { m: u256; n: u256; }
    @struct class P { q: Q; pre: Arr<u256, 2>; tag: u256; }
    @contract class C {
      @external @pure rdq(i: u256): bytes { let xs: P[] = new Array<P>(2n); xs[i].q.m = 5n; xs[i].q.n = 6n; return abi.encode(xs[i].q); }
      @external @pure rdpre(i: u256): bytes { let xs: P[] = new Array<P>(2n); xs[i].pre[0n] = 7n; xs[i].pre[1n] = 8n; return abi.encode(xs[i].pre); }
    }`;
    const S = `struct Q { uint256 m; uint256 n; }
    struct P { Q q; uint256[2] pre; uint256 tag; }
    contract C {
      function rdq(uint256 i) external pure returns (bytes memory){ P[] memory xs=new P[](2); xs[i].q.m=5; xs[i].q.n=6; return abi.encode(xs[i].q); }
      function rdpre(uint256 i) external pure returns (bytes memory){ P[] memory xs=new P[](2); xs[i].pre[0]=7; xs[i].pre[1]=8; return abi.encode(xs[i].pre); }
    }`;
    const hj = await Harness.create();
    const hs = await Harness.create();
    const aj = await hj.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await hs.deploy(compileSolidity(SPDX + S, 'C').creation);
    const P = (await import('../src/evm.js')).pad32;
    for (const fn of ['rdq', 'rdpre']) {
      const data = '0x' + sel(fn + '(uint256)') + P(1n);
      const rj = await hj.call(aj, data);
      const rs = await hs.call(as, data);
      expect(rj.success, fn).toBe(rs.success);
      expect(rj.returnHex, fn).toBe(rs.returnHex);
    }

    // whole-member WRITE into an inline static-struct-array element: copy-vs-re-point -> sound JETH429 reject.
    const codes = (src: string): string[] => {
      try {
        compile(src, { fileName: 'C.jeth' });
        return [];
      } catch (e: any) {
        return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
      }
    };
    expect(codes(`@struct class Q { m: u256; n: u256; }
    @struct class P { q: Q; pre: Arr<u256, 2>; tag: u256; }
    @contract class C { @external @pure wrq(i: u256): bytes { let xs: P[] = new Array<P>(2n); xs[i].q = Q(11n, 22n); return abi.encode(xs[i].q.m, xs[i].q.n); } }`)).toContain('JETH429');
    expect(codes(`@struct class Q { m: u256; n: u256; }
    @struct class P { q: Q; pre: Arr<u256, 2>; tag: u256; }
    @contract class C { @external @pure wrpre(i: u256): bytes { let xs: P[] = new Array<P>(2n); xs[i].pre = [33n, 44n]; return abi.encode(xs[i].pre[0n], xs[i].pre[1n]); } }`)).toContain('JETH429');
  });

  it('runtime array index into a struct-array-element field xs[i].pre[j] (read+write, 2D, OOB) [was JETH151]', async () => {
    const J = `@struct class P { pre: Arr<u256, 2>; tag: u256; }
    @struct class G { grid: Arr<Arr<u256, 2>, 2>; }
    @contract class C {
      @external @pure rd(i: u256, j: u256): u256 { let xs: P[] = new Array<P>(3n); xs[0n].pre[0n] = 5n; xs[0n].pre[1n] = 6n; xs[2n].pre[0n] = 77n; xs[2n].pre[1n] = 88n; return xs[i].pre[j]; }
      @external @pure wr(i: u256, j: u256, v: u256): bytes { let xs: P[] = new Array<P>(3n); xs[i].pre[j] = v; return abi.encode(xs[i].pre[0n], xs[i].pre[1n]); }
      @external @pure rdoob(i: u256, j: u256): u256 { let xs: P[] = new Array<P>(2n); return xs[i].pre[j]; }
      @external @pure twoD(i: u256, j: u256, k: u256): u256 { let xs: G[] = new Array<G>(2n); xs[1n].grid[0n][1n] = 42n; return xs[i].grid[j][k]; }
    }`;
    const S = `struct P { uint256[2] pre; uint256 tag; }
    struct G { uint256[2][2] grid; }
    contract C {
      function rd(uint256 i, uint256 j) external pure returns (uint256){ P[] memory xs = new P[](3); xs[0].pre[0]=5; xs[0].pre[1]=6; xs[2].pre[0]=77; xs[2].pre[1]=88; return xs[i].pre[j]; }
      function wr(uint256 i, uint256 j, uint256 v) external pure returns (bytes memory){ P[] memory xs = new P[](3); xs[i].pre[j]=v; return abi.encode(xs[i].pre[0], xs[i].pre[1]); }
      function rdoob(uint256 i, uint256 j) external pure returns (uint256){ P[] memory xs = new P[](2); return xs[i].pre[j]; }
      function twoD(uint256 i, uint256 j, uint256 k) external pure returns (uint256){ G[] memory xs = new G[](2); xs[1].grid[0][1]=42; return xs[i].grid[j][k]; }
    }`;
    const hj = await Harness.create();
    const hs = await Harness.create();
    const aj = await hj.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await hs.deploy(compileSolidity(SPDX + S, 'C').creation);
    const P = (await import('../src/evm.js')).pad32;
    const cases: [string, string][] = [
      ['rd(uint256,uint256)', P(0n) + P(1n)],
      ['rd(uint256,uint256)', P(2n) + P(0n)],
      ['wr(uint256,uint256,uint256)', P(1n) + P(0n) + P(99n)],
      ['rdoob(uint256,uint256)', P(0n) + P(2n)], // inner OOB -> Panic 0x32
      ['rdoob(uint256,uint256)', P(2n) + P(0n)], // outer OOB -> Panic 0x32
      ['twoD(uint256,uint256,uint256)', P(1n) + P(0n) + P(1n)],
      ['twoD(uint256,uint256,uint256)', P(0n) + P(0n) + P(2n)], // inner-inner OOB
    ];
    for (const [sig, args] of cases) {
      const data = '0x' + sel(sig) + args;
      const rj = await hj.call(aj, data);
      const rs = await hs.call(as, data);
      expect(rj.success, sig).toBe(rs.success);
      expect(rj.returnHex, sig).toBe(rs.returnHex);
    }
  });
});
