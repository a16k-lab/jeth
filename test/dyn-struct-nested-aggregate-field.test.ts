// Batch B: a DYNAMIC-field struct memory local may have a NESTED STATIC AGGREGATE field (a nested
// static struct, or a static fixed array Arr<T,N>), stored INLINE in the pointer-headed image as
// flattened head words (the tuple-head layout). Construct / read (p.inner.x, p.fa[j], whole p.inner) /
// encode / return / decode are byte-identical to solc 0.8.35. Plus whole-field re-point p.xs = arr
// (a dynamic-array field). A fixed-array element OOB Panics 0x32 like solc.
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

describe('Batch B: dyn-struct with a nested static-aggregate field - byte-identical to solc 0.8.35', () => {
  it('nested static struct field: construct / read p.inner.x / whole p.inner / encode / return', async () => {
    const J = `type In = { x: u256; y: u256; };
    type S = { a: u256; inner: In; b: bytes; };
    class C {
      get enc(): External<bytes> { let s: S = S(1n, In(3n, 4n), bytes("z")); return abi.encode(s); }
      get read(): External<u256> { let s: S = S(1n, In(3n, 4n), bytes("zz")); return s.a + s.inner.x + s.inner.y + s.b.length; }
      get whole(): External<bytes> { let s: S = S(1n, In(3n, 4n), bytes("z")); return abi.encode(s.inner); }
      get ret(): External<S> { let s: S = S(5n, In(6n, 7n), bytes("hi")); return s; } }`;
    const Sol = `struct In { uint256 x; uint256 y; }
    struct S { uint256 a; In inner; bytes b; }
    contract C {
      function enc() external pure returns(bytes memory){ S memory s=S(1,In(3,4),bytes("z")); return abi.encode(s); }
      function read() external pure returns(uint256){ S memory s=S(1,In(3,4),bytes("zz")); return s.a + s.inner.x + s.inner.y + s.b.length; }
      function whole() external pure returns(bytes memory){ S memory s=S(1,In(3,4),bytes("z")); return abi.encode(s.inner); }
      function ret() external pure returns(S memory){ S memory s=S(5,In(6,7),bytes("hi")); return s; } }`;
    await diff(J, Sol, [['enc()', ''], ['read()', ''], ['whole()', ''], ['ret()', '']]);
  });

  it('static fixed-array field: construct / read p.fa[j] (const + runtime + OOB Panic 0x32) / encode', async () => {
    const J = `type S = { a: u256; fa: Arr<u256, 3>; b: bytes; };
    class C {
      get enc(): External<bytes> { let s: S = S(1n, [u256(7n), 8n, 9n], bytes("z")); return abi.encode(s); }
      get rd(): External<u256> { let s: S = S(1n, [u256(7n), 8n, 9n], bytes("z")); return s.fa[0n] + s.fa[2n]; }
      get dyn(i: u256): External<u256> { let s: S = S(1n, [u256(7n), 8n, 9n], bytes("z")); return s.fa[i]; } }`;
    const Sol = `struct S { uint256 a; uint256[3] fa; bytes b; }
    contract C {
      function enc() external pure returns(bytes memory){ uint256[3] memory pp;pp[0]=7;pp[1]=8;pp[2]=9; S memory s=S(1,pp,bytes("z")); return abi.encode(s); }
      function rd() external pure returns(uint256){ uint256[3] memory pp;pp[0]=7;pp[1]=8;pp[2]=9; S memory s=S(1,pp,bytes("z")); return s.fa[0] + s.fa[2]; }
      function dyn(uint256 i) external pure returns(uint256){ uint256[3] memory pp;pp[0]=7;pp[1]=8;pp[2]=9; S memory s=S(1,pp,bytes("z")); return s.fa[i]; } }`;
    await diff(J, Sol, [['enc()', ''], ['rd()', ''], ['dyn(uint256)', pad32(1n)], ['dyn(uint256)', pad32(5n)]]);
  });

  it('deep nesting (p.outer.inner.x) + nested-agg field ordering', async () => {
    const J = `type In = { x: u256; y: u256; };
    type Mid = { q: u256; inner: In; };
    type S = { fa: Arr<u256, 2>; a: u256; outer: Mid; b: bytes; };
    class C {
      get read(): External<u256> { let s: S = S([u256(10n), 20n], 1n, Mid(5n, In(3n, 4n)), bytes("z")); return s.fa[1n] + s.a + s.outer.q + s.outer.inner.x + s.outer.inner.y; }
      get enc(): External<bytes> { let s: S = S([u256(10n), 20n], 1n, Mid(5n, In(3n, 4n)), bytes("z")); return abi.encode(s); } }`;
    const Sol = `struct In { uint256 x; uint256 y; }
    struct Mid { uint256 q; In inner; }
    struct S { uint256[2] fa; uint256 a; Mid outer; bytes b; }
    contract C {
      function read() external pure returns(uint256){ uint256[2] memory pp;pp[0]=10;pp[1]=20; S memory s=S(pp,1,Mid(5,In(3,4)),bytes("z")); return s.fa[1] + s.a + s.outer.q + s.outer.inner.x + s.outer.inner.y; }
      function enc() external pure returns(bytes memory){ uint256[2] memory pp;pp[0]=10;pp[1]=20; S memory s=S(pp,1,Mid(5,In(3,4)),bytes("z")); return abi.encode(s); } }`;
    await diff(J, Sol, [['read()', ''], ['enc()', '']]);
  });

  it('re-point a dynamic-array field p.xs = arr (value-array) / p.tags = bytes[] (leaf-array)', async () => {
    const J = `type S = { a: u256; xs: u256[]; };
    type T = { a: u256; tags: bytes[]; };
    class C {
      get vf(): External<u256> { let ini: u256[] = [9n]; let s: S = S(1n, ini); let arr: u256[] = [5n, 6n]; s.xs = arr; return s.xs[0n] + s.xs[1n] + s.xs.length; }
      get lf(): External<bytes> { let ini: bytes[] = [bytes("q")]; let t: T = T(1n, ini); let n: bytes[] = [bytes("aa"), bytes("bbb")]; t.tags = n; return abi.encode(t); } }`;
    const Sol = `struct S { uint256 a; uint256[] xs; }
    struct T { uint256 a; bytes[] tags; }
    contract C {
      function vf() external pure returns(uint256){ uint256[] memory ini=new uint256[](1);ini[0]=9; S memory s=S(1,ini); uint256[] memory arr=new uint256[](2);arr[0]=5;arr[1]=6; s.xs=arr; return s.xs[0] + s.xs[1] + s.xs.length; }
      function lf() external pure returns(bytes memory){ bytes[] memory ini=new bytes[](1);ini[0]=bytes("q"); T memory t=T(1,ini); bytes[] memory n=new bytes[](2);n[0]=bytes("aa");n[1]=bytes("bbb"); t.tags=n; return abi.encode(t); } }`;
    await diff(J, Sol, [['vf()', ''], ['lf()', '']]);
  });
});
