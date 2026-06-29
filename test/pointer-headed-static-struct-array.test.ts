// Cat B redesign: STATIC-struct memory arrays P[] are now POINTER-HEADED in memory (matching solc:
// [len][ptr0][ptr1]..., each ptr -> a fresh [a][b] element image), while the ABI ENCODING stays INLINE.
// This makes element aliasing (xs[i]=xs[j], let p=xs[i]) and nested P[][] byte-identical to solc 0.8.35.
// Value arrays (u256[]) and FIXED outers (Arr<P,N>) are unaffected (the latter still cleanly rejects).
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

describe('Cat B: pointer-headed static-struct memory arrays - byte-identical to solc 0.8.35', () => {
  it('construct / read / encode / return / OOB / zero-init / fixed-array field', async () => {
    const J = `@struct class P { a: u256; b: u256; }
    @struct class N { a: u256; pre: Arr<u256, 2>; }
    @contract class C {
      @external @pure lit(): bytes { let xs: P[] = [P(1n, 2n), P(3n, 4n), P(5n, 6n)]; return abi.encode(xs); }
      @external @pure read(): u256 { let xs: P[] = [P(1n, 2n), P(3n, 4n)]; return xs[1n].a + xs[0n].b + xs.length; }
      @external @pure ret(): P[] { let xs: P[] = [P(7n, 8n), P(9n, 10n)]; return xs; }
      @external @pure zero(): bytes { let xs: P[] = new Array<P>(3n); xs[1n] = P(7n, 8n); return abi.encode(xs); }
      @external @pure oob(): u256 { let xs: P[] = [P(1n, 2n)]; return xs[5n].a; }
      @external @pure fafield(): bytes { let xs: N[] = new Array<N>(2n); xs[0n] = N(5n, [6n, 7n]); return abi.encode(xs, xs[0n].pre[1n]); } }`;
    const S = `struct P { uint256 a; uint256 b; }
    struct N { uint256 a; uint256[2] pre; }
    contract C {
      function lit() external pure returns(bytes memory){ P[] memory xs=new P[](3); xs[0]=P(1,2);xs[1]=P(3,4);xs[2]=P(5,6); return abi.encode(xs); }
      function read() external pure returns(uint256){ P[] memory xs=new P[](2); xs[0]=P(1,2);xs[1]=P(3,4); return xs[1].a + xs[0].b + xs.length; }
      function ret() external pure returns(P[] memory){ P[] memory xs=new P[](2); xs[0]=P(7,8);xs[1]=P(9,10); return xs; }
      function zero() external pure returns(bytes memory){ P[] memory xs=new P[](3); xs[1]=P(7,8); return abi.encode(xs); }
      function oob() external pure returns(uint256){ P[] memory xs=new P[](1); xs[0]=P(1,2); return xs[5].a; }
      function fafield() external pure returns(bytes memory){ N[] memory xs=new N[](2); uint256[2] memory pp;pp[0]=6;pp[1]=7; xs[0]=N(5,pp); return abi.encode(xs, xs[0].pre[1]); } }`;
    await diff(J, S, ['lit()', 'read()', 'ret()', 'zero()', 'oob()', 'fafield()']);
  });

  it('element ALIASING: xs[i]=xs[j] / let p=xs[i] / for-of (write-through, re-point independence)', async () => {
    const J = `@struct class P { a: u256; b: u256; }
    @contract class C {
      @external @pure e2e(): u256 { let xs: P[] = [P(1n, 2n), P(8n, 9n)]; xs[1n] = xs[0n]; xs[0n].a = 7n; return xs[1n].a; }
      @external @pure repoint(): u256 { let xs: P[] = [P(1n, 2n), P(8n, 9n)]; xs[1n] = xs[0n]; xs[0n] = P(5n, 5n); return xs[1n].a; }
      @external @pure letp(): u256 { let xs: P[] = [P(1n, 2n)]; let p: P = xs[0n]; p.a = 9n; return xs[0n].a; }
      @external @pure letpkeep(): u256 { let xs: P[] = [P(1n, 2n)]; let p: P = xs[0n]; xs[0n] = P(9n, 9n); return p.a; }
      @external @pure forof(): u256 { let xs: P[] = [P(1n, 2n), P(3n, 4n)]; let n: u256 = 0n; for (const p of xs) { n = n + p.a + p.b; } return n; }
      @external @pure encalias(): bytes { let xs: P[] = [P(1n, 2n), P(8n, 9n)]; xs[1n] = xs[0n]; xs[0n].a = 7n; return abi.encode(xs); } }`;
    const S = `struct P { uint256 a; uint256 b; }
    contract C {
      function e2e() external pure returns(uint256){ P[] memory xs=new P[](2); xs[0]=P(1,2);xs[1]=P(8,9); xs[1]=xs[0]; xs[0].a=7; return xs[1].a; }
      function repoint() external pure returns(uint256){ P[] memory xs=new P[](2); xs[0]=P(1,2);xs[1]=P(8,9); xs[1]=xs[0]; xs[0]=P(5,5); return xs[1].a; }
      function letp() external pure returns(uint256){ P[] memory xs=new P[](1); xs[0]=P(1,2); P memory p=xs[0]; p.a=9; return xs[0].a; }
      function letpkeep() external pure returns(uint256){ P[] memory xs=new P[](1); xs[0]=P(1,2); P memory p=xs[0]; xs[0]=P(9,9); return p.a; }
      function forof() external pure returns(uint256){ P[] memory xs=new P[](2); xs[0]=P(1,2);xs[1]=P(3,4); uint256 n=0; for(uint i=0;i<xs.length;i++){ P memory p=xs[i]; n+=p.a+p.b; } return n; }
      function encalias() external pure returns(bytes memory){ P[] memory xs=new P[](2); xs[0]=P(1,2);xs[1]=P(8,9); xs[1]=xs[0]; xs[0].a=7; return abi.encode(xs); } }`;
    await diff(J, S, ['e2e()', 'repoint()', 'letp()', 'letpkeep()', 'forof()', 'encalias()']);
  });

  it('nested P[][] build / read / encode / inner alias', async () => {
    const J = `@struct class P { a: u256; b: u256; }
    @contract class C {
      @external @pure enc(): bytes { let m: P[][] = [[P(1n, 2n)], [P(3n, 4n), P(5n, 6n)]]; return abi.encode(m, m[1n][1n].a); }
      @external @pure newz(): bytes { let m: P[][] = new Array<P[]>(2n); m[0n] = [P(1n, 2n)]; return abi.encode(m); }
      @external @pure inalias(): u256 { let m: P[][] = [[P(1n, 2n)], [P(9n, 9n)]]; m[1n] = m[0n]; m[0n][0n].a = 7n; return m[1n][0n].a; } }`;
    const S = `struct P { uint256 a; uint256 b; }
    contract C {
      function enc() external pure returns(bytes memory){ P[][] memory m=new P[][](2); m[0]=new P[](1);m[0][0]=P(1,2); m[1]=new P[](2);m[1][0]=P(3,4);m[1][1]=P(5,6); return abi.encode(m, m[1][1].a); }
      function newz() external pure returns(bytes memory){ P[][] memory m=new P[][](2); m[0]=new P[](1);m[0][0]=P(1,2); return abi.encode(m); }
      function inalias() external pure returns(uint256){ P[][] memory m=new P[][](2); m[0]=new P[](1);m[0][0]=P(1,2); m[1]=new P[](1);m[1][0]=P(9,9); m[1]=m[0]; m[0][0].a=7; return m[1][0].a; } }`;
    await diff(J, S, ['enc()', 'newz()', 'inalias()']);
  });

  it('abi.decode(b, P[]) and abi.decode(b, P[][]) round-trip + malformed reverts byte-identical', async () => {
    const J = `@struct class P { a: u256; b: u256; }
    @contract class C {
      @external dec1(d: bytes): bytes { let xs: P[] = abi.decode(d, P[]); return abi.encode(xs); }
      @external dec2(d: bytes): bytes { let m: P[][] = abi.decode(d, P[][]); return abi.encode(m); }
      @external @pure mk1(): bytes { let xs: P[] = [P(11n, 22n), P(33n, 44n)]; return abi.encode(xs); }
      @external @pure mk2(): bytes { let m: P[][] = [[P(1n, 2n)], [P(3n, 4n)]]; return abi.encode(m); } }`;
    const S = `struct P { uint256 a; uint256 b; }
    contract C {
      function dec1(bytes calldata d) external pure returns(bytes memory){ P[] memory xs=abi.decode(d,(P[])); return abi.encode(xs); }
      function dec2(bytes calldata d) external pure returns(bytes memory){ P[][] memory m=abi.decode(d,(P[][])); return abi.encode(m); }
      function mk1() external pure returns(bytes memory){ P[] memory xs=new P[](2);xs[0]=P(11,22);xs[1]=P(33,44); return abi.encode(xs); }
      function mk2() external pure returns(bytes memory){ P[][] memory m=new P[][](2);m[0]=new P[](1);m[0][0]=P(1,2);m[1]=new P[](1);m[1][0]=P(3,4); return abi.encode(m); } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const eb = (hx: string) => { const len = hx.length / 2; return pad32(BigInt(len)) + hx + '00'.repeat((32 - (len % 32)) % 32); };
    for (const [mk, dec] of [['mk1()', 'dec1(bytes)'], ['mk2()', 'dec2(bytes)']] as const) {
      const ret = (await h.call(as, sel(mk))).returnHex.slice(2);
      const blob = ret.slice(128, 128 + parseInt(ret.slice(64, 128), 16) * 2);
      const cases: [string, string][] = [
        ['well-formed', pad32(0x20n) + eb(blob)],
        ['truncated', pad32(0x20n) + eb(blob.slice(0, Math.max(0, blob.length - 64)))],
        ['huge-outer-len', pad32(0x20n) + eb(pad32(0xffffffffffffffffn) + blob.slice(64))],
      ];
      for (const [label, payload] of cases) {
        const data = sel(dec) + payload;
        const rj = await h.call(aj, data);
        const rs = await h.call(as, data);
        expect(rj.success, `${dec} ${label}`).toBe(rs.success);
        expect(rj.returnHex, `${dec} ${label}`).toBe(rs.returnHex);
      }
    }
  });

  it('FIXED-outer / FIXED-element static-struct arrays now ACCEPT (Batch A, byte-identical)', () => {
    // Arr<P,N> / Arr<P,N>[] are pointer-headed like solc (byte-identity in fixed-static-struct-array.test.ts).
    expect(codes(`@struct class P{a:u256;b:u256;} @contract class C { @external @pure f(): Arr<P,2> { let m: Arr<P,2> = [P(1n,2n),P(3n,4n)]; return m; } }`)).toEqual([]);
    expect(codes(`@struct class P{a:u256;b:u256;} @contract class C { @external @pure f(): u256 { let m: Arr<P,2>[] = [[P(1n,2n),P(3n,4n)]]; return m[0n][0n].a; } }`)).toEqual([]);
    // value arrays stay inline (unchanged) and accept:
    expect(codes(`@contract class C { @external @pure f(): u256 { let a: u256[] = [1n,2n]; return a[1n]; } }`)).toEqual([]);
  });
});
