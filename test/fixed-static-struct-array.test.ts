// Batch A: FIXED-outer / FIXED-element static-struct arrays - Arr<P,N> (P[N] memory) and Arr<P,N>[]
// (P[N][] memory). A fixed array of a reference-type element is POINTER-HEADED in memory (N pointer
// words, no length header), like solc; the ABI encoding of Arr<P,N> (a static type) is INLINE.
// Byte-identical to solc 0.8.35. Value fixed arrays (Arr<u256,N>) stay inline and are unaffected.
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

describe('Batch A: fixed-outer / fixed-element static-struct arrays - byte-identical to solc 0.8.35', () => {
  it('Arr<P,N>: construct / read m[i].a (const + runtime + OOB Panic 0x32) / whole m[i] / encode / return', async () => {
    const J = `type P = { a: u256; b: u256; };
    class C {
      get enc(): External<bytes> { let m: Arr<P, 3> = [P(1n, 2n), P(3n, 4n), P(5n, 6n)]; return abi.encode(m, m[1n].a, m[2n].b); }
      get ret(): External<Arr<P, 2>> { let m: Arr<P, 2> = [P(7n, 8n), P(9n, 10n)]; return m; }
      get dyn(i: u256): External<u256> { let m: Arr<P, 3> = [P(1n, 2n), P(3n, 4n), P(5n, 6n)]; return m[i].a + m[i].b; }
      get whole(): External<bytes> { let m: Arr<P, 2> = [P(7n, 8n), P(9n, 10n)]; return abi.encode(m[1n]); } }`;
    const S = `struct P { uint256 a; uint256 b; }
    contract C {
      function enc() external pure returns(bytes memory){ P[3] memory m; m[0]=P(1,2);m[1]=P(3,4);m[2]=P(5,6); return abi.encode(m, m[1].a, m[2].b); }
      function ret() external pure returns(P[2] memory){ P[2] memory m; m[0]=P(7,8);m[1]=P(9,10); return m; }
      function dyn(uint256 i) external pure returns(uint256){ P[3] memory m; m[0]=P(1,2);m[1]=P(3,4);m[2]=P(5,6); return m[i].a + m[i].b; }
      function whole() external pure returns(bytes memory){ P[2] memory m; m[0]=P(7,8);m[1]=P(9,10); return abi.encode(m[1]); } }`;
    await diff(J, S, [['enc()', ''], ['ret()', ''], ['dyn(uint256)', pad32(2n)], ['dyn(uint256)', pad32(5n)], ['whole()', '']]);
  });

  it('Arr<P,N>[] (dynamic outer, fixed-struct-array element): construct / read m[i][j].a / encode', async () => {
    const J = `type P = { a: u256; b: u256; };
    class C {
      get enc(): External<bytes> { let m: Arr<P, 2>[] = [[P(1n, 2n), P(3n, 4n)], [P(5n, 6n), P(7n, 8n)]]; return abi.encode(m, m[1n][0n].a, m[0n][1n].b); } }`;
    const S = `struct P { uint256 a; uint256 b; }
    contract C {
      function enc() external pure returns(bytes memory){ P[2][] memory m=new P[2][](2); m[0][0]=P(1,2);m[0][1]=P(3,4);m[1][0]=P(5,6);m[1][1]=P(7,8); return abi.encode(m, m[1][0].a, m[0][1].b); } }`;
    await diff(J, S, [['enc()', '']]);
  });

  it('packed P(u128,u128) and P with a fixed-array field, as the Arr element', async () => {
    const J = `type P = { a: u128; b: u128; };
    type Q = { a: u256; pre: Arr<u256, 2>; };
    class C {
      get pk(): External<bytes> { let m: Arr<P, 2> = [P(1n, 2n), P(3n, 4n)]; return abi.encode(m, m[1n].a); }
      get ff(): External<bytes> { let q0: Q = Q(5n, [6n, 7n]); let m: Arr<Q, 2> = [q0, Q(8n, [9n, 10n])]; return abi.encode(m, m[1n].pre[1n]); } }`;
    const S = `struct P { uint128 a; uint128 b; }
    struct Q { uint256 a; uint256[2] pre; }
    contract C {
      function pk() external pure returns(bytes memory){ P[2] memory m; m[0]=P(1,2);m[1]=P(3,4); return abi.encode(m, m[1].a); }
      function ff() external pure returns(bytes memory){ uint256[2] memory p0;p0[0]=6;p0[1]=7; uint256[2] memory p1;p1[0]=9;p1[1]=10; Q[2] memory m; m[0]=Q(5,p0);m[1]=Q(8,p1); return abi.encode(m, m[1].pre[1]); } }`;
    await diff(J, S, [['pk()', ''], ['ff()', '']]);
  });

  it('abi.decode(b, Arr<P,N>) round-trip + malformed reverts byte-identical', async () => {
    const J = `type P = { a: u256; b: u256; };
    class C {
      get dec(d: bytes): External<bytes> { let m: Arr<P, 2> = abi.decode(d, Arr<P, 2>); return abi.encode(m); }
      get mk(): External<bytes> { let m: Arr<P, 2> = [P(11n, 22n), P(33n, 44n)]; return abi.encode(m); } }`;
    const S = `struct P { uint256 a; uint256 b; }
    contract C {
      function dec(bytes calldata d) external pure returns(bytes memory){ P[2] memory m=abi.decode(d,(P[2])); return abi.encode(m); }
      function mk() external pure returns(bytes memory){ P[2] memory m; m[0]=P(11,22);m[1]=P(33,44); return abi.encode(m); } }`;
    const h = await Harness.create();
    const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
    const eb = (hx: string) => { const len = hx.length / 2; return pad32(BigInt(len)) + hx + '00'.repeat((32 - (len % 32)) % 32); };
    const blob = (await h.call(as, sel('mk()'))).returnHex.slice(2);
    const body = blob.slice(128, 128 + parseInt(blob.slice(64, 128), 16) * 2);
    for (const [label, payload] of [
      ['well-formed', pad32(0x20n) + eb(body)],
      ['truncated', pad32(0x20n) + eb(body.slice(0, Math.max(0, body.length - 64)))],
    ] as [string, string][]) {
      const data = sel('dec(bytes)') + payload;
      const rj = await h.call(aj, data);
      const rs = await h.call(as, data);
      expect(rj.success, label).toBe(rs.success);
      expect(rj.returnHex, label).toBe(rs.returnHex);
    }
  });

  it('value fixed arrays (Arr<u256,N>, Arr<u256,N>[]) stay inline and accept (invariance)', () => {
    const codes = (src: string): string[] => {
      try { compile(src, { fileName: 'C.jeth' }); return []; } catch (e: any) { return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW']; }
    };
    expect(codes(`class C { get f(): External<u256> { let a: Arr<u256,3> = [1n,2n,3n]; return a[2n]; } }`)).toEqual([]);
    expect(codes(`class C { get f(): External<u256> { let a: Arr<u256,2>[] = [[1n,2n]]; return a[0n][1n]; } }`)).toEqual([]);
  });
});
