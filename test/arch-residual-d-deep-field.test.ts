// Residual D: a DEEP static sub-field/element read on a memory-array STATIC-struct element -
// xs[i].q.m (nested-struct field), xs[i].pre[0] (constant index into a fixed-array field),
// xs[i].t[2] (packed u8 fixed-array field). Residual B added only the single-level xs[i].a;
// deeper reads over-rejected (JETH245/JETH151/JETH217). The fix (resolveMemArrayElemFieldChain)
// walks the chain to a static word offset in the element's inline image and reads the value leaf via
// aggFieldRead. Works identically whether xs was built from a literal or decoded (abi.decode, Residual
// C). A RUNTIME array index into a struct-array-element field stays a clean over-rejection (later step).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';
import { Address } from '@ethereumjs/util';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const sel = (s: string) => '0x' + functionSelector(s);
const wrapBytes = (blob: string) => {
  const b = blob.startsWith('0x') ? blob.slice(2) : blob;
  const len = b.length / 2;
  const W = (n: bigint) => n.toString(16).padStart(64, '0');
  const pad = b.length % 64 ? b + '0'.repeat(64 - (b.length % 64)) : b;
  return '0x' + W(0x20n) + W(BigInt(len)) + pad;
};

const MK = `[P(1n,Q(2n,3n),[u256(4n),5n],[6n,7n,8n]),P(11n,Q(12n,13n),[u256(14n),15n],[16n,17n,18n])]`;
const J = `type Q = { m: u256; n: u256; }; type P = { a: u256; q: Q; pre: Arr<u256,2>; t: Arr<u8,3>; };
class C {
  get a(): External<u256> { let xs: P[] = ${MK}; return xs[1n].a; }
  get qm(): External<u256> { let xs: P[] = ${MK}; return xs[0n].q.m; }
  get qn(): External<u256> { let xs: P[] = ${MK}; return xs[1n].q.n; }
  get p0(): External<u256> { let xs: P[] = ${MK}; return xs[0n].pre[0n]; }
  get p1(): External<u256> { let xs: P[] = ${MK}; return xs[1n].pre[1n]; }
  get t2(): External<u256> { let xs: P[] = ${MK}; return xs[0n].t[2n]; }
  get dq(b: bytes): External<u256> { let xs: P[] = abi.decode(b, P[]); return xs[1n].q.n; }
  get dp(b: bytes): External<u256> { let xs: P[] = abi.decode(b, P[]); return xs[0n].pre[1n]; } }`;
const S = `struct Q { uint m; uint n; } struct P { uint a; Q q; uint[2] pre; uint8[3] t; }
contract C {
  function mk() internal pure returns (P[] memory) { P[] memory xs=new P[](2); xs[0]=P(1,Q(2,3),[uint(4),5],[uint8(6),7,8]); xs[1]=P(11,Q(12,13),[uint(14),15],[uint8(16),17,18]); return xs; }
  function a() external pure returns(uint){ return mk()[1].a; }
  function qm() external pure returns(uint){ return mk()[0].q.m; }
  function qn() external pure returns(uint){ return mk()[1].q.n; }
  function p0() external pure returns(uint){ return mk()[0].pre[0]; }
  function p1() external pure returns(uint){ return mk()[1].pre[1]; }
  function t2() external pure returns(uint){ return mk()[0].t[2]; }
  function enc() external pure returns(bytes memory){ return abi.encode(mk()); }
  function dq(bytes calldata b) external pure returns(uint){ P[] memory xs=abi.decode(b,(P[])); return xs[1].q.n; }
  function dp(bytes calldata b) external pure returns(uint){ P[] memory xs=abi.decode(b,(P[])); return xs[0].pre[1]; } }`;

describe('Residual D: deep sub-field read on a memory-array struct element (literal + decoded)', () => {
  it('byte-identical to solc 0.8.35 across nested-struct field, fixed-array field, packed u8 field', async () => {
    const h = await Harness.create();
    await h.fund(me, 10n ** 20n);
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
    for (const sg of ['a()', 'qm()', 'qn()', 'p0()', 'p1()', 't2()']) {
      const jr = await h.call(ja, sel(sg));
      const sr = await h.call(sa, sel(sg));
      expect(jr.returnHex, sg).toBe(sr.returnHex);
      expect(jr.success, sg).toBe(sr.success);
    }
    // decoded P[] (Residual C) then a deep read (Residual D) - they compose.
    const encHx = (await h.call(sa, sel('enc()'))).returnHex.slice(2);
    const len = parseInt(encHx.slice(64, 128), 16);
    const blob = '0x' + encHx.slice(128, 128 + len * 2);
    for (const dec of ['dq(bytes)', 'dp(bytes)']) {
      const cd = sel(dec) + wrapBytes(blob).slice(2);
      const jr = await h.call(ja, cd);
      const sr = await h.call(sa, cd);
      expect(jr.returnHex, dec).toBe(sr.returnHex);
      expect(jr.success, dec).toBe(sr.success);
    }
  });

  it('now ACCEPTS a RUNTIME array index into a struct-array-element field (over-rejection lifted; byte-identity in lift-over-rejections.test.ts)', () => {
    const codes = (src: string): string[] => {
      try {
        compile(src, { fileName: 'C.jeth' });
        return [];
      } catch (e: any) {
        return e?.diagnostics ? e.diagnostics.map((d: any) => d.code) : ['THROW'];
      }
    };
    expect(
      codes(`type P = { a: u256; pre: Arr<u256,2>; }; class C { get f(j: u256): External<u256> { let xs: P[] = [P(1n,[u256(2n),3n])]; return xs[0n].pre[j]; } }`),
    ).toEqual([]);
  });
});
