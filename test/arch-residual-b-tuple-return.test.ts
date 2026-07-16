// Residual B follow-up: an aggregate-leaf MEMORY array (P[] / bytes[] / string[]) returned as a
// NON-SOLE component of a multi-value tuple. The adversarial verification of Residual B caught a SILENT
// MISCOMPILE here: encodeReturnTuple's memory-array branch did a verbatim mcopy of (len+1) words, which
// is correct ONLY for a flat value array (image == ABI). It TRUNCATED a static-struct array (wrong
// stride: 1 word instead of abiHeadWords(P)) and CORRUPTED bytes[]/string[]/nested arrays (whose memory
// image is pointer-headed, not the ABI layout). The fix routes everything except a flat value array
// through abiEncFromMem - the SAME recursive memory->ABI encoder the single-return `return xs` path
// uses. This also fixed a PRE-EXISTING #2 bug: a nested value array u256[][] as a tuple component.
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';
import { Address } from '@ethereumjs/util';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const sel = (s: string) => '0x' + functionSelector(s);
const P32 = 'p'.repeat(32);
const Q33 = 'q'.repeat(33);
const hexlit = (s: string) => 'hex"' + Buffer.from(s).toString('hex') + '"';

const J = `type P = { a: u256; b: u256; }; type W = { x: Arr<u256,2>; y: u256; };
class C {
  get t1(): External<[P[], u256]> { let xs: P[] = [P(1n,2n),P(3n,4n)]; return [xs, 42n]; }
  get t2(): External<[u256, P[]]> { let xs: P[] = [P(1n,2n),P(3n,4n)]; return [42n, xs]; }
  get t3(): External<[W[], u256]> { let xs: W[] = [W([u256(1n),2n],3n),W([u256(4n),5n],6n)]; return [xs, 7n]; }
  get t4(): External<[u256, bytes[]]> { let bs: bytes[] = [bytes("${P32}"),bytes("${Q33}")]; return [42n, bs]; }
  get t5(): External<[bytes[], u256]> { let bs: bytes[] = [bytes("${P32}"),bytes("${Q33}")]; return [bs, 42n]; }
  get t6(): External<[u256, string[]]> { let ss: string[] = ["${P32}","${Q33}"]; return [7n, ss]; }
  get cv(): External<[u256[], u256]> { let xs: u256[] = [1n,2n,3n]; return [xs, 9n]; }
  get nn(): External<[u256[][], u256]> { let m: u256[][] = [[1n,2n],[3n]]; return [m, 9n]; }
  get m3(): External<[P[], bytes[], u256]> { let xs: P[] = [P(1n,2n)]; let bs: bytes[] = [bytes("ab"),bytes("cde")]; return [xs, bs, 5n]; } }`;

const S = `struct P { uint a; uint b; } struct W { uint[2] x; uint y; }
contract C {
  function t1() external pure returns (P[] memory, uint) { P[] memory xs=new P[](2); xs[0]=P(1,2); xs[1]=P(3,4); return (xs,42); }
  function t2() external pure returns (uint, P[] memory) { P[] memory xs=new P[](2); xs[0]=P(1,2); xs[1]=P(3,4); return (42,xs); }
  function t3() external pure returns (W[] memory, uint) { W[] memory xs=new W[](2); xs[0]=W([uint(1),2],3); xs[1]=W([uint(4),5],6); return (xs,7); }
  function t4() external pure returns (uint, bytes[] memory) { bytes[] memory bs=new bytes[](2); bs[0]=${hexlit(P32)}; bs[1]=${hexlit(Q33)}; return (42,bs); }
  function t5() external pure returns (bytes[] memory, uint) { bytes[] memory bs=new bytes[](2); bs[0]=${hexlit(P32)}; bs[1]=${hexlit(Q33)}; return (bs,42); }
  function t6() external pure returns (uint, string[] memory) { string[] memory ss=new string[](2); ss[0]=string(${hexlit(P32)}); ss[1]=string(${hexlit(Q33)}); return (7,ss); }
  function cv() external pure returns (uint[] memory, uint) { uint[] memory xs=new uint[](3); xs[0]=1;xs[1]=2;xs[2]=3; return (xs,9); }
  function nn() external pure returns (uint[][] memory, uint) { uint[][] memory m=new uint[][](2); m[0]=new uint[](2);m[0][0]=1;m[0][1]=2; m[1]=new uint[](1);m[1][0]=3; return (m,9); }
  function m3() external pure returns (P[] memory, bytes[] memory, uint) { P[] memory xs=new P[](1); xs[0]=P(1,2); bytes[] memory bs=new bytes[](2); bs[0]=hex"6162"; bs[1]=hex"636465"; return (xs,bs,5); } }`;

describe('Residual B: aggregate-leaf memory array as a multi-return tuple component (miscompile fixed)', () => {
  it('byte-identical to solc 0.8.35: P[]/W[]/bytes[]/string[]/u256[]/u256[][] as a non-sole tuple component', async () => {
    const h = await Harness.create();
    await h.fund(me, 10n ** 20n);
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
    for (const sg of ['t1()', 't2()', 't3()', 't4()', 't5()', 't6()', 'cv()', 'nn()', 'm3()']) {
      const jr = await h.call(ja, sel(sg));
      const sr = await h.call(sa, sel(sg));
      expect(jr.returnHex, sg).toBe(sr.returnHex);
      expect(jr.success, sg).toBe(sr.success);
    }
  });
});
