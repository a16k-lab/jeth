// Residual C follow-up (R1): the natural one-liner `return abi.decode(b, T)` for an ARRAY target T
// (no intermediate local). The adversarial verification of Residual C flagged this as a clean
// over-rejection (JETH900 "cannot encode array from abiDecode"): the return-array handler fell through
// to encodeArrayReturn, which requires an arrayValue, but a raw abi.decode evaluates to an abiDecode
// value that was never materialized. The fix materializes the decoded image via lowerAbiDecode (the
// SAME decoder the `let a: T = abi.decode(b,T); return a;` local form uses) and routes it to the SAME
// encoder that local form's return uses - encodeNestedMemReturn for an aggregate-leaf/nested image,
// encodeMemArrayReturn for a flat value array. So it is byte-identical to solc's direct-return decode.
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

const J = `@struct class P { a: u256; b: u256; } @contract class C {
  @external @pure d_mm(b: bytes): u256[][] { return abi.decode(b, u256[][]); }
  @external @pure d_ps(b: bytes): P[] { return abi.decode(b, P[]); }
  @external @pure d_bs(b: bytes): bytes[] { return abi.decode(b, bytes[]); }
  @external @pure d_ss(b: bytes): string[] { return abi.decode(b, string[]); }
  @external @pure d_vv(b: bytes): u256[] { return abi.decode(b, u256[]); } }`;

const S = `struct P { uint a; uint b; }
contract C {
  function d_mm(bytes calldata b) external pure returns (uint[][] memory) { return abi.decode(b,(uint[][])); }
  function d_ps(bytes calldata b) external pure returns (P[] memory) { return abi.decode(b,(P[])); }
  function d_bs(bytes calldata b) external pure returns (bytes[] memory) { return abi.decode(b,(bytes[])); }
  function d_ss(bytes calldata b) external pure returns (string[] memory) { return abi.decode(b,(string[])); }
  function d_vv(bytes calldata b) external pure returns (uint[] memory) { return abi.decode(b,(uint[])); }
  function e_mm() external pure returns (bytes memory){ uint[][] memory m=new uint[][](2); m[0]=new uint[](2);m[0][0]=1;m[0][1]=2; m[1]=new uint[](1);m[1][0]=3; return abi.encode(m); }
  function e_ps() external pure returns (bytes memory){ P[] memory p=new P[](2); p[0]=P(1,2);p[1]=P(3,4); return abi.encode(p); }
  function e_bs() external pure returns (bytes memory){ bytes[] memory x=new bytes[](2); x[0]=hex"aabb"; x[1]=hex"ccddee"; return abi.encode(x); }
  function e_ss() external pure returns (bytes memory){ string[] memory x=new string[](2); x[0]="hi"; x[1]="world!"; return abi.encode(x); }
  function e_vv() external pure returns (bytes memory){ uint[] memory x=new uint[](3); x[0]=7;x[1]=8;x[2]=9; return abi.encode(x); } }`;

describe('Residual C (R1): direct return abi.decode(b, T) for an array target', () => {
  it('byte-identical to solc 0.8.35 (u256[][], P[], bytes[], string[], u256[])', async () => {
    const h = await Harness.create();
    await h.fund(me, 10n ** 20n);
    const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
    const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
    const innerBlob = async (encSig: string) => {
      const r = await h.call(sa, sel(encSig));
      const hx = r.returnHex.slice(2);
      const len = parseInt(hx.slice(64, 128), 16);
      return '0x' + hx.slice(128, 128 + len * 2);
    };
    for (const [dec, enc] of [
      ['d_mm(bytes)', 'e_mm()'],
      ['d_ps(bytes)', 'e_ps()'],
      ['d_bs(bytes)', 'e_bs()'],
      ['d_ss(bytes)', 'e_ss()'],
      ['d_vv(bytes)', 'e_vv()'],
    ]) {
      const cd = sel(dec) + wrapBytes(await innerBlob(enc)).slice(2);
      const jr = await h.call(ja, cd);
      const sr = await h.call(sa, cd);
      expect(jr.returnHex, dec).toBe(sr.returnHex);
      expect(jr.success, dec).toBe(sr.success);
    }
  });
});
