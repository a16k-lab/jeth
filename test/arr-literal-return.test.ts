// Regression: a STATIC fixed-array LITERAL return (return [..] typed Arr<T,N>) must ABI-encode as
// the N bare inline words, NOT a dynamic offset+length wrapper. (A dynamic u256[] return keeps the
// wrapper.) Surfaced by the F4 audit; fixed in src/yul.ts return lowering. Differential vs solc.
import { describe, it, expect, beforeAll } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, encodeCall } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const sel = (s: string) => functionSelector(s);

const J = `@struct class P { x: u256; y: u256; }
@contract class C {
  @external @pure lit3(a: u256): Arr<u256,3> { return [a, a + 1n, a + 2n]; }
  @external @pure signed2(a: i128): Arr<i128,2> { return [a, -a]; }
  @external @pure nested(a: u256): Arr<Arr<u256,2>,2> { return [[a, a + 1n], [a + 2n, a + 3n]]; }
  @external @pure structs(a: u256): Arr<P,2> { return [P(a, a + 1n), P(a + 2n, a + 3n)]; }
  @external @pure bytesN2(a: bytes32): Arr<bytes32,2> { return [a, a]; }
  @external @pure dynLit(a: u256): u256[] { return [a, a + 1n]; }
  @external @pure echo(a: Arr<u256,3>): Arr<u256,3> { return a; }
}`;
const S = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;
contract C {
  struct P { uint256 x; uint256 y; }
  function lit3(uint256 a) external pure returns (uint256[3] memory) { return [a, a + 1, a + 2]; }
  function signed2(int128 a) external pure returns (int128[2] memory) { return [a, -a]; }
  function nested(uint256 a) external pure returns (uint256[2][2] memory) { return [[a, a + 1], [a + 2, a + 3]]; }
  function structs(uint256 a) external pure returns (P[2] memory) { return [P(a, a + 1), P(a + 2, a + 3)]; }
  function bytesN2(bytes32 a) external pure returns (bytes32[2] memory) { return [a, a]; }
  function dynLit(uint256 a) external pure returns (uint256[] memory) { uint256[] memory r = new uint256[](2); r[0] = a; r[1] = a + 1; return r; }
  function echo(uint256[3] calldata a) external pure returns (uint256[3] memory) { return a; }
}`;

describe('static fixed-array literal return vs solc', () => {
  let h: Harness, hs: Harness, jv: Address, sv: Address;
  async function eq(label: string, data: string) {
    const j = await h.call(jv, data);
    const s = await hs.call(sv, data);
    expect(j.success, `${label} jeth=${j.exceptionError}`).toBe(s.success);
    expect(j.returnHex, `${label} returndata`).toBe(s.returnHex);
  }
  beforeAll(async () => {
    h = await Harness.create();
    hs = await Harness.create();
    jv = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
    sv = await hs.deploy(compileSolidity(S, 'C').creation);
  });
  it('value / signed / nested / struct-element / bytesN literals encode as bare words', async () => {
    await eq('lit3', encodeCall(sel('lit3(uint256)'), [5n]));
    await eq('signed2', encodeCall(sel('signed2(int128)'), [7n]));
    await eq('nested', encodeCall(sel('nested(uint256)'), [10n]));
    await eq('structs', encodeCall(sel('structs(uint256)'), [20n]));
    await eq('bytesN2', encodeCall(sel('bytesN2(bytes32)'), [0x1234n]));
    // a static uint256[3] return is exactly 96 bytes (no offset/length wrapper)
    const r = await h.call(jv, encodeCall(sel('lit3(uint256)'), [5n]));
    expect((r.returnHex.length - 2) / 2).toBe(96);
  });
  it('a dynamic u256[] literal return KEEPS the offset+length wrapper (unchanged)', async () => {
    await eq('dynLit', encodeCall(sel('dynLit(uint256)'), [3n]));
    const r = await h.call(jv, encodeCall(sel('dynLit(uint256)'), [3n]));
    expect((r.returnHex.length - 2) / 2).toBe(128); // offset + length + 2 words
  });
  it('echoing a calldata Arr<u256,3> param still matches (static, unchanged)', async () => {
    const data =
      '0x' +
      sel('echo(uint256[3])') +
      5n.toString(16).padStart(64, '0') +
      6n.toString(16).padStart(64, '0') +
      7n.toString(16).padStart(64, '0');
    await eq('echo', data);
  });
});
