// Edge F: abi.encode(s) / return s / getters for a CALLDATA dyn-struct param whose struct has a
// LEAF-array field (bytes[]/string[]/T[][]). The calldata struct is materialized into a fresh
// pointer-headed memory image (buildDynStructFromCalldata + the new abiDecFromCdToImage) then encoded
// from the proven mem source. Byte-identical to solc 0.8.35 for all honest + realistic-malformed input;
// malformed calldata EMPTY-reverts like solc's calldata tuple-member decode. (A pathological calldata
// tuple-member offset with bit 255 set that WRAPS in-bounds is a pre-existing safer-than-solc deviation
// shared with the value-array path: JETH reverts, solc decodes garbage - not exercised here.)
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint) => pad32(n);

async function diff(J: string, S: string, calls: [string, string][]) {
  const h = await Harness.create();
  const aj = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode);
  const as = await h.deploy(compileSolidity(SPDX + S, 'C').creation);
  for (const [sig, args] of calls) {
    const data = sel(sig) + args;
    const rj = await h.call(aj, data);
    const rs = await h.call(as, data);
    expect(rj.success, sig + ' ' + args.slice(0, 16)).toBe(rs.success);
    expect(rj.returnHex, sig + ' ' + args.slice(0, 16)).toBe(rs.returnHex);
  }
}

describe('Edge F: abi.encode/return of a calldata dyn-struct with a leaf-array field vs solc 0.8.35', () => {
  it('S{a; tags:bytes[]} well-formed encode/getter + malformed reverts (empty)', async () => {
    const J = `@struct class S { a: u256; tags: bytes[]; }
    @contract class C { @external @pure f(s: S): bytes { return abi.encode(s); } @external @pure g(s: S): u256 { return s.a + s.tags.length + s.tags[1n].length; } }`;
    const Sl = `struct S { uint256 a; bytes[] tags; }
    contract C { function f(S calldata s) external pure returns(bytes memory){ return abi.encode(s); } function g(S calldata s) external pure returns(uint256){ return s.a + s.tags.length + s.tags[1].length; } }`;
    const tags = W(2n) + W(0x40n) + W(0x80n) + W(2n) + '6161'.padEnd(64, '0') + W(4n) + '62626262'.padEnd(64, '0');
    const wf = W(0x20n) + W(7n) + W(0x40n) + tags;
    const big = W(0x20n) + W(7n) + W(0x40n) + W(0x10000000000000000n) + tags.slice(64);
    const elemBig = W(0x20n) + W(7n) + W(0x40n) + W(2n) + W(0x40n) + W(0x80n) + W(0x10000000000000000n) + '6161'.padEnd(64, '0') + W(4n) + '62626262'.padEnd(64, '0');
    const trunc = wf.slice(0, wf.length - 64);
    await diff(J, Sl, [
      ['f((uint256,bytes[]))', wf],
      ['g((uint256,bytes[]))', wf],
      ['f((uint256,bytes[]))', big], // oversized array len -> empty revert
      ['f((uint256,bytes[]))', elemBig], // oversized element len -> empty revert
      ['f((uint256,bytes[]))', trunc], // truncated tail -> empty revert
    ]);
  });

  it('S{a; xs:string[]} and S{a; grid:u256[][]} well-formed encode (leaf-array variants)', async () => {
    const Js = `@struct class S { a: u256; xs: string[]; }
    @contract class C { @external @pure f(s: S): bytes { return abi.encode(s); } }`;
    const Ss = `struct S { uint256 a; string[] xs; }
    contract C { function f(S calldata s) external pure returns(bytes memory){ return abi.encode(s); } }`;
    const sxs = W(2n) + W(0x40n) + W(0x80n) + W(2n) + '6869'.padEnd(64, '0') + W(2n) + '796f'.padEnd(64, '0');
    await diff(Js, Ss, [['f((uint256,string[]))', W(0x20n) + W(5n) + W(0x40n) + sxs]]);

    const Jg = `@struct class S { a: u256; grid: u256[][]; }
    @contract class C { @external @pure f(s: S): bytes { return abi.encode(s); } @external @pure g(s: S): u256 { return s.grid[0n][1n] + s.grid[1n][0n]; } }`;
    const Sg = `struct S { uint256 a; uint256[][] grid; }
    contract C { function f(S calldata s) external pure returns(bytes memory){ return abi.encode(s); } function g(S calldata s) external pure returns(uint256){ return s.grid[0][1] + s.grid[1][0]; } }`;
    const grid = W(2n) + W(0x40n) + W(0xc0n) + W(2n) + W(1n) + W(2n) + W(1n) + W(3n);
    await diff(Jg, Sg, [['f((uint256,uint256[][]))', W(0x20n) + W(9n) + W(0x40n) + grid], ['g((uint256,uint256[][]))', W(0x20n) + W(9n) + W(0x40n) + grid]]);
  });

  it('regression: value-array field + bytes field calldata structs unchanged', async () => {
    await diff(
      `@struct class S { a: u256; xs: u256[]; } @contract class C { @external @pure f(s: S): bytes { return abi.encode(s); } }`,
      `struct S { uint256 a; uint256[] xs; } contract C { function f(S calldata s) external pure returns(bytes memory){ return abi.encode(s); } }`,
      [['f((uint256,uint256[]))', W(0x20n) + W(9n) + W(0x40n) + W(3n) + W(5n) + W(6n) + W(7n)]],
    );
    await diff(
      `@struct class S { a: u256; s: bytes; } @contract class C { @external @pure f(s: S): bytes { return abi.encode(s); } }`,
      `struct S { uint256 a; bytes s; } contract C { function f(S calldata s) external pure returns(bytes memory){ return abi.encode(s); } }`,
      [['f((uint256,bytes))', W(0x20n) + W(9n) + W(0x40n) + W(2n) + '6161'.padEnd(64, '0')]],
    );
  });
});
