// MC-ARRLIT-STOR-SCRATCH (pre-existing silent MISCOMPILE, found by the OR-cluster verification
// sweep): a static array/struct literal encoded to the ABI return/head buffer (built at absolute
// memory offsets from 0x00) whose elements read a KECCAK-addressed storage location (a dynamic
// array `this.A[i]` or a mapping `this.m[k]`) zeroed an earlier slot. The keccak scratch write
// (mstore(0x00, slot)) overlaps the buffer, so an interleaved write-then-lower let a later
// element's scratch clobber an earlier written word: `return [this.A[0], this.A[1]]` returned
// [0, 6] instead of [5, 6]; `return P(this.A[1], this.A[0])` was corrupted likewise.
//
// Fix: encodeArrayLitHead and encodeStructReturn now HOIST every element/field value to a temp
// FIRST (all element lowering + keccak scratch runs), THEN flush the buffer mstores - no scratch
// write happens between two buffer writes. Left-to-right evaluation order is preserved.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const sel = (s: string) => '0x' + functionSelector(s);
const run = async (J: string, S: string, calls: ReadonlyArray<readonly [string, string]>) => {
  const h = await Harness.create();
  await h.fund(me, 10n ** 20n);
  const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
  const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
  for (const [sg, args] of calls) {
    const jr = await h.call(ja, sel(sg) + args);
    const sr = await h.call(sa, sel(sg) + args);
    expect(jr.returnHex, `${sg}`).toBe(sr.returnHex);
    expect(jr.success, sg).toBe(sr.success);
  }
};

describe('MC-ARRLIT-STOR-SCRATCH: static array/struct literal from keccak-storage reads (byte-identical)', () => {
  it('array literal returns/encodes from dynamic-array and mapping reads', async () => {
    await run(
      `class C { A: u256[]; seed(): External<void> { this.A.push(5n); this.A.push(6n); this.A.push(7n); this.A.push(8n); }
        get r2(): External<Arr<u256,2>> { return [this.A[0n], this.A[1n]]; }
        get rLitFirst(): External<Arr<u256,2>> { return [99n, this.A[1n]]; }
        get r4(): External<Arr<u256,4>> { return [this.A[0n], this.A[1n], this.A[2n], this.A[3n]]; }
        get enc(): External<bytes> { return abi.encode([this.A[0n], this.A[1n]]); } }`,
      `contract C { uint256[] A; function seed() public { A.push(5); A.push(6); A.push(7); A.push(8); }
        function r2() external view returns (uint256[2] memory) { return [A[0], A[1]]; }
        function rLitFirst() external view returns (uint256[2] memory) { return [uint256(99), A[1]]; }
        function r4() external view returns (uint256[4] memory) { return [A[0], A[1], A[2], A[3]]; }
        function enc() external view returns (bytes memory) { return abi.encode([A[0], A[1]]); } }`,
      [['seed()', ''], ['r2()', ''], ['rLitFirst()', ''], ['r4()', ''], ['enc()', '']] as const,
    );
    await run(
      `class C { m: mapping<u256,u256>; seed(): External<void> { this.m[0n]=5n; this.m[1n]=6n; }
        get g(): External<Arr<u256,2>> { return [this.m[0n], this.m[1n]]; } }`,
      `contract C { mapping(uint256=>uint256) m; function seed() public { m[0]=5; m[1]=6; }
        function g() external view returns (uint256[2] memory) { return [m[0], m[1]]; } }`,
      [['seed()', ''], ['g()', '']] as const,
    );
  });

  it('struct literal returns from keccak-storage reads (both field orders)', async () => {
    await run(
      `type P = { a: u256; b: u256 };
class C { A: u256[]; seed(): External<void> { this.A.push(5n); this.A.push(6n); }
        get swapped(): External<P> { return P(this.A[1n], this.A[0n]); }
        get same(): External<P> { return P(this.A[0n], this.A[1n]); } }`,
      `contract C { struct P { uint256 a; uint256 b; } uint256[] A; function seed() public { A.push(5); A.push(6); }
        function swapped() external view returns (P memory) { return P(A[1], A[0]); }
        function same() external view returns (P memory) { return P(A[0], A[1]); } }`,
      [['seed()', ''], ['swapped()', ''], ['same()', '']] as const,
    );
    // array of structs from mapping reads (each element is itself a keccak read).
    await run(
      `type In = { x: u256; y: u256 };
class C { m: mapping<u256,In>; seed(): External<void> { this.m[0n]=In(5n,6n); this.m[1n]=In(7n,8n); }
        get g(): External<Arr<In,2>> { return [this.m[0n], this.m[1n]]; } }`,
      `contract C { struct In { uint256 x; uint256 y; } mapping(uint256=>In) m; function seed() public { m[0]=In(5,6); m[1]=In(7,8); }
        function g() external view returns (In[2] memory) { return [m[0], m[1]]; } }`,
      [['seed()', ''], ['g()', '']] as const,
    );
  });
});
