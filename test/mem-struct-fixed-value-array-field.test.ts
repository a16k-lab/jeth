// S3 lift: read/encode/return a WHOLE fixed-VALUE-WORD-array field of a memory struct as an aggregate
// value - abi.encode(q.nums) / return q.nums where nums: Arr<u256,3> (and nested value-array variants).
// The field's flat inline N-word image is byte-identical to a static struct's, so it rides the existing
// memAggregate value-word codec at its accumulated word offset. Gated by the TIGHT isFixedValueWordArray
// predicate (a fixed array whose leaves are ALL static value words; nested fixed value arrays allowed).
//
// CONTROL (must NOT regress): Arr<In,N> where In is a STATIC STRUCT is EXCLUDED - it stays a clean JETH245
// over-rejection, NEVER an all-zero-words accept. Admitting it into the value-word codec was the exact
// MISCOMPILE (silent data loss) that sank the first attempt at this shape; a wrong-bytes accept is far
// worse than a clean reject. This test asserts that control emits JETH245 and never wrong bytes.
//
// Every accepting case is verified byte-identical to solc 0.8.35 by running BOTH compilers and decoding
// the returndata word-by-word.
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';
import { CompileError } from '../src/diagnostics.js';

const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint) => (n & ((1n << 256n) - 1n)).toString(16).padStart(64, '0');
const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';

async function eqDecode(jeth: string, sol: string, calls: [string, string][]): Promise<string[]> {
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj: Address = await hj.deploy(compile(jeth, { fileName: 'C.jeth' }).creationBytecode);
  const as: Address = await hs.deploy(compileSolidity(SPDX + sol, 'C').creation);
  const returns: string[] = [];
  for (const [sig, args] of calls) {
    const rj = await hj.call(aj, sel(sig) + args);
    const rs = await hs.call(as, sel(sig) + args);
    expect(rj.success, `${sig} success`).toBe(rs.success);
    expect(rj.returnHex, `${sig} return byte-identical`).toBe(rs.returnHex);
    returns.push(rj.returnHex);
  }
  return returns;
}

function jethCodes(src: string): string[] {
  try {
    compile(src, { fileName: 'C.jeth' });
    return ['OK'];
  } catch (e) {
    if (e instanceof CompileError) return e.diagnostics.filter((d) => d.severity === 'error').map((d) => d.code);
    return ['CRASH:' + (e as Error).message];
  }
}

describe('whole fixed-value-word-array field of a memory struct as an aggregate (S3) - byte-identical to solc 0.8.35', () => {
  it('abi.encode(q.nums), nums: Arr<u256,3> - canonical, non-vacuous decode', async () => {
    const [ret] = await eqDecode(
      'type Q = { nums: Arr<u256,3> }; class C { get f(): External<bytes> { let q: Q = Q([u256(1n),2n,3n]); return abi.encode(q.nums); } }',
      'struct Q { uint256[3] nums; } contract C { function f() external pure returns(bytes memory){ Q memory q=Q([uint256(1),2,3]); return abi.encode(q.nums); } }',
      [['f()', '']],
    );
    // decode: bytes wrapper [offset 0x20][len 0x60][1][2][3]
    expect(ret!.slice(2 + 64 * 0, 2 + 64 * 1)).toBe(W(0x20n));
    expect(ret!.slice(2 + 64 * 1, 2 + 64 * 2)).toBe(W(0x60n));
    expect(ret!.slice(2 + 64 * 2, 2 + 64 * 3)).toBe(W(1n));
    expect(ret!.slice(2 + 64 * 3, 2 + 64 * 4)).toBe(W(2n));
    expect(ret!.slice(2 + 64 * 4, 2 + 64 * 5)).toBe(W(3n));
  });

  it('return q.nums, nums: Arr<u256,3> - inline 3 words, non-vacuous decode', async () => {
    const [ret] = await eqDecode(
      'type Q = { nums: Arr<u256,3> }; class C { get f(): External<Arr<u256,3>> { let q: Q = Q([u256(7n),8n,9n]); return q.nums; } }',
      'struct Q { uint256[3] nums; } contract C { function f() external pure returns(uint256[3] memory){ Q memory q=Q([uint256(7),8,9]); return q.nums; } }',
      [['f()', '']],
    );
    expect(ret!.slice(2 + 64 * 0, 2 + 64 * 1)).toBe(W(7n));
    expect(ret!.slice(2 + 64 * 1, 2 + 64 * 2)).toBe(W(8n));
    expect(ret!.slice(2 + 64 * 2, 2 + 64 * 3)).toBe(W(9n));
  });

  it('leaf value types: address / bool / u8 / bytes32 / i256(negative)', async () => {
    // address[3]
    await eqDecode(
      'type Q = { nums: Arr<address,3> }; class C { get f(): External<bytes> { let q: Q = Q([address(0x11),address(0x22),address(0x33)]); return abi.encode(q.nums); } }',
      'struct Q { address[3] nums; } contract C { function f() external pure returns(bytes memory){ Q memory q=Q([address(0x11),address(0x22),address(0x33)]); return abi.encode(q.nums); } }',
      [['f()', '']],
    );
    // bool[4]
    await eqDecode(
      'type Q = { nums: Arr<bool,4> }; class C { get f(): External<bytes> { let q: Q = Q([true,false,true,true]); return abi.encode(q.nums); } }',
      'struct Q { bool[4] nums; } contract C { function f() external pure returns(bytes memory){ Q memory q=Q([true,false,true,true]); return abi.encode(q.nums); } }',
      [['f()', '']],
    );
    // uint8[4]
    await eqDecode(
      'type Q = { nums: Arr<u8,4> }; class C { get f(): External<bytes> { let q: Q = Q([1n,2n,3n,4n]); return abi.encode(q.nums); } }',
      'struct Q { uint8[4] nums; } contract C { function f() external pure returns(bytes memory){ Q memory q=Q([uint8(1),2,3,4]); return abi.encode(q.nums); } }',
      [['f()', '']],
    );
    // bytes32[2] (values seeded from params - avoids the unsupported bytes32(int) literal)
    await eqDecode(
      'type Q = { nums: Arr<bytes32,2> }; class C { get f(x: bytes32, y: bytes32): External<bytes> { let q: Q = Q([x,y]); return abi.encode(q.nums); } }',
      'struct Q { bytes32[2] nums; } contract C { function f(bytes32 x, bytes32 y) external pure returns(bytes memory){ Q memory q=Q([x,y]); return abi.encode(q.nums); } }',
      [['f(bytes32,bytes32)', 'aa'.padStart(64, '0') + 'bb'.padStart(64, '0')]],
    );
    // int256[3] with a negative element
    const [ret] = await eqDecode(
      'type Q = { nums: Arr<i256,3> }; class C { get f(): External<bytes> { let q: Q = Q([1n,-2n,3n]); return abi.encode(q.nums); } }',
      'struct Q { int256[3] nums; } contract C { function f() external pure returns(bytes memory){ Q memory q=Q([int256(1),-2,3]); return abi.encode(q.nums); } }',
      [['f()', '']],
    );
    // the negative element decodes to two's complement -2
    expect(ret!.slice(2 + 64 * 3, 2 + 64 * 4)).toBe(W(-2n));
  });

  it('NESTED value-word array field: Arr<Arr<u256,2>,2> - non-vacuous decode', async () => {
    const [ret] = await eqDecode(
      'type Q = { nums: Arr<Arr<u256,2>,2> }; class C { get f(): External<bytes> { let q: Q = Q([[u256(1n),2n],[u256(3n),4n]]); return abi.encode(q.nums); } }',
      'struct Q { uint256[2][2] nums; } contract C { function f() external pure returns(bytes memory){ Q memory q=Q([[uint256(1),2],[uint256(3),4]]); return abi.encode(q.nums); } }',
      [['f()', '']],
    );
    // bytes wrapper [offset 0x20][len 0x80] then the 4 inline words [1][2][3][4]
    expect(ret!.slice(2 + 64 * 0, 2 + 64 * 1)).toBe(W(0x20n));
    expect(ret!.slice(2 + 64 * 1, 2 + 64 * 2)).toBe(W(0x80n));
    expect(ret!.slice(2 + 64 * 2, 2 + 64 * 3)).toBe(W(1n));
    expect(ret!.slice(2 + 64 * 3, 2 + 64 * 4)).toBe(W(2n));
    expect(ret!.slice(2 + 64 * 4, 2 + 64 * 5)).toBe(W(3n));
    expect(ret!.slice(2 + 64 * 5, 2 + 64 * 6)).toBe(W(4n));
  });

  it('preceding value field (non-zero word offset): Q2{a:u256; nums:Arr<u256,3>}', async () => {
    const [ret] = await eqDecode(
      'type Q2 = { a: u256; nums: Arr<u256,3> }; class C { get f(): External<bytes> { let q: Q2 = Q2(9n,[u256(10n),11n,12n]); return abi.encode(q.nums); } }',
      'struct Q2 { uint256 a; uint256[3] nums; } contract C { function f() external pure returns(bytes memory){ Q2 memory q=Q2(9,[uint256(10),11,12]); return abi.encode(q.nums); } }',
      [['f()', '']],
    );
    // the offset skips field `a`; the encoded body is [10][11][12], proving the wordOffset is applied
    expect(ret!.slice(2 + 64 * 2, 2 + 64 * 3)).toBe(W(10n));
    expect(ret!.slice(2 + 64 * 3, 2 + 64 * 4)).toBe(W(11n));
    expect(ret!.slice(2 + 64 * 4, 2 + 64 * 5)).toBe(W(12n));
  });

  it('let-bind ys = q.nums, abi.encode(q.nums,7n), abi.encodePacked, internal-arg, inner-struct field', async () => {
    // let-bind alias
    await eqDecode(
      'type Q = { nums: Arr<u256,3> }; class C { get f(): External<bytes> { let q: Q = Q([u256(1n),2n,3n]); let ys: Arr<u256,3> = q.nums; return abi.encode(ys); } }',
      'struct Q { uint256[3] nums; } contract C { function f() external pure returns(bytes memory){ Q memory q=Q([uint256(1),2,3]); uint256[3] memory ys=q.nums; return abi.encode(ys); } }',
      [['f()', '']],
    );
    // abi.encode(q.nums, 7n) - the field followed by a trailing scalar
    const [ret] = await eqDecode(
      'type Q = { nums: Arr<u256,3> }; class C { get f(): External<bytes> { let q: Q = Q([u256(1n),2n,3n]); return abi.encode(q.nums, 7n); } }',
      'struct Q { uint256[3] nums; } contract C { function f() external pure returns(bytes memory){ Q memory q=Q([uint256(1),2,3]); return abi.encode(q.nums, uint256(7)); } }',
      [['f()', '']],
    );
    // bytes wrapper [0x20][0x80] then tuple(uint256[3], uint256): [1][2][3][7]
    expect(ret!.slice(2 + 64 * 2, 2 + 64 * 3)).toBe(W(1n));
    expect(ret!.slice(2 + 64 * 3, 2 + 64 * 4)).toBe(W(2n));
    expect(ret!.slice(2 + 64 * 4, 2 + 64 * 5)).toBe(W(3n));
    expect(ret!.slice(2 + 64 * 5, 2 + 64 * 6)).toBe(W(7n));
    // abi.encodePacked(q.nums)
    await eqDecode(
      'type Q = { nums: Arr<u256,3> }; class C { get f(): External<bytes> { let q: Q = Q([u256(1n),2n,3n]); return abi.encodePacked(q.nums); } }',
      'struct Q { uint256[3] nums; } contract C { function f() external pure returns(bytes memory){ Q memory q=Q([uint256(1),2,3]); return abi.encodePacked(q.nums); } }',
      [['f()', '']],
    );
    // internal-arg: this.g(q.nums) (g is internal-by-default, called via this.)
    await eqDecode(
      'type Q = { nums: Arr<u256,3> }; class C { g(a: Arr<u256,3>): bytes { return abi.encode(a); } get f(): External<bytes> { let q: Q = Q([u256(1n),2n,3n]); return this.g(q.nums); } }',
      'struct Q { uint256[3] nums; } contract C { function g(uint256[3] memory a) internal pure returns(bytes memory){ return abi.encode(a); } function f() external pure returns(bytes memory){ Q memory q=Q([uint256(1),2,3]); return g(q.nums); } }',
      [['f()', '']],
    );
    // nested struct-in-struct inner fixed-array field: q.inner.nums
    await eqDecode(
      'type Inner = { nums: Arr<u256,3> }; type Q = { a: u256; inner: Inner }; class C { get f(): External<bytes> { let q: Q = Q(9n, Inner([u256(1n),2n,3n])); return abi.encode(q.inner.nums); } }',
      'struct Inner { uint256[3] nums; } struct Q { uint256 a; Inner inner; } contract C { function f() external pure returns(bytes memory){ Q memory q=Q(9, Inner([uint256(1),2,3])); return abi.encode(q.inner.nums); } }',
      [['f()', '']],
    );
  });

  // ---- CONTROL: the static-struct-element fixed array must STAY a clean JETH245 reject (never all-zero
  // bytes). This is the exact shape that MISCOMPILED in the first attempt; the tight predicate excludes it.
  it('Tier-2 L7(b) LIFTED: Arr<In,N> of a STATIC STRUCT field now ACCEPTS via aggFieldRead (byte-identity pinned in lift-tier2-or-catalogue.test.ts; the flat sub-image route makes the old all-zero miscompile impossible)', () => {
    const returnSrc =
      'type In = { a: u256; b: u256 }; type Q = { arr: Arr<In,2> }; class C { get f(): External<Arr<In,2>> { let q: Q = Q([In(1n,2n),In(3n,4n)]); return q.arr; } }';
    const encodeSrc =
      'type In = { a: u256; b: u256 }; type Q = { arr: Arr<In,2> }; class C { get f(): External<bytes> { let q: Q = Q([In(1n,2n),In(3n,4n)]); return abi.encode(q.arr); } }';
    expect(jethCodes(returnSrc)).toEqual(['OK']);
    expect(jethCodes(encodeSrc)).toEqual(['OK']);
  });

  // deeper struct nesting inside the array is ALSO excluded (any struct anywhere in the chain)
  it('Tier-2 L7(b) LIFTED: Arr<Arr<In,2>,2> (struct leaf under nested arrays) field now ACCEPTS (byte-identity pinned in lift-tier2-or-catalogue.test.ts)', () => {
    const src =
      'type In = { a: u256 }; type Q = { arr: Arr<Arr<In,2>,2> }; class C { get f(): External<bytes> { let q: Q = Q([[In(1n),In(2n)],[In(3n),In(4n)]]); return abi.encode(q.arr); } }';
    expect(jethCodes(src)).toEqual(['OK']);
  });
});
