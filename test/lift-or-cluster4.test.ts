// OR cluster 4 (literal typing), byte-identical to solc 0.8.35:
//
// A-LIT-RESID: mixed bytesN widths in an array literal (abi.encode([bytes4(..), bytes8(..)])) now
//   unify to the WIDEST bytesN, matching solc's implicit bytesN widening. A bytesN value is
//   left-aligned in its 32-byte word and the pad bytes are zero, so widening is a no-op on the word
//   (unifyLitElemTypes picks the widest; coerce re-types a bytesN literal to a wider bytesN).
//
// L2-MOBILE: an array literal self-types to solc's common type, mirroring solc's inline-array
//   typing: SEED with element 0's MOBILE type (the smallest uintN/intN holding it), then fold
//   Type::commonType over the rest. This covers all-bare literals AND the cast+bare mix
//   ([uint256(1), 2] -> uint256[2], [uint8(1), 300] -> uint16[2]) - the full matrix lives in
//   test/lift-l2-mobile-mixed-array-literal.test.ts. The seed makes MIXED SIGN order-sensitive:
//   [1, -1] rejects but [-1, 1] is int8[2]. Cross-family casts still reject (no common type).
import { describe, it, expect } from 'vitest';
import { Address } from '@ethereumjs/util';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const me = new Address(Buffer.from('11'.repeat(20), 'hex'));
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: bigint | number) => pad32(BigInt(n));
const run = async (J: string, S: string, calls: ReadonlyArray<readonly [string, string]>) => {
  const h = await Harness.create();
  await h.fund(me, 10n ** 20n);
  const ja = await h.deploy(compile(J, { fileName: 'C.jeth' }).creationBytecode, { caller: me });
  const sa = await h.deploy(compileSolidity(SPDX + S, 'C').creation, { caller: me });
  for (const [sg, args] of calls) {
    const jr = await h.call(ja, sel(sg) + args);
    const sr = await h.call(sa, sel(sg) + args);
    expect(jr.returnHex, `${sg} ${args.slice(0, 12)}`).toBe(sr.returnHex);
    expect(jr.success, sg).toBe(sr.success);
  }
};
const rejects = (src: string): boolean => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return false;
  } catch {
    return true;
  }
};

describe('OR cluster 4: literal typing (A-LIT-RESID + L2-MOBILE) byte-identical to solc 0.8.35', () => {
  it('A-LIT-RESID: mixed bytesN widths widen to the widest', async () => {
    await run(
      `class C { get f(): External<bytes> { return abi.encode([bytes4(0x11223344n), bytes8(0x5566778899aabbccn)]); } }`,
      `contract C { function f() external pure returns (bytes memory) { return abi.encode([bytes4(0x11223344), bytes8(0x5566778899aabbcc)]); } }`,
      [['f()', '']] as const,
    );
    await run(
      `class C { get f(): External<bytes> { return abi.encode([bytes2(0x1122n), bytes4(0x33445566n), bytes8(0x778899aabbccddeen)]); } }`,
      `contract C { function f() external pure returns (bytes memory) { return abi.encode([bytes2(0x1122), bytes4(0x33445566), bytes8(0x778899aabbccddee)]); } }`,
      [['f()', '']] as const,
    );
    // the implicit bytesN widening also holds in plain assign/return (solc widens a bytesN constant).
    await run(
      `class C { get f(): External<bytes8> { return bytes4(0x11223344n); } }`,
      `contract C { function f() external pure returns (bytes8) { return bytes4(0x11223344); } }`,
      [['f()', '']] as const,
    );
  });

  it('L2-MOBILE: bare integer-literal arrays self-type to the mobile common type', async () => {
    // non-negative -> u256; the encoding is byte-identical to solc's uint8[2]/uint16[2]/... (32-byte words).
    for (const [j, s] of [
      ['[1n, 2n]', '[uint8(1), 2]'],
      ['[1n, 300n]', '[uint16(1), 300]'],
      ['[255n, 256n]', '[uint16(255), 256]'],
    ] as const) {
      await run(
        `class C { get f(): External<bytes> { return abi.encode(${j}); } }`,
        `contract C { function f() external pure returns (bytes memory) { return abi.encode(${s}); } }`,
        [['f()', '']] as const,
      );
    }
    // all-negative -> i256, byte-identical to solc's int8[2]/int16[2].
    await run(
      `class C { get f(): External<bytes> { return abi.encode([-1n, -2n]); } }`,
      `contract C { function f() external pure returns (bytes memory) { return abi.encode([int8(-1), -2]); } }`,
      [['f()', '']] as const,
    );
    await run(
      `class C { get f(): External<bytes> { return abi.encode([-128n, -129n]); } }`,
      `contract C { function f() external pure returns (bytes memory) { return abi.encode([int16(-128), -129]); } }`,
      [['f()', '']] as const,
    );
    // encodePacked is likewise width-independent for arrays (each element padded to 32 bytes).
    await run(
      `class C { get f(): External<bytes> { return abi.encodePacked([1n, 300n]); } }`,
      `contract C { function f() external pure returns (bytes memory) { return abi.encodePacked([uint16(1), 300]); } }`,
      [['f()', '']] as const,
    );
    // ternary of two bare-literal arrays.
    await run(
      `class C { get f(c: bool): External<bytes> { return abi.encode(c ? [1n, 2n] : [3n, 4n]); } }`,
      `contract C { function f(bool c) external pure returns (bytes memory) { return abi.encode(c ? [uint8(1), 2] : [uint8(3), 4]); } }`,
      [['f(bool)', W(1)], ['f(bool)', W(0)]] as const,
    );
  });

  it('gates that must stay rejects', () => {
    // MIXED SIGN with an UNSIGNED seed: solc seeds the inline-array type with element 0's mobile
    // type (uint8 here) and -1 neither fits uint8 nor takes uint8 into int8 -> "Unable to deduce
    // common type". NOTE the seed makes this ORDER-SENSITIVE: [-1n, 1n] seeds int8 and ACCEPTS
    // (int8[2]) - see test/lift-l2-mobile-mixed-array-literal.test.ts.
    expect(rejects(`class C { get f(): External<bytes> { return abi.encode([1n, -1n]); } }`)).toBe(true);
    expect(rejects(`class C { get f(): External<bytes> { return abi.encode([0n, -1n]); } }`)).toBe(true);
    // CROSS-FAMILY casts (no common type at ANY width, u8|i16 and even u8|i256 - probed).
    expect(rejects(`class C { get f(): External<bytes> { return abi.encode([u8(1n), i16(2n)]); } }`)).toBe(true);
    // an untyped array-literal local (would need width-sensitive inference) still rejects.
    expect(rejects(`class C { get f(): External<u256> { let x = [200n, 100n]; return x[0n] + x[1n]; } }`)).toBe(true);
  });

  // L2-MOBILE lift: a cast + BARE mix DOES have a solc common type - the cast fixes the seed and the
  // bare literal folds into it when it fits ([uint256(1), 2] -> uint256[2], probed at 0.8.35). This
  // row previously asserted a REJECT on the mistaken premise that "a bare literal is mobile, so
  // there is no common type"; it is lifted and byte-identity-verified in
  // test/lift-l2-mobile-mixed-array-literal.test.ts (all consumers).
  it('cast + BARE mix self-types to solc common type, byte-identical', async () => {
    expect(rejects(`class C { get f(): External<bytes> { return abi.encode([u256(1n), 2n]); } }`)).toBe(false);
    await run(
      `class C { get f(): External<bytes> { return abi.encode([u256(1n), 2n]); } }`,
      `contract C { function f() public pure returns (bytes memory) { return abi.encode([uint256(1), 2]); } }`,
      [['f()', '']],
    );
  });
});
