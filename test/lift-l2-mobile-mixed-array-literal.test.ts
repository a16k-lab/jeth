// L2-MOBILE lift: an array literal MIXING a cast/typed element with BARE int literals self-types to
// solc's common type with NO outer expected type ([u8(1n), 300n] -> uint16[2], [u256(1n), 2n] ->
// uint256[2]), exactly like solc's inline-array typing: SEED with element 0's MOBILE type (the
// smallest uintN/intN, N a multiple of 8, holding the value), then fold Type::commonType over the
// rest. Every accept row is run and asserted byte-identical to solc 0.8.35 on returndata.
//
// The seed-then-fold is ORDER-SENSITIVE and that asymmetry is REAL (probed at 0.8.35, not guessed):
// [-1, 1] -> int8[2] ACCEPTS but [1, -1] REJECTS. Width is invisible to abi.encode/encodePacked
// (both pad every ARRAY element to a full 32-byte word - encodePacked([uint8(1),uint8(2)]) is 64
// bytes, not 2; only bare SCALAR encodePacked args pack tight), but it is NOT invisible to the type
// system: solc types each ternary branch on its own, so `c ? [1,2] : [300,4]` (uint8[2] vs uint16[2])
// REJECTS - pinned below, and the reason this fold carries solc's EXACT width instead of widening
// to u256 (widening over-accepted that ternary before this lift).
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
    expect(rj.success, sg + ' ' + args).toBe(rs.success);
    expect(rj.returnHex, sg + ' ' + args).toBe(rs.returnHex);
  }
}

const rejects = (src: string): boolean => {
  try {
    compile(src, { fileName: 'C.jeth' });
    return false;
  } catch {
    return true;
  }
};
const solRejects = (src: string): boolean => {
  try {
    compileSolidity(SPDX + src, 'C');
    return false;
  } catch {
    return true;
  }
};

// [label, jeth elements, solidity elements]
const ACCEPTS: [string, string, string][] = [
  ['u8 + 300 -> uint16[2]', '[u8(1n), 300n]', '[uint8(1), 300]'],
  ['u8 + 255 -> uint8[2] (fits, no widen)', '[u8(1n), 255n]', '[uint8(1), 255]'],
  ['u8 + 256 -> uint16[2]', '[u8(1n), 256n]', '[uint8(1), 256]'],
  ['u256 + 2 -> uint256[2]', '[u256(1n), 2n]', '[uint256(1), 2]'],
  ['i8 + -1 -> int8[2]', '[i8(1n), -1n]', '[int8(1), -1]'],
  ['i8 + 127 -> int8[2]', '[i8(1n), 127n]', '[int8(1), 127]'],
  ['u16 + 70000 -> uint24[2] (not uint32)', '[u16(1n), 70000n]', '[uint16(1), 70000]'],
  ['literal-first: 1 + u8 -> uint8[2]', '[1n, u8(2n)]', '[1, uint8(2)]'],
  ['literal-first: 300 + u8 -> uint16[2]', '[300n, u8(1n)]', '[300, uint8(1)]'],
  ['3-elem u8,300,2 -> uint16[3]', '[u8(1n), 300n, 2n]', '[uint8(1), 300, 2]'],
  ['3-elem u8,2,300 -> uint16[3]', '[u8(1n), 2n, 300n]', '[uint8(1), 2, 300]'],
  ['u8,u16,300 -> uint16[3]', '[u8(1n), u16(2n), 300n]', '[uint8(1), uint16(2), 300]'],
  ['u8 + 2**255 -> uint256[2]', '[u8(1n), 2n**255n]', '[uint8(1), 2**255]'],
  ['i8 + -(2**255) -> int256[2]', '[i8(1n), -(2n**255n)]', '[int8(1), -(2**255)]'],
  ['u24 + 2 -> uint24[2]', '[u24(7n), 2n]', '[uint24(7), 2]'],
  // ALREADY-LIFTED controls (all-bare / all-cast) must not regress
  ['control all-bare [1,2] -> uint8[2]', '[1n, 2n]', '[1, 2]'],
  ['control all-bare [1,300] -> uint16[2]', '[1n, 300n]', '[1, 300]'],
  ['control all-bare [1,70000] -> uint24[2]', '[1n, 70000n]', '[1, 70000]'],
  ['control all-cast [u8,u8] -> uint8[2]', '[u8(1n), u8(2n)]', '[uint8(1), uint8(2)]'],
  // order-sensitivity: the ACCEPTING direction
  ['[-1, 1] -> int8[2] (negative seed)', '[-1n, 1n]', '[-1, 1]'],
];

// solc: "Unable to deduce common type for array elements" - the fold must keep rejecting these
const REJECTS: [string, string, string][] = [
  ['i8 + 200 (200 does not fit int8, no widen to int16)', '[i8(1n), 200n]', '[int8(1), 200]'],
  ['i8 + 128 (just past int8 max)', '[i8(1n), 128n]', '[int8(1), 128]'],
  ['u8 + -1 (negative literal, unsigned cast)', '[u8(1n), -1n]', '[uint8(1), -1]'],
  ['[1, -1] (mixed sign, unsigned seed)', '[1n, -1n]', '[1, -1]'],
  ['[0, -1] (mixed sign, unsigned seed)', '[0n, -1n]', '[0, -1]'],
  ['[127, -1] (mixed sign, unsigned seed)', '[127n, -1n]', '[127, -1]'],
  ['3-elem u8,300,-1 (mixed sign after widen)', '[u8(1n), 300n, -1n]', '[uint8(1), 300, -1]'],
  ['u8 + i16 (cross-family)', '[u8(1n), i16(2n)]', '[uint8(1), int16(2)]'],
  ['u8 + i256 (cross-family, any width)', '[u8(1n), i256(2n)]', '[uint8(1), int256(2)]'],
  ['u8 + bool', '[u8(1n), true]', '[uint8(1), true]'],
  ['bool + 1', '[true, 1n]', '[true, 1]'],
];

describe('L2-MOBILE lift - mixed cast/bare array literals self-type byte-identical to solc 0.8.35', () => {
  for (const [label, je, se] of ACCEPTS) {
    it(`abi.encode ${label}`, async () => {
      await diff(
        `class C { get f(): External<bytes> { return abi.encode(${je}); } }`,
        `contract C { function f() public pure returns (bytes memory) { return abi.encode(${se}); } }`,
        [['f()', '']],
      );
    });
    it(`abi.encodePacked ${label}`, async () => {
      await diff(
        `class C { get f(): External<bytes> { return abi.encodePacked(${je}); } }`,
        `contract C { function f() public pure returns (bytes memory) { return abi.encodePacked(${se}); } }`,
        [['f()', '']],
      );
    });
    it(`keccak256(abi.encodePacked) ${label}`, async () => {
      await diff(
        `class C { get f(): External<bytes32> { return keccak256(abi.encodePacked(${je})); } }`,
        `contract C { function f() public pure returns (bytes32) { return keccak256(abi.encodePacked(${se})); } }`,
        [['f()', '']],
      );
    });
  }

  for (const [label, je, se] of REJECTS) {
    it(`rejects (solc parity) ${label}`, () => {
      const J = `class C { get f(): External<bytes> { return abi.encode(${je}); } }`;
      const S = `contract C { function f() public pure returns (bytes memory) { return abi.encode(${se}); } }`;
      expect(solRejects(S), 'solc must reject ' + label).toBe(true);
      expect(rejects(J), 'JETH must reject ' + label).toBe(true);
    });
  }

  // NON-VACUITY: the encoding really carries both values (1 and 300 = 0x12c), padded to 32-byte
  // words - a vacuous empty/zero return would pass a bare equality check against a broken mirror.
  it('non-vacuous: encode([u8(1n), 300n]) carries 1 and 300 in two padded words', async () => {
    const h = await Harness.create();
    const a = await h.deploy(
      compile('class C { get f(): External<bytes> { return abi.encode([u8(1n), 300n]); } }', { fileName: 'C.jeth' })
        .creationBytecode,
    );
    const r = await h.call(a, sel('f()'));
    const hex = r.returnHex.slice(2);
    const len = parseInt(hex.slice(64, 128), 16);
    expect(len).toBe(64);
    expect(hex.slice(128, 192)).toBe(pad32(1n));
    expect(hex.slice(192, 256)).toBe(pad32(300n));
  });

  // TERNARY: solc types each branch on its OWN, so a branch-type mismatch rejects. Widening the
  // element type to u256 erased this (an over-acceptance before this lift); the exact common type
  // restores the reject. The MATCHING-branch ternary still accepts, byte-identical.
  it('rejects ternary with mismatched branch types (uint8[2] vs uint16[2]) - solc parity', () => {
    const J = 'class C { get f(c: bool): External<bytes> { return abi.encode(c ? [1n, 2n] : [300n, 4n]); } }';
    const S =
      'contract C { function f(bool c) public pure returns (bytes memory) { return abi.encode(c ? [1, 2] : [300, 4]); } }';
    expect(solRejects(S)).toBe(true);
    expect(rejects(J)).toBe(true);
  });

  it('rejects ternary with mismatched branch lengths (uint8[2] vs uint8[3]) - solc parity', () => {
    const J = 'class C { get f(c: bool): External<bytes> { return abi.encode(c ? [1n, 2n] : [3n, 4n, 5n]); } }';
    const S =
      'contract C { function f(bool c) public pure returns (bytes memory) { return abi.encode(c ? [1, 2] : [3, 4, 5]); } }';
    expect(solRejects(S)).toBe(true);
    expect(rejects(J)).toBe(true);
  });

  it('accepts ternary with matching branch types, byte-identical (both branches exercised)', async () => {
    await diff(
      'class C { get f(c: bool): External<bytes> { return abi.encode(c ? [1n, 2n] : [3n, 4n]); } }',
      'contract C { function f(bool c) public pure returns (bytes memory) { return abi.encode(c ? [1, 2] : [3, 4]); } }',
      [
        ['f(bool)', pad32(1n)],
        ['f(bool)', pad32(0n)],
      ],
    );
  });

  // CONSUMERS beyond the encoders: a declared type drives these (the expected-type path), so the
  // self-typing fold must agree with solc's convertibility at the boundary too.
  it('memory local with a declared wider type accepts, byte-identical', async () => {
    await diff(
      'class C { get f(): External<bytes> { const a: Arr<u16,2> = [u8(1n), 300n]; return abi.encode(a); } }',
      'contract C { function f() public pure returns (bytes memory) { uint16[2] memory a = [uint16(1), 300]; return abi.encode(a); } }',
      [['f()', '']],
    );
  });

  it('memory local with a declared NARROW type rejects (300 does not fit uint8) - solc parity', () => {
    const J = 'class C { get f(): External<bytes> { const a: Arr<u8,2> = [u8(1n), 300n]; return abi.encode(a); } }';
    const S =
      'contract C { function f() public pure returns (bytes memory) { uint8[2] memory a = [uint8(1), 300]; return abi.encode(a); } }';
    expect(solRejects(S)).toBe(true);
    expect(rejects(J)).toBe(true);
  });

  it('internal-call argument accepts, byte-identical', async () => {
    await diff(
      'class C { g(a: Arr<u16,2>): u256 { return u256(a[1]); } get f(): External<u256> { return this.g([u8(1n), 300n]); } }',
      'contract C { function g(uint16[2] memory a) internal pure returns (uint256) { return uint256(a[1]); } function f() public pure returns (uint256) { return g([uint16(1), 300]); } }',
      [['f()', '']],
    );
  });

  it('storage write + read-back accepts, byte-identical', async () => {
    await diff(
      'class C { s: Arr<u16,2>; set(): External<void> { this.s = [u8(1n), 300n]; } get g(): External<u256> { return u256(this.s[1]); } }',
      'contract C { uint16[2] s; function set() public { s = [uint16(1), 300]; } function g() public view returns (uint256) { return uint256(s[1]); } }',
      [
        ['set()', ''],
        ['g()', ''],
      ],
    );
  });

  // Deliberate NARROW gate: solc converts ONLY the zero literal to bytesN ([bytes1(hex"01"), 0] ->
  // bytes1[2]). This fold keeps that one-value quirk REJECTING - a safe over-rejection, never a
  // miscompile. Pinned so a future widening of litFitsType has to face this row.
  it('keeps bytesN + literal 0 rejecting (deliberate narrow gate; solc would accept)', () => {
    const J = 'class C { get f(): External<bytes> { return abi.encode([bytes1(0x01), 0n]); } }';
    const S = 'contract C { function f() public pure returns (bytes memory) { return abi.encode([bytes1(hex"01"), 0]); } }';
    expect(solRejects(S), 'solc accepts this (the quirk)').toBe(false);
    expect(rejects(J), 'JETH deliberately rejects it (safe over-rejection)').toBe(true);
  });
});
