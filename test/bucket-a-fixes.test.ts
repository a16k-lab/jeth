// Regression tests for the "what's left" Bucket-A over-rejection fixes (vs solc 0.8.35).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { functionSelector } from '../src/selectors.js';
import { compileSolidity } from './_solidity.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => functionSelector(s);
const W = (n: bigint) => pad32(n);

async function diff(jeth: string, sol: string, calls: { sig: string; args?: string }[]) {
  const jb = compile(jeth, { fileName: 'C.jeth' });
  const sb = compileSolidity(SPDX + sol, 'C');
  const hj = await Harness.create();
  const hs = await Harness.create();
  const aj = await hj.deploy(jb.creationBytecode);
  const as = await hs.deploy(sb.creation);
  for (const c of calls) {
    const data = '0x' + sel(c.sig) + (c.args ?? '');
    const rj = await hj.call(aj, data);
    const rs = await hs.call(as, data);
    expect(rj.success, `${c.sig}: success`).toBe(rs.success);
    expect(rj.returnHex, `${c.sig}: returndata`).toBe(rs.returnHex);
    expect(JSON.stringify(rj.logs), `${c.sig}: logs`).toBe(JSON.stringify(rs.logs));
  }
}

describe('Bucket-A over-rejection fixes vs Solidity', () => {
  it('addmod / mulmod builtins (full precision, m==0 -> Panic 0x12, widened args)', async () => {
    const M = (1n << 256n) - 1n;
    await diff(
      `class C { get am(a: u256, b: u256, m: u256): External<u256> { return addmod(a, b, m); } get mm(a: u256, b: u256, m: u256): External<u256> { return mulmod(a, b, m); } get w(a: u8, b: u16): External<u256> { return addmod(a, b, 5n); } }`,
      `contract C { function am(uint256 a, uint256 b, uint256 m) external pure returns (uint256){ return addmod(a,b,m); } function mm(uint256 a, uint256 b, uint256 m) external pure returns (uint256){ return mulmod(a,b,m); } function w(uint8 a, uint16 b) external pure returns (uint256){ return addmod(a,b,5); } }`,
      [
        { sig: 'am(uint256,uint256,uint256)', args: W(M) + W(M) + W(7n) },
        { sig: 'am(uint256,uint256,uint256)', args: W(10n) + W(20n) + W(0n) },
        { sig: 'mm(uint256,uint256,uint256)', args: W(M) + W(M) + W(13n) },
        { sig: 'mm(uint256,uint256,uint256)', args: W(10n) + W(20n) + W(0n) },
        { sig: 'w(uint8,uint16)', args: W(200n) + W(300n) },
      ],
    );
  });

  it('abi.encode / encodePacked of a string literal arg', async () => {
    await diff(
      `class C { get p(): External<bytes32> { return keccak256(abi.encodePacked("DOMAIN")); } get e(x: u256): External<bytes> { return abi.encode("hi", x); } }`,
      `contract C { function p() external pure returns (bytes32){ return keccak256(abi.encodePacked("DOMAIN")); } function e(uint256 x) external pure returns (bytes memory){ return abi.encode("hi", x); } }`,
      [{ sig: 'p()' }, { sig: 'e(uint256)', args: W(9n) }],
    );
  });

  it('binary-op with a literal operand exceeding the operand type (common-type widening + overflow)', async () => {
    await diff(
      `class C {
        get add(a: u8): External<u16> { return a + 1000n; }
        get mul(a: u8): External<u16> { return a * 1000n; }
        get mul32(a: u8): External<u32> { return a * 1000n; }
        get left(a: u8): External<u16> { return 1000n + a; }
        get bor(a: u8): External<u16> { return a | 0x1ffn; }
        get fits(a: u8): External<u8> { return a + 100n; }
        get wide(a: u16): External<u32> { return a + 70000n; }
        get neg(a: i8): External<i16> { return a + -1000n; }
        get unc(a: u8): External<u16> { unchecked: { return a * 1000n; } }
      }`,
      `contract C {
        function add(uint8 a) external pure returns (uint16){ return a + 1000; }
        function mul(uint8 a) external pure returns (uint16){ return a * 1000; }
        function mul32(uint8 a) external pure returns (uint32){ return a * 1000; }
        function left(uint8 a) external pure returns (uint16){ return 1000 + a; }
        function bor(uint8 a) external pure returns (uint16){ return a | 0x1ff; }
        function fits(uint8 a) external pure returns (uint8){ return a + 100; }
        function wide(uint16 a) external pure returns (uint32){ return a + 70000; }
        function neg(int8 a) external pure returns (int16){ return a + -1000; }
        function unc(uint8 a) external pure returns (uint16){ unchecked { return a * 1000; } }
      }`,
      [
        { sig: 'add(uint8)', args: W(255n) }, // 1255, no overflow at u16
        { sig: 'mul(uint8)', args: W(1n) }, // 1000
        { sig: 'mul(uint8)', args: W(255n) }, // 255000 -> Panic at u16
        { sig: 'mul32(uint8)', args: W(255n) }, // overflow still at the common type u16 -> Panic
        { sig: 'mul32(uint8)', args: W(60n) }, // 60000, ok
        { sig: 'left(uint8)', args: W(200n) },
        { sig: 'bor(uint8)', args: W(0x80n) },
        { sig: 'fits(uint8)', args: W(200n) }, // 300 -> Panic at u8 (literal fits u8, stays u8)
        { sig: 'wide(uint16)', args: W(5n) },
        { sig: 'neg(int8)', args: W((1n << 256n) - 5n) },
        { sig: 'unc(uint8)', args: W(255n) }, // wraps at u16
      ],
    );
  });

  it('indexed static-aggregate event params from a local / constructor', async () => {
    await diff(
      `type P = { x: u256; y: u256; }; class C { A: event<{ a: indexed<Arr<u256,3>>; n: u256 }>; S: event<{ p: indexed<P>; n: u256 }>; fa(): External<void> { let a: Arr<u256,3> = [u256(10n), 20n, 30n]; emit(A(a, 7n)); } fs(x: u256, y: u256): External<void> { emit(S(P(x, y), 7n)); } }`,
      `struct P { uint256 x; uint256 y; } contract C { event A(uint256[3] indexed a, uint256 n); event S(P indexed p, uint256 n); function fa() external { uint256[3] memory a=[uint256(10),20,30]; emit A(a, 7); } function fs(uint256 x, uint256 y) external { emit S(P(x,y), 7); } }`,
      [{ sig: 'fa()' }, { sig: 'fs(uint256,uint256)', args: W(1n) + W(2n) }],
    );
  });
});
