// A-LIT-RESID(enum) lift: a bare array literal of enum elements ([Color.Green, cb]) self-types to the
// enum's fixed array (Color[N]) with NO outer expected type, exactly like solc. An enum is a value word
// (uint8 underlying), so abi.encode / abi.encodePacked pad each element to a full 32-byte word - the
// encoding is width-independent and byte-identical to solc's enum-array encoding. Every row is run and
// asserted byte-identical to solc 0.8.35 on returndata (incl. out-of-range revert parity). Boundary:
// two DIFFERENT enums / enum+int have no solc common type -> both reject (parity, pinned as rejects).
import { describe, it, expect } from 'vitest';
import { compile } from '../src/compile.js';
import { Harness, pad32 } from '../src/evm.js';
import { compileSolidity } from './_solidity.js';
import { functionSelector } from '../src/selectors.js';

const SPDX = '// SPDX-License-Identifier: MIT\npragma solidity 0.8.35;\n';
const sel = (s: string) => '0x' + functionSelector(s);
const W = (n: number | bigint) => pad32(BigInt(n));
const EN = `enum Color { Red, Green, Blue }`;

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

describe('A-LIT-RESID(enum) lift - enum array literals self-type byte-identical to solc 0.8.35', () => {
  it('abi.encode([Color.Green, cb]) - member + runtime enum, all values incl OOB revert', async () => {
    await diff(
      `${EN}
       @contract class C { @external @pure e(cb: Color): bytes { return abi.encode([Color.Green, cb]); } }`,
      `enum Color { Red, Green, Blue }
       contract C { function e(Color cb) external pure returns(bytes memory){ return abi.encode([Color.Green, cb]); } }`,
      [['e(uint8)', W(0)], ['e(uint8)', W(1)], ['e(uint8)', W(2)], ['e(uint8)', W(5)]],
    );
  });

  it('abi.encodePacked([Color.Green, cb]) - packed still pads array elements to 32 bytes', async () => {
    await diff(
      `${EN}
       @contract class C { @external @pure e(cb: Color): bytes { return abi.encodePacked([Color.Green, cb]); } }`,
      `enum Color { Red, Green, Blue }
       contract C { function e(Color cb) external pure returns(bytes memory){ return abi.encodePacked([Color.Green, cb]); } }`,
      [['e(uint8)', W(0)], ['e(uint8)', W(2)]],
    );
  });

  it('3-element order + all-const + single-element', async () => {
    await diff(
      `${EN}
       @contract class C {
         @external @pure a(cb: Color): bytes { return abi.encode([cb, Color.Blue, Color.Red]); }
         @external @pure b(): bytes { return abi.encode([Color.Red, Color.Green, Color.Blue]); }
         @external @pure c(): bytes { return abi.encode([Color.Green]); } }`,
      `enum Color { Red, Green, Blue }
       contract C {
         function a(Color cb) external pure returns(bytes memory){ return abi.encode([cb, Color.Blue, Color.Red]); }
         function b() external pure returns(bytes memory){ return abi.encode([Color.Red, Color.Green, Color.Blue]); }
         function c() external pure returns(bytes memory){ return abi.encode([Color.Green]); } }`,
      [['a(uint8)', W(1)], ['b()', ''], ['c()', '']],
    );
  });

  it('ternary over enum array literals c ? [Red,Blue] : [Green,cb]', async () => {
    await diff(
      `${EN}
       @contract class C { @external @pure e(c: bool, cb: Color): bytes { return abi.encode(c ? [Color.Red, Color.Blue] : [Color.Green, cb]); } }`,
      `enum Color { Red, Green, Blue }
       contract C { function e(bool c, Color cb) external pure returns(bytes memory){ return abi.encode(c ? [Color.Red, Color.Blue] : [Color.Green, cb]); } }`,
      [['e(bool,uint8)', W(1) + W(2)], ['e(bool,uint8)', W(0) + W(2)]],
    );
  });

  it('boundary: different enums / enum+int have no common type -> reject (parity)', () => {
    expect(rejects(`${EN} enum St { Off, On } @contract class C { @external @pure f(): bytes { return abi.encode([Color.Green, St.On]); } }`)).toBe(true);
    expect(rejects(`${EN} @contract class C { @external @pure f(): bytes { return abi.encode([Color.Green, 1n]); } }`)).toBe(true);
    // same-enum self-types (the lift)
    expect(rejects(`${EN} @contract class C { @external @pure f(): bytes { return abi.encode([Color.Green, Color.Red]); } }`)).toBe(false);
  });
});
